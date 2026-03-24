//! iOS FFI layer — exposes three C-callable functions so that the Swift
//! `NodeService` can drive the zerox1-node in-process without spawning a
//! subprocess (which is not permitted on iOS).
//!
//! Compile with `--features ios-ffi`.  The resulting `staticlib` is linked
//! into the Xcode project; the symbols are declared in
//! `Zerox1-Bridging-Header.h`.

#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::missing_safety_doc)]

use clap::Parser as _;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use ed25519_dalek::SigningKey;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static IS_RUNNING: AtomicBool = AtomicBool::new(false);

/// Holds the tokio `Runtime` that drives the node.  Dropping (or explicitly
/// shutting down) the runtime cancels all tasks, which stops the node.
static RUNTIME: Mutex<Option<tokio::runtime::Runtime>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a (possibly null) C string pointer to an `Option<&str>`.
///
/// # Safety
/// `ptr` must be either null or a valid NUL-terminated C string.
unsafe fn cstr_opt<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        None
    } else {
        // SAFETY: caller guarantees the pointer is valid and NUL-terminated.
        unsafe { CStr::from_ptr(ptr) }.to_str().ok()
    }
}

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

/// Start the zerox1 node in a background tokio runtime.
///
/// Returns `0` on success (or if already running), `-1` on failure.
///
/// # Parameters
/// - `data_dir`     — writable directory for identity key, logs, etc.
/// - `api_addr`     — HTTP API listen address (e.g. `"127.0.0.1:9090"`).
/// - `api_secret`   — bearer token for authenticated API routes (nullable).
/// - `identity_key` — base58-encoded 32-byte Ed25519 secret key (nullable;
///                    generates / loads from `data_dir/identity.key` if null).
/// - `relay_addr`   — libp2p circuit-relay multiaddr (nullable).
/// - `agent_name`   — human-readable display name (nullable → empty string).
/// - `rpc_url`      — Solana RPC endpoint (nullable → mainnet default).
///
/// # Safety
/// All non-null pointer arguments must point to valid NUL-terminated C strings
/// that remain valid for the duration of this call.
#[no_mangle]
pub extern "C" fn zerox1_node_start(
    data_dir: *const c_char,
    api_addr: *const c_char,
    api_secret: *const c_char,
    identity_key: *const c_char,
    relay_addr: *const c_char,
    agent_name: *const c_char,
    rpc_url: *const c_char,
) -> i32 {
    // Already running — idempotent.
    if IS_RUNNING.load(Ordering::SeqCst) {
        return 0;
    }

    // ── Parse C strings while we're still on the Swift/ObjC thread ─────────
    // SAFETY: Swift guarantees these are valid NUL-terminated strings (or null)
    // for the duration of the call.
    let data_dir_str = unsafe { cstr_opt(data_dir) }
        .unwrap_or(".")
        .to_string();
    let api_addr_str = unsafe { cstr_opt(api_addr) }
        .unwrap_or("127.0.0.1:9090")
        .to_string();
    let api_secret_str = unsafe { cstr_opt(api_secret) }.map(str::to_string);
    let identity_key_str = unsafe { cstr_opt(identity_key) }.map(str::to_string);
    let relay_addr_str = unsafe { cstr_opt(relay_addr) }.map(str::to_string);
    let agent_name_str = unsafe { cstr_opt(agent_name) }
        .unwrap_or("")
        .to_string();
    let rpc_url_str = unsafe { cstr_opt(rpc_url) }
        .unwrap_or("https://api.mainnet-beta.solana.com")
        .to_string();

    // ── Build tokio runtime ─────────────────────────────────────────────────
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("[zerox1-ffi] failed to build tokio runtime: {e}");
            return -1;
        }
    };

    // ── Spawn the node task ─────────────────────────────────────────────────
    rt.spawn(async move {
        // -- Build clap Config from defaults + explicit overrides ------------
        let mut args: Vec<&str> = vec![
            "zerox1-node",
            "--api-addr",
            &api_addr_str,
            "--agent-name",
            &agent_name_str,
            "--rpc-url",
            &rpc_url_str,
        ];

        // Keep owned Strings alive until after try_parse_from returns.
        let relay_owned: Option<String> = relay_addr_str.clone();
        if let Some(ref r) = relay_owned {
            args.push("--relay-addr");
            args.push(r.as_str());
        }

        let keypair_path_str = format!("{}/identity.key", data_dir_str);
        args.push("--keypair-path");
        args.push(&keypair_path_str);

        let log_dir_str = data_dir_str.clone();
        args.push("--log-dir");
        args.push(&log_dir_str);

        let mut config = match crate::config::Config::try_parse_from(args) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[zerox1-ffi] config parse error: {e}");
                IS_RUNNING.store(false, Ordering::SeqCst);
                return;
            }
        };

        // Override fields that clap can't set via args (Option<String> fields
        // whose env vars we don't want to rely on in the FFI path).
        if let Some(secret) = api_secret_str {
            config.api_secret = Some(secret);
        }
        config.keypair_path = PathBuf::from(&keypair_path_str);

        // -- Resolve / generate identity ------------------------------------
        let identity = if let Some(ref b58) = identity_key_str {
            // Decode base58 → 32-byte secret.
            match bs58::decode(b58).into_vec() {
                Ok(bytes) if bytes.len() == 32 => {
                    let arr: [u8; 32] = bytes.try_into().unwrap();
                    let sk = SigningKey::from_bytes(&arr);
                    let id = crate::identity::AgentIdentity::from_signing_key(sk);
                    // Persist so load_or_generate works on subsequent launches.
                    if let Err(e) = id.save(&config.keypair_path) {
                        tracing::warn!("[zerox1-ffi] could not save identity key: {e}");
                    }
                    id
                }
                Ok(_) => {
                    eprintln!("[zerox1-ffi] identity_key decoded to wrong length (expected 32 bytes)");
                    IS_RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
                Err(e) => {
                    eprintln!("[zerox1-ffi] identity_key base58 decode failed: {e}");
                    IS_RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
            }
        } else {
            match crate::identity::AgentIdentity::load_or_generate(&config.keypair_path) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("[zerox1-ffi] identity load/generate failed: {e}");
                    IS_RUNNING.store(false, Ordering::SeqCst);
                    return;
                }
            }
        };

        // -- Run the node (blocks until shutdown) ---------------------------
        if let Err(e) = crate::run_from_parts(config, identity).await {
            eprintln!("[zerox1-ffi] node exited with error: {e}");
        }

        IS_RUNNING.store(false, Ordering::SeqCst);
    });

    // Store the runtime so it stays alive.  Dropping it would cancel all tasks.
    *RUNTIME.lock().unwrap() = Some(rt);
    IS_RUNNING.store(true, Ordering::SeqCst);
    0
}

/// Stop the node by dropping (shutting down) the tokio runtime.
///
/// Blocks up to 3 seconds for graceful shutdown, then forcibly terminates.
/// Returns `0`.
#[no_mangle]
pub extern "C" fn zerox1_node_stop() -> i32 {
    if let Some(rt) = RUNTIME.lock().unwrap().take() {
        rt.shutdown_timeout(std::time::Duration::from_secs(3));
    }
    IS_RUNNING.store(false, Ordering::SeqCst);
    0
}

/// Returns `1` if the node is currently running, `0` otherwise.
#[no_mangle]
pub extern "C" fn zerox1_node_is_running() -> i32 {
    IS_RUNNING.load(Ordering::SeqCst) as i32
}
