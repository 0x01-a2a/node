use clap::Parser;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let raw: Vec<String> = std::env::args().collect();

    match raw.get(1).map(|s| s.as_str()) {
        Some("start")            => daemon_start(&raw),
        Some("stop")             => daemon_stop(&raw),
        Some("status")           => daemon_status(&raw),
        Some("install-service")  => install_service(&raw),
        Some("uninstall-service")=> uninstall_service(&raw),
        _                        => run_foreground(),
    }
}

// ── Foreground (SDK path, Docker, systemd ExecStart) ─────────────────────────

fn run_foreground() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zerox1_node=info,libp2p=warn".parse().unwrap()),
        )
        .init();

    let config = zerox1_node::config::Config::parse();
    let identity =
        zerox1_node::identity::AgentIdentity::load_or_generate(&config.keypair_path)?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(zerox1_node::run_from_parts(config, identity))
}

// ── Shared helpers ───────────────────────────────────────────────────────────

/// Extract `--flag VALUE` or `--flag=VALUE` from a raw arg list.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let eq_prefix = format!("{flag}=");
    for (i, a) in args.iter().enumerate() {
        if a == flag {
            return args.get(i + 1).map(|s| s.as_str());
        }
        if let Some(v) = a.strip_prefix(&eq_prefix) {
            return Some(v);
        }
    }
    None
}

/// Home directory via $HOME / USERPROFILE, no extra deps.
fn home_dir() -> PathBuf {
    #[cfg(unix)]
    {
        std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
    }
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOMEPATH"))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\"))
    }
}

/// Default log/data directory: ~/.zerox1
fn default_data_dir() -> PathBuf {
    home_dir().join(".zerox1")
}

fn pid_file(log_dir: &std::path::Path) -> PathBuf {
    log_dir.join("zerox1-node.pid")
}

fn node_log_file(log_dir: &std::path::Path) -> PathBuf {
    log_dir.join("zerox1-node.log")
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(pid: u32) -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()))
        .unwrap_or(false)
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> anyhow::Result<()> {
    if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } != 0 {
        anyhow::bail!("kill({pid}, SIGTERM) failed: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_sigterm(pid: u32) -> anyhow::Result<()> {
    std::process::Command::new("taskkill")
        .args(["/PID", &pid.to_string()])
        .status()?;
    Ok(())
}

/// Poll the API port with a minimal HTTP/1.0 probe until it responds or timeout.
fn wait_for_api(host: &str, timeout: Duration) {
    use std::io::{Read, Write};
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(mut s) = std::net::TcpStream::connect(host) {
            let req = format!("GET /health HTTP/1.0\r\nHost: {host}\r\n\r\n");
            if s.write_all(req.as_bytes()).is_ok() {
                let mut buf = [0u8; 12];
                if s.read(&mut buf).is_ok() && buf.starts_with(b"HTTP/1") {
                    return;
                }
            }
        }
        if Instant::now() >= deadline {
            return;
        }
        eprint!(".");
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// Build the one-click dashboard connect URL from the persisted token.
fn build_connect_url(log_dir: &std::path::Path, api_addr: &str) -> Option<String> {
    use base64::Engine as _;
    let token = std::fs::read_to_string(log_dir.join("dashboard_token")).ok()?;
    let node_url = format!(
        "http://{}",
        api_addr.replace("0.0.0.0", "localhost").replace("127.0.0.1", "localhost")
    );
    let payload = format!("{}|{}", node_url, token.trim());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
    Some(format!("https://dashboard.0x01.world/connect?c={encoded}"))
}

// ── zerox1-node start ────────────────────────────────────────────────────────

fn daemon_start(raw: &[String]) -> anyhow::Result<()> {
    let fwd: Vec<&str> = raw.iter().skip(2).map(|s| s.as_str()).collect();

    let log_dir = PathBuf::from(flag_value(raw, "--log-dir").unwrap_or("."));
    std::fs::create_dir_all(&log_dir)?;

    let pf = pid_file(&log_dir);
    let lf = node_log_file(&log_dir);

    if pf.exists() {
        let existing = std::fs::read_to_string(&pf).unwrap_or_default();
        if let Ok(pid) = existing.trim().parse::<u32>() {
            if process_alive(pid) {
                eprintln!(
                    "zerox1-node is already running (PID {pid}).\n\
                     Run 'zerox1-node stop --log-dir {}' to stop it first.",
                    log_dir.display()
                );
                std::process::exit(1);
            }
        }
        let _ = std::fs::remove_file(&pf);
    }

    let log_out = std::fs::OpenOptions::new()
        .create(true).append(true).open(&lf)
        .map_err(|e| anyhow::anyhow!("Cannot open log file {}: {e}", lf.display()))?;
    let log_err = log_out.try_clone()?;

    let exe = std::env::current_exe()?;
    let child = std::process::Command::new(&exe)
        .args(&fwd)
        .stdin(std::process::Stdio::null())
        .stdout(log_out)
        .stderr(log_err)
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn node: {e}"))?;

    let pid = child.id();
    std::mem::forget(child);
    std::fs::write(&pf, pid.to_string())?;

    let api_addr = flag_value(raw, "--api-addr").unwrap_or("127.0.0.1:9090");
    let poll_host = api_addr.replace("0.0.0.0", "127.0.0.1");

    eprint!("Starting node (PID {pid})");
    wait_for_api(&poll_host, Duration::from_secs(20));
    eprintln!();

    print_startup_box(pid, &lf, &log_dir, api_addr, false);
    Ok(())
}

// ── zerox1-node stop ─────────────────────────────────────────────────────────

fn daemon_stop(raw: &[String]) -> anyhow::Result<()> {
    let log_dir = PathBuf::from(flag_value(raw, "--log-dir").unwrap_or("."));
    let pf = pid_file(&log_dir);

    if !pf.exists() {
        eprintln!("No PID file at {}. Is the node running as a daemon?", pf.display());
        std::process::exit(1);
    }

    let pid: u32 = std::fs::read_to_string(&pf)?
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("Malformed PID file"))?;

    if !process_alive(pid) {
        eprintln!("Process {pid} is not running (stale PID file). Cleaning up.");
        let _ = std::fs::remove_file(&pf);
        std::process::exit(1);
    }

    send_sigterm(pid)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && process_alive(pid) {
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = std::fs::remove_file(&pf);

    if process_alive(pid) {
        eprintln!("Node (PID {pid}) did not exit in 5 s. Sending SIGKILL.");
        #[cfg(unix)]
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL); }
    } else {
        println!("Node stopped (PID {pid}).");
    }
    Ok(())
}

// ── zerox1-node status ───────────────────────────────────────────────────────

fn daemon_status(raw: &[String]) -> anyhow::Result<()> {
    let log_dir = PathBuf::from(flag_value(raw, "--log-dir").unwrap_or("."));
    let pf = pid_file(&log_dir);

    if !pf.exists() {
        println!("zerox1-node: stopped");
        return Ok(());
    }

    match std::fs::read_to_string(&pf).unwrap_or_default().trim().parse::<u32>() {
        Ok(pid) if process_alive(pid) => {
            let api_addr = flag_value(raw, "--api-addr").unwrap_or("127.0.0.1:9090");
            println!("zerox1-node: running (PID {pid})");
            println!("  Logs: {}", node_log_file(&log_dir).display());
            if let Some(url) = build_connect_url(&log_dir, api_addr) {
                println!("  Dashboard: {url}");
            }
        }
        Ok(pid) => {
            println!("zerox1-node: stopped (stale PID {pid})");
            let _ = std::fs::remove_file(&pf);
        }
        Err(_) => println!("zerox1-node: unknown state (malformed PID file)"),
    }
    Ok(())
}

// ── zerox1-node install-service ──────────────────────────────────────────────
//
//   zerox1-node install-service [--log-dir PATH] [--system] [all node flags]
//
//   Writes a systemd (Linux) or launchd (macOS) service unit that runs
//   zerox1-node on boot with auto-restart, then enables and starts it.
//   Default: user-level service (no root required).
//   --system: system-wide service (requires root / sudo).
//
//   The service uses the current executable path so it works correctly with
//   per-user npm installs, nvm paths, etc.

fn install_service(raw: &[String]) -> anyhow::Result<()> {
    // Strip "install-service" and "--system" from the forwarded args.
    let is_system = raw.iter().any(|a| a == "--system");
    let fwd: Vec<&str> = raw.iter().skip(2)
        .filter(|a| *a != "--system")
        .map(|s| s.as_str())
        .collect();

    let exe = std::env::current_exe()
        .map_err(|e| anyhow::anyhow!("Cannot determine executable path: {e}"))?;
    let exe_str = exe.to_string_lossy();

    // Resolve log_dir: explicit flag → default ~/.zerox1
    let log_dir = PathBuf::from(
        flag_value(raw, "--log-dir")
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_data_dir().to_string_lossy().to_string())
    );
    std::fs::create_dir_all(&log_dir)?;

    // Build the forward arg list, injecting log-dir if the caller didn't supply it.
    let mut svc_args: Vec<String> = fwd.iter().map(|s| s.to_string()).collect();
    if flag_value(raw, "--log-dir").is_none() {
        svc_args.push("--log-dir".to_string());
        svc_args.push(log_dir.to_string_lossy().to_string());
    }

    // Pick API addr from args (for the readiness probe after start).
    let api_addr = flag_value(raw, "--api-addr").unwrap_or("127.0.0.1:9090");

    #[cfg(target_os = "linux")]
    {
        install_service_systemd(&exe_str, &svc_args, &log_dir, api_addr, is_system)?;
    }
    #[cfg(target_os = "macos")]
    {
        install_service_launchd(&exe_str, &svc_args, &log_dir, api_addr, is_system)?;
    }
    #[cfg(windows)]
    {
        install_service_windows(&exe_str, &svc_args, &log_dir, api_addr)?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        anyhow::bail!(
            "install-service is not supported on this platform.\n\
             Use 'zerox1-node start' for background operation instead."
        );
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_service_systemd(
    exe: &str,
    svc_args: &[String],
    log_dir: &std::path::Path,
    api_addr: &str,
    system: bool,
) -> anyhow::Result<()> {
    let exec_start = std::iter::once(shell_escape(exe))
        .chain(svc_args.iter().map(|s| shell_escape(s)))
        .collect::<Vec<_>>()
        .join(" ");

    let wants_by = if system {
        ("network-online.target", "multi-user.target")
    } else {
        ("network-online.target", "default.target")
    };

    let unit = format!(
        "[Unit]\n\
         Description=0x01 Mesh Node\n\
         After={}\n\
         Wants={}\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy={}\n",
        wants_by.0, wants_by.0, exec_start, wants_by.1
    );

    let unit_dir = if system {
        PathBuf::from("/etc/systemd/system")
    } else {
        home_dir().join(".config/systemd/user")
    };
    std::fs::create_dir_all(&unit_dir)?;
    let unit_path = unit_dir.join("zerox1-node.service");
    std::fs::write(&unit_path, &unit)?;
    println!("Wrote {}", unit_path.display());

    let base = if system { vec!["systemctl"] } else { vec!["systemctl", "--user"] };

    // daemon-reload so systemd sees the new unit.
    run_cmd(&base, &["daemon-reload"], "systemctl daemon-reload failed")?;
    run_cmd(&base, &["enable", "zerox1-node.service"], "systemctl enable failed")?;
    run_cmd(&base, &["start", "zerox1-node.service"], "systemctl start failed")?;

    println!("Service enabled and started.");
    finish_install(log_dir, api_addr, true);
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_service_launchd(
    exe: &str,
    svc_args: &[String],
    log_dir: &std::path::Path,
    api_addr: &str,
    system: bool,
) -> anyhow::Result<()> {
    let log_path = node_log_file(log_dir).to_string_lossy().to_string();

    // Build the <array> of ProgramArguments entries.
    let mut prog_args = format!("        <string>{}</string>\n", xml_escape(exe));
    for a in svc_args {
        prog_args.push_str(&format!("        <string>{}</string>\n", xml_escape(a)));
    }

    let label = "world.0x01.zerox1-node";
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
             <key>Label</key>\n\
             <string>{label}</string>\n\
             <key>ProgramArguments</key>\n\
             <array>\n\
         {prog_args}\
             </array>\n\
             <key>KeepAlive</key>\n\
             <true/>\n\
             <key>RunAtLoad</key>\n\
             <true/>\n\
             <key>StandardOutPath</key>\n\
             <string>{log_path}</string>\n\
             <key>StandardErrorPath</key>\n\
             <string>{log_path}</string>\n\
         </dict>\n\
         </plist>\n"
    );

    let plist_dir = if system {
        PathBuf::from("/Library/LaunchDaemons")
    } else {
        home_dir().join("Library/LaunchAgents")
    };
    std::fs::create_dir_all(&plist_dir)?;
    let plist_path = plist_dir.join(format!("{label}.plist"));
    std::fs::write(&plist_path, &plist)?;
    println!("Wrote {}", plist_path.display());

    // Unload any stale copy first (ignore errors — it may not have been loaded).
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &plist_path.to_string_lossy()])
        .status();

    std::process::Command::new("launchctl")
        .args(["load", "-w", &plist_path.to_string_lossy()])
        .status()
        .map_err(|e| anyhow::anyhow!("launchctl load failed: {e}"))?;

    println!("Service loaded and will run at login.");
    finish_install(log_dir, api_addr, false);
    Ok(())
}

#[cfg(windows)]
fn install_service_windows(
    exe: &str,
    svc_args: &[String],
    log_dir: &std::path::Path,
    api_addr: &str,
) -> anyhow::Result<()> {
    // Build binPath — sc.exe needs the full command in a single string.
    let bin_path = std::iter::once(format!("\"{}\"", exe))
        .chain(svc_args.iter().map(|a| {
            if a.contains(' ') { format!("\"{}\"", a) } else { a.clone() }
        }))
        .collect::<Vec<_>>()
        .join(" ");

    // Remove stale service if present (ignore error).
    let _ = std::process::Command::new("sc.exe")
        .args(["stop", "zerox1-node"])
        .status();
    let _ = std::process::Command::new("sc.exe")
        .args(["delete", "zerox1-node"])
        .status();
    std::thread::sleep(Duration::from_millis(1000));

    let status = std::process::Command::new("sc.exe")
        .args(["create", "zerox1-node",
               "binPath=", &bin_path,
               "DisplayName=", "0x01 Mesh Node",
               "start=", "auto"])
        .status()
        .map_err(|e| anyhow::anyhow!("sc.exe create failed: {e}"))?;

    if !status.success() {
        anyhow::bail!(
            "sc.exe create failed. Run this command as Administrator."
        );
    }

    std::process::Command::new("sc.exe")
        .args(["start", "zerox1-node"])
        .status()
        .map_err(|e| anyhow::anyhow!("sc.exe start failed: {e}"))?;

    println!("Windows Service 'zerox1-node' created and started.");
    finish_install(log_dir, api_addr, false);
    Ok(())
}

/// Wait for API readiness then print the final info box.
fn finish_install(log_dir: &std::path::Path, api_addr: &str, is_systemd: bool) {
    let poll_host = api_addr.replace("0.0.0.0", "127.0.0.1");
    eprint!("Waiting for node to be ready");
    wait_for_api(&poll_host, Duration::from_secs(20));
    eprintln!();

    let lf = node_log_file(log_dir);
    let svc_note = if is_systemd {
        "  Logs:      journalctl --user -u zerox1-node -f".to_string()
    } else {
        format!("  Logs:      {}", lf.display())
    };

    if let Some(url) = build_connect_url(log_dir, api_addr) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  Service:   zerox1-node (auto-restarts on crash/reboot)");
        println!("{svc_note}");
        println!("  Dashboard: {url}");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    } else {
        println!("Node service is running. {svc_note}");
    }
}

// ── zerox1-node uninstall-service ────────────────────────────────────────────

fn uninstall_service(raw: &[String]) -> anyhow::Result<()> {
    let is_system = raw.iter().any(|a| a == "--system");

    #[cfg(target_os = "linux")]
    uninstall_service_systemd(is_system)?;

    #[cfg(target_os = "macos")]
    uninstall_service_launchd(is_system)?;

    #[cfg(windows)]
    uninstall_service_windows()?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = is_system;
        anyhow::bail!("uninstall-service is not supported on this platform.");
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_service_systemd(system: bool) -> anyhow::Result<()> {
    let base = if system { vec!["systemctl"] } else { vec!["systemctl", "--user"] };

    // Disable and stop (ignore errors — service may already be stopped).
    let _ = run_cmd(&base, &["disable", "--now", "zerox1-node.service"], "");

    let unit_path = if system {
        PathBuf::from("/etc/systemd/system/zerox1-node.service")
    } else {
        home_dir().join(".config/systemd/user/zerox1-node.service")
    };

    if unit_path.exists() {
        std::fs::remove_file(&unit_path)?;
        println!("Removed {}", unit_path.display());
    } else {
        println!("Unit file not found at {} — nothing to remove.", unit_path.display());
    }

    let _ = run_cmd(&base, &["daemon-reload"], "");
    println!("Service uninstalled.");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_service_launchd(system: bool) -> anyhow::Result<()> {
    let label = "world.0x01.zerox1-node";
    let plist_dir = if system {
        PathBuf::from("/Library/LaunchDaemons")
    } else {
        home_dir().join("Library/LaunchAgents")
    };
    let plist_path = plist_dir.join(format!("{label}.plist"));

    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .args(["unload", "-w", &plist_path.to_string_lossy()])
            .status();
        std::fs::remove_file(&plist_path)?;
        println!("Removed {} and unloaded service.", plist_path.display());
    } else {
        println!("Plist not found at {} — nothing to remove.", plist_path.display());
    }
    Ok(())
}

#[cfg(windows)]
fn uninstall_service_windows() -> anyhow::Result<()> {
    let _ = std::process::Command::new("sc.exe").args(["stop", "zerox1-node"]).status();
    std::thread::sleep(Duration::from_millis(1000));
    std::process::Command::new("sc.exe")
        .args(["delete", "zerox1-node"])
        .status()
        .map_err(|e| anyhow::anyhow!("sc.exe delete failed: {e}"))?;
    println!("Windows Service 'zerox1-node' removed.");
    Ok(())
}

// ── Formatting helpers ───────────────────────────────────────────────────────

fn print_startup_box(pid: u32, lf: &std::path::Path, log_dir: &std::path::Path, api_addr: &str, _is_service: bool) {
    if let Some(url) = build_connect_url(log_dir, api_addr) {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  PID:       {pid}");
        println!("  Logs:      {}", lf.display());
        println!("  Dashboard: {url}");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    } else {
        println!("Node started (PID {pid}). Logs: {}", lf.display());
    }
}

/// Run a sub-process composed of a prefix slice + extra args.
#[cfg(target_os = "linux")]
fn run_cmd(prefix: &[&str], args: &[&str], err_msg: &str) -> anyhow::Result<()> {
    let (cmd, rest) = prefix.split_first().expect("non-empty prefix");
    let full: Vec<&str> = rest.iter().chain(args.iter()).copied().collect();
    let status = std::process::Command::new(cmd)
        .args(&full)
        .status()
        .map_err(|e| anyhow::anyhow!("{err_msg}: {e}"))?;
    if !status.success() && !err_msg.is_empty() {
        anyhow::bail!("{err_msg} (exit {})", status);
    }
    Ok(())
}

/// Minimal shell escaping for systemd ExecStart: wrap in single-quotes, escape
/// any embedded single-quotes as '\''.
#[cfg(target_os = "linux")]
fn shell_escape(s: &str) -> String {
    if s.contains(|c: char| c.is_ascii_whitespace() || matches!(c, '\'' | '"' | '\\')) {
        format!("'{}'", s.replace('\'', r"'\''"))
    } else {
        s.to_string()
    }
}

/// Minimal XML escaping for launchd plist string values.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
