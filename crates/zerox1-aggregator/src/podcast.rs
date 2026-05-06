//! Podcast production endpoints — produces, clips, and publishes podcast episodes
//! from agent conversation transcripts using ElevenLabs APIs.
//!
//! # Tiers (same gate as LLM proxy)
//! - Free:    generates intro/outro jingle only (ElevenLabs Music). Owner's real audio
//!            from voice note CIDs is used for the conversation body.
//! - Premium: full two-voice recreation via ElevenLabs TTS + Music. Requires ≥500k 01PL.
//!
//! # Endpoints
//! - POST /podcast/produce  — produce a full episode from a transcript
//! - POST /podcast/clip     — generate a short-form video clip with captions
//! - POST /podcast/publish  — publish to RSS feed + Telegram channel
//! - GET  /podcast/episodes — list published episodes for an agent

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::api::AppState;

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ProduceRequest {
    pub title: Option<String>,
    pub tier: Option<String>, // "free" or "premium"
    pub transcript: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ProduceResponse {
    pub episode_id: String,
    pub audio_url: String,
    pub duration_secs: u64,
    pub title: String,
    pub description: String,
    pub tier_used: String,
}

/// POST /podcast/enhance — premium ElevenLabs processing on an uploaded MP3.
/// Pipeline: voice isolation → text-to-dialogue recreation → music jingle.
#[derive(Debug, Deserialize)]
pub struct EnhanceRequest {
    /// Episode ID (must exist from a prior produce call, or new upload).
    pub episode_id: Option<String>,
    /// Base64-encoded MP3 audio to enhance (uploaded from phone).
    pub audio_b64: Option<String>,
    /// Transcript for text-to-dialogue recreation.
    pub transcript: Option<serde_json::Value>,
    /// What to do: "clean" (isolation only), "polish" (full text-to-dialogue),
    /// "all" (clean + polish + music). Default: "all".
    pub mode: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnhanceResponse {
    pub episode_id: String,
    pub audio_url: String,
    pub duration_secs: u64,
    pub enhancements_applied: Vec<String>,
}

/// POST /podcast/translate — dub an episode into another language.
#[derive(Debug, Deserialize)]
pub struct TranslateRequest {
    /// Episode ID to translate (must have audio in blob storage).
    pub episode_id: String,
    /// Target language code (e.g. "es", "ja", "hi", "zh").
    pub target_language: String,
}

#[derive(Debug, Serialize)]
pub struct TranslateResponse {
    pub episode_id: String,
    pub translated_audio_url: String,
    pub target_language: String,
    pub duration_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct ClipRequest {
    pub episode_id: String,
    pub start_secs: u64,
    pub end_secs: u64,
    /// Background video: "particles", "streaks", "gradient", "flow", "neon".
    /// Defaults to "particles".
    pub background: Option<String>,
    /// Transcript for burned-in captions. If omitted, no captions.
    pub transcript: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct ClipResponse {
    pub clip_url: String,
    pub duration_secs: u64,
    pub caption_srt: String,
}

#[derive(Debug, Deserialize)]
pub struct PublishRequest {
    pub episode_id: String,
    pub publish_rss: Option<bool>,
    pub publish_telegram: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct PublishResponse {
    pub rss_url: Option<String>,
    pub telegram_message_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct Episode {
    pub episode_id: String,
    pub title: String,
    pub audio_url: String,
    pub duration_secs: u64,
    pub published_at: u64,
    pub tier_used: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn gen_episode_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

/// Extract agent_id from Authorization header (Bearer token = node API token).
/// In production this would validate the token against the store; for now we
/// extract the agent_id from X-Agent-Id header (same pattern as /llm/chat).
fn extract_agent_id(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("x-agent-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Check if agent holds ≥500k 01PL (premium tier eligible).
/// Uses the shared PlCache from AppState (same cache as llm_proxy).
async fn is_premium_eligible(
    client: &reqwest::Client,
    pl_cache: &crate::llm_proxy::PlCache,
    agent_id: &str,
) -> bool {
    let wallet_b58 = match hex_to_base58(agent_id) {
        Some(w) => w,
        None => return false,
    };

    // Check the shared cache directly via its inner Arc<Mutex<HashMap>>.
    {
        let map = pl_cache.0.lock().unwrap();
        if let Some((eligible, ts)) = map.get(&wallet_b58) {
            if ts.elapsed() < std::time::Duration::from_secs(300) {
                return *eligible;
            }
        }
    }

    let eligible = check_01pl_balance(client, &wallet_b58).await;

    {
        let mut map = pl_cache.0.lock().unwrap();
        map.insert(wallet_b58, (eligible, std::time::Instant::now()));
    }

    eligible
}

fn hex_to_base58(hex_str: &str) -> Option<String> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(bs58::encode(&bytes).into_string())
}

async fn check_01pl_balance(client: &reqwest::Client, wallet_b58: &str) -> bool {
    const SOL_RPC: &str = "https://api.mainnet-beta.solana.com";
    const PILOT_TOKEN_MINT: &str = "2MchUMEvadoTbSvC4b1uLAmEhv8Yz8ngwEt24q21BAGS";
    const PRESENCE_THRESHOLD: u64 = 500_000_000_000;

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getTokenAccountsByOwner",
        "params": [
            wallet_b58,
            { "mint": PILOT_TOKEN_MINT },
            { "encoding": "jsonParsed" }
        ]
    });

    let resp = match client
        .post(SOL_RPC)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return false, // fail open = false for premium (safe default)
    };

    let data: serde_json::Value = match resp.json().await {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Parse token balance from the RPC response.
    let accounts = data["result"]["value"].as_array();
    if let Some(accounts) = accounts {
        for acc in accounts {
            if let Some(amount_str) = acc["account"]["data"]["parsed"]["info"]["tokenAmount"]
                ["amount"]
                .as_str()
            {
                if let Ok(amount) = amount_str.parse::<u64>() {
                    if amount >= PRESENCE_THRESHOLD {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ── ElevenLabs API calls ──────────────────────────────────────────────────────

/// Generate a short jingle via ElevenLabs Music API.
/// Returns the audio bytes (MP3).
async fn generate_jingle(
    client: &reqwest::Client,
    api_key: &str,
    prompt: &str,
    duration_ms: u64,
) -> Result<Vec<u8>, String> {
    let resp = client
        .post("https://api.elevenlabs.io/v1/music")
        .header("xi-api-key", api_key)
        .json(&json!({
            "prompt": prompt,
            "duration_ms": duration_ms,
            "output_format": "mp3_44100_128"
        }))
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|e| format!("ElevenLabs Music API error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("ElevenLabs Music API returned {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read music response: {e}"))
}

/// Generate TTS audio via ElevenLabs TTS API (premium tier only).
/// Returns MP3 bytes.
async fn generate_tts(
    client: &reqwest::Client,
    api_key: &str,
    text: &str,
    voice_id: &str,
) -> Result<Vec<u8>, String> {
    let url = format!(
        "https://api.elevenlabs.io/v1/text-to-speech/{}",
        voice_id
    );

    let resp = client
        .post(&url)
        .header("xi-api-key", api_key)
        .json(&json!({
            "text": text,
            "model_id": "eleven_turbo_v2_5",
            "output_format": "mp3_44100_128"
        }))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("ElevenLabs TTS error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("ElevenLabs TTS returned {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read TTS response: {e}"))
}

/// Voice isolation — remove background noise from audio.
/// POST https://api.elevenlabs.io/v1/audio-isolation/stream
/// Input: multipart form with audio file. Output: cleaned audio bytes.
async fn isolate_voice(
    client: &reqwest::Client,
    api_key: &str,
    audio_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let part = reqwest::multipart::Part::bytes(audio_bytes.to_vec())
        .file_name("audio.mp3")
        .mime_str("audio/mpeg")
        .map_err(|e| format!("Failed to build multipart: {e}"))?;
    let form = reqwest::multipart::Form::new().part("audio", part);

    let resp = client
        .post("https://api.elevenlabs.io/v1/audio-isolation/stream")
        .header("xi-api-key", api_key)
        .multipart(form)
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("Voice isolation error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Voice isolation returned {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read isolation response: {e}"))
}

/// Text-to-Dialogue — generate a full multi-speaker conversation.
/// POST https://api.elevenlabs.io/v1/text-to-dialogue
/// Input: { inputs: [{text, voice_id}], model_id, output_format }
/// Requires: Eleven v3 model, max 2000 chars total, max 10 unique voices.
///
/// Default voices:
///   Host (owner): "CwhRBWXzGAHq8TQ4Fs17" (Roger — laid-back male)
///   Co-host (agent): "EXAVITQu4vr4xnSDxMaL" (Sarah — confident female)
async fn text_to_dialogue(
    client: &reqwest::Client,
    api_key: &str,
    inputs: &[serde_json::Value],
) -> Result<Vec<u8>, String> {
    let resp = client
        .post("https://api.elevenlabs.io/v1/text-to-dialogue")
        .header("xi-api-key", api_key)
        .json(&json!({
            "inputs": inputs,
            "model_id": "eleven_v3",
            "output_format": "mp3_44100_128"
        }))
        .timeout(std::time::Duration::from_secs(120))
        .send()
        .await
        .map_err(|e| format!("Text-to-dialogue error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Text-to-dialogue returned {status}: {body}"));
    }

    resp.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| format!("Failed to read dialogue response: {e}"))
}

/// Dubbing — translate audio to another language preserving voice.
/// POST https://api.elevenlabs.io/v1/dubbing
/// Returns a dubbing project ID; then poll for completion and download.
async fn create_dubbing(
    client: &reqwest::Client,
    api_key: &str,
    audio_bytes: &[u8],
    source_lang: &str,
    target_lang: &str,
) -> Result<String, String> {
    let part = reqwest::multipart::Part::bytes(audio_bytes.to_vec())
        .file_name("episode.mp3")
        .mime_str("audio/mpeg")
        .map_err(|e| format!("Multipart error: {e}"))?;
    let form = reqwest::multipart::Form::new()
        .part("file", part)
        .text("source_lang", source_lang.to_string())
        .text("target_lang", target_lang.to_string())
        .text("num_speakers", "2")
        .text("highest_resolution", "false");

    let resp = client
        .post("https://api.elevenlabs.io/v1/dubbing")
        .header("xi-api-key", api_key)
        .multipart(form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Dubbing create error: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Dubbing returned {status}: {body}"));
    }

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("Parse error: {e}"))?;
    data["dubbing_id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No dubbing_id in response".to_string())
}

/// Poll dubbing status and download when complete.
async fn poll_and_download_dubbing(
    client: &reqwest::Client,
    api_key: &str,
    dubbing_id: &str,
    target_lang: &str,
) -> Result<Vec<u8>, String> {
    // Poll up to 60 times (5s intervals = 5 min max)
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let status_resp = client
            .get(&format!(
                "https://api.elevenlabs.io/v1/dubbing/{}",
                dubbing_id
            ))
            .header("xi-api-key", api_key)
            .send()
            .await
            .map_err(|e| format!("Dubbing poll error: {e}"))?;

        if !status_resp.status().is_success() {
            continue;
        }

        let data: serde_json::Value =
            status_resp.json().await.map_err(|e| format!("Parse: {e}"))?;
        let status = data["status"].as_str().unwrap_or("");

        if status == "dubbed" {
            // Download the dubbed audio
            let dl_resp = client
                .get(&format!(
                    "https://api.elevenlabs.io/v1/dubbing/{}/audio/{}",
                    dubbing_id, target_lang
                ))
                .header("xi-api-key", api_key)
                .send()
                .await
                .map_err(|e| format!("Dubbing download error: {e}"))?;

            return dl_resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| format!("Download error: {e}"));
        } else if status == "failed" {
            return Err("Dubbing failed".to_string());
        }
        // else: still processing, keep polling
    }
    Err("Dubbing timed out after 5 minutes".to_string())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// POST /podcast/produce
pub async fn post_produce(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ProduceRequest>,
) -> impl IntoResponse {
    let agent_id = match extract_agent_id(&headers) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Agent-Id header"})),
            )
                .into_response()
        }
    };

    // Determine tier
    let requested_tier = req.tier.as_deref().unwrap_or("free");
    let tier = if requested_tier == "premium" {
        if is_premium_eligible(&state.http_client, &state.pl_cache, &agent_id).await {
            "premium"
        } else {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({
                    "error": "Premium tier requires ≥500,000 01PL. Hold 01PL or use tier: free.",
                    "required_01pl": 500_000
                })),
            )
                .into_response();
        }
    } else {
        "free"
    };

    let elevenlabs_key = std::env::var("ELEVENLABS_API_KEY").unwrap_or_default();

    let episode_id = gen_episode_id();
    let title = req
        .title
        .unwrap_or_else(|| format!("Episode {}", &episode_id[..8]));

    let blob_dir = match state.blob_dir.as_ref() {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Blob storage not configured"})),
            )
                .into_response()
        }
    };

    // ── Collect audio segments ────────────────────────────────────────────
    // The transcript contains messages with optional audio_uri fields.
    // Download each audio segment to a temp file for FFmpeg concatenation.
    let tmp_dir = blob_dir.join(format!("tmp_podcast_{}", &episode_id));
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        tracing::error!("Failed to create temp dir: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to create temp directory"})),
        )
            .into_response();
    }

    let mut segment_paths: Vec<std::path::PathBuf> = Vec::new();

    // Static jingle (bundled on aggregator filesystem or generated once).
    // For free tier: use a pre-generated static jingle if available, else skip.
    // For premium tier: generate fresh jingle via ElevenLabs.
    let jingle_path = blob_dir.join("podcast_jingle.mp3");
    if tier == "premium" && !elevenlabs_key.is_empty() {
        let jingle_prompt = "Short podcast intro jingle, upbeat and modern, 8 seconds, electronic lo-fi";
        if let Ok(jingle_bytes) =
            generate_jingle(&state.http_client, &elevenlabs_key, jingle_prompt, 8000).await
        {
            let _ = tokio::fs::write(&jingle_path, &jingle_bytes).await;
        }
    }
    if tokio::fs::metadata(&jingle_path).await.is_ok() {
        segment_paths.push(jingle_path.clone());
    }

    // Download/collect conversation audio segments from transcript.
    if let Some(messages) = req.transcript.as_array() {
        for (i, msg) in messages.iter().enumerate() {
            if let Some(audio_url) = msg["audio_uri"].as_str().or(msg["audioUri"].as_str()) {
                if audio_url.is_empty() {
                    continue;
                }
                let seg_path = tmp_dir.join(format!("seg_{:04}.mp3", i));
                // Download from blob storage or local reference
                let url = if audio_url.starts_with("http") {
                    audio_url.to_string()
                } else {
                    // Local file path from the device — the node should have uploaded
                    // it to blob storage before calling produce. Skip if not a URL.
                    continue;
                };
                match state.http_client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        if let Ok(bytes) = resp.bytes().await {
                            let _ = tokio::fs::write(&seg_path, &bytes).await;
                            segment_paths.push(seg_path);
                        }
                    }
                    _ => {
                        tracing::warn!("Failed to download audio segment: {url}");
                    }
                }
            } else if tier == "premium"
                && !elevenlabs_key.is_empty()
                && msg["role"].as_str() == Some("assistant")
            {
                // Premium: generate TTS for agent text lines without audio
                if let Some(text) = msg["text"].as_str() {
                    if text.len() > 10 {
                        let seg_path = tmp_dir.join(format!("seg_{:04}.mp3", i));
                        if let Ok(tts_bytes) = generate_tts(
                            &state.http_client,
                            &elevenlabs_key,
                            text,
                            "EXAVITQu4vr4xnSDxMaL", // Rachel voice
                        )
                        .await
                        {
                            let _ = tokio::fs::write(&seg_path, &tts_bytes).await;
                            segment_paths.push(seg_path);
                        }
                    }
                }
            }
        }
    }

    // Append outro jingle
    if tokio::fs::metadata(&jingle_path).await.is_ok() {
        segment_paths.push(jingle_path);
    }

    // ── Concatenate with FFmpeg ───────────────────────────────────────────
    let output_path = blob_dir.join(format!("podcast_{}.mp3", episode_id));
    let duration_secs: u64;

    if segment_paths.is_empty() {
        // No audio segments — return error
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "No audio segments found in transcript. Record a voice conversation first."})),
        )
            .into_response();
    }

    if segment_paths.len() == 1 {
        // Single segment — just copy it
        let _ = tokio::fs::copy(&segment_paths[0], &output_path).await;
        duration_secs = 30; // estimate
    } else {
        // Build FFmpeg concat file
        let concat_list_path = tmp_dir.join("concat.txt");
        let concat_content: String = segment_paths
            .iter()
            .map(|p| format!("file '{}'\n", p.display()))
            .collect();
        if let Err(e) = tokio::fs::write(&concat_list_path, &concat_content).await {
            tracing::error!("Failed to write concat list: {e}");
            let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "Failed to prepare audio concatenation"})),
            )
                .into_response();
        }

        // Run FFmpeg
        let ffmpeg_result = tokio::process::Command::new("ffmpeg")
            .args([
                "-y",
                "-f", "concat",
                "-safe", "0",
                "-i", concat_list_path.to_str().unwrap_or(""),
                "-c:a", "libmp3lame",
                "-b:a", "128k",
                "-ar", "44100",
                output_path.to_str().unwrap_or(""),
            ])
            .output()
            .await;

        match ffmpeg_result {
            Ok(output) if output.status.success() => {
                tracing::info!("FFmpeg concat succeeded for episode {}", episode_id);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::error!("FFmpeg concat failed: {stderr}");
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "Audio concatenation failed"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!("FFmpeg not found or failed to execute: {e}");
                let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "FFmpeg not available on server. Install ffmpeg to enable podcast production."})),
                )
                    .into_response();
            }
        }

        // Get duration from output file size (rough estimate: 128kbps = 16KB/sec)
        let file_size = tokio::fs::metadata(&output_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        duration_secs = file_size / 16_000;
    }

    // Cleanup temp dir
    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

    let audio_url = format!("https://api.0x01.world/blobs/podcast_{}.mp3", episode_id);

    // Store episode metadata in DB
    state.store.insert_podcast_episode(
        &episode_id,
        &agent_id,
        &title,
        &audio_url,
        duration_secs,
        tier,
    );

    let description = format!("Podcast episode produced by agent {}", &agent_id[..8]);

    (
        StatusCode::OK,
        Json(json!(ProduceResponse {
            episode_id,
            audio_url,
            duration_secs,
            title,
            description,
            tier_used: tier.to_string(),
        })),
    )
        .into_response()
}

/// POST /podcast/clip — generate a vertical video clip (MP4) from a podcast episode.
///
/// Combines:
/// 1. Background loop video from /var/lib/zerox1/podcast-backgrounds/
/// 2. Podcast audio (extracted segment from the episode MP3)
/// 3. Burned-in captions from transcript (if provided)
///
/// Requires FFmpeg on the server.
pub async fn post_clip(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ClipRequest>,
) -> impl IntoResponse {
    let _agent_id = match extract_agent_id(&headers) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Agent-Id header"})),
            )
                .into_response()
        }
    };

    // Validate duration (max 90s)
    if req.end_secs <= req.start_secs || (req.end_secs - req.start_secs) > 90 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Clip duration must be 1-90 seconds"})),
        )
            .into_response();
    }

    let blob_dir = match state.blob_dir.as_ref() {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Blob storage not configured"})),
            )
                .into_response()
        }
    };

    // Find the episode audio — check both produced and enhanced versions
    let audio_path = {
        let enhanced = blob_dir.join(format!("podcast_{}_enhanced.mp3", req.episode_id));
        let produced = blob_dir.join(format!("podcast_{}.mp3", req.episode_id));
        if enhanced.exists() { enhanced } else { produced }
    };

    if !audio_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Episode audio not found. Produce or enhance first."})),
        )
            .into_response();
    }

    // Select background video
    let bg_dir = std::path::PathBuf::from("/var/lib/zerox1/podcast-backgrounds");
    let bg_name = match req.background.as_deref().unwrap_or("particles") {
        "particles" => "01_particles.mp4",
        "streaks"   => "02_streaks.mp4",
        "gradient"  => "03_gradient.mp4",
        "flow"      => "04_flow.mp4",
        "neon"      => "05_neon.mp4",
        _           => "01_particles.mp4",
    };
    let bg_path = bg_dir.join(bg_name);
    if !bg_path.exists() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": format!("Background video '{}' not found on server", bg_name)})),
        )
            .into_response();
    }

    let clip_id = gen_episode_id();
    let duration_secs = req.end_secs - req.start_secs;
    let tmp_dir = blob_dir.join(format!("tmp_clip_{}", clip_id));
    let _ = tokio::fs::create_dir_all(&tmp_dir).await;

    // Step 1: Extract audio segment from the episode
    let segment_path = tmp_dir.join("segment.mp3");
    let extract_result = tokio::process::Command::new("ffmpeg")
        .args([
            "-y",
            "-i", audio_path.to_str().unwrap_or(""),
            "-ss", &req.start_secs.to_string(),
            "-t", &duration_secs.to_string(),
            "-c:a", "copy",
            segment_path.to_str().unwrap_or(""),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    if !matches!(extract_result, Ok(s) if s.success()) {
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to extract audio segment"})),
        )
            .into_response();
    }

    // Step 2: Build caption filter from transcript (if provided)
    let caption_filter = if let Some(ref transcript) = req.transcript {
        build_caption_filter(transcript, req.start_secs, req.end_secs)
    } else {
        String::new()
    };

    // Step 3: Combine background + audio + captions → MP4
    let output_path = blob_dir.join(format!("clip_{}.mp4", clip_id));
    let vf = if caption_filter.is_empty() {
        "null".to_string()
    } else {
        caption_filter
    };

    let clip_result = tokio::process::Command::new("ffmpeg")
        .args([
            "-y",
            "-stream_loop", "-1",
            "-i", bg_path.to_str().unwrap_or(""),
            "-i", segment_path.to_str().unwrap_or(""),
            "-vf", &vf,
            "-shortest",
            "-c:v", "libx264",
            "-preset", "fast",
            "-crf", "23",
            "-c:a", "aac",
            "-b:a", "128k",
            "-movflags", "+faststart",
            output_path.to_str().unwrap_or(""),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    // Cleanup temp dir
    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

    match clip_result {
        Ok(s) if s.success() => {
            let file_size = tokio::fs::metadata(&output_path)
                .await
                .map(|m| m.len())
                .unwrap_or(0);

            let clip_url = format!("https://api.0x01.world/blobs/clip_{}.mp4", clip_id);

            // Generate SRT from transcript
            let srt = if let Some(ref transcript) = req.transcript {
                build_srt(transcript, req.start_secs, req.end_secs)
            } else {
                format!("1\n00:00:00,000 --> 00:00:{:02},000\n[Podcast clip]\n", duration_secs)
            };

            (
                StatusCode::OK,
                Json(json!(ClipResponse {
                    clip_url,
                    duration_secs,
                    caption_srt: srt,
                })),
            )
                .into_response()
        }
        _ => {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "FFmpeg video generation failed"})),
            )
                .into_response()
        }
    }
}

/// POST /podcast/publish
pub async fn post_publish(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<PublishRequest>,
) -> impl IntoResponse {
    let agent_id = match extract_agent_id(&headers) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Agent-Id header"})),
            )
                .into_response()
        }
    };

    let episode = match state.store.get_podcast_episode(&req.episode_id) {
        Some(ep) => ep,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Episode not found"})),
            )
                .into_response()
        }
    };

    let mut rss_url: Option<String> = None;
    let mut telegram_message_id: Option<i64> = None;

    // Publish to RSS
    if req.publish_rss.unwrap_or(false) {
        rss_url = Some(format!(
            "https://api.0x01.world/podcast/{}/feed.xml",
            agent_id
        ));
        state
            .store
            .mark_podcast_published(&req.episode_id, "rss");
        // TODO: generate/update actual RSS XML in blob storage
    }

    // Publish to Telegram
    if req.publish_telegram.unwrap_or(false) {
        // TODO: send audio to agent's Telegram channel via Bot API
        // For now, mark as published and return a placeholder message_id
        telegram_message_id = Some(0);
        state
            .store
            .mark_podcast_published(&req.episode_id, "telegram");
    }

    let _ = episode; // suppress unused warning

    (
        StatusCode::OK,
        Json(json!(PublishResponse {
            rss_url,
            telegram_message_id,
        })),
    )
        .into_response()
}

/// GET /podcast/episodes?agent_id=hex64
pub async fn get_episodes(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let agent_id = match params.get("agent_id") {
        Some(id) if id.len() == 64 => id.clone(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "agent_id query parameter required (64 hex chars)"})),
            )
                .into_response()
        }
    };

    let episodes = state.store.list_podcast_episodes(&agent_id);

    (StatusCode::OK, Json(json!({ "episodes": episodes }))).into_response()
}

/// POST /podcast/enhance — premium ElevenLabs processing pipeline.
/// Requires 01PL. Applies: voice isolation → text-to-dialogue → music.
pub async fn post_enhance(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<EnhanceRequest>,
) -> impl IntoResponse {
    let agent_id = match extract_agent_id(&headers) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Agent-Id header"})),
            )
                .into_response()
        }
    };

    // Premium only — check USDC subscription first, then 01PL balance
    let is_subscriber = state.store.is_premium_subscriber(&agent_id);
    if !is_subscriber && !is_premium_eligible(&state.http_client, &state.pl_cache, &agent_id).await {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"error": "Premium required. Subscribe for $9.99/mo or hold 500,000 01PL.", "required_01pl": 500_000})),
        )
            .into_response();
    }

    let elevenlabs_key = match std::env::var("ELEVENLABS_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "ELEVENLABS_API_KEY not configured"})),
            )
                .into_response()
        }
    };

    let blob_dir = match state.blob_dir.as_ref() {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Blob storage not configured"})),
            )
                .into_response()
        }
    };

    // Get the audio — either from base64 upload or existing episode file.
    let audio_bytes: Vec<u8> = if let Some(ref b64) = req.audio_b64 {
        match base64::decode(b64) {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "Invalid base64 audio"})),
                )
                    .into_response()
            }
        }
    } else if let Some(ref eid) = req.episode_id {
        let path = blob_dir.join(format!("podcast_{}.mp3", eid));
        match tokio::fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(_) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "Episode audio not found"})),
                )
                    .into_response()
            }
        }
    } else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Provide audio_b64 or episode_id"})),
        )
            .into_response();
    };

    let mode = req.mode.as_deref().unwrap_or("all");
    let episode_id = req
        .episode_id
        .unwrap_or_else(|| gen_episode_id());
    let mut enhancements: Vec<String> = Vec::new();
    let mut current_audio = audio_bytes;

    // Step 1: Voice isolation (clean background noise)
    if mode == "clean" || mode == "all" {
        match isolate_voice(&state.http_client, &elevenlabs_key, &current_audio).await {
            Ok(cleaned) => {
                current_audio = cleaned;
                enhancements.push("voice_isolation".to_string());
                tracing::info!("Voice isolation complete for {episode_id}");
            }
            Err(e) => tracing::warn!("Voice isolation failed (continuing): {e}"),
        }
    }

    // Step 2: Text-to-dialogue (full recreation with natural conversation)
    if (mode == "polish" || mode == "all") && req.transcript.is_some() {
        let inputs = build_dialogue_inputs(req.transcript.as_ref().unwrap());
        if !inputs.is_empty() {
            match text_to_dialogue(&state.http_client, &elevenlabs_key, &inputs).await {
                Ok(dialogue_audio) => {
                    current_audio = dialogue_audio;
                    enhancements.push("text_to_dialogue".to_string());
                    tracing::info!("Text-to-dialogue complete for {episode_id}");
                }
                Err(e) => tracing::warn!("Text-to-dialogue failed (keeping isolated audio): {e}"),
            }
        }
    }

    // Step 3: Generate and prepend/append jingle
    if mode == "all" {
        let jingle_prompt = "Short podcast intro jingle, upbeat and modern, 8 seconds, electronic lo-fi";
        if let Ok(jingle) =
            generate_jingle(&state.http_client, &elevenlabs_key, jingle_prompt, 8000).await
        {
            // Prepend jingle + append outro
            let mut final_audio = jingle.clone();
            final_audio.extend_from_slice(&current_audio);
            final_audio.extend_from_slice(&jingle);
            current_audio = final_audio;
            enhancements.push("music_jingle".to_string());
        }
    }

    // Save enhanced audio
    let filename = format!("podcast_{}_enhanced.mp3", episode_id);
    let output_path = blob_dir.join(&filename);
    if let Err(e) = tokio::fs::write(&output_path, &current_audio).await {
        tracing::error!("Failed to write enhanced audio: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to store enhanced audio"})),
        )
            .into_response();
    }

    let duration_secs = current_audio.len() as u64 / 16_000; // rough estimate at 128kbps
    let audio_url = format!("https://api.0x01.world/blobs/{}", filename);

    (
        StatusCode::OK,
        Json(json!(EnhanceResponse {
            episode_id,
            audio_url,
            duration_secs,
            enhancements_applied: enhancements,
        })),
    )
        .into_response()
}

/// POST /podcast/translate — dub an episode into another language.
pub async fn post_translate(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<TranslateRequest>,
) -> impl IntoResponse {
    let agent_id = match extract_agent_id(&headers) {
        Some(id) => id,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing X-Agent-Id header"})),
            )
                .into_response()
        }
    };

    // Premium only — check USDC subscription first, then 01PL balance
    let is_subscriber = state.store.is_premium_subscriber(&agent_id);
    if !is_subscriber && !is_premium_eligible(&state.http_client, &state.pl_cache, &agent_id).await {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({"error": "Premium required. Subscribe for $9.99/mo or hold 500,000 01PL.", "required_01pl": 500_000})),
        )
            .into_response();
    }

    let elevenlabs_key = match std::env::var("ELEVENLABS_API_KEY") {
        Ok(k) if !k.is_empty() => k,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "ELEVENLABS_API_KEY not configured"})),
            )
                .into_response()
        }
    };

    let blob_dir = match state.blob_dir.as_ref() {
        Some(d) => d.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "Blob storage not configured"})),
            )
                .into_response()
        }
    };

    // Load episode audio
    let audio_path = blob_dir.join(format!("podcast_{}.mp3", req.episode_id));
    let enhanced_path = blob_dir.join(format!("podcast_{}_enhanced.mp3", req.episode_id));
    let source_path = if enhanced_path.exists() {
        enhanced_path
    } else {
        audio_path
    };

    let audio_bytes = match tokio::fs::read(&source_path).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "Episode audio not found. Produce or enhance first."})),
            )
                .into_response()
        }
    };

    // Create dubbing project
    let dubbing_id = match create_dubbing(
        &state.http_client,
        &elevenlabs_key,
        &audio_bytes,
        "en",
        &req.target_language,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Dubbing failed: {e}")})),
            )
                .into_response()
        }
    };

    // Poll and download
    let dubbed_audio = match poll_and_download_dubbing(
        &state.http_client,
        &elevenlabs_key,
        &dubbing_id,
        &req.target_language,
    )
    .await
    {
        Ok(audio) => audio,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Dubbing failed: {e}")})),
            )
                .into_response()
        }
    };

    // Save translated audio
    let filename = format!(
        "podcast_{}_{}.mp3",
        req.episode_id, req.target_language
    );
    let output_path = blob_dir.join(&filename);
    if let Err(e) = tokio::fs::write(&output_path, &dubbed_audio).await {
        tracing::error!("Failed to write dubbed audio: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "Failed to store translated audio"})),
        )
            .into_response();
    }

    let duration_secs = dubbed_audio.len() as u64 / 16_000;
    let audio_url = format!("https://api.0x01.world/blobs/{}", filename);

    let _ = agent_id; // used for gate check above

    (
        StatusCode::OK,
        Json(json!(TranslateResponse {
            episode_id: req.episode_id,
            translated_audio_url: audio_url,
            target_language: req.target_language,
            duration_secs,
        })),
    )
        .into_response()
}

/// Build inputs array for the text-to-dialogue API.
/// Format: [{ "text": "...", "voice_id": "..." }, ...]
/// Max 2000 chars total, max 10 unique voices.
///
/// Voices:
///   User/Host: "pNInz6obpgDQGcFmaJgB" (Adam)
///   Agent/Co-host: "EXAVITQu4vr4xnSDxMaL" (Rachel)
fn build_dialogue_inputs(transcript: &serde_json::Value) -> Vec<serde_json::Value> {
    const HOST_VOICE: &str = "CwhRBWXzGAHq8TQ4Fs17";   // Roger
    const COHOST_VOICE: &str = "EXAVITQu4vr4xnSDxMaL"; // Sarah

    let messages = match transcript.as_array() {
        Some(m) => m,
        None => return vec![],
    };

    let mut inputs = Vec::new();
    let mut total_chars = 0usize;

    for msg in messages {
        let role = msg["role"].as_str().unwrap_or("user");
        let text = msg["text"].as_str().unwrap_or("");
        if text.is_empty() || text.len() < 5 {
            continue;
        }

        // Respect 2000 char limit
        let remaining = 2000usize.saturating_sub(total_chars);
        if remaining < 20 {
            break;
        }
        let trimmed = if text.len() > remaining { &text[..remaining] } else { text };
        total_chars += trimmed.len();

        let voice_id = if role == "user" { HOST_VOICE } else { COHOST_VOICE };
        inputs.push(json!({
            "text": trimmed,
            "voice_id": voice_id,
        }));
    }

    inputs
}

/// Build FFmpeg drawtext filter for burned-in captions from transcript.
/// Generates a chain of drawtext filters with enable='between(t,start,end)'.
fn build_caption_filter(transcript: &serde_json::Value, clip_start: u64, clip_end: u64) -> String {
    let messages = match transcript.as_array() {
        Some(m) => m,
        None => return String::new(),
    };

    let mut filters = Vec::new();
    let mut offset_secs = 0f64;

    for msg in messages {
        let role = msg["role"].as_str().unwrap_or("user");
        let text = msg["text"].as_str().unwrap_or("").trim();
        if text.is_empty() { continue; }

        let words = text.split_whitespace().count() as f64;
        let dur = (words / 2.5).max(1.0); // ~150 wpm

        let msg_start = offset_secs;
        let msg_end = offset_secs + dur;
        offset_secs = msg_end;

        // Only include captions that overlap with the clip range
        let rel_start = msg_start - clip_start as f64;
        let rel_end = msg_end - clip_start as f64;
        if rel_end < 0.0 || rel_start > (clip_end - clip_start) as f64 { continue; }

        let start = rel_start.max(0.0);
        let end = rel_end.min((clip_end - clip_start) as f64);

        let speaker = if role == "user" { "Host" } else { "Co-host" };
        // Truncate long captions for readability
        let display_text = if text.len() > 80 { &text[..80] } else { text };
        // Escape FFmpeg special chars
        let escaped = display_text
            .replace('\\', "\\\\")
            .replace('\'', "'\\\\\\''")
            .replace(':', "\\:")
            .replace('%', "%%");

        filters.push(format!(
            "drawtext=text='[{}] {}':fontsize=28:fontcolor=white:borderw=2:bordercolor=black:x=(w-tw)/2:y=h-120:enable='between(t,{:.1},{:.1})'",
            speaker, escaped, start, end
        ));
    }

    if filters.is_empty() {
        return String::new();
    }

    filters.join(",")
}

/// Build SRT subtitle text for a clip range from transcript.
fn build_srt(transcript: &serde_json::Value, clip_start: u64, clip_end: u64) -> String {
    let messages = match transcript.as_array() {
        Some(m) => m,
        None => return String::new(),
    };

    let mut srt = String::new();
    let mut index = 1;
    let mut offset_secs = 0f64;

    for msg in messages {
        let role = msg["role"].as_str().unwrap_or("user");
        let text = msg["text"].as_str().unwrap_or("").trim();
        if text.is_empty() { continue; }

        let words = text.split_whitespace().count() as f64;
        let dur = (words / 2.5).max(1.0);

        let msg_start = offset_secs;
        let msg_end = offset_secs + dur;
        offset_secs = msg_end;

        let rel_start = msg_start - clip_start as f64;
        let rel_end = msg_end - clip_start as f64;
        if rel_end < 0.0 || rel_start > (clip_end - clip_start) as f64 { continue; }

        let start = rel_start.max(0.0);
        let end = rel_end.min((clip_end - clip_start) as f64);

        let speaker = if role == "user" { "Host" } else { "Co-host" };
        let display_text = if text.len() > 120 { &text[..120] } else { text };

        srt.push_str(&format!(
            "{}\n{} --> {}\n[{}] {}\n\n",
            index,
            format_srt_time(start),
            format_srt_time(end),
            speaker,
            display_text,
        ));
        index += 1;
    }

    srt
}

fn format_srt_time(secs: f64) -> String {
    let h = (secs / 3600.0) as u32;
    let m = ((secs % 3600.0) / 60.0) as u32;
    let s = (secs % 60.0) as u32;
    let ms = ((secs * 1000.0) % 1000.0) as u32;
    format!("{:02}:{:02}:{:02},{:03}", h, m, s, ms)
}

use std::collections::HashMap;
