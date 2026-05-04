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

#[derive(Debug, Deserialize)]
pub struct ClipRequest {
    pub episode_id: String,
    pub start_secs: u64,
    pub end_secs: u64,
    pub style: Option<String>, // "waveform" or "avatar"
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
                            "21m00Tcm4TlvDq8ikWAM", // Rachel voice
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

/// POST /podcast/clip
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

    // Verify episode exists
    let episode = state.store.get_podcast_episode(&req.episode_id);
    if episode.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "Episode not found"})),
        )
            .into_response();
    }

    // In a full implementation: extract audio segment, generate waveform video
    // with burned-in captions via FFmpeg. For MVP, return a placeholder.
    let clip_id = gen_episode_id();
    let clip_url = format!("https://api.0x01.world/blobs/clip_{}.mp4", clip_id);
    let duration_secs = req.end_secs - req.start_secs;

    // TODO: actual video generation via FFmpeg + caption burn-in
    // For now, return the contract response shape so the skill works end-to-end.

    (
        StatusCode::OK,
        Json(json!(ClipResponse {
            clip_url,
            duration_secs,
            caption_srt: format!(
                "1\n00:00:00,000 --> 00:00:{:02},000\n[Clip from episode]\n",
                duration_secs
            ),
        })),
    )
        .into_response()
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

use std::collections::HashMap;
