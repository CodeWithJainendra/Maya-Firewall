//! Dashboard REST API endpoints.

use axum::{
    Json,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::Uri,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use base64::Engine;
use chrono::{Duration, Utc};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::time::{Duration as TokioDuration, timeout};
use tracing::warn;

use crate::state::DashboardState;

#[derive(Clone)]
pub struct DashboardApiState {
    pub dashboard: DashboardState,
    pub auth_token: Option<String>,
    pub cookie_name: String,
    pub started_at: Instant,
    pub ai_endpoint: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct WsAuthQuery {
    pub token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub authenticated: bool,
}

const SESSION_TTL_SECS: i64 = 60 * 60 * 12;

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: u64,
    pub components: ComponentStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComponentStatus {
    pub network_engine: String,
    pub deception_engine: String,
    pub ai_brain: String,
    pub sandbox: String,
    pub crypto: String,
    pub consensus: String,
    pub profiler: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GridStats {
    pub active_decoys: u32,
    pub active_sessions: u32,
    pub trapped_attackers: u32,
    pub malware_captured: u32,
    pub scans_detected: u64,
    pub alerts_generated: u32,
}

pub async fn login(
    State(state): State<DashboardApiState>,
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let expected = state.auth_token.as_deref().ok_or(StatusCode::NOT_FOUND)?;

    if payload.token != expected {
        warn!("Rejected dashboard login attempt");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let cookie = build_session_cookie(&state.cookie_name, expected)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(SessionResponse {
            authenticated: true,
        }),
    ))
}

pub async fn logout(State(state): State<DashboardApiState>) -> impl IntoResponse {
    (
        [(header::SET_COOKIE, clear_session_cookie(&state.cookie_name))],
        Json(SessionResponse {
            authenticated: false,
        }),
    )
}

pub async fn session_status(
    State(state): State<DashboardApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    authorize_request(&state, &headers, None)?;
    Ok(Json(SessionResponse {
        authenticated: true,
    }))
}

pub async fn health_check(
    State(state): State<DashboardApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    authorize_request(&state, &headers, None)?;

    let ai_brain_status = if probe_ai_brain(state.ai_endpoint.as_deref()).await {
        "active"
    } else {
        "degraded"
    };

    let components = ComponentStatus {
        network_engine: "active".into(),
        deception_engine: "active".into(),
        ai_brain: ai_brain_status.into(),
        sandbox: "active".into(),
        crypto: "active".into(),
        consensus: "active".into(),
        profiler: "active".into(),
    };

    Ok(Json(HealthResponse {
        status: aggregate_health_status(&components),
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: state.started_at.elapsed().as_secs(),
        components,
    }))
}

pub async fn grid_stats(
    State(state): State<DashboardApiState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    authorize_request(&state, &headers, None)?;
    Ok(Json(state.dashboard.stats_snapshot().await))
}

pub async fn ws_feed(
    ws: WebSocketUpgrade,
    State(state): State<DashboardApiState>,
    headers: HeaderMap,
    query: Query<WsAuthQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    authorize_request(&state, &headers, query.token.as_deref())?;
    Ok(ws.on_upgrade(move |socket| ws_feed_loop(socket, state.dashboard)))
}

async fn ws_feed_loop(mut socket: WebSocket, state: DashboardState) {
    let mut stream_rx = state.subscribe_stream();

    let backlog = state.recent_stream(20).await;
    for packet in backlog {
        if send_json(&mut socket, &packet).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            recv = socket.recv() => {
                match recv {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            packet = stream_rx.recv() => {
                match packet {
                    Ok(message) => {
                        if send_json(&mut socket, &message).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}

async fn send_json<T: Serialize>(socket: &mut WebSocket, value: &T) -> Result<(), ()> {
    let payload = serde_json::to_string(value).map_err(|_| ())?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(|_| ())
}

fn authorize_request(
    state: &DashboardApiState,
    headers: &HeaderMap,
    query_token: Option<&str>,
) -> Result<(), StatusCode> {
    let Some(expected) = state.auth_token.as_deref() else {
        return Ok(());
    };

    let supplied = query_token
        .map(str::to_owned)
        .or_else(|| session_cookie(headers, &state.cookie_name, expected))
        .or_else(|| bearer_token(headers))
        .or_else(|| header_token(headers, "x-maya-dashboard-token"));

    match supplied {
        Some(token) if token == expected => Ok(()),
        _ => {
            warn!("Rejected unauthorized dashboard API/WS request");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|token| token.to_string())
}

fn header_token(headers: &HeaderMap, name: &'static str) -> Option<String> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(|value| value.to_string())
}

fn session_cookie(headers: &HeaderMap, cookie_name: &str, expected_token: &str) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    let encoded = cookie_header
        .split(';')
        .filter_map(|part| {
            let trimmed = part.trim();
            let (name, value) = trimmed.split_once('=')?;
            (name == cookie_name).then_some(value)
        })
        .next()?;

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (expiry, signature_hex) = decoded.split_once('.')?;
    let expires_at = expiry.parse::<i64>().ok()?;
    if Utc::now().timestamp() > expires_at {
        return None;
    }

    let expected_signature = sign_session(expected_token);
    let provided_signature = hex::decode(signature_hex).ok()?;
    hmac::verify(&expected_signature, expiry.as_bytes(), &provided_signature).ok()?;

    Some(expected_token.to_string())
}

fn build_session_cookie(cookie_name: &str, auth_token: &str) -> anyhow::Result<HeaderValue> {
    let expires_at = (Utc::now() + Duration::seconds(SESSION_TTL_SECS)).timestamp();
    let expiry = expires_at.to_string();
    let signature = hmac::sign(&sign_session(auth_token), expiry.as_bytes());
    let value = format!("{}.{}", expiry, hex::encode(signature.as_ref()));
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    let cookie = format!(
        "{cookie_name}={encoded}; Max-Age={SESSION_TTL_SECS}; Path=/; HttpOnly; SameSite=Strict"
    );
    Ok(HeaderValue::from_str(&cookie)?)
}

fn clear_session_cookie(cookie_name: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{cookie_name}=deleted; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"
    ))
    .expect("static logout cookie")
}

async fn probe_ai_brain(endpoint: Option<&str>) -> bool {
    let Some(endpoint) = endpoint else {
        return false;
    };

    let Ok(uri) = endpoint.parse::<Uri>() else {
        return false;
    };

    let Some(host) = uri.host() else {
        return false;
    };

    let port = uri.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    });

    let address = format!("{host}:{port}");
    timeout(TokioDuration::from_millis(350), TcpStream::connect(address))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn aggregate_health_status(components: &ComponentStatus) -> String {
    let statuses = [
        components.network_engine.as_str(),
        components.deception_engine.as_str(),
        components.ai_brain.as_str(),
        components.sandbox.as_str(),
        components.crypto.as_str(),
        components.consensus.as_str(),
        components.profiler.as_str(),
    ];

    if statuses
        .iter()
        .any(|status| matches!(*status, "down" | "failed" | "critical"))
    {
        return "critical".to_string();
    }

    if statuses
        .iter()
        .any(|status| matches!(*status, "degraded" | "inactive" | "standby" | "unknown"))
    {
        return "degraded".to_string();
    }

    "operational".to_string()
}

fn sign_session(auth_token: &str) -> hmac::Key {
    let mut seed = Vec::with_capacity(auth_token.len() + 32);
    seed.extend_from_slice(auth_token.as_bytes());
    seed.extend_from_slice(b":maya-dashboard-session:v1");
    hmac::Key::new(hmac::HMAC_SHA256, &seed)
}
