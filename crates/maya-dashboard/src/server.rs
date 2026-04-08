//! Dashboard HTTP Server with WebSocket support.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use axum::{
    Router,
    http::{HeaderName, HeaderValue, Method, header},
    routing::{get, get_service},
};
use tower_http::cors::CorsLayer;
use tower_http::services::{ServeDir, ServeFile};
use tracing::{info, warn};

use maya_core::events::EventBus;

use crate::api;
use crate::api::DashboardApiState;
use crate::state::DashboardState;

pub struct DashboardServer {
    listen_addr: String,
    port: u16,
    assets_dir: PathBuf,
    state: DashboardState,
    auth_token: Option<String>,
    ai_endpoint: Option<String>,
    allowed_origins: Vec<String>,
    event_bus: Option<Arc<EventBus>>,
}

impl DashboardServer {
    pub fn new(listen_addr: &str, port: u16) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            port,
            assets_dir: PathBuf::from("./dashboard/dist"),
            state: DashboardState::new(),
            auth_token: None,
            ai_endpoint: None,
            allowed_origins: Vec::new(),
            event_bus: None,
        }
    }

    pub fn with_assets_dir(mut self, assets_dir: impl AsRef<Path>) -> Self {
        self.assets_dir = resolve_assets_dir(assets_dir.as_ref());
        self
    }

    pub fn with_event_bus(mut self, event_bus: Arc<EventBus>) -> Self {
        self.event_bus = Some(event_bus);
        self
    }

    pub fn with_security(
        mut self,
        auth_token: Option<String>,
        allowed_origins: Vec<String>,
    ) -> Self {
        self.auth_token = auth_token.filter(|token| !token.trim().is_empty());
        self.allowed_origins = allowed_origins;
        self
    }

    pub fn with_ai_endpoint(mut self, ai_endpoint: Option<String>) -> Self {
        self.ai_endpoint = ai_endpoint.filter(|endpoint| !endpoint.trim().is_empty());
        self
    }

    pub fn router(&self) -> Result<Router> {
        let api_state = DashboardApiState {
            dashboard: self.state.clone(),
            auth_token: self.auth_token.clone(),
            cookie_name: "maya_dashboard_session".to_string(),
            started_at: std::time::Instant::now(),
            ai_endpoint: self.ai_endpoint.clone(),
        };

        let mut api_router = Router::new()
            .route("/api/auth/login", axum::routing::post(api::login))
            .route("/api/auth/logout", axum::routing::post(api::logout))
            .route("/api/auth/session", get(api::session_status))
            .route("/api/health", get(api::health_check))
            .route("/api/stats", get(api::grid_stats))
            .route("/ws/feed", get(api::ws_feed))
            .with_state(api_state);

        if !self.allowed_origins.is_empty() {
            api_router = api_router.layer(self.build_cors_layer()?);
        }

        if self.assets_dir.exists() {
            let index = self.assets_dir.join("index.html");
            Ok(api_router.fallback_service(get_service(
                ServeDir::new(&self.assets_dir).not_found_service(ServeFile::new(index)),
            )))
        } else {
            warn!(
                assets = %self.assets_dir.display(),
                "Dashboard assets directory not found; serving API routes only"
            );
            Ok(api_router)
        }
    }

    pub async fn start(&self) -> Result<()> {
        self.validate_security_posture()?;

        if let Some(event_bus) = &self.event_bus {
            self.spawn_event_listener(event_bus.clone());
        }

        let app = self.router()?;
        let addr = format!("{}:{}", self.listen_addr, self.port);
        info!(
            assets = %self.assets_dir.display(),
            "📊 SOC Dashboard listening on http://{}",
            addr
        );

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }

    fn spawn_event_listener(&self, event_bus: Arc<EventBus>) {
        let mut rx = event_bus.subscribe();
        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => state.apply_event(event).await,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!(
                            skipped,
                            "Dashboard event listener lagged; dropped stale events"
                        );
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });
    }

    fn build_cors_layer(&self) -> Result<CorsLayer> {
        let origins = self
            .allowed_origins
            .iter()
            .map(|origin| HeaderValue::from_str(origin))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(CorsLayer::new()
            .allow_origin(origins)
            .allow_credentials(true)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                HeaderName::from_static("x-maya-dashboard-token"),
            ]))
    }

    fn validate_security_posture(&self) -> Result<()> {
        if self.is_public_bind() {
            if self.auth_token.is_none() {
                anyhow::bail!(
                    "dashboard auth_token is required when binding publicly on {}:{}",
                    self.listen_addr,
                    self.port
                );
            }

            if self.allowed_origins.is_empty() {
                anyhow::bail!(
                    "dashboard allowed_origins must be configured when binding publicly on {}:{}",
                    self.listen_addr,
                    self.port
                );
            }
        }

        Ok(())
    }

    fn is_public_bind(&self) -> bool {
        if self.listen_addr.eq_ignore_ascii_case("localhost") {
            return false;
        }

        self.listen_addr
            .parse::<IpAddr>()
            .map(|ip| !ip.is_loopback())
            .unwrap_or(true)
    }
}

fn resolve_assets_dir(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }

    if path.exists() {
        return path.to_path_buf();
    }

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workspace_candidate = workspace_root.join(path);
    if workspace_candidate.exists() {
        return workspace_candidate;
    }

    path.to_path_buf()
}
