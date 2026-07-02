//! Sophos Central cloud API client — OAuth2 client-credentials auth, `whoami`
//! tenant/region resolution, and the SIEM `events`/`alerts` polling endpoints.
//!
//! This is a *different* Sophos product surface than [`crate::client`]: the
//! on-box SFOS XML API talks to one firewall's local config, while this talks
//! to the Sophos Central cloud — the aggregated event/alert stream for
//! whatever a tenant has enrolled, including any Access Points managed
//! through Central rather than the firewall's own Wireless subsystem.
//!
//! The token endpoint, `whoami/v1`, and the `/siem/v1/events` and
//! `/siem/v1/alerts` paths below are confirmed against the official
//! `sophos/Sophos-Central-SIEM-Integration` reference client. There is no
//! server-side product/category filter on those endpoints, so "wireless"
//! events can only be found by filtering the returned `type` field
//! client-side; [`is_wireless_event`] is a best-effort guess at that type
//! string and needs validating against a live tenant with an enrolled AP.
//!
//! NOTE: like [`crate::client`], the HTTP round-trip cannot be exercised
//! without live credentials — request-building and cursor-state logic are
//! unit-tested offline below.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const DEFAULT_AUTH_URL: &str = "https://id.sophos.com/api/v2/oauth2/token";
const DEFAULT_API_HOST: &str = "api.central.sophos.com";

#[derive(Debug, thiserror::Error)]
pub enum CentralError {
    #[error("HTTP transport error: {0}")]
    Transport(String),
    #[error("HTTP status {0}: {1}")]
    Http(u16, String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("JSON parse error: {0}")]
    Json(String),
    #[error("no tenant id available — pass one explicitly, or authenticate with a tenant-scoped credential")]
    NoTenant,
}

/// One authenticated Sophos Central session: bearer token (cached until near
/// expiry) plus the resolved tenant id and regional API host.
pub struct CentralClient {
    http: reqwest::blocking::Client,
    auth_url: String,
    client_id: String,
    client_secret: String,
    token: Option<String>,
    token_expires_at: Option<u64>,
    tenant_id: Option<String>,
    api_host: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhoAmI {
    pub id: String,
    #[serde(rename = "idType")]
    pub id_type: String,
    #[serde(rename = "apiHosts")]
    pub api_hosts: Option<ApiHosts>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiHosts {
    #[serde(rename = "dataRegion")]
    pub data_region: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Query params for one [`CentralClient::events`] / [`CentralClient::alerts`] page.
#[derive(Debug, Clone, Default)]
pub struct PollQuery {
    /// Resume from a prior page's [`EventsPage::next_cursor`]. Takes priority
    /// over `from_date` once a poll loop has one.
    pub cursor: Option<String>,
    /// First poll only: Unix timestamp to fetch from (max 24h back, per the API).
    pub from_date: Option<u64>,
    pub limit: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EventsPage {
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub has_more: Option<bool>,
}

impl CentralClient {
    pub fn new(client_id: &str, client_secret: &str) -> Result<Self, CentralError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CentralError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            auth_url: DEFAULT_AUTH_URL.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            token: None,
            token_expires_at: None,
            tenant_id: None,
            api_host: DEFAULT_API_HOST.to_string(),
        })
    }

    /// Pin the tenant id instead of discovering it via `whoami` — needed for
    /// partner/organization credentials scoped to more than one tenant.
    pub fn with_tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    fn token_request_body(&self) -> [(&'static str, String); 4] {
        [
            ("grant_type", "client_credentials".to_string()),
            ("client_id", self.client_id.clone()),
            ("client_secret", self.client_secret.clone()),
            ("scope", "token".to_string()),
        ]
    }

    /// True once a cached token exists with at least 30s left before expiry.
    fn token_is_valid(&self) -> bool {
        match (&self.token, self.token_expires_at) {
            (Some(_), Some(exp)) => now_unix() + 30 < exp,
            _ => false,
        }
    }

    /// Authenticate (client-credentials grant), caching the token until it's
    /// near expiry. Cheap to call before every request — a no-op if cached.
    pub fn authenticate(&mut self) -> Result<(), CentralError> {
        if self.token_is_valid() {
            return Ok(());
        }
        let resp = self
            .http
            .post(&self.auth_url)
            .form(&self.token_request_body())
            .send()
            .map_err(|e| CentralError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().map_err(|e| CentralError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(CentralError::Auth(format!("{status}: {body}")));
        }
        let tok: TokenResponse = serde_json::from_str(&body).map_err(|e| CentralError::Json(e.to_string()))?;
        self.token_expires_at = Some(now_unix() + tok.expires_in);
        self.token = Some(tok.access_token);
        Ok(())
    }

    fn bearer(&self) -> Result<&str, CentralError> {
        self.token.as_deref().ok_or_else(|| CentralError::Auth("not authenticated".into()))
    }

    /// Resolve the tenant id and regional API host via `whoami/v1`. Skippable
    /// if a tenant id was already supplied with [`Self::with_tenant_id`] —
    /// but the events/alerts endpoints still need the regional host, so call
    /// this at least once per session unless you also override the host.
    pub fn whoami(&mut self) -> Result<WhoAmI, CentralError> {
        self.authenticate()?;
        let url = format!("https://{}/whoami/v1", self.api_host);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(self.bearer()?)
            .send()
            .map_err(|e| CentralError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().map_err(|e| CentralError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(CentralError::Http(status.as_u16(), body));
        }
        let who: WhoAmI = serde_json::from_str(&body).map_err(|e| CentralError::Json(e.to_string()))?;
        if self.tenant_id.is_none() {
            self.tenant_id = Some(who.id.clone());
        }
        if let Some(hosts) = &who.api_hosts {
            self.api_host = hosts.data_region.trim_start_matches("https://").trim_end_matches('/').to_string();
        }
        Ok(who)
    }

    fn poll_url(&self, path: &str) -> String {
        format!("https://{}{path}", self.api_host)
    }

    fn poll(&mut self, path: &str, q: &PollQuery) -> Result<EventsPage, CentralError> {
        self.authenticate()?;
        let tenant_id = self.tenant_id.clone().ok_or(CentralError::NoTenant)?;
        let mut query: Vec<(&str, String)> = vec![("limit", q.limit.to_string())];
        if let Some(cursor) = &q.cursor {
            query.push(("cursor", cursor.clone()));
        } else if let Some(from) = q.from_date {
            query.push(("from_date", from.to_string()));
        }
        let resp = self
            .http
            .get(self.poll_url(path))
            .bearer_auth(self.bearer()?)
            .header("X-Tenant-ID", tenant_id)
            .query(&query)
            .send()
            .map_err(|e| CentralError::Transport(e.to_string()))?;
        let status = resp.status();
        let body = resp.text().map_err(|e| CentralError::Transport(e.to_string()))?;
        if !status.is_success() {
            return Err(CentralError::Http(status.as_u16(), body));
        }
        serde_json::from_str(&body).map_err(|e| CentralError::Json(e.to_string()))
    }

    /// Poll `/siem/v1/events` — one page, resuming from `query.cursor` when set.
    pub fn events(&mut self, query: &PollQuery) -> Result<EventsPage, CentralError> {
        self.poll("/siem/v1/events", query)
    }

    /// Poll `/siem/v1/alerts` — one page, resuming from `query.cursor` when set.
    pub fn alerts(&mut self, query: &PollQuery) -> Result<EventsPage, CentralError> {
        self.poll("/siem/v1/alerts", query)
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Best-effort client-side category filter for wireless/AP events. Central's
/// events and alerts endpoints have no server-side product filter (confirmed
/// against the reference SIEM client), so this inspects the `type` field
/// returned in each item. The exact type string Sophos uses for AP events is
/// unconfirmed without a live tenant — treat a false negative here as a cue
/// to widen the match, not as proof wireless events don't exist.
pub fn is_wireless_event(item: &serde_json::Value) -> bool {
    item.get("type")
        .and_then(|t| t.as_str())
        .map(|t| {
            let t = t.to_ascii_lowercase();
            t.contains("wireless") || t.contains("accesspoint") || t.contains("::ap::")
        })
        .unwrap_or(false)
}

// ── Cursor state (resume across runs, per the SIEM-integration state-file pattern) ──

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CentralState {
    #[serde(default)]
    pub events_cursor: Option<String>,
    #[serde(default)]
    pub alerts_cursor: Option<String>,
}

impl CentralState {
    /// Load cursor state from disk, or a fresh default if the file doesn't
    /// exist yet (first run) or fails to parse.
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> CentralClient {
        CentralClient::new("id-123", "secret-xyz").unwrap()
    }

    #[test]
    fn token_request_body_is_client_credentials_grant() {
        let c = client();
        let body = c.token_request_body();
        assert!(body.contains(&("grant_type", "client_credentials".to_string())));
        assert!(body.contains(&("client_id", "id-123".to_string())));
        assert!(body.contains(&("client_secret", "secret-xyz".to_string())));
        assert!(body.contains(&("scope", "token".to_string())));
    }

    #[test]
    fn token_validity_respects_expiry_and_skew_margin() {
        let mut c = client();
        assert!(!c.token_is_valid(), "no token yet");
        c.token = Some("tok".into());
        c.token_expires_at = Some(now_unix() + 3600);
        assert!(c.token_is_valid());
        c.token_expires_at = Some(now_unix() + 10); // inside the 30s skew margin
        assert!(!c.token_is_valid());
    }

    #[test]
    fn whoami_url_and_regional_host_override() {
        let c = client();
        assert_eq!(c.poll_url("/siem/v1/events"), "https://api.central.sophos.com/siem/v1/events");
    }

    #[test]
    fn with_tenant_id_pins_tenant_without_whoami() {
        let c = client().with_tenant_id("tenant-abc");
        assert_eq!(c.tenant_id.as_deref(), Some("tenant-abc"));
    }

    #[test]
    fn poll_without_tenant_id_errors_before_any_request() {
        let mut c = client();
        c.token = Some("tok".into());
        c.token_expires_at = Some(now_unix() + 3600);
        let err = c.events(&PollQuery::default()).unwrap_err();
        assert!(matches!(err, CentralError::NoTenant));
    }

    #[test]
    fn is_wireless_event_matches_expected_type_shapes() {
        assert!(is_wireless_event(&serde_json::json!({"type": "Event::Wireless::APOffline"})));
        assert!(is_wireless_event(&serde_json::json!({"type": "Event::Endpoint::AccessPoint::Rebooted"})));
        assert!(!is_wireless_event(&serde_json::json!({"type": "Event::Endpoint::Threat::Detected"})));
        assert!(!is_wireless_event(&serde_json::json!({})));
    }

    #[test]
    fn central_state_roundtrips_through_disk() {
        let dir = std::env::temp_dir().join(format!("sfos-rs-central-state-test-{}", std::process::id()));
        let path = dir.join("cursor.json");
        // Missing file -> default state, not an error.
        assert!(CentralState::load(&path).events_cursor.is_none());

        let state = CentralState { events_cursor: Some("cur-1".into()), alerts_cursor: None };
        state.save(&path).unwrap();
        let loaded = CentralState::load(&path);
        assert_eq!(loaded.events_cursor, Some("cur-1".to_string()));
        assert_eq!(loaded.alerts_cursor, None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
