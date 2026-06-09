//! Sophos SFOS XML API client — Rust port of the `sophos-firewall-sdk` core.
//!
//! The SFOS API accepts an XML request POSTed as the `reqxml` form field to
//! `https://<host>:<port>/webconsole/APIController`:
//!
//! ```xml
//! <Request>
//!   <Login><Username>admin</Username><Password>secret</Password></Login>
//!   <Get><IPHost></IPHost></Get>
//! </Request>
//! ```
//!
//! Responses share the entity element shapes of a backup `Entities.xml`, so we
//! reuse [`crate::sophos::parse_entities`] to deserialise them.
//!
//! NOTE: the HTTP round-trip cannot be exercised without a live firewall; the
//! request-building and response-handling logic below is unit-tested offline.
//! SFOS ships a self-signed certificate by default, so `verify_certs = false`
//! is the common case.

use std::time::Duration;

use crate::entity::SophosEntity;
use crate::sophos::{parse_entities, SophosConfig};

/// Comparison operator for a `<Get>` `<Filter>` (per the SFOS XML API).
#[derive(Debug, Clone, Copy)]
pub enum FilterCriteria {
    Eq,
    Neq,
    Like,
}

impl FilterCriteria {
    fn as_attr(&self) -> &'static str {
        match self {
            FilterCriteria::Eq => "=",
            FilterCriteria::Neq => "!=",
            FilterCriteria::Like => "like",
        }
    }
}

/// Entity types this SDK can export from a live firewall, in dependency order.
pub const EXPORTABLE_ENTITIES: &[&str] =
    &["Zone", "IPHost", "IPHostGroup", "Services", "FirewallRule"];

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("HTTP transport error: {0}")]
    Transport(String),
    #[error("HTTP status {0}")]
    Http(u16),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("API error: status {code}")]
    Api { code: u32 },
    #[error("XML parse error: {0}")]
    Xml(String),
}

/// A connection to one SFOS firewall's XML API.
pub struct Client {
    endpoint: String,
    username: String,
    password: String,
    http: reqwest::blocking::Client,
}

impl Client {
    /// Build a client. `verify_certs = false` skips TLS validation (needed for
    /// the default self-signed SFOS certificate).
    pub fn new(
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        verify_certs: bool,
    ) -> Result<Self, SdkError> {
        let http = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(!verify_certs)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        Ok(Self {
            endpoint: format!("https://{host}:{port}/webconsole/APIController"),
            username: username.to_string(),
            password: password.to_string(),
            http,
        })
    }

    fn login_block(&self) -> String {
        format!(
            "<Login><Username>{}</Username><Password>{}</Password></Login>",
            xml_escape(&self.username),
            xml_escape(&self.password)
        )
    }

    fn get_request_xml(&self, entity: &str) -> String {
        format!("<Request>{}<Get><{e}></{e}></Get></Request>", self.login_block(), e = entity)
    }

    fn set_request_xml(&self, entity_xml: &str, operation: &str) -> String {
        format!(
            "<Request>{}<Set operation=\"{}\">{}</Set></Request>",
            self.login_block(),
            operation,
            entity_xml
        )
    }

    fn remove_request_xml(&self, entity: &str, name: &str) -> String {
        format!(
            "<Request>{}<Remove><{e}><Name>{}</Name></{e}></Remove></Request>",
            self.login_block(),
            xml_escape(name),
            e = entity
        )
    }

    /// POST a `reqxml` body and return the response text (after an auth check).
    fn post(&self, reqxml: &str) -> Result<String, SdkError> {
        let resp = self
            .http
            .post(&self.endpoint)
            .form(&[("reqxml", reqxml)])
            .send()
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(SdkError::Http(status.as_u16()));
        }
        let body = resp.text().map_err(|e| SdkError::Transport(e.to_string()))?;
        check_login(&body)?;
        Ok(body)
    }

    /// Fetch one entity type, parsed into a (partial) [`SophosConfig`].
    pub fn get_entities(&self, entity: &str) -> Result<SophosConfig, SdkError> {
        let body = self.post(&self.get_request_xml(entity))?;
        parse_entities(&body).map_err(|e| SdkError::Xml(e.to_string()))
    }

    /// Fetch one entity type and return the raw response XML. Works for ANY
    /// entity tag, including ones not modelled by a typed struct.
    pub fn get_raw(&self, entity: &str) -> Result<String, SdkError> {
        self.post(&self.get_request_xml(entity))
    }

    /// Fetch one entity type and return it as a JSON string (generic conversion).
    pub fn get_json(&self, entity: &str) -> Result<String, SdkError> {
        Ok(crate::xmljson::to_json(&self.get_raw(entity)?))
    }

    /// Pull every entity in the [`crate::registry`] catalog. Resilient: each
    /// entity's result is captured independently so one failure (or an entity
    /// that doesn't apply to this firewall) does not abort the whole export.
    pub fn export_all(&self) -> Vec<(&'static str, Result<String, SdkError>)> {
        crate::registry::ENTITIES
            .iter()
            .map(|ent| (ent.tag, self.get_raw(ent.tag)))
            .collect()
    }

    /// Export the modelled entity types from a live firewall into one config —
    /// the live equivalent of parsing a backup `Entities.xml`.
    pub fn export(&self) -> Result<SophosConfig, SdkError> {
        let mut cfg = SophosConfig::default();
        for entity in EXPORTABLE_ENTITIES {
            merge(&mut cfg, self.get_entities(entity)?);
        }
        Ok(cfg)
    }

    /// Create or update an entity. `entity_xml` is the full element, e.g.
    /// `<IPHost><Name>h</Name>...</IPHost>`; `operation` is `add` or `update`.
    pub fn set(&self, entity_xml: &str, operation: &str) -> Result<(), SdkError> {
        let body = self.post(&self.set_request_xml(entity_xml, operation))?;
        check_status(&body)
    }

    /// Remove a named entity (e.g. `remove("IPHost", "old-host")`).
    pub fn remove(&self, entity: &str, name: &str) -> Result<(), SdkError> {
        let body = self.post(&self.remove_request_xml(entity, name))?;
        check_status(&body)
    }

    // ── Typed helpers (parity with the Python SDK's per-entity methods) ──

    /// Create a typed entity, e.g. `client.create(&IpHost::ip("web", "10.0.0.5"))`.
    pub fn create<T: SophosEntity>(&self, entity: &T) -> Result<(), SdkError> {
        self.set(&entity.to_xml(), "add")
    }

    /// Update a typed entity.
    pub fn update<T: SophosEntity>(&self, entity: &T) -> Result<(), SdkError> {
        self.set(&entity.to_xml(), "update")
    }

    /// Delete a typed entity by its own name.
    pub fn delete<T: SophosEntity>(&self, entity: &T) -> Result<(), SdkError> {
        self.remove(T::TAG, entity.name())
    }

    // ── Filtered get (server-side `<Filter>`) ──

    fn get_filter_request_xml(&self, entity: &str, key: &str, criteria: FilterCriteria, value: &str) -> String {
        format!(
            "<Request>{}<Get><{e}><Filter><key name=\"{}\" criteria=\"{}\">{}</key></Filter></{e}></Get></Request>",
            self.login_block(),
            key,
            criteria.as_attr(),
            xml_escape(value),
            e = entity
        )
    }

    /// Fetch entities matching a filter (e.g. name `like` "web"), as raw XML.
    pub fn get_raw_filtered(
        &self,
        entity: &str,
        key: &str,
        criteria: FilterCriteria,
        value: &str,
    ) -> Result<String, SdkError> {
        self.post(&self.get_filter_request_xml(entity, key, criteria, value))
    }

    /// Fetch entities matching a filter, parsed into a (partial) [`SophosConfig`].
    pub fn get_entities_filtered(
        &self,
        entity: &str,
        key: &str,
        criteria: FilterCriteria,
        value: &str,
    ) -> Result<SophosConfig, SdkError> {
        let body = self.get_raw_filtered(entity, key, criteria, value)?;
        parse_entities(&body).map_err(|e| SdkError::Xml(e.to_string()))
    }
}

fn merge(into: &mut SophosConfig, part: SophosConfig) {
    into.zones.extend(part.zones);
    into.firewall_rules.extend(part.firewall_rules);
    into.ip_hosts.extend(part.ip_hosts);
    into.ip_host_groups.extend(part.ip_host_groups);
    into.services.extend(part.services);
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// SFOS reports bad credentials with an "Authentication Failure" login status.
fn check_login(body: &str) -> Result<(), SdkError> {
    if body.contains("Authentication Failure") {
        return Err(SdkError::Auth("Authentication Failure".into()));
    }
    Ok(())
}

/// SFOS embeds a `<Status code="NNN">` in Set/Remove responses; 2xx is success.
fn check_status(body: &str) -> Result<(), SdkError> {
    match extract_status_code(body) {
        Some(code) if (200..300).contains(&code) => Ok(()),
        Some(code) => Err(SdkError::Api { code }),
        None => Ok(()), // no status element — treat as benign
    }
}

fn extract_status_code(body: &str) -> Option<u32> {
    let start = body.find("code=\"")? + 6;
    let rest = &body[start..];
    let end = rest.find('"')?;
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::new("fw.example", 4444, "admin", "p@ss<&", false).unwrap()
    }

    #[test]
    fn get_request_xml_is_well_formed_and_escaped() {
        let c = client();
        let xml = c.get_request_xml("IPHost");
        assert!(xml.contains("<Get><IPHost></IPHost></Get>"));
        assert!(xml.contains("<Username>admin</Username>"));
        // password special chars are escaped
        assert!(xml.contains("<Password>p@ss&lt;&amp;</Password>"));
    }

    #[test]
    fn set_and_remove_request_shapes() {
        let c = client();
        let set = c.set_request_xml("<IPHost><Name>h</Name></IPHost>", "add");
        assert!(set.contains("<Set operation=\"add\"><IPHost><Name>h</Name></IPHost></Set>"));
        let rm = c.remove_request_xml("IPHost", "old");
        assert!(rm.contains("<Remove><IPHost><Name>old</Name></IPHost></Remove>"));
    }

    #[test]
    fn filter_request_xml_is_well_formed() {
        let c = client();
        let xml = c.get_filter_request_xml("IPHost", "Name", FilterCriteria::Like, "web");
        assert!(xml.contains(
            "<Get><IPHost><Filter><key name=\"Name\" criteria=\"like\">web</key></Filter></IPHost></Get>"
        ));
    }

    #[test]
    fn typed_create_body_shape() {
        use crate::sophos::IpHost;
        let c = client();
        let body = c.set_request_xml(&IpHost::ip("web", "10.0.0.5").to_xml(), "add");
        assert!(body.contains("<Set operation=\"add\"><IPHost><Name>web</Name>"));
    }

    #[test]
    fn detects_auth_failure() {
        let body = r#"<Response APIVersion="2000.1"><Login><status>Authentication Failure</status></Login></Response>"#;
        assert!(matches!(check_login(body), Err(SdkError::Auth(_))));
    }

    #[test]
    fn status_code_success_and_failure() {
        assert!(check_status(r#"<Status code="200">OK</Status>"#).is_ok());
        assert!(matches!(
            check_status(r#"<Status code="502">failed</Status>"#),
            Err(SdkError::Api { code: 502 })
        ));
    }

    #[test]
    fn parses_an_api_response_into_config() {
        // A Get response carries entity elements as children of <Response>,
        // which parse_entities maps the same as a backup <Configuration>.
        let body = r#"<Response APIVersion="2000.1">
            <Login><status>Authentication Successful</status></Login>
            <IPHost><Name>WebServer</Name><HostType>IP</HostType><IPAddress>10.0.10.5</IPAddress></IPHost>
            <IPHost><Name>DB</Name><HostType>IP</HostType><IPAddress>10.0.10.6</IPAddress></IPHost>
        </Response>"#;
        let cfg = parse_entities(body).unwrap();
        assert_eq!(cfg.ip_hosts.len(), 2);
        assert_eq!(cfg.ip_hosts[0].name, "WebServer");
    }
}
