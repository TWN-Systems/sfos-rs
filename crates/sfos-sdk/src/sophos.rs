//! Sophos SFOS configuration: typed model + parser + search primitives.
//!
//! Deserialised from the `Entities.xml` inside an SFOS backup tarball, or from
//! an XML API `<Response>` body — both share the same entity element shapes
//! (root `<Configuration>` for backups, `<Response>` for the API). Field renames
//! mirror the Sophos XML API tag names. Unmodelled elements are ignored on
//! deserialisation, so a full real export parses even though we consume a subset.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum SophosParseError {
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse an `Entities.xml` (or API response) string.
pub fn parse_entities(xml: &str) -> Result<SophosConfig, SophosParseError> {
    quick_xml::de::from_str(xml).map_err(|e| SophosParseError::Xml(e.to_string()))
}

/// Parse from a file path.
pub fn parse_entities_file(path: &Path) -> Result<SophosConfig, SophosParseError> {
    let content = std::fs::read_to_string(path)?;
    parse_entities(&content)
}

// ── Model ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SophosConfig {
    #[serde(rename = "Zone", default)]
    pub zones: Vec<Zone>,
    #[serde(rename = "FirewallRule", default)]
    pub firewall_rules: Vec<FirewallRule>,
    #[serde(rename = "IPHost", default)]
    pub ip_hosts: Vec<IpHost>,
    #[serde(rename = "IPHostGroup", default)]
    pub ip_host_groups: Vec<IpHostGroup>,
    #[serde(rename = "Services", default)]
    pub services: Vec<ServiceObj>,
    #[serde(rename = "VPNIPSecConnection", default)]
    pub ipsec: Vec<IpsecConnection>,
    #[serde(rename = "Interface", default)]
    pub interfaces: Vec<Interface>,
    #[serde(rename = "NATRule", default)]
    pub nat_rules: Vec<NatRule>,
    #[serde(rename = "UnicastRoute", default)]
    pub static_routes: Vec<StaticRoute>,
    #[serde(rename = "AdminSettings", default)]
    pub admin_settings: Option<AdminSettings>,
    #[serde(rename = "Hotfix", default)]
    pub hotfix: Option<Hotfix>,
}

/// `<VPNIPSecConnection>` — confirmed to wrap its body in `<Configuration>`
/// (migration-utility template). Use [`SophosConfig::ipsec_connections`] to
/// iterate the inner [`IpsecConfig`] bodies.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpsecConnection {
    #[serde(rename = "Configuration", default)]
    pub configuration: IpsecConfig,
}

/// The IPsec connection body (the children of `<Configuration>`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpsecConfig {
    #[serde(rename = "Name", default)]
    pub name: String,
    /// SiteToSite | RemoteAccess | HostToHost
    #[serde(rename = "ConnectionType", default)]
    pub connection_type: Option<String>,
    /// IPsec profile name (proposals/PFS/lifetimes/IKE version live in the profile).
    #[serde(rename = "Policy", default)]
    pub policy: Option<String>,
    /// PresharedKey | RSAKey | DigitalCertificate
    #[serde(rename = "AuthenticationType", default)]
    pub authentication_type: Option<String>,
    #[serde(rename = "Status", default)]
    pub status: Option<String>,
    /// Local WAN port/interface bound to the tunnel.
    #[serde(rename = "LocalWANPort", alias = "LocalGateway", default)]
    pub local_gateway: Option<String>,
    #[serde(rename = "RemoteHost", default)]
    pub remote_gateway: Option<String>,
    /// Local subnet host-object name(s) — `<LocalSubnet>` repeated.
    #[serde(rename = "LocalSubnet", default)]
    pub local_subnets: Vec<String>,
    /// Remote networks — `<RemoteNetwork><Network>…</Network></RemoteNetwork>`.
    #[serde(rename = "RemoteNetwork", default)]
    pub remote_network: Option<NetworkRefList>,
    /// IKE version if present at connection level (often only in the profile).
    #[serde(rename = "IKEVersion", default)]
    pub ike_version: Option<String>,
}

impl IpsecConfig {
    pub fn is_site_to_site(&self) -> bool {
        self.connection_type.as_deref().map(|t| t.to_ascii_lowercase().contains("site")).unwrap_or(false)
    }
    pub fn remote_subnets(&self) -> &[String] {
        self.remote_network.as_ref().map(|n| n.networks.as_slice()).unwrap_or(&[])
    }
}

/// A network interface and the zone/addressing bound to it. Schema confirmed
/// against the Sophos migration utility / config templates: the zone tag is
/// `NetworkZone` (we accept `Zone` as an alias too).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Interface {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hardware", default)]
    pub hardware: Option<String>,
    #[serde(rename = "NetworkZone", alias = "Zone", default)]
    pub zone: Option<String>,
    #[serde(rename = "IPAddress", default)]
    pub ip_address: Option<String>,
    #[serde(rename = "Netmask", default)]
    pub netmask: Option<String>,
}

/// A NAT rule. We model the destination-NAT (DNAT) fields used to follow a
/// public address to its internal host (best-effort schema; self-validates).
/// NAT rule. Schema confirmed against the migration-utility `NATRule` template:
/// original source/destination are network-object lists; translated source/
/// destination are scalar host-object names.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatRule {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Status", default)]
    pub status: Option<String>,
    #[serde(rename = "OriginalSourceNetworks", default)]
    pub original_source_networks: Option<NetworkRefList>,
    #[serde(rename = "OriginalDestinationNetworks", default)]
    pub original_destination_networks: Option<NetworkRefList>,
    /// Post-NAT (internal) destination host-object name.
    #[serde(rename = "TranslatedDestination", default)]
    pub translated_destination: Option<String>,
    /// Post-NAT (masqueraded) source host-object name.
    #[serde(rename = "TranslatedSource", default)]
    pub translated_source: Option<String>,
}

impl NatRule {
    pub fn original_destinations(&self) -> &[String] {
        self.original_destination_networks.as_ref().map(|n| n.networks.as_slice()).unwrap_or(&[])
    }
    pub fn original_sources(&self) -> &[String] {
        self.original_source_networks.as_ref().map(|n| n.networks.as_slice()).unwrap_or(&[])
    }
}

/// A static (unicast) route. Best-effort schema; self-validates against a live export.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaticRoute {
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    // Confirmed tag is `DestinationIP` (migration-utility UnicastRoute template).
    #[serde(rename = "DestinationIP", alias = "Destination", default)]
    pub destination: Option<String>,
    #[serde(rename = "Netmask", default)]
    pub netmask: Option<String>,
    #[serde(rename = "Gateway", default)]
    pub gateway: Option<String>,
    #[serde(rename = "Interface", default)]
    pub interface: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type", default)]
    pub zone_type: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
}

impl Zone {
    pub fn is_wan(&self) -> bool {
        self.zone_type.as_deref().map(|t| t.eq_ignore_ascii_case("WAN")).unwrap_or(false)
            || self.name.to_uppercase().contains("WAN")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Status", default)]
    pub status: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "IPFamily", default)]
    pub ip_family: Option<String>,
    #[serde(rename = "Position", default)]
    pub position: Option<String>,
    #[serde(rename = "PolicyType", default)]
    pub policy_type: Option<String>,
    #[serde(rename = "NetworkPolicy", default)]
    pub network_policy: Option<NetworkPolicy>,
    #[serde(rename = "UserPolicy", default)]
    pub user_policy: Option<NetworkPolicy>,
    #[serde(rename = "HTTPBasedPolicy", default)]
    pub http_policy: Option<HttpBasedPolicy>,
}

impl FirewallRule {
    pub fn enabled(&self) -> bool {
        !matches!(self.status.as_deref(), Some("Disable"))
    }
    pub fn policy(&self) -> Option<&NetworkPolicy> {
        self.network_policy.as_ref().or(self.user_policy.as_ref())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(rename = "Action", default)]
    pub action: Option<String>,
    #[serde(rename = "LogTraffic", default)]
    pub log_traffic: Option<String>,
    #[serde(rename = "Schedule", default)]
    pub schedule: Option<String>,
    #[serde(rename = "SourceZones", default)]
    pub source_zones: Option<ZoneRefList>,
    #[serde(rename = "DestinationZones", default)]
    pub destination_zones: Option<ZoneRefList>,
    #[serde(rename = "SourceNetworks", default)]
    pub source_networks: Option<NetworkRefList>,
    #[serde(rename = "DestinationNetworks", default)]
    pub destination_networks: Option<NetworkRefList>,
    #[serde(rename = "Services", default)]
    pub services: Option<ServiceRefList>,
    #[serde(rename = "ScanVirus", default)]
    pub scan_virus: Option<String>,
    #[serde(rename = "IntrusionPrevention", default)]
    pub intrusion_prevention: Option<String>,
    #[serde(rename = "DecryptHTTPS", default)]
    pub decrypt_https: Option<String>,
    #[serde(rename = "ApplicationControl", default)]
    pub application_control: Option<String>,
}

impl NetworkPolicy {
    pub fn action_accepts(&self) -> bool {
        matches!(self.action.as_deref(), Some(a) if a.eq_ignore_ascii_case("Accept"))
    }
    pub fn source_zone_names(&self) -> &[String] {
        self.source_zones.as_ref().map(|z| z.zones.as_slice()).unwrap_or(&[])
    }
    pub fn destination_zone_names(&self) -> &[String] {
        self.destination_zones.as_ref().map(|z| z.zones.as_slice()).unwrap_or(&[])
    }
    pub fn service_names(&self) -> &[String] {
        self.services.as_ref().map(|s| s.services.as_slice()).unwrap_or(&[])
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpBasedPolicy {
    #[serde(rename = "HTTPS", default)]
    pub https: Option<String>,
    #[serde(rename = "ListenPort", default)]
    pub listen_port: Option<String>,
    #[serde(rename = "IntrusionPrevention", default)]
    pub intrusion_prevention: Option<String>,
    #[serde(rename = "Domains", default)]
    pub domains: Option<DomainList>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZoneRefList {
    #[serde(rename = "Zone", default)]
    pub zones: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkRefList {
    #[serde(rename = "Network", default)]
    pub networks: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceRefList {
    #[serde(rename = "Service", default)]
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainList {
    #[serde(rename = "Domain", default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHost {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "IPFamily", default)]
    pub ip_family: Option<String>,
    #[serde(rename = "HostType", default)]
    pub host_type: Option<String>,
    #[serde(rename = "IPAddress", default)]
    pub ip_address: Option<String>,
    #[serde(rename = "Subnet", default)]
    pub subnet: Option<String>,
    #[serde(rename = "StartIPAddress", default)]
    pub start_ip: Option<String>,
    #[serde(rename = "EndIPAddress", default)]
    pub end_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpHostGroup {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "HostList", default)]
    pub host_list: Option<HostList>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostList {
    #[serde(rename = "Host", default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceObj {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Type", default)]
    pub svc_type: Option<String>,
    #[serde(rename = "ServiceDetails", default)]
    pub details: Option<ServiceDetails>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceDetails {
    #[serde(rename = "ServiceDetail", default)]
    pub details: Vec<ServiceDetail>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceDetail {
    #[serde(rename = "SourcePort", default)]
    pub source_port: Option<String>,
    #[serde(rename = "DestinationPort", default)]
    pub destination_port: Option<String>,
    #[serde(rename = "Protocol", default)]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdminSettings {
    #[serde(rename = "LoginSecurity", default)]
    pub login_security: Option<LoginSecurity>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginSecurity {
    #[serde(rename = "BlockLogin", default)]
    pub block_login: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Hotfix {
    #[serde(rename = "AllowAutoInstallOfHotFixes", default)]
    pub auto_install: Option<String>,
}

// ── Search / query primitives ───────────────────────────────────────────────

impl SophosConfig {
    /// Iterate the IPsec connection bodies (unwrapping the `<Configuration>` layer).
    pub fn ipsec_connections(&self) -> impl Iterator<Item = &IpsecConfig> + '_ {
        self.ipsec.iter().map(|c| &c.configuration)
    }

    /// Rules carrying traffic from `src_zone` into `dst_zone` (case-insensitive).
    pub fn rules_from_to(&self, src_zone: &str, dst_zone: &str) -> Vec<&FirewallRule> {
        self.firewall_rules
            .iter()
            .filter(|r| {
                r.policy().is_some_and(|p| {
                    contains_ci(p.source_zone_names(), src_zone) && contains_ci(p.destination_zone_names(), dst_zone)
                })
            })
            .collect()
    }

    /// Rules referencing a named object (network, service, or zone) anywhere.
    pub fn rules_referencing(&self, object: &str) -> Vec<&FirewallRule> {
        self.firewall_rules
            .iter()
            .filter(|r| {
                r.policy().is_some_and(|p| {
                    contains_ci(p.source_zone_names(), object)
                        || contains_ci(p.destination_zone_names(), object)
                        || contains_ci(p.service_names(), object)
                        || p.source_networks.as_ref().is_some_and(|n| contains_ci(&n.networks, object))
                        || p.destination_networks.as_ref().is_some_and(|n| contains_ci(&n.networks, object))
                })
            })
            .collect()
    }

    #[allow(dead_code)] // search primitive, not yet wired to a CLI verb
    pub fn host_group_members(&self, group: &str) -> Option<&[String]> {
        self.ip_host_groups
            .iter()
            .find(|g| g.name.eq_ignore_ascii_case(group))
            .and_then(|g| g.host_list.as_ref())
            .map(|h| h.hosts.as_slice())
    }

    /// Zones referenced by rules but never defined as a `<Zone>` object.
    pub fn undefined_zone_refs(&self) -> Vec<String> {
        let defined: BTreeSet<String> = self.zones.iter().map(|z| z.name.to_lowercase()).collect();
        let mut missing = BTreeSet::new();
        for rule in &self.firewall_rules {
            if let Some(p) = rule.policy() {
                for z in p.source_zone_names().iter().chain(p.destination_zone_names()) {
                    if !defined.contains(&z.to_lowercase()) {
                        missing.insert(z.clone());
                    }
                }
            }
        }
        missing.into_iter().collect()
    }
}

fn contains_ci(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|h| h.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTITIES: &str = include_str!("../tests/fixtures/entities-sample.xml");

    #[test]
    fn parses_core_entities() {
        let cfg = parse_entities(ENTITIES).unwrap();
        assert_eq!(cfg.zones.len(), 3);
        assert_eq!(cfg.firewall_rules.len(), 3);
        assert_eq!(cfg.ip_hosts.len(), 2);
        assert_eq!(cfg.services.len(), 1);
    }

    #[test]
    fn search_referencing_and_from_to() {
        let cfg = parse_entities(ENTITIES).unwrap();
        assert_eq!(cfg.rules_referencing("HTTPS").len(), 2);
        assert_eq!(cfg.rules_from_to("lan", "wan").len(), 1);
        assert_eq!(cfg.undefined_zone_refs(), vec!["GUEST".to_string()]);
    }
}
