//! Catalog of Sophos SFOS XML API entities, grouped by the firewall's own menu
//! categories (derived from the SFOS 21.5 API reference).
//!
//! The XML API is uniform — every entity is retrieved with
//! `<Get><Tag></Tag></Get>` — so this table plus a generic `get` is enough to
//! pull the *entire* configuration. `export_all` iterates this catalog and is
//! resilient: an entity that doesn't apply to a given firewall (e.g. wireless on
//! a virtual appliance) or whose tag needs adjustment is reported per-entity,
//! not fatal. Tags are best-effort from the 21.5 docs and self-validate against
//! a live box; `Client::get_raw` accepts any tag string for entities not yet
//! catalogued here.

pub struct Entity {
    pub category: &'static str,
    pub display: &'static str,
    pub tag: &'static str,
}

pub const ENTITIES: &[Entity] = &[
    // ── Hosts and services ──
    e("Hosts and services", "IP Host", "IPHost"),
    e("Hosts and services", "IP Host Group", "IPHostGroup"),
    e("Hosts and services", "MAC Host", "MACHost"),
    e("Hosts and services", "FQDN Host", "FQDNHost"),
    e("Hosts and services", "FQDN Host Group", "FQDNHostGroup"),
    e("Hosts and services", "Country Group", "CountryGroup"),
    e("Hosts and services", "Service", "Services"),
    e("Hosts and services", "Service Group", "ServiceGroup"),
    // ── Firewall ──
    e("Firewall", "Firewall Rule", "FirewallRule"),
    e("Firewall", "Firewall Rule Group", "FirewallRuleGroup"),
    e("Firewall", "NAT Rule", "NATRule"),
    e("Firewall", "SSL/TLS Inspection Rule", "SSLTLSInspectionRule"),
    e("Firewall", "Local Service ACL", "LocalServiceACL"),
    // ── Intrusion prevention ──
    e("Intrusion prevention", "IPS Policy", "IPSPolicy"),
    e("Intrusion prevention", "Custom IPS Signature", "CustomIPSSignatures"),
    e("Intrusion prevention", "DoS Settings", "DoSSettings"),
    // ── Web ──
    e("Web", "Web Filter Policy", "WebFilterPolicy"),
    e("Web", "URL Group", "WebFilterURLGroup"),
    e("Web", "Web Filter Exception", "WebFilterException"),
    e("Web", "File Type", "FileType"),
    e("Web", "User Activity", "UserActivity"),
    // ── Applications ──
    e("Applications", "Application Filter Policy", "ApplicationFilterPolicy"),
    e("Applications", "Application Filter", "ApplicationFilter"),
    // ── Email ──
    e("Email", "SMTP Policy", "SMTPPolicy"),
    e("Email", "Trusted Domain", "TrustedDomain"),
    // ── VPN ──
    e("VPN", "IPSec Connection", "VPNIPSecConnection"),
    e("VPN", "L2TP Connection", "L2TP"),
    // ── Network ──
    e("Network", "Interface", "Interface"),
    e("Network", "VLAN", "VLAN"),
    e("Network", "Alias", "Alias"),
    e("Network", "Bridge", "BridgePair"),
    e("Network", "LAG", "LAG"),
    e("Network", "Zone", "Zone"),
    e("Network", "Gateway", "Gateway"),
    e("Network", "DNS", "DNS"),
    e("Network", "DNS Host Entry", "DNSHostEntry"),
    e("Network", "DHCP Server", "DHCPServer"),
    e("Network", "DHCP Relay", "DHCPRelay"),
    e("Network", "IP Tunnel", "IPTunnel"),
    e("Network", "GRE Tunnel", "GRETunnel"),
    e("Network", "Dynamic DNS", "DynamicDNS"),
    // ── Routing ──
    e("Routing", "Static Route", "UnicastRoute"),
    e("Routing", "SD-WAN Policy Route", "SDWANPolicyRoute"),
    e("Routing", "Gateway Object", "GatewayConfiguration"),
    // ── Authentication ──
    e("Authentication", "Authentication Server", "AuthenticationServer"),
    e("Authentication", "LDAP Server", "LDAPServer"),
    e("Authentication", "RADIUS Server", "RADIUSServer"),
    e("Authentication", "Users", "User"),
    e("Authentication", "Groups", "UserGroup"),
    e("Authentication", "Guest User", "GuestUser"),
    e("Authentication", "OTP Token", "OTPToken"),
    // ── System services ──
    e("System services", "HA Configuration", "HAConfiguration"),
    e("System services", "Syslog Server", "SyslogServers"),
    e("System services", "QoS Policy", "QoSPolicy"),
    e("System services", "Notification", "Notification"),
    // ── Profiles ──
    e("Profiles", "Schedule", "Schedule"),
    e("Profiles", "Access Time", "AccessTime"),
    e("Profiles", "Decryption Profile", "DecryptionProfile"),
    // ── Administration ──
    e("Administration", "Admin Settings", "AdminSettings"),
    e("Administration", "Web Admin Settings", "WebAdminSettings"),
    e("Administration", "SNMP Community", "SNMPCommunity"),
    e("Administration", "Login Security", "LoginSecurity"),
    // ── Certificates ──
    e("Certificates", "Certificate", "Certificate"),
    e("Certificates", "Certificate Authority", "CertificateAuthority"),
    // ── System ──
    e("System", "Hotfix", "Hotfix"),
    e("System", "Central Management", "CentralManagement"),
];

const fn e(category: &'static str, display: &'static str, tag: &'static str) -> Entity {
    Entity { category, display, tag }
}

/// All catalogued entity tags, in catalog order.
pub fn tags() -> Vec<&'static str> {
    ENTITIES.iter().map(|x| x.tag).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_populated_and_unique() {
        assert!(ENTITIES.len() >= 50);
        let mut seen = std::collections::BTreeSet::new();
        for x in ENTITIES {
            assert!(seen.insert(x.tag), "duplicate tag {}", x.tag);
        }
    }
}
