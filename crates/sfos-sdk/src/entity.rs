//! Typed entity helpers — the ergonomic create/update/delete layer that brings
//! the SDK toward parity with the Python `sophos-firewall-sdk`'s per-entity
//! methods.
//!
//! Each supported entity implements [`SophosEntity`] (its XML API tag + a
//! serialiser for `Set` request bodies) and gains constructors mirroring the
//! Python `create_*` helpers (e.g. `IpHost::ip("web", "10.0.0.5")`). The client
//! then offers generic `create`/`update`/`delete` over any `SophosEntity`.

use crate::sophos::{
    FirewallRule, IpHost, IpHostGroup, NetworkPolicy, ServiceDetail, ServiceDetails, ServiceObj, ServiceRefList, Zone,
    ZoneRefList,
};

/// An entity that can be written to the firewall via the XML API.
pub trait SophosEntity {
    /// The XML API element tag, e.g. `"IPHost"`.
    const TAG: &'static str;
    /// The object's name (its identifier for `Remove`).
    fn name(&self) -> &str;
    /// The `<TAG>…</TAG>` body for a `Set` request (only populated fields).
    fn to_xml(&self) -> String;
}

// ── helpers ─────────────────────────────────────────────────────────────────

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn req(tag: &str, v: &str) -> String {
    format!("<{tag}>{}</{tag}>", esc(v))
}

fn opt(tag: &str, v: &Option<String>) -> String {
    match v {
        Some(x) => req(tag, x),
        None => String::new(),
    }
}

fn list(outer: &str, inner: &str, items: &[String]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let body: String = items.iter().map(|i| req(inner, i)).collect();
    format!("<{outer}>{body}</{outer}>")
}

// ── IPHost ──────────────────────────────────────────────────────────────────

impl IpHost {
    /// A single-IP host (mirrors Python `create_ip_host(name, ip, mask=None)`).
    pub fn ip(name: &str, address: &str) -> Self {
        IpHost {
            name: name.into(),
            ip_family: Some("IPv4".into()),
            host_type: Some("IP".into()),
            ip_address: Some(address.into()),
            subnet: None,
            start_ip: None,
            end_ip: None,
        }
    }
    /// A network host (`address` + dotted `mask`, e.g. `255.255.255.0`).
    pub fn network(name: &str, address: &str, mask: &str) -> Self {
        IpHost {
            name: name.into(),
            ip_family: Some("IPv4".into()),
            host_type: Some("Network".into()),
            ip_address: Some(address.into()),
            subnet: Some(mask.into()),
            start_ip: None,
            end_ip: None,
        }
    }
    /// An IP range host.
    pub fn range(name: &str, start: &str, end: &str) -> Self {
        IpHost {
            name: name.into(),
            ip_family: Some("IPv4".into()),
            host_type: Some("IPRange".into()),
            ip_address: None,
            subnet: None,
            start_ip: Some(start.into()),
            end_ip: Some(end.into()),
        }
    }
}

impl SophosEntity for IpHost {
    const TAG: &'static str = "IPHost";
    fn name(&self) -> &str {
        &self.name
    }
    fn to_xml(&self) -> String {
        format!(
            "<IPHost>{}{}{}{}{}{}{}</IPHost>",
            req("Name", &self.name),
            opt("IPFamily", &self.ip_family),
            opt("HostType", &self.host_type),
            opt("IPAddress", &self.ip_address),
            opt("Subnet", &self.subnet),
            opt("StartIPAddress", &self.start_ip),
            opt("EndIPAddress", &self.end_ip),
        )
    }
}

// ── IPHostGroup ─────────────────────────────────────────────────────────────

impl IpHostGroup {
    pub fn new(name: &str, hosts: &[&str]) -> Self {
        IpHostGroup {
            name: name.into(),
            host_list: Some(crate::sophos::HostList { hosts: hosts.iter().map(|h| h.to_string()).collect() }),
        }
    }
}

impl SophosEntity for IpHostGroup {
    const TAG: &'static str = "IPHostGroup";
    fn name(&self) -> &str {
        &self.name
    }
    fn to_xml(&self) -> String {
        let hosts = self.host_list.as_ref().map(|h| h.hosts.as_slice()).unwrap_or(&[]);
        format!("<IPHostGroup>{}{}</IPHostGroup>", req("Name", &self.name), list("HostList", "Host", hosts))
    }
}

// ── Zone ────────────────────────────────────────────────────────────────────

impl Zone {
    pub fn new(name: &str, zone_type: &str) -> Self {
        Zone { name: name.into(), zone_type: Some(zone_type.into()), description: None }
    }
}

impl SophosEntity for Zone {
    const TAG: &'static str = "Zone";
    fn name(&self) -> &str {
        &self.name
    }
    fn to_xml(&self) -> String {
        format!(
            "<Zone>{}{}{}</Zone>",
            req("Name", &self.name),
            opt("Type", &self.zone_type),
            opt("Description", &self.description),
        )
    }
}

// ── Service ─────────────────────────────────────────────────────────────────

impl ServiceObj {
    /// A TCP service for a destination port (mirrors Python `create_service`).
    pub fn tcp(name: &str, dst_port: &str) -> Self {
        Self::tcp_udp(name, "TCP", dst_port)
    }
    pub fn udp(name: &str, dst_port: &str) -> Self {
        Self::tcp_udp(name, "UDP", dst_port)
    }
    fn tcp_udp(name: &str, proto: &str, dst_port: &str) -> Self {
        ServiceObj {
            name: name.into(),
            svc_type: Some("TCPorUDP".into()),
            details: Some(ServiceDetails {
                details: vec![ServiceDetail {
                    source_port: Some("1:65535".into()),
                    destination_port: Some(dst_port.into()),
                    protocol: Some(proto.into()),
                }],
            }),
        }
    }
}

impl SophosEntity for ServiceObj {
    const TAG: &'static str = "Services";
    fn name(&self) -> &str {
        &self.name
    }
    fn to_xml(&self) -> String {
        let mut details = String::new();
        if let Some(d) = &self.details {
            let inner: String = d
                .details
                .iter()
                .map(|sd| {
                    format!(
                        "<ServiceDetail>{}{}{}</ServiceDetail>",
                        opt("SourcePort", &sd.source_port),
                        opt("DestinationPort", &sd.destination_port),
                        opt("Protocol", &sd.protocol),
                    )
                })
                .collect();
            details = format!("<ServiceDetails>{inner}</ServiceDetails>");
        }
        format!("<Services>{}{}{}</Services>", req("Name", &self.name), opt("Type", &self.svc_type), details)
    }
}

// ── FirewallRule ────────────────────────────────────────────────────────────

impl FirewallRule {
    /// An accept rule from source zones to destination zones for the given
    /// services (mirrors Python `create_rule` for the common case).
    pub fn allow(name: &str, from: &[&str], to: &[&str], services: &[&str]) -> Self {
        Self::network_rule(name, "Accept", from, to, services)
    }
    pub fn deny(name: &str, from: &[&str], to: &[&str], services: &[&str]) -> Self {
        Self::network_rule(name, "Drop", from, to, services)
    }
    fn network_rule(name: &str, action: &str, from: &[&str], to: &[&str], services: &[&str]) -> Self {
        FirewallRule {
            name: name.into(),
            status: Some("Enable".into()),
            description: None,
            ip_family: Some("IPv4".into()),
            position: None,
            policy_type: Some("Network".into()),
            network_policy: Some(NetworkPolicy {
                action: Some(action.into()),
                log_traffic: Some("Enable".into()),
                source_zones: Some(ZoneRefList { zones: from.iter().map(|s| s.to_string()).collect() }),
                destination_zones: Some(ZoneRefList { zones: to.iter().map(|s| s.to_string()).collect() }),
                services: Some(ServiceRefList { services: services.iter().map(|s| s.to_string()).collect() }),
                ..Default::default()
            }),
            user_policy: None,
            http_policy: None,
        }
    }
}

fn network_policy_xml(p: &NetworkPolicy) -> String {
    let mut s = String::new();
    s += &opt("Action", &p.action);
    s += &opt("LogTraffic", &p.log_traffic);
    s += &opt("Schedule", &p.schedule);
    if let Some(z) = &p.source_zones {
        s += &list("SourceZones", "Zone", &z.zones);
    }
    if let Some(z) = &p.destination_zones {
        s += &list("DestinationZones", "Zone", &z.zones);
    }
    if let Some(n) = &p.source_networks {
        s += &list("SourceNetworks", "Network", &n.networks);
    }
    if let Some(n) = &p.destination_networks {
        s += &list("DestinationNetworks", "Network", &n.networks);
    }
    if let Some(sv) = &p.services {
        s += &list("Services", "Service", &sv.services);
    }
    s += &opt("IntrusionPrevention", &p.intrusion_prevention);
    s += &opt("ScanVirus", &p.scan_virus);
    s += &opt("ApplicationControl", &p.application_control);
    s
}

impl SophosEntity for FirewallRule {
    const TAG: &'static str = "FirewallRule";
    fn name(&self) -> &str {
        &self.name
    }
    fn to_xml(&self) -> String {
        let mut policy = String::new();
        if let Some(p) = &self.network_policy {
            policy = format!("<NetworkPolicy>{}</NetworkPolicy>", network_policy_xml(p));
        } else if let Some(p) = &self.user_policy {
            policy = format!("<UserPolicy>{}</UserPolicy>", network_policy_xml(p));
        }
        format!(
            "<FirewallRule>{}{}{}{}{}{}</FirewallRule>",
            req("Name", &self.name),
            opt("Status", &self.status),
            opt("Description", &self.description),
            opt("IPFamily", &self.ip_family),
            opt("PolicyType", &self.policy_type),
            policy,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_host_xml() {
        assert_eq!(
            IpHost::ip("web", "10.0.0.5").to_xml(),
            "<IPHost><Name>web</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.0.0.5</IPAddress></IPHost>"
        );
        assert_eq!(
            IpHost::network("lan", "10.0.0.0", "255.255.0.0").to_xml(),
            "<IPHost><Name>lan</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType><IPAddress>10.0.0.0</IPAddress><Subnet>255.255.0.0</Subnet></IPHost>"
        );
    }

    #[test]
    fn host_group_and_zone_xml() {
        assert_eq!(
            IpHostGroup::new("servers", &["web", "db"]).to_xml(),
            "<IPHostGroup><Name>servers</Name><HostList><Host>web</Host><Host>db</Host></HostList></IPHostGroup>"
        );
        assert_eq!(Zone::new("DMZ", "DMZ").to_xml(), "<Zone><Name>DMZ</Name><Type>DMZ</Type></Zone>");
    }

    #[test]
    fn service_xml() {
        assert_eq!(
            ServiceObj::tcp("HTTPS", "443").to_xml(),
            "<Services><Name>HTTPS</Name><Type>TCPorUDP</Type><ServiceDetails><ServiceDetail><SourcePort>1:65535</SourcePort><DestinationPort>443</DestinationPort><Protocol>TCP</Protocol></ServiceDetail></ServiceDetails></Services>"
        );
    }

    #[test]
    fn firewall_rule_xml() {
        let xml = FirewallRule::allow("LAN-to-WAN", &["LAN"], &["WAN"], &["HTTPS"]).to_xml();
        assert!(xml.starts_with("<FirewallRule><Name>LAN-to-WAN</Name><Status>Enable</Status>"));
        assert!(xml.contains("<NetworkPolicy><Action>Accept</Action>"));
        assert!(xml.contains("<SourceZones><Zone>LAN</Zone></SourceZones>"));
        assert!(xml.contains("<DestinationZones><Zone>WAN</Zone></DestinationZones>"));
        assert!(xml.contains("<Services><Service>HTTPS</Service></Services>"));
        assert_eq!(SophosEntity::name(&FirewallRule::allow("r", &[], &[], &[])), "r");
    }
}
