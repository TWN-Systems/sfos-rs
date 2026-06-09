//! Differential reachability explainer.
//!
//! Answers questions like *"why can on-site (LAN) users reach this network but
//! remote VPN users can't?"* — it evaluates the firewall rule base from several
//! source zones (vantage points) to one destination + service, and names the
//! rule that decided each verdict, plus every rule relevant to that destination.
//!
//! Scope: this reasons at the firewall-rule layer — source zones, destination
//! network objects (resolved to CIDRs), and services (resolved to proto/port).
//! NAT and interface/route effects are not yet modelled (a destination behind
//! DNAT, or routing/zone-of-interface nuances, are out of scope for now).

use std::net::IpAddr;

use crate::extract::{resolve_network, resolve_service};
use crate::ir::Protocol;
use crate::sophos::{FirewallRule, SophosConfig};

/// A firewall rule, flattened to the fields relevant to a reachability answer.
#[derive(Debug, Clone)]
pub struct RuleRef {
    pub name: String,
    pub action: String,
    pub enabled: bool,
    pub source_zones: Vec<String>,
    pub destination_zones: Vec<String>,
    pub destination_networks: Vec<String>,
    pub services: Vec<String>,
}

impl RuleRef {
    fn from(r: &FirewallRule) -> Self {
        let p = r.policy();
        RuleRef {
            name: r.name.clone(),
            action: p.and_then(|p| p.action.clone()).unwrap_or_else(|| "?".into()),
            enabled: r.enabled(),
            source_zones: p.map(|p| p.source_zone_names().to_vec()).unwrap_or_default(),
            destination_zones: p.map(|p| p.destination_zone_names().to_vec()).unwrap_or_default(),
            destination_networks: p
                .and_then(|p| p.destination_networks.as_ref())
                .map(|n| n.networks.clone())
                .unwrap_or_default(),
            services: p.map(|p| p.service_names().to_vec()).unwrap_or_default(),
        }
    }
}

/// The verdict from one vantage (source zone) to the destination.
#[derive(Debug, Clone)]
pub struct VantageVerdict {
    pub zone: String,
    pub allowed: bool,
    pub matched: Option<RuleRef>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ExplainResult {
    pub vantages: Vec<VantageVerdict>,
    /// Every rule that touches this destination + service, for context.
    pub related: Vec<RuleRef>,
}

impl ExplainResult {
    /// True if the vantages don't all agree (the interesting case).
    pub fn diverges(&self) -> bool {
        let mut it = self.vantages.iter().map(|v| v.allowed);
        match it.next() {
            Some(first) => it.any(|a| a != first),
            None => false,
        }
    }
}

/// Explain reachability to `dst`:`proto`/`dport` from each of `zones`.
pub fn explain(
    cfg: &SophosConfig,
    dst: IpAddr,
    proto: Protocol,
    dport: u16,
    zones: &[String],
) -> ExplainResult {
    let vantages = zones.iter().map(|z| evaluate_zone(cfg, z, dst, proto, dport)).collect();
    let related = cfg
        .firewall_rules
        .iter()
        .filter(|r| dst_matches(cfg, r, dst) && service_matches(cfg, r, proto, dport))
        .map(RuleRef::from)
        .collect();
    ExplainResult { vantages, related }
}

fn evaluate_zone(cfg: &SophosConfig, zone: &str, dst: IpAddr, proto: Protocol, dport: u16) -> VantageVerdict {
    for r in &cfg.firewall_rules {
        if !r.enabled() {
            continue;
        }
        if src_zone_matches(r, zone) && dst_matches(cfg, r, dst) && service_matches(cfg, r, proto, dport) {
            let rr = RuleRef::from(r);
            let allowed = rr.action.eq_ignore_ascii_case("Accept");
            let reason = if allowed {
                format!("allowed by rule '{}' (source zones: {})", rr.name, fmt(&rr.source_zones))
            } else {
                format!("blocked by rule '{}' (action {})", rr.name, rr.action)
            };
            return VantageVerdict { zone: zone.to_string(), allowed, matched: Some(rr), reason };
        }
    }
    VantageVerdict {
        zone: zone.to_string(),
        allowed: false,
        matched: None,
        reason: "no matching rule — implicit default drop".into(),
    }
}

fn fmt(z: &[String]) -> String {
    if z.is_empty() {
        "any".into()
    } else {
        z.join(",")
    }
}

fn src_zone_matches(r: &FirewallRule, zone: &str) -> bool {
    match r.policy() {
        Some(p) => {
            let s = p.source_zone_names();
            s.is_empty() || s.iter().any(|z| z.eq_ignore_ascii_case(zone))
        }
        None => false,
    }
}

fn dst_matches(cfg: &SophosConfig, r: &FirewallRule, dst: IpAddr) -> bool {
    let Some(p) = r.policy() else { return false };
    let Some(nets) = p.destination_networks.as_ref() else { return true };
    if nets.networks.is_empty() {
        return true;
    }
    nets.networks
        .iter()
        .any(|n| resolve_network(cfg, n).map(|net| net.contains(dst)).unwrap_or(false))
}

fn service_matches(cfg: &SophosConfig, r: &FirewallRule, proto: Protocol, dport: u16) -> bool {
    let Some(p) = r.policy() else { return false };
    let svcs = p.service_names();
    if svcs.is_empty() {
        return true;
    }
    svcs.iter().any(|s| {
        let (sp, ports) = resolve_service(cfg, std::slice::from_ref(s));
        let proto_ok = matches!(sp, None | Some(Protocol::Any)) || sp == Some(proto);
        let port_ok = match ports {
            None => true,
            Some((lo, hi)) => dport >= lo && dport <= hi,
        };
        proto_ok && port_ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    const ENTITIES: &str = include_str!("../tests/fixtures/entities-vpn.xml");

    #[test]
    fn lan_reaches_dmz_but_vpn_does_not() {
        let cfg = parse_entities(ENTITIES).unwrap();
        let dst: IpAddr = "10.0.10.5".parse().unwrap();
        let zones = vec!["LAN".to_string(), "VPN".to_string()];
        let r = explain(&cfg, dst, Protocol::Tcp, 443, &zones);

        assert!(r.diverges(), "LAN and VPN should differ");
        let lan = r.vantages.iter().find(|v| v.zone == "LAN").unwrap();
        let vpn = r.vantages.iter().find(|v| v.zone == "VPN").unwrap();
        assert!(lan.allowed, "LAN should reach the DMZ web server");
        assert!(!vpn.allowed, "VPN should be blocked");
        assert_eq!(lan.matched.as_ref().unwrap().name, "LAN-to-DMZ-web");
        assert!(vpn.matched.is_none()); // default drop
        // the rule is relevant context for both
        assert!(r.related.iter().any(|rr| rr.name == "LAN-to-DMZ-web"));
    }
}
