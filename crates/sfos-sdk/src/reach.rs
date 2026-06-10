//! Reachability: a single-node forwarding model plus a differential explainer.
//!
//! [`explain`] answers *"why can zone A reach X but zone B can't?"* across many
//! source zones. [`forward`] simulates one packet end-to-end through the SFOS
//! pipeline: ingress zone → DNAT → route lookup (egress interface/zone) →
//! firewall (source zone → destination zone, post-DNAT destination, service) →
//! SNAT → delivery.
//!
//! Modelled at the config layer; tag schemas for interfaces/NAT/routes are
//! best-effort and self-validate against a live export.

use std::net::IpAddr;

use crate::extract::{resolve_network, resolve_service, zone_of_ip};
use crate::ir::Protocol;
use crate::route;
use crate::sophos::{FirewallRule, SophosConfig};

/// A firewall rule flattened to the fields relevant to a reachability answer.
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

#[derive(Debug, Clone)]
pub struct VantageVerdict {
    pub zone: String,
    pub allowed: bool,
    pub matched: Option<RuleRef>,
    pub reason: String,
}

/// A destination-NAT translation applied before firewall evaluation.
#[derive(Debug, Clone)]
pub struct NatHop {
    pub rule: String,
    pub original: String,
    pub translated: String,
}

#[derive(Debug, Clone)]
pub struct ExplainResult {
    pub vantages: Vec<VantageVerdict>,
    pub related: Vec<RuleRef>,
    pub nat: Option<NatHop>,
    /// Routed egress zone of the (post-DNAT) destination, when routing is modelled.
    pub egress_zone: Option<String>,
    /// True when routing is modelled but no route covers the destination.
    pub no_route: bool,
}

impl ExplainResult {
    pub fn diverges(&self) -> bool {
        let mut it = self.vantages.iter().map(|v| v.allowed);
        match it.next() {
            Some(first) => it.any(|a| a != first),
            None => false,
        }
    }
}

/// Differential reachability from each of `zones` to `dst`:`proto`/`dport`.
pub fn explain(cfg: &SophosConfig, dst: IpAddr, proto: Protocol, dport: u16, zones: &[String]) -> ExplainResult {
    let (effective_dst, nat) = apply_dnat(cfg, dst);

    let rt = route::build(cfg);
    let routed = !rt.is_empty();
    let egress_zone = if routed { rt.zone_of(effective_dst) } else { None };
    let no_route = routed && rt.lookup(effective_dst).is_none();

    let vantages = zones
        .iter()
        .map(|z| {
            if no_route {
                VantageVerdict {
                    zone: z.clone(),
                    allowed: false,
                    matched: None,
                    reason: format!("no route to {effective_dst} — unreachable"),
                }
            } else {
                first_match(cfg, Some(z), egress_zone.as_deref(), effective_dst, proto, dport)
            }
        })
        .collect();

    let related = cfg
        .firewall_rules
        .iter()
        .filter(|r| dst_matches(cfg, r, effective_dst) && service_matches(cfg, r, proto, dport))
        .map(RuleRef::from)
        .collect();

    ExplainResult { vantages, related, nat, egress_zone, no_route }
}

/// One end-to-end forwarding decision for a single packet.
#[derive(Debug, Clone)]
pub struct ForwardResult {
    pub ingress_zone: Option<String>,
    pub nat: Option<NatHop>,
    pub egress_zone: Option<String>,
    pub egress_interface: Option<String>,
    pub snat: Option<String>,
    pub verdict: VantageVerdict,
    pub delivered: bool,
    pub stages: Vec<String>,
}

pub fn forward(cfg: &SophosConfig, src: IpAddr, dst: IpAddr, proto: Protocol, dport: u16) -> ForwardResult {
    let mut stages = Vec::new();

    let ingress_zone = zone_of_ip(cfg, src);
    stages.push(format!("ingress: {src} -> zone {}", opt(&ingress_zone)));

    let (effective_dst, nat) = apply_dnat(cfg, dst);
    if let Some(n) = &nat {
        stages.push(format!("dnat: {} -> {} (rule {})", n.original, n.translated, n.rule));
    }

    let rt = route::build(cfg);
    let routed = !rt.is_empty();
    let route = rt.lookup(effective_dst);
    let (egress_zone, egress_interface) = match route {
        Some(r) => (r.zone.clone(), r.interface.clone()),
        None => (None, None),
    };
    match route {
        Some(r) => stages.push(format!("route: {effective_dst} via {} (zone {})", opt(&r.interface), opt(&r.zone))),
        None if routed => stages.push(format!("route: no route to {effective_dst}")),
        None => stages.push("route: not modelled (no interfaces/routes in config)".into()),
    }

    let verdict = if routed && route.is_none() {
        VantageVerdict {
            zone: opt(&ingress_zone),
            allowed: false,
            matched: None,
            reason: "no route to destination".into(),
        }
    } else {
        first_match(cfg, ingress_zone.as_deref(), egress_zone.as_deref(), effective_dst, proto, dport)
    };
    stages.push(format!("firewall: {}", verdict.reason));

    let snat = snat_for(cfg, src, effective_dst);
    if let Some(s) = &snat {
        stages.push(format!("snat: {s}"));
    }

    let delivered = verdict.allowed && !(routed && route.is_none());
    stages.push(format!("result: {}", if delivered { "DELIVERED" } else { "BLOCKED" }));

    ForwardResult { ingress_zone, nat, egress_zone, egress_interface, snat, verdict, delivered, stages }
}

// ── cross-firewall (multi-hop over a site-to-site tunnel) ────────────────────

#[derive(Debug, Clone)]
pub struct SitePathResult {
    pub tunnel_a: Option<String>,
    pub tunnel_b: Option<String>,
    pub paired: bool,
    pub delivered: bool,
    pub stages: Vec<String>,
}

/// Trace a flow from a host at site A to a host at site B, through A's firewall,
/// the IPsec site-to-site tunnel, and B's firewall. IPsec traffic is assumed to
/// land in the `VPN` zone (the SFOS convention).
#[allow(clippy::too_many_arguments)] // two sites × (name, config) + the 4-tuple flow is the natural signature
pub fn site_path(
    a_name: &str,
    a: &SophosConfig,
    b_name: &str,
    b: &SophosConfig,
    src: IpAddr,
    dst: IpAddr,
    proto: Protocol,
    dport: u16,
) -> SitePathResult {
    const VPN: &str = "VPN";
    let mut stages = Vec::new();

    // Site A: out to the tunnel that covers the destination.
    let src_zone_a = zone_of_ip(a, src).unwrap_or_else(|| "?".into());
    let tunnel_a = a
        .ipsec_connections()
        .filter(|c| c.is_site_to_site())
        .find(|c| subnets_contain(a, c.remote_subnets(), dst))
        .map(|c| c.name.clone());

    let a_allow = match &tunnel_a {
        None => {
            stages.push(format!("{a_name}: no site-to-site tunnel covers {dst} — not routed off-site"));
            false
        }
        Some(t) => {
            let v = first_match(a, Some(&src_zone_a), Some(VPN), dst, proto, dport);
            stages.push(format!("{a_name}: {src_zone_a} -> VPN (tunnel '{t}'): {}", v.reason));
            v.allowed
        }
    };

    // Tunnel pairing on B (B must have a tunnel back covering this flow).
    let tunnel_b = b
        .ipsec_connections()
        .filter(|c| c.is_site_to_site())
        .find(|c| subnets_contain(b, c.remote_subnets(), src) && subnets_contain(b, &c.local_subnets, dst))
        .map(|c| c.name.clone());
    let paired = tunnel_a.is_some() && tunnel_b.is_some();
    match (&tunnel_a, &tunnel_b) {
        (Some(_), Some(t)) => stages.push(format!("tunnel: paired with {b_name} tunnel '{t}'")),
        (Some(_), None) => {
            stages.push(format!("tunnel: {b_name} has no matching tunnel for {src} -> {dst} (asymmetric or missing)"))
        }
        _ => {}
    }

    // Site B: in from the tunnel to the destination.
    let b_allow = if tunnel_b.is_some() {
        let dst_zone_b = route::build(b).zone_of(dst).unwrap_or_else(|| "?".into());
        let v = first_match(b, Some(VPN), Some(&dst_zone_b), dst, proto, dport);
        stages.push(format!("{b_name}: VPN -> {dst_zone_b}: {}", v.reason));
        v.allowed
    } else {
        false
    };

    let delivered = a_allow && paired && b_allow;
    stages.push(format!("result: {}", if delivered { "DELIVERED" } else { "BLOCKED" }));

    SitePathResult { tunnel_a, tunnel_b, paired, delivered, stages }
}

fn subnets_contain(cfg: &SophosConfig, names: &[String], ip: IpAddr) -> bool {
    names.iter().any(|n| resolve_network(cfg, n).map(|net| net.contains(ip)).unwrap_or(false))
}

// ── internals ───────────────────────────────────────────────────────────────

fn apply_dnat(cfg: &SophosConfig, dst: IpAddr) -> (IpAddr, Option<NatHop>) {
    match dnat_for(cfg, dst) {
        Some((rule, tip)) => (tip, Some(NatHop { rule, original: dst.to_string(), translated: tip.to_string() })),
        None => (dst, None),
    }
}

fn dnat_for(cfg: &SophosConfig, dst: IpAddr) -> Option<(String, IpAddr)> {
    for n in &cfg.nat_rules {
        if matches!(n.status.as_deref(), Some(s) if s.eq_ignore_ascii_case("Disable")) {
            continue;
        }
        let hits = n
            .original_destinations()
            .iter()
            .any(|name| resolve_network(cfg, name).map(|net| net.contains(dst)).unwrap_or(false));
        if !hits {
            continue;
        }
        if let Some(t) = n.translated_destination.as_deref() {
            if let Some(tnet) = resolve_network(cfg, t) {
                return Some((n.name.clone(), tnet.network()));
            }
        }
    }
    None
}

fn snat_for(cfg: &SophosConfig, src: IpAddr, _dst: IpAddr) -> Option<String> {
    for n in &cfg.nat_rules {
        if matches!(n.status.as_deref(), Some(s) if s.eq_ignore_ascii_case("Disable")) {
            continue;
        }
        let Some(ts) = n.translated_source.as_deref() else { continue };
        let srcs = n.original_sources();
        let src_ok = srcs.is_empty()
            || srcs.iter().any(|name| resolve_network(cfg, name).map(|net| net.contains(src)).unwrap_or(false));
        if src_ok {
            return Some(format!("source NAT'd to '{ts}' by rule '{}'", n.name));
        }
    }
    None
}

/// First matching enabled rule; default-drop if none.
fn first_match(
    cfg: &SophosConfig,
    src_zone: Option<&str>,
    egress_zone: Option<&str>,
    dst: IpAddr,
    proto: Protocol,
    dport: u16,
) -> VantageVerdict {
    let label = src_zone.unwrap_or("*").to_string();
    for r in &cfg.firewall_rules {
        if !r.enabled() {
            continue;
        }
        if src_ok(r, src_zone)
            && dest_zone_ok(r, egress_zone)
            && dst_matches(cfg, r, dst)
            && service_matches(cfg, r, proto, dport)
        {
            let rr = RuleRef::from(r);
            let allowed = rr.action.eq_ignore_ascii_case("Accept");
            let reason = if allowed {
                format!("allowed by rule '{}' (source zones: {})", rr.name, fmt(&rr.source_zones))
            } else {
                format!("blocked by rule '{}' (action {})", rr.name, rr.action)
            };
            return VantageVerdict { zone: label, allowed, matched: Some(rr), reason };
        }
    }
    VantageVerdict {
        zone: label,
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

fn opt(z: &Option<String>) -> String {
    z.clone().unwrap_or_else(|| "?".into())
}

fn src_ok(r: &FirewallRule, sz: Option<&str>) -> bool {
    match r.policy() {
        Some(p) => {
            let s = p.source_zone_names();
            s.is_empty() || sz.map(|z| s.iter().any(|x| x.eq_ignore_ascii_case(z))).unwrap_or(true)
        }
        None => false,
    }
}

fn dest_zone_ok(r: &FirewallRule, egress: Option<&str>) -> bool {
    let Some(eg) = egress else { return true };
    match r.policy() {
        Some(p) => {
            let d = p.destination_zone_names();
            d.is_empty() || d.iter().any(|z| z.eq_ignore_ascii_case(eg))
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
    nets.networks.iter().any(|n| resolve_network(cfg, n).map(|net| net.contains(dst)).unwrap_or(false))
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

    const VPN: &str = include_str!("../tests/fixtures/entities-vpn.xml");
    const NAT: &str = include_str!("../tests/fixtures/entities-nat.xml");

    #[test]
    fn lan_reaches_dmz_but_vpn_does_not() {
        let cfg = parse_entities(VPN).unwrap();
        let dst: IpAddr = "10.0.10.5".parse().unwrap();
        let r = explain(&cfg, dst, Protocol::Tcp, 443, &["LAN".into(), "VPN".into()]);
        assert!(r.diverges());
        assert!(r.vantages.iter().find(|v| v.zone == "LAN").unwrap().allowed);
        assert!(!r.vantages.iter().find(|v| v.zone == "VPN").unwrap().allowed);
    }

    #[test]
    fn dnat_is_followed_and_routed() {
        let cfg = parse_entities(NAT).unwrap();
        let public: IpAddr = "203.0.113.10".parse().unwrap();
        let r = explain(&cfg, public, Protocol::Tcp, 443, &["WAN".into()]);
        assert_eq!(r.nat.as_ref().unwrap().translated, "10.0.10.5");
        assert_eq!(r.egress_zone.as_deref(), Some("DMZ"));
        assert!(!r.no_route);
        assert!(r.vantages[0].allowed);
    }

    #[test]
    fn cross_site_path_delivers_over_tunnel() {
        let a = parse_entities(include_str!("../tests/fixtures/sp-site-a.xml")).unwrap();
        let b = parse_entities(include_str!("../tests/fixtures/sp-site-b.xml")).unwrap();
        let src: IpAddr = "10.1.5.5".parse().unwrap(); // host at site A
        let dst: IpAddr = "10.2.5.5".parse().unwrap(); // host at site B
        let r = site_path("site-a", &a, "site-b", &b, src, dst, Protocol::Tcp, 443);
        assert_eq!(r.tunnel_a.as_deref(), Some("to-b"));
        assert_eq!(r.tunnel_b.as_deref(), Some("to-a"));
        assert!(r.paired);
        assert!(r.delivered, "stages: {:?}", r.stages);
    }

    #[test]
    fn forward_pipeline_delivers_dnat_flow() {
        let cfg = parse_entities(NAT).unwrap();
        let src: IpAddr = "203.0.113.50".parse().unwrap(); // WAN side
        let dst: IpAddr = "203.0.113.10".parse().unwrap(); // public, DNAT'd
        let f = forward(&cfg, src, dst, Protocol::Tcp, 443);
        assert_eq!(f.ingress_zone.as_deref(), Some("WAN"));
        assert_eq!(f.egress_zone.as_deref(), Some("DMZ"));
        assert!(f.nat.is_some());
        assert!(f.delivered);
    }
}
