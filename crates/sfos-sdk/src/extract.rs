//! IR bridge: Sophos config → lean [`FirewallModel`].
//!
//! Sophos uses a single ordered rule base where each rule lists source and
//! destination zones. We synthesise one rule set per (source-zone,
//! destination-zone) pair, preserving global rule order within each pair, and
//! resolve Sophos host/service objects to concrete CIDRs/ports so the ACL and
//! shadow passes can reason precisely.

use std::collections::BTreeMap;

use ipnetwork::{IpNetwork, Ipv4Network};

use crate::ir::{AddrSpec, FilterAction, FirewallModel, Protocol, Rule, RuleSet};
use crate::sophos::SophosConfig;

pub fn to_model(cfg: &SophosConfig) -> FirewallModel {
    let mut model = FirewallModel::default();
    for z in &cfg.zones {
        model.zones.insert(z.name.clone());
    }

    let mut pairs: BTreeMap<(String, String), Vec<Rule>> = BTreeMap::new();
    for (idx, rule) in cfg.firewall_rules.iter().enumerate() {
        let Some(p) = rule.policy() else { continue };
        let (proto, dport) = resolve_service(cfg, p.service_names());
        let ir = Rule {
            seq: (idx as u32 + 1) * 10,
            action: map_action(p.action.as_deref()),
            description: rule.description.clone(),
            src: resolve_addr(cfg, p.source_networks.as_ref().map(|n| n.networks.as_slice()), None),
            dst: resolve_addr(cfg, p.destination_networks.as_ref().map(|n| n.networks.as_slice()), dport),
            protocol: proto,
            disabled: !rule.enabled(),
        };
        for s in nonempty(p.source_zone_names()) {
            for d in nonempty(p.destination_zone_names()) {
                model.zones.insert(s.clone());
                model.zones.insert(d.clone());
                pairs.entry((s.clone(), d)).or_default().push(ir.clone());
            }
        }
    }

    for ((src, dst), rules) in pairs {
        let name = format!("{src}-to-{dst}");
        model.rule_sets.insert((src, dst), RuleSet { name, default_action: FilterAction::Drop, rules });
    }
    model
}

fn nonempty(zones: &[String]) -> Vec<String> {
    if zones.is_empty() {
        vec!["Any".to_string()]
    } else {
        zones.to_vec()
    }
}

fn map_action(action: Option<&str>) -> FilterAction {
    match action.map(str::to_ascii_lowercase).as_deref() {
        Some("accept") => FilterAction::Accept,
        Some("reject") => FilterAction::Reject,
        _ => FilterAction::Drop,
    }
}

fn resolve_addr(cfg: &SophosConfig, names: Option<&[String]>, port_range: Option<(u16, u16)>) -> Option<AddrSpec> {
    let names = names.unwrap_or(&[]);
    if names.is_empty() && port_range.is_none() {
        return None;
    }
    let network = if names.len() == 1 { resolve_network(cfg, &names[0]) } else { None };
    let group = if network.is_none() && !names.is_empty() { Some(names.join(",")) } else { None };
    Some(AddrSpec { network, group, port_range })
}

/// Resolve a Sophos IPHost object name to a CIDR (when it is an IP or Network host).
pub fn resolve_network(cfg: &SophosConfig, name: &str) -> Option<IpNetwork> {
    let host = cfg.ip_hosts.iter().find(|h| h.name.eq_ignore_ascii_case(name))?;
    match host.host_type.as_deref() {
        Some("IP") => {
            let ip = host.ip_address.as_deref()?.parse().ok()?;
            Some(IpNetwork::V4(Ipv4Network::new(ip, 32).ok()?))
        }
        Some("Network") => {
            let ip = host.ip_address.as_deref()?.parse().ok()?;
            let mask = host.subnet.as_deref()?.parse().ok()?;
            Some(IpNetwork::V4(Ipv4Network::with_netmask(ip, mask).ok()?))
        }
        _ => None,
    }
}

/// Resolve a service-object name list to (protocol, destination-port-range) from the first entry.
pub fn resolve_service(cfg: &SophosConfig, services: &[String]) -> (Option<Protocol>, Option<(u16, u16)>) {
    let Some(name) = services.first() else { return (None, None) };
    let Some(svc) = cfg.services.iter().find(|s| s.name.eq_ignore_ascii_case(name)) else {
        return (None, None);
    };
    let detail = svc.details.as_ref().and_then(|d| d.details.first());
    let proto = detail
        .and_then(|d| d.protocol.as_deref())
        .map(map_protocol)
        .or_else(|| map_service_type(svc.svc_type.as_deref()));
    let ports = detail.and_then(|d| d.destination_port.as_deref()).and_then(parse_port_range);
    (proto, ports)
}

fn map_protocol(p: &str) -> Protocol {
    match p.to_ascii_uppercase().as_str() {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        "ICMP" => Protocol::Icmp,
        "ICMPV6" => Protocol::Icmpv6,
        _ => Protocol::Any,
    }
}

fn map_service_type(t: Option<&str>) -> Option<Protocol> {
    match t {
        Some("ICMP") => Some(Protocol::Icmp),
        Some("ICMPv6") => Some(Protocol::Icmpv6),
        _ => None,
    }
}

fn parse_port_range(s: &str) -> Option<(u16, u16)> {
    let s = s.trim();
    if let Some((lo, hi)) = s.split_once(':') {
        Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?))
    } else {
        let p = s.parse().ok()?;
        Some((p, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    const ENTITIES: &str = include_str!("../tests/fixtures/entities-sample.xml");

    #[test]
    fn bridges_pairs_and_resolves_objects() {
        let cfg = parse_entities(ENTITIES).unwrap();
        let m = to_model(&cfg);
        assert!(m.rule_sets.contains_key(&("LAN".into(), "WAN".into())));
        let rs = &m.rule_sets[&("WAN".into(), "DMZ".into())];
        let rule = &rs.rules[0];
        assert_eq!(rule.protocol, Some(Protocol::Tcp));
        let dst = rule.dst.as_ref().unwrap();
        assert_eq!(dst.port_range, Some((443, 443)));
        assert_eq!(dst.network.map(|n| n.to_string()), Some("10.0.10.5/32".to_string()));
    }

    #[test]
    fn network_object_resolves_with_netmask() {
        let cfg = parse_entities(ENTITIES).unwrap();
        assert_eq!(resolve_network(&cfg, "LAN-Net").unwrap().to_string(), "10.0.0.0/16");
    }
}
