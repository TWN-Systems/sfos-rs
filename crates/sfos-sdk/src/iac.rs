//! IaC export — a normalized, declarative, version-controllable view of the
//! firewall, emitted from a parsed config (live or backup). Serialises to JSON
//! today (diff-friendly, drift-trackable, and re-appliable via the typed
//! `client.create` helpers); an Ansible-playbook emitter is a natural follow-on.

use serde::Serialize;

use crate::sophos::{IpHost, SophosConfig};

#[derive(Serialize)]
pub struct NormalizedConfig {
    pub zones: Vec<NormZone>,
    pub interfaces: Vec<NormInterface>,
    pub hosts: Vec<NormHost>,
    pub host_groups: Vec<NormGroup>,
    pub services: Vec<NormService>,
    pub rules: Vec<NormRule>,
    pub nat: Vec<NormNat>,
    pub ipsec: Vec<NormIpsec>,
}

#[derive(Serialize)]
pub struct NormZone {
    pub name: String,
    pub r#type: Option<String>,
}

#[derive(Serialize)]
pub struct NormInterface {
    pub name: String,
    pub zone: Option<String>,
    pub address: Option<String>,
}

#[derive(Serialize)]
pub struct NormNat {
    pub name: String,
    pub original_sources: Vec<String>,
    pub original_destinations: Vec<String>,
    pub translated_source: Option<String>,
    pub translated_destination: Option<String>,
}

#[derive(Serialize)]
pub struct NormHost {
    pub name: String,
    pub r#type: Option<String>,
    pub address: String,
}

#[derive(Serialize)]
pub struct NormGroup {
    pub name: String,
    pub hosts: Vec<String>,
}

#[derive(Serialize)]
pub struct NormService {
    pub name: String,
    pub r#type: Option<String>,
    pub ports: Vec<String>,
}

#[derive(Serialize)]
pub struct NormRule {
    pub name: String,
    pub enabled: bool,
    pub action: Option<String>,
    pub source_zones: Vec<String>,
    pub destination_zones: Vec<String>,
    pub source_networks: Vec<String>,
    pub destination_networks: Vec<String>,
    pub services: Vec<String>,
}

#[derive(Serialize)]
pub struct NormIpsec {
    pub name: String,
    pub connection_type: Option<String>,
    pub policy: Option<String>,
    pub authentication: Option<String>,
    pub ike_version: Option<String>,
    pub remote_gateway: Option<String>,
    pub local_subnets: Vec<String>,
    pub remote_subnets: Vec<String>,
}

pub fn normalize(cfg: &SophosConfig) -> NormalizedConfig {
    NormalizedConfig {
        zones: cfg.zones.iter().map(|z| NormZone { name: z.name.clone(), r#type: z.zone_type.clone() }).collect(),
        interfaces: cfg
            .interfaces
            .iter()
            .map(|i| NormInterface {
                name: i.name.clone(),
                zone: i.zone.clone(),
                address: match (i.ip_address.as_deref(), i.netmask.as_deref()) {
                    (Some(a), Some(m)) => Some(format!("{a}/{m}")),
                    (Some(a), None) => Some(a.to_string()),
                    _ => None,
                },
            })
            .collect(),
        nat: cfg
            .nat_rules
            .iter()
            .map(|n| NormNat {
                name: n.name.clone(),
                original_sources: n.original_sources().to_vec(),
                original_destinations: n.original_destinations().to_vec(),
                translated_source: n.translated_source.clone(),
                translated_destination: n.translated_destination.clone(),
            })
            .collect(),
        hosts: cfg
            .ip_hosts
            .iter()
            .map(|h| NormHost { name: h.name.clone(), r#type: h.host_type.clone(), address: host_addr(h) })
            .collect(),
        host_groups: cfg
            .ip_host_groups
            .iter()
            .map(|g| NormGroup {
                name: g.name.clone(),
                hosts: g.host_list.as_ref().map(|h| h.hosts.clone()).unwrap_or_default(),
            })
            .collect(),
        services: cfg
            .services
            .iter()
            .map(|s| NormService {
                name: s.name.clone(),
                r#type: s.svc_type.clone(),
                ports: s
                    .details
                    .as_ref()
                    .map(|d| {
                        d.details
                            .iter()
                            .map(|sd| {
                                format!(
                                    "{}/{}",
                                    sd.protocol.as_deref().unwrap_or("?"),
                                    sd.destination_port.as_deref().unwrap_or("?")
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect(),
        rules: cfg
            .firewall_rules
            .iter()
            .map(|r| {
                let p = r.policy();
                NormRule {
                    name: r.name.clone(),
                    enabled: r.enabled(),
                    action: p.and_then(|p| p.action.clone()),
                    source_zones: p.map(|p| p.source_zone_names().to_vec()).unwrap_or_default(),
                    destination_zones: p.map(|p| p.destination_zone_names().to_vec()).unwrap_or_default(),
                    source_networks: p
                        .and_then(|p| p.source_networks.as_ref())
                        .map(|n| n.networks.clone())
                        .unwrap_or_default(),
                    destination_networks: p
                        .and_then(|p| p.destination_networks.as_ref())
                        .map(|n| n.networks.clone())
                        .unwrap_or_default(),
                    services: p.map(|p| p.service_names().to_vec()).unwrap_or_default(),
                }
            })
            .collect(),
        ipsec: cfg
            .ipsec_connections()
            .map(|c| NormIpsec {
                name: c.name.clone(),
                connection_type: c.connection_type.clone(),
                policy: c.policy.clone(),
                authentication: c.authentication_type.clone(),
                ike_version: c.ike_version.clone(),
                remote_gateway: c.remote_gateway.clone(),
                local_subnets: c.local_subnets.clone(),
                remote_subnets: c.remote_subnets().to_vec(),
            })
            .collect(),
    }
}

fn host_addr(h: &IpHost) -> String {
    match (h.ip_address.as_deref(), h.subnet.as_deref(), h.start_ip.as_deref(), h.end_ip.as_deref()) {
        (Some(ip), Some(sub), _, _) => format!("{ip}/{sub}"),
        (Some(ip), None, _, _) => ip.to_string(),
        (_, _, Some(s), Some(e)) => format!("{s}-{e}"),
        _ => "-".to_string(),
    }
}

/// Emit a `sophos.sophos_firewall` Ansible playbook that recreates the modelled
/// objects. Module argument names are best-effort against the collection and may
/// need tuning to your collection version; the playbook is a re-deploy/BCDR
/// scaffold, not a guaranteed apply.
pub fn to_ansible(cfg: &SophosConfig) -> String {
    let mut o = String::new();
    o.push_str("---\n");
    o.push_str("- name: Recreate Sophos SFOS configuration\n");
    o.push_str("  hosts: sophos_firewalls\n");
    o.push_str("  gather_facts: false\n");
    o.push_str("  collections:\n    - sophos.sophos_firewall\n");
    o.push_str("  tasks:\n");

    for z in &cfg.zones {
        let mut sc = vec![("name", z.name.clone())];
        if let Some(t) = &z.zone_type {
            sc.push(("zone_type", t.clone()));
        }
        task(&mut o, &format!("Zone {}", z.name), "sophos.sophos_firewall.sfos_zone", &sc, &[]);
    }
    for h in &cfg.ip_hosts {
        let mut sc = vec![("name", h.name.clone())];
        if let Some(t) = &h.host_type {
            sc.push(("host_type", t.clone()));
        }
        if let Some(a) = &h.ip_address {
            sc.push(("ip_address", a.clone()));
        }
        if let Some(s) = &h.subnet {
            sc.push(("subnet_mask", s.clone()));
        }
        task(&mut o, &format!("IP host {}", h.name), "sophos.sophos_firewall.sfos_ip_host", &sc, &[]);
    }
    for g in &cfg.ip_host_groups {
        let hosts = g.host_list.as_ref().map(|h| h.hosts.clone()).unwrap_or_default();
        task(
            &mut o,
            &format!("IP host group {}", g.name),
            "sophos.sophos_firewall.sfos_ip_hostgroup",
            &[("name", g.name.clone())],
            &[("host_list", &hosts)],
        );
    }
    for r in &cfg.firewall_rules {
        let p = r.policy();
        let mut sc = vec![("name", r.name.clone())];
        if let Some(a) = p.and_then(|p| p.action.clone()) {
            sc.push(("action", a));
        }
        sc.push(("status", if r.enabled() { "enable".into() } else { "disable".into() }));
        let sz = p.map(|p| p.source_zone_names().to_vec()).unwrap_or_default();
        let dz = p.map(|p| p.destination_zone_names().to_vec()).unwrap_or_default();
        let sn = p.and_then(|p| p.source_networks.as_ref()).map(|n| n.networks.clone()).unwrap_or_default();
        let dn = p.and_then(|p| p.destination_networks.as_ref()).map(|n| n.networks.clone()).unwrap_or_default();
        let sv = p.map(|p| p.service_names().to_vec()).unwrap_or_default();
        task(
            &mut o,
            &format!("Firewall rule {}", r.name),
            "sophos.sophos_firewall.sfos_firewall_rule",
            &sc,
            &[
                ("source_zones", &sz),
                ("destination_zones", &dz),
                ("source_networks", &sn),
                ("destination_networks", &dn),
                ("service_list", &sv),
            ],
        );
    }
    o
}

fn task(o: &mut String, comment: &str, module: &str, scalars: &[(&str, String)], lists: &[(&str, &[String])]) {
    o.push_str(&format!("    - name: {comment}\n      {module}:\n"));
    for (k, v) in scalars {
        o.push_str(&format!("        {k}: {}\n", yq(v)));
    }
    for (k, items) in lists {
        if items.is_empty() {
            continue;
        }
        o.push_str(&format!("        {k}:\n"));
        for it in *items {
            o.push_str(&format!("          - {}\n", yq(it)));
        }
    }
    o.push_str("        state: present\n");
}

fn yq(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    const ENTITIES: &str = include_str!("../tests/fixtures/entities-vpn.xml");

    #[test]
    fn ansible_playbook_has_expected_tasks() {
        let cfg = parse_entities(ENTITIES).unwrap();
        let yaml = to_ansible(&cfg);
        assert!(yaml.contains("sophos.sophos_firewall.sfos_zone"));
        assert!(yaml.contains("sophos.sophos_firewall.sfos_firewall_rule"));
        assert!(yaml.contains("name: \"LAN-to-DMZ-web\""));
        assert!(yaml.contains("source_zones:\n          - \"LAN\""));
    }
}
