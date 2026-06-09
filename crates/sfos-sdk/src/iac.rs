//! IaC export — a normalized, declarative, version-controllable view of the
//! firewall, emitted from a parsed config (live or backup). Serialises to JSON
//! today (diff-friendly, drift-trackable, and re-appliable via the typed
//! `client.create` helpers); an Ansible-playbook emitter is a natural follow-on.

use serde::Serialize;

use crate::sophos::{IpHost, SophosConfig};

#[derive(Serialize)]
pub struct NormalizedConfig {
    pub zones: Vec<NormZone>,
    pub hosts: Vec<NormHost>,
    pub host_groups: Vec<NormGroup>,
    pub services: Vec<NormService>,
    pub rules: Vec<NormRule>,
    pub ipsec: Vec<NormIpsec>,
}

#[derive(Serialize)]
pub struct NormZone {
    pub name: String,
    pub r#type: Option<String>,
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
            .ipsec_connections
            .iter()
            .map(|c| NormIpsec {
                name: c.name.clone(),
                connection_type: c.connection_type.clone(),
                policy: c.policy.clone(),
                authentication: c.authentication_type.clone(),
                ike_version: c.ike_version.clone(),
                remote_gateway: c.remote_gateway.clone(),
                local_subnets: c.local_subnets.clone(),
                remote_subnets: c.remote_subnets.clone(),
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
