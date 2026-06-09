//! Granular, per-subsystem firewall state report — the "ascertain the state of
//! a firewall" deliverable. Aggregates a summary, an IPsec tunnel inventory,
//! and findings (undefined-zone refs, VPN posture, shadowed rules) into one
//! serialisable structure with a text renderer.

use serde::Serialize;

use crate::sophos::{IpsecConfig, SophosConfig};
use crate::{extract, shadow, vpn};

#[derive(Serialize)]
pub struct Report {
    pub hostname: String,
    pub summary: Summary,
    pub ipsec_tunnels: Vec<TunnelInfo>,
    pub findings: Vec<Finding>,
}

#[derive(Serialize)]
pub struct Summary {
    pub zones: usize,
    pub firewall_rules: usize,
    pub disabled_rules: usize,
    pub ip_hosts: usize,
    pub ip_host_groups: usize,
    pub services: usize,
    pub ipsec_connections: usize,
    pub interfaces: usize,
    pub nat_rules: usize,
    pub static_routes: usize,
}

#[derive(Serialize)]
pub struct TunnelInfo {
    pub name: String,
    pub connection_type: Option<String>,
    pub policy: Option<String>,
    pub authentication: Option<String>,
    pub ike_version: Option<String>,
    pub remote_gateway: Option<String>,
    pub local_subnets: Vec<String>,
    pub remote_subnets: Vec<String>,
}

#[derive(Serialize, Clone)]
pub struct Finding {
    pub severity: String,
    pub check: String,
    pub object: String,
    pub message: String,
}

pub fn build(hostname: &str, cfg: &SophosConfig) -> Report {
    let summary = Summary {
        zones: cfg.zones.len(),
        firewall_rules: cfg.firewall_rules.len(),
        disabled_rules: cfg.firewall_rules.iter().filter(|r| !r.enabled()).count(),
        ip_hosts: cfg.ip_hosts.len(),
        ip_host_groups: cfg.ip_host_groups.len(),
        services: cfg.services.len(),
        ipsec_connections: cfg.ipsec_connections().count(),
        interfaces: cfg.interfaces.len(),
        nat_rules: cfg.nat_rules.len(),
        static_routes: cfg.static_routes.len(),
    };

    let ipsec_tunnels = cfg.ipsec_connections().map(tunnel_info).collect();

    let mut findings: Vec<Finding> = Vec::new();
    for z in cfg.undefined_zone_refs() {
        findings.push(Finding {
            severity: "HIGH".into(),
            check: "SFOS-UNDEFINED-ZONE".into(),
            object: z.clone(),
            message: format!("rule references undefined zone '{z}'"),
        });
    }
    for vf in vpn::posture(cfg) {
        findings.push(Finding { severity: vf.severity, check: vf.check, object: vf.object, message: vf.message });
    }
    let model = extract::to_model(cfg);
    for ((s, d), rs) in &model.rule_sets {
        for sh in shadow::detect(rs) {
            let kind = if sh.same_action { "unreachable" } else { "overridden" };
            findings.push(Finding {
                severity: "MEDIUM".into(),
                check: "SHADOW".into(),
                object: format!("{s}->{d}"),
                message: format!("rule {} {kind} by rule {}", sh.shadowed, sh.shadowing),
            });
        }
    }

    Report { hostname: hostname.into(), summary, ipsec_tunnels, findings }
}

fn tunnel_info(c: &IpsecConfig) -> TunnelInfo {
    TunnelInfo {
        name: c.name.clone(),
        connection_type: c.connection_type.clone(),
        policy: c.policy.clone(),
        authentication: c.authentication_type.clone(),
        ike_version: c.ike_version.clone(),
        remote_gateway: c.remote_gateway.clone(),
        local_subnets: c.local_subnets.clone(),
        remote_subnets: c.remote_subnets().to_vec(),
    }
}

pub fn render_text(r: &Report) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    let s = &r.summary;
    let _ = writeln!(o, "# Firewall report: {}", r.hostname);
    let _ = writeln!(o, "\n## Summary");
    let _ = writeln!(
        o,
        "  zones {}   interfaces {}   routes {}   rules {} ({} disabled)   hosts {}   groups {}   services {}   nat {}   ipsec {}",
        s.zones,
        s.interfaces,
        s.static_routes,
        s.firewall_rules,
        s.disabled_rules,
        s.ip_hosts,
        s.ip_host_groups,
        s.services,
        s.nat_rules,
        s.ipsec_connections
    );
    if !r.ipsec_tunnels.is_empty() {
        let _ = writeln!(o, "\n## IPsec tunnels");
        for t in &r.ipsec_tunnels {
            let _ = writeln!(
                o,
                "  {} [{}]  {} -> {}  {} / {}",
                t.name,
                t.connection_type.as_deref().unwrap_or("?"),
                join(&t.local_subnets),
                join(&t.remote_subnets),
                t.ike_version.as_deref().unwrap_or("?"),
                t.authentication.as_deref().unwrap_or("?"),
            );
        }
    }
    let _ = writeln!(o, "\n## Findings ({})", r.findings.len());
    if r.findings.is_empty() {
        let _ = writeln!(o, "  none");
    }
    for f in &r.findings {
        let _ = writeln!(o, "  [{}] {} {} — {}", f.severity, f.check, f.object, f.message);
    }
    o
}

fn join(v: &[String]) -> String {
    if v.is_empty() {
        "-".into()
    } else {
        v.join(",")
    }
}
