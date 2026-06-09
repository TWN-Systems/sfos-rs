//! VPN analysis: single-firewall posture and cross-firewall site-to-site
//! symmetry checking.
//!
//! Site-to-site IPsec only works when both ends agree. Tunnels are *paired*
//! across two firewalls by IP-space overlap (each end's local subnet overlaps
//! the other's remote subnet), then checked for the asymmetries that break or
//! destabilise a tunnel: exact subnet mirror, authentication type, and IKE
//! version. Subnets resolve to CIDRs via each firewall's own host objects, so
//! object-naming differences between the two boxes don't cause false mismatches.

use std::collections::BTreeSet;

use ipnetwork::IpNetwork;

use crate::extract::resolve_network;
use crate::sophos::{IpsecConfig, SophosConfig};

#[derive(Debug, Clone)]
pub struct VpnFinding {
    pub severity: String,
    pub check: String,
    pub object: String,
    pub message: String,
}

fn finding(sev: &str, check: &str, object: String, message: String) -> VpnFinding {
    VpnFinding { severity: sev.into(), check: check.into(), object, message }
}

/// Single-firewall VPN best-practice / deprecation posture.
pub fn posture(cfg: &SophosConfig) -> Vec<VpnFinding> {
    let mut out = Vec::new();
    for c in cfg.ipsec_connections() {
        if is_ikev1(c) {
            out.push(finding(
                "MEDIUM",
                "VPN-IKEV1",
                c.name.clone(),
                "IPsec connection negotiates IKEv1 — migrate to IKEv2".into(),
            ));
        }
    }
    out
}

fn is_ikev1(c: &IpsecConfig) -> bool {
    match c.ike_version.as_deref() {
        Some(v) => {
            let v = v.to_ascii_lowercase();
            v.contains("ikev1") || v == "1" || v == "v1"
        }
        None => false,
    }
}

/// Compare site-to-site IPsec tunnels between two firewalls and report the
/// asymmetries that would prevent a tunnel coming up or make it unstable.
pub fn compare_site_to_site(
    a_name: &str,
    a: &SophosConfig,
    b_name: &str,
    b: &SophosConfig,
) -> Vec<VpnFinding> {
    let mut out = Vec::new();
    let a_s2s: Vec<&IpsecConfig> = a.ipsec_connections().filter(|c| c.is_site_to_site()).collect();
    let b_s2s: Vec<&IpsecConfig> = b.ipsec_connections().filter(|c| c.is_site_to_site()).collect();

    for ca in &a_s2s {
        let la = nets(a, &ca.local_subnets);
        let ra = nets(a, ca.remote_subnets());

        let mate = b_s2s.iter().find(|cb| {
            let lb = nets(b, &cb.local_subnets);
            let rb = nets(b, cb.remote_subnets());
            overlaps(&la, &rb) && overlaps(&ra, &lb)
        });

        match mate {
            None => out.push(finding(
                "HIGH",
                "S2S-UNPAIRED",
                ca.name.clone(),
                format!(
                    "{a_name} tunnel '{}' (local {:?} ↔ remote {:?}) has no matching site-to-site tunnel on {b_name}",
                    ca.name,
                    cidrs(&la),
                    cidrs(&ra)
                ),
            )),
            Some(cb) => {
                let lb = nets(b, &cb.local_subnets);
                let rb = nets(b, cb.remote_subnets());
                let pair = format!("{}↔{}", ca.name, cb.name);
                if set(&la) != set(&rb) || set(&ra) != set(&lb) {
                    out.push(finding(
                        "HIGH",
                        "S2S-SUBNET-ASYMMETRY",
                        pair.clone(),
                        format!(
                            "subnets not mirrored: {a_name}(local {:?}/remote {:?}) vs {b_name}(local {:?}/remote {:?})",
                            cidrs(&la),
                            cidrs(&ra),
                            cidrs(&lb),
                            cidrs(&rb)
                        ),
                    ));
                }
                if !eq_ci(&ca.authentication_type, &cb.authentication_type) {
                    out.push(finding(
                        "MEDIUM",
                        "S2S-AUTH-MISMATCH",
                        pair.clone(),
                        format!("authentication differs: {:?} vs {:?}", ca.authentication_type, cb.authentication_type),
                    ));
                }
                if !eq_ci(&ca.ike_version, &cb.ike_version) {
                    out.push(finding(
                        "MEDIUM",
                        "S2S-IKE-MISMATCH",
                        pair,
                        format!("IKE version differs: {:?} vs {:?}", ca.ike_version, cb.ike_version),
                    ));
                }
            }
        }
    }

    for cb in &b_s2s {
        let lb = nets(b, &cb.local_subnets);
        let rb = nets(b, cb.remote_subnets());
        let mated = a_s2s.iter().any(|ca| {
            let la = nets(a, &ca.local_subnets);
            let ra = nets(a, ca.remote_subnets());
            overlaps(&lb, &ra) && overlaps(&rb, &la)
        });
        if !mated {
            out.push(finding(
                "HIGH",
                "S2S-UNPAIRED",
                cb.name.clone(),
                format!("{b_name} tunnel '{}' has no matching site-to-site tunnel on {a_name}", cb.name),
            ));
        }
    }

    out
}

fn nets(cfg: &SophosConfig, names: &[String]) -> Vec<IpNetwork> {
    names.iter().filter_map(|n| resolve_network(cfg, n)).collect()
}

/// IP-space overlap: any network in `a` contains a network base in `b` or vice versa.
fn overlaps(a: &[IpNetwork], b: &[IpNetwork]) -> bool {
    a.iter().any(|x| b.iter().any(|y| x.contains(y.network()) || y.contains(x.network())))
}

fn set(nets: &[IpNetwork]) -> BTreeSet<String> {
    nets.iter().map(|n| n.to_string()).collect()
}

fn cidrs(nets: &[IpNetwork]) -> Vec<String> {
    nets.iter().map(|n| n.to_string()).collect()
}

fn eq_ci(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
        (None, None) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    const SITE_A: &str = include_str!("../tests/fixtures/s2s-site-a.xml");
    const SITE_B: &str = include_str!("../tests/fixtures/s2s-site-b.xml");

    #[test]
    fn detects_subnet_asymmetry_between_sites() {
        let a = parse_entities(SITE_A).unwrap();
        let b = parse_entities(SITE_B).unwrap();
        let findings = compare_site_to_site("site-a", &a, "site-b", &b);
        assert!(
            findings.iter().any(|f| f.check == "S2S-SUBNET-ASYMMETRY"),
            "expected subnet asymmetry, got: {:?}",
            findings.iter().map(|f| &f.check).collect::<Vec<_>>()
        );
        // It should still pair them (overlap), not report them as unpaired.
        assert!(!findings.iter().any(|f| f.check == "S2S-UNPAIRED"));
    }
}
