//! Concrete shadow / unreachable-rule detection.
//!
//! A rule is "shadowed" when an earlier enabled rule matches every packet it
//! could match — superset containment over protocol, source/destination CIDR,
//! and destination port. This is *sound* (no false positives) but *incomplete*:
//! it does not detect coverage spread across several earlier rules. (A Z3-backed
//! exact pass can be added later as an optional feature.)

use crate::ir::{AddrSpec, Protocol, Rule, RuleSet};

#[derive(Debug, Clone)]
pub struct ShadowFinding {
    pub shadowed: u32,
    pub shadowing: u32,
    /// true = redundant (same action); false = overridden (earlier rule has a
    /// different action, so this rule never fires and changes nothing).
    pub same_action: bool,
}

pub fn detect(rs: &RuleSet) -> Vec<ShadowFinding> {
    let rules: Vec<&Rule> = rs.rules.iter().filter(|r| !r.disabled).collect();
    let mut out = Vec::new();
    for i in 0..rules.len() {
        for j in 0..i {
            if covers(rules[j], rules[i]) {
                out.push(ShadowFinding {
                    shadowed: rules[i].seq,
                    shadowing: rules[j].seq,
                    same_action: rules[j].action == rules[i].action,
                });
                break; // report the first earlier rule that covers it
            }
        }
    }
    out
}

/// Does earlier rule `e` match every packet that `r` matches?
fn covers(e: &Rule, r: &Rule) -> bool {
    proto_covers(e.protocol, r.protocol)
        && addr_covers(e.src.as_ref(), r.src.as_ref())
        && addr_covers(e.dst.as_ref(), r.dst.as_ref())
}

fn proto_covers(e: Option<Protocol>, r: Option<Protocol>) -> bool {
    match e {
        None | Some(Protocol::Any) => true,
        Some(ep) => matches!(r, Some(rp) if rp == ep),
    }
}

fn addr_covers(e: Option<&AddrSpec>, r: Option<&AddrSpec>) -> bool {
    let Some(e) = e else { return true }; // e matches any address/port
    if e.group.is_some() {
        return false; // unresolved object — can't prove coverage, so don't report
    }
    let net_ok = match e.network {
        None => true,
        Some(en) => match r.and_then(|x| x.network) {
            Some(rn) => en.contains(rn.network()) && en.prefix() <= rn.prefix(),
            None => false, // r is any but e is specific — e is narrower
        },
    };
    if !net_ok {
        return false;
    }
    match e.port_range {
        None => true,
        Some((elo, ehi)) => match r.and_then(|x| x.port_range) {
            Some((rlo, rhi)) => elo <= rlo && rhi <= ehi,
            None => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::FilterAction;

    fn rule(seq: u32, action: FilterAction, proto: Option<Protocol>, dport: Option<(u16, u16)>) -> Rule {
        Rule {
            seq,
            action,
            description: None,
            src: None,
            dst: dport.map(|p| AddrSpec { network: None, group: None, port_range: Some(p) }),
            protocol: proto,
            disabled: false,
        }
    }

    #[test]
    fn broad_rule_shadows_narrow_same_action() {
        // rule 10 = accept any; rule 20 = accept tcp/443 → 20 is redundant
        let rs = RuleSet {
            name: "t".into(),
            default_action: FilterAction::Drop,
            rules: vec![
                rule(10, FilterAction::Accept, None, None),
                rule(20, FilterAction::Accept, Some(Protocol::Tcp), Some((443, 443))),
            ],
        };
        let f = detect(&rs);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].shadowed, 20);
        assert_eq!(f[0].shadowing, 10);
        assert!(f[0].same_action);
    }

    #[test]
    fn narrow_rule_does_not_shadow_broad() {
        // rule 10 = accept tcp/443; rule 20 = accept any → 20 not shadowed by 10
        let rs = RuleSet {
            name: "t".into(),
            default_action: FilterAction::Drop,
            rules: vec![
                rule(10, FilterAction::Accept, Some(Protocol::Tcp), Some((443, 443))),
                rule(20, FilterAction::Accept, None, None),
            ],
        };
        assert!(detect(&rs).is_empty());
    }
}
