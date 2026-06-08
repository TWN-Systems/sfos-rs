//! Stateless ACL evaluation over the lean firewall model.
//!
//! Rules are processed in order; the first match wins, else the rule set's
//! default action applies.

use crate::ir::{FilterAction, Protocol, Rule, RuleSet};
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: Protocol,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub action: FilterAction,
    /// Sequence number of the matching rule, or `None` if the default fired.
    pub matched: Option<u32>,
}

pub fn evaluate(rs: &RuleSet, pkt: &Packet) -> Verdict {
    for r in &rs.rules {
        if r.disabled {
            continue;
        }
        if rule_matches(r, pkt) {
            return Verdict { action: r.action, matched: Some(r.seq) };
        }
    }
    Verdict { action: rs.default_action, matched: None }
}

fn rule_matches(r: &Rule, p: &Packet) -> bool {
    if let Some(rp) = r.protocol {
        if rp != Protocol::Any && rp != p.protocol {
            return false;
        }
    }
    if let Some(s) = &r.src {
        if let Some(net) = s.network {
            if !net.contains(p.src) {
                return false;
            }
        }
    }
    if let Some(d) = &r.dst {
        if let Some(net) = d.network {
            if !net.contains(p.dst) {
                return false;
            }
        }
        if let Some((lo, hi)) = d.port_range {
            if p.dst_port < lo || p.dst_port > hi {
                return false;
            }
        }
    }
    true
}
