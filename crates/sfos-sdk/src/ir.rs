//! Lean vendor-neutral firewall model used for reachability and shadow analysis.
//!
//! This is intentionally self-contained — the standalone tool depends on no
//! external network-modelling crate. Sophos config is bridged onto this model
//! by `extract`, then evaluated by `acl` (reachability) and `shadow`.

use ipnetwork::IpNetwork;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterAction {
    Accept,
    Drop,
    Reject,
}

impl FilterAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            FilterAction::Accept => "ACCEPT",
            FilterAction::Drop => "DROP",
            FilterAction::Reject => "REJECT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
}

/// An address/port match specification. `None` fields mean "any".
#[derive(Debug, Clone, Default)]
pub struct AddrSpec {
    /// Resolved CIDR (when a single host/network object resolved cleanly).
    pub network: Option<IpNetwork>,
    /// Unresolved object name(s) — retained for display when not a single CIDR.
    pub group: Option<String>,
    /// Destination port range (inclusive).
    pub port_range: Option<(u16, u16)>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub seq: u32,
    pub action: FilterAction,
    /// Carried through from the Sophos rule for future display; not matched on.
    #[allow(dead_code)]
    pub description: Option<String>,
    pub src: Option<AddrSpec>,
    pub dst: Option<AddrSpec>,
    pub protocol: Option<Protocol>,
    pub disabled: bool,
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub name: String,
    pub default_action: FilterAction,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Default)]
pub struct FirewallModel {
    pub zones: BTreeSet<String>,
    /// (source zone, destination zone) → ordered rule set.
    pub rule_sets: BTreeMap<(String, String), RuleSet>,
}
