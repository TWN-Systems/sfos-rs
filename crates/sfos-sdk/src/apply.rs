//! Plan / apply — diff a desired configuration against the live (or a saved)
//! configuration and express the difference as add/update/remove actions.
//!
//! This is the safe write path: the *plan* is pure and side-effect free (and
//! shows exactly the `<Set>`/`<Remove>` body that would be sent); the CLI only
//! transmits when explicitly told to commit. Covers the entity types the SDK
//! can serialise (zones, hosts, host groups, services, firewall rules).

use crate::entity::SophosEntity;
use crate::sophos::SophosConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Add,
    Update,
    Remove,
}

impl Action {
    pub fn symbol(&self) -> char {
        match self {
            Action::Add => '+',
            Action::Update => '~',
            Action::Remove => '-',
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Action::Add => "ADD",
            Action::Update => "UPDATE",
            Action::Remove => "REMOVE",
        }
    }
    /// The `Set operation` value (`Remove` is sent via the Remove verb, not Set).
    pub fn operation(&self) -> &'static str {
        match self {
            Action::Add => "add",
            Action::Update => "update",
            Action::Remove => "remove",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlanItem {
    pub action: Action,
    pub tag: &'static str,
    pub name: String,
    /// Entity body XML for Add/Update; empty for Remove.
    pub xml: String,
}

/// Diff `desired` against `live`. With `prune`, live objects absent from
/// `desired` become Remove actions.
pub fn plan(desired: &SophosConfig, live: &SophosConfig, prune: bool) -> Vec<PlanItem> {
    let mut out = Vec::new();
    diff(&desired.zones, &live.zones, prune, &mut out);
    diff(&desired.ip_hosts, &live.ip_hosts, prune, &mut out);
    diff(&desired.ip_host_groups, &live.ip_host_groups, prune, &mut out);
    diff(&desired.services, &live.services, prune, &mut out);
    diff(&desired.firewall_rules, &live.firewall_rules, prune, &mut out);
    out
}

fn diff<T: SophosEntity>(desired: &[T], live: &[T], prune: bool, out: &mut Vec<PlanItem>) {
    for d in desired {
        match live.iter().find(|l| l.name().eq_ignore_ascii_case(d.name())) {
            None => out.push(PlanItem {
                action: Action::Add,
                tag: T::TAG,
                name: d.name().to_string(),
                xml: d.to_xml(),
            }),
            Some(l) if l.to_xml() != d.to_xml() => out.push(PlanItem {
                action: Action::Update,
                tag: T::TAG,
                name: d.name().to_string(),
                xml: d.to_xml(),
            }),
            Some(_) => {}
        }
    }
    if prune {
        for l in live {
            if !desired.iter().any(|d| d.name().eq_ignore_ascii_case(l.name())) {
                out.push(PlanItem {
                    action: Action::Remove,
                    tag: T::TAG,
                    name: l.name().to_string(),
                    xml: String::new(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    const DESIRED: &str = r#"<Configuration>
        <IPHost><Name>A</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.0.0.1</IPAddress></IPHost>
        <IPHost><Name>B</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.0.0.2</IPAddress></IPHost>
    </Configuration>"#;

    const LIVE: &str = r#"<Configuration>
        <IPHost><Name>B</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.0.0.99</IPAddress></IPHost>
        <IPHost><Name>C</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType><IPAddress>10.0.0.3</IPAddress></IPHost>
    </Configuration>"#;

    #[test]
    fn plan_computes_add_update_and_prune() {
        let d = parse_entities(DESIRED).unwrap();
        let l = parse_entities(LIVE).unwrap();

        let p = plan(&d, &l, false);
        assert_eq!(p.iter().filter(|i| i.action == Action::Add).count(), 1); // A
        assert_eq!(p.iter().filter(|i| i.action == Action::Update).count(), 1); // B changed
        assert!(p.iter().all(|i| i.action != Action::Remove));
        assert!(p.iter().any(|i| i.action == Action::Add && i.name == "A"));
        assert!(p.iter().any(|i| i.action == Action::Update && i.name == "B"));

        let pruned = plan(&d, &l, true);
        assert!(pruned.iter().any(|i| i.action == Action::Remove && i.name == "C"));
    }

    #[test]
    fn identical_configs_yield_empty_plan() {
        let d = parse_entities(DESIRED).unwrap();
        assert!(plan(&d, &d, true).is_empty());
    }
}
