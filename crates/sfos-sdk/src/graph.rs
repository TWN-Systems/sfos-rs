//! Zone-reachability graph: derive an inter-zone "who can reach whom" model
//! from the enabled accept rules and render it as Graphviz DOT or Mermaid.
//!
//! The rendered views (DOT, Mermaid) are tuned for reading: self-loops and the
//! uninformative `any` label are dropped, zones with no accept rules are pushed
//! into a side bucket, and WAN-sourced edges (the inbound-exposure ones) are
//! highlighted. The JSON view ([`Graph::edges_json`]) stays a faithful, complete
//! dump — every edge, including self-loops — for programmatic consumers.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::sophos::SophosConfig;

/// One directed zone→zone reachability edge (JSON view).
#[derive(Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub services: Vec<String>,
    /// The source zone is a WAN zone — i.e. this is inbound from the internet.
    pub from_wan: bool,
    /// Intra-zone edge (`from == to`); kept in JSON, dropped from rendered views.
    pub self_loop: bool,
}

/// The derived reachability graph.
pub struct Graph {
    /// Every zone seen (defined zones plus any referenced by a rule).
    nodes: BTreeSet<String>,
    /// `(from, to)` → set of service names (`any` is the empty-service sentinel).
    edges: BTreeMap<(String, String), BTreeSet<String>>,
    /// Lower-cased names of zones classified as WAN.
    wan: BTreeSet<String>,
}

/// Build the reachability graph from a config's enabled accept rules.
pub fn build(cfg: &SophosConfig) -> Graph {
    let wan: BTreeSet<String> = cfg.zones.iter().filter(|z| z.is_wan()).map(|z| z.name.to_lowercase()).collect();
    let mut nodes: BTreeSet<String> = cfg.zones.iter().map(|z| z.name.clone()).collect();
    let mut edges: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();

    for r in &cfg.firewall_rules {
        if !r.enabled() {
            continue;
        }
        let Some(p) = r.policy() else { continue };
        if !p.action_accepts() {
            continue;
        }
        let svcs = p.service_names();
        for s in zones_or_any(p.source_zone_names()) {
            for d in zones_or_any(p.destination_zone_names()) {
                nodes.insert(s.clone());
                nodes.insert(d.clone());
                let set = edges.entry((s.clone(), d)).or_default();
                if svcs.is_empty() {
                    set.insert("any".into());
                } else {
                    set.extend(svcs.iter().cloned());
                }
            }
        }
    }

    Graph { nodes, edges, wan }
}

fn zones_or_any(zones: &[String]) -> Vec<String> {
    if zones.is_empty() {
        vec!["Any".to_string()]
    } else {
        zones.to_vec()
    }
}

impl Graph {
    /// Is `zone` a WAN zone (inbound-from-internet)?
    pub fn is_wan(&self, zone: &str) -> bool {
        self.wan.contains(&zone.to_lowercase()) || zone.eq_ignore_ascii_case("WAN")
    }

    /// Faithful edge list for JSON output — every edge, self-loops included.
    pub fn edges_json(&self) -> Vec<Edge> {
        self.edges
            .iter()
            .map(|((s, d), svcs)| Edge {
                from: s.clone(),
                to: d.clone(),
                services: svcs.iter().cloned().collect(),
                from_wan: self.is_wan(s),
                self_loop: s == d,
            })
            .collect()
    }

    /// Render as Graphviz DOT.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph sfos {\n  rankdir=LR; node [shape=box];\n");
        for n in &self.nodes {
            out.push_str(&format!("  \"{}\";\n", dot_escape(n)));
        }
        for ((s, d), svcs) in &self.edges {
            if s == d {
                continue; // intra-zone self-loop — noise in a reachability view
            }
            let mut attrs: Vec<String> = Vec::new();
            if let Some(lbl) = edge_label(svcs) {
                attrs.push(format!("label=\"{}\"", dot_escape(&lbl)));
            }
            if self.is_wan(s) {
                attrs.push("color=\"red\"".into());
                attrs.push("fontcolor=\"red\"".into());
            }
            let attr = if attrs.is_empty() { String::new() } else { format!(" [{}]", attrs.join(", ")) };
            out.push_str(&format!("  \"{}\" -> \"{}\"{};\n", dot_escape(s), dot_escape(d), attr));
        }
        out.push_str("}\n");
        out
    }

    /// Render as Mermaid (`graph LR`). Labels are quoted so service names with
    /// `(`, `)`, `,` (e.g. `SMTP(S)`) don't trip the Mermaid parser; node IDs are
    /// sanitised with the real name carried as a display label.
    pub fn to_mermaid(&self) -> String {
        let ids = self.assign_ids();

        // Renderable edges: everything except self-loops.
        let rendered: Vec<(&String, &String, &BTreeSet<String>)> =
            self.edges.iter().filter(|((s, d), _)| s != d).map(|((s, d), v)| (s, d, v)).collect();
        let mut connected: BTreeSet<&str> = BTreeSet::new();
        for &(s, d, _) in &rendered {
            connected.insert(s.as_str());
            connected.insert(d.as_str());
        }

        let mut out = String::from("graph LR\n");

        // Declare connected nodes once, with their real name as the label.
        for n in &self.nodes {
            if connected.contains(n.as_str()) {
                out.push_str(&format!("  {}[\"{}\"]\n", ids[n], mermaid_text(n)));
            }
        }

        // Edges, tracking which links are WAN-sourced for highlighting.
        let mut wan_links: Vec<usize> = Vec::new();
        for (i, &(s, d, svcs)) in rendered.iter().enumerate() {
            match edge_label(svcs) {
                Some(lbl) => out.push_str(&format!("  {} -->|\"{}\"| {}\n", ids[s], mermaid_text(&lbl), ids[d])),
                None => out.push_str(&format!("  {} --> {}\n", ids[s], ids[d])),
            }
            if self.is_wan(s) {
                wan_links.push(i);
            }
        }
        if !wan_links.is_empty() {
            let list = wan_links.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
            out.push_str(&format!("  linkStyle {list} stroke:#d33,stroke-width:2px;\n"));
        }

        // Zones with no accept rules: park them so they don't distort the layout.
        let edgeless: Vec<&String> = self.nodes.iter().filter(|n| !connected.contains(n.as_str())).collect();
        if !edgeless.is_empty() {
            out.push_str("  subgraph unused_zones[\"no accept rules\"]\n");
            for n in edgeless {
                out.push_str(&format!("    {}[\"{}\"]\n", ids[n], mermaid_text(n)));
            }
            out.push_str("  end\n");
        }

        out
    }

    /// Assign each node a unique, Mermaid-safe identifier.
    fn assign_ids(&self) -> BTreeMap<String, String> {
        let mut used: BTreeSet<String> = BTreeSet::new();
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for name in &self.nodes {
            let mut id = mermaid_id(name);
            if is_mermaid_keyword(&id) {
                id = format!("z_{id}");
            }
            let base = id.clone();
            let mut n = 1;
            while used.contains(&id) {
                n += 1;
                id = format!("{base}_{n}");
            }
            used.insert(id.clone());
            map.insert(name.clone(), id);
        }
        map
    }
}

/// The service label for an edge, or `None` when it's just `any` (a bare arrow
/// already conveys "allowed", so labelling it `any` is pure noise). A redundant
/// `any` mixed with real services is dropped.
fn edge_label(svcs: &BTreeSet<String>) -> Option<String> {
    let real: Vec<&str> = svcs.iter().map(String::as_str).filter(|s| *s != "any").collect();
    if real.is_empty() {
        None
    } else {
        Some(real.join(", "))
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A Mermaid-safe node ID: keep `[A-Za-z0-9_]`, map the rest to `_`, and ensure
/// it starts with a letter or underscore.
fn mermaid_id(s: &str) -> String {
    let mut id: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    match id.chars().next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => id,
        _ => {
            id.insert_str(0, "z_");
            id
        }
    }
}

fn is_mermaid_keyword(id: &str) -> bool {
    matches!(
        id.to_ascii_lowercase().as_str(),
        "end" | "graph" | "subgraph" | "class" | "classdef" | "click" | "style" | "linkstyle" | "direction"
    )
}

/// Escape text used inside a quoted Mermaid string (a literal `"` becomes the
/// `#quot;` entity).
fn mermaid_text(s: &str) -> String {
    s.replace('"', "#quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sophos::parse_entities;

    // LAN, WAN, an edgeless DMZ; a WAN->LAN rule on a paren-bearing service, and
    // an intra-LAN self-loop with no service.
    const XML: &str = r#"<Configuration>
        <Zone><Name>LAN</Name><Type>LAN</Type></Zone>
        <Zone><Name>WAN</Name><Type>WAN</Type></Zone>
        <Zone><Name>DMZ</Name><Type>DMZ</Type></Zone>
        <FirewallRule><Name>inbound</Name><Status>Enable</Status><PolicyType>Network</PolicyType>
          <NetworkPolicy><Action>Accept</Action><LogTraffic>Enable</LogTraffic>
            <SourceZones><Zone>WAN</Zone></SourceZones>
            <DestinationZones><Zone>LAN</Zone></DestinationZones>
            <Services><Service>SMTP(S)</Service></Services>
          </NetworkPolicy></FirewallRule>
        <FirewallRule><Name>intra</Name><Status>Enable</Status><PolicyType>Network</PolicyType>
          <NetworkPolicy><Action>Accept</Action><LogTraffic>Enable</LogTraffic>
            <SourceZones><Zone>LAN</Zone></SourceZones>
            <DestinationZones><Zone>LAN</Zone></DestinationZones>
          </NetworkPolicy></FirewallRule>
    </Configuration>"#;

    #[test]
    fn mermaid_quotes_special_labels_and_drops_self_loops() {
        let m = build(&parse_entities(XML).unwrap()).to_mermaid();
        // The paren-bearing label is quoted, so Mermaid won't read `(` as a shape.
        assert!(m.contains(r#"-->|"SMTP(S)"|"#), "{m}");
        // The intra-LAN self-loop is not rendered.
        assert!(!m.contains("LAN --> LAN"), "{m}");
    }

    #[test]
    fn mermaid_buckets_edgeless_zones_and_highlights_wan() {
        let m = build(&parse_entities(XML).unwrap()).to_mermaid();
        // DMZ has no accept rules → parked in the unused subgraph.
        assert!(m.contains("subgraph unused_zones"), "{m}");
        assert!(m.contains(r#"DMZ["DMZ"]"#), "{m}");
        // The single rendered edge (WAN→LAN) is WAN-sourced → highlighted.
        assert!(m.contains("linkStyle 0 stroke:#d33"), "{m}");
    }

    #[test]
    fn dot_quotes_skips_self_loops_and_colours_wan() {
        let d = build(&parse_entities(XML).unwrap()).to_dot();
        assert!(d.contains(r#""WAN" -> "LAN""#), "{d}");
        assert!(d.contains("color=\"red\""), "{d}"); // WAN edge highlighted
        assert!(!d.contains(r#""LAN" -> "LAN""#), "{d}"); // self-loop skipped
    }

    #[test]
    fn json_view_stays_faithful() {
        let edges = build(&parse_entities(XML).unwrap()).edges_json();
        // The self-loop survives in the data export…
        assert!(edges.iter().any(|e| e.self_loop && e.from == "LAN"));
        // …and the WAN-sourced edge is flagged.
        assert!(edges.iter().any(|e| e.from == "WAN" && e.to == "LAN" && e.from_wan));
    }

    #[test]
    fn mermaid_id_is_sanitised_and_keyword_safe() {
        assert_eq!(mermaid_id("Guest WiFi"), "Guest_WiFi");
        assert_eq!(mermaid_id("3rd-party"), "z_3rd_party");
        assert!(is_mermaid_keyword("end"));
    }
}
