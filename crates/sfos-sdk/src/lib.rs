//! sfos-sdk — a Rust SDK for Sophos SFOS firewalls.
//!
//! - [`sophos`] — typed config model + `Entities.xml` / XML-API parser + search.
//! - [`client`] — live XML API client (auth, get/set/remove, full export).
//! - [`ir`] / [`extract`] — vendor-neutral firewall IR and the Sophos→IR bridge.
//! - [`acl`] — packet-forwarding (reachability) evaluation.
//! - [`shadow`] — shadowed / unreachable rule detection.
//!
//! Port of the official `sophos-firewall-sdk` (XML API) plus the offline
//! analysis from `sfos_analyzer_tool`, unified under one model.

pub mod acl;
pub mod apply;
pub mod client;
pub mod entity;
pub mod extract;
pub mod graph;
pub mod iac;
pub mod ir;
pub mod reach;
pub mod registry;
pub mod report;
pub mod route;
pub mod shadow;
pub mod sophos;
pub mod vpn;
pub mod xmljson;
