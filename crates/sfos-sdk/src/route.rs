//! Single-node route table: connected routes (from interface addressing) plus
//! static (unicast) routes, with longest-prefix-match lookup. Used to find the
//! egress interface and zone for a destination during forwarding.

use std::net::{IpAddr, Ipv4Addr};

use ipnetwork::{IpNetwork, Ipv4Network};

use crate::sophos::{SophosConfig, StaticRoute};

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub network: IpNetwork,
    pub interface: Option<String>,
    pub zone: Option<String>,
    pub connected: bool,
}

pub struct RouteTable {
    entries: Vec<RouteEntry>,
}

pub fn build(cfg: &SophosConfig) -> RouteTable {
    let mut entries: Vec<RouteEntry> = Vec::new();

    // Connected routes from interface addressing.
    for i in &cfg.interfaces {
        if let (Some(a), Some(m)) = (i.ip_address.as_deref(), i.netmask.as_deref()) {
            if let (Ok(a), Ok(m)) = (a.parse::<Ipv4Addr>(), m.parse::<Ipv4Addr>()) {
                if let Ok(net) = Ipv4Network::with_netmask(a, m) {
                    entries.push(RouteEntry {
                        network: IpNetwork::V4(net),
                        interface: Some(i.name.clone()),
                        zone: i.zone.clone(),
                        connected: true,
                    });
                }
            }
        }
    }

    // Static routes — zone via the route's interface, else the gateway's connected zone.
    let connected = entries.clone();
    for r in &cfg.static_routes {
        if let Some(net) = route_network(r) {
            let zone = r.interface.as_deref().and_then(|n| iface_zone(cfg, n)).or_else(|| {
                r.gateway
                    .as_deref()
                    .and_then(|g| g.parse::<IpAddr>().ok())
                    .and_then(|gip| connected_zone(&connected, gip))
            });
            entries.push(RouteEntry { network: net, interface: r.interface.clone(), zone, connected: false });
        }
    }

    // Most specific first.
    entries.sort_by_key(|e| std::cmp::Reverse(e.network.prefix()));
    RouteTable { entries }
}

impl RouteTable {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<&RouteEntry> {
        self.entries.iter().find(|e| e.network.contains(ip))
    }
    pub fn zone_of(&self, ip: IpAddr) -> Option<String> {
        self.lookup(ip).and_then(|e| e.zone.clone())
    }
}

fn route_network(r: &StaticRoute) -> Option<IpNetwork> {
    let d = r.destination.as_deref()?;
    if let Ok(net) = d.parse::<IpNetwork>() {
        return Some(net);
    }
    let a = d.parse::<Ipv4Addr>().ok()?;
    let m = r.netmask.as_deref()?.parse::<Ipv4Addr>().ok()?;
    Ipv4Network::with_netmask(a, m).ok().map(IpNetwork::V4)
}

fn iface_zone(cfg: &SophosConfig, iname: &str) -> Option<String> {
    cfg.interfaces.iter().find(|i| i.name.eq_ignore_ascii_case(iname)).and_then(|i| i.zone.clone())
}

fn connected_zone(entries: &[RouteEntry], gip: IpAddr) -> Option<String> {
    entries.iter().filter(|e| e.connected).find(|e| e.network.contains(gip)).and_then(|e| e.zone.clone())
}
