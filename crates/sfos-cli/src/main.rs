//! sfos-rs — standalone Sophos SFOS firewall configuration analysis & search.
//!
//! Parses an SFOS `Entities.xml` export (or XML API response) and offers:
//! summary (`parse`), object dump (`dump`), rule search (`search`), baseline
//! checks (`check`), packet-forwarding simulation (`trace`), shadowed/
//! unreachable-rule detection (`verify`), and zone-reachability graph export
//! (`graph`), plus live config fetch over the XML API (`fetch`). Analysis is
//! powered by the `sfos-sdk` library crate.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};

use sfos_sdk::acl::{evaluate, Packet};
use sfos_sdk::client::Client;
use sfos_sdk::ir::{FilterAction, Protocol};
use sfos_sdk::sophos::{load_entities_file, FirewallRule, IpHost, SophosConfig};
use sfos_sdk::{extract, reach, shadow, vpn};

#[derive(Parser)]
#[command(name = "sfos-rs", version, about = "Sophos SFOS firewall configuration analysis & search")]
struct Cli {
    /// Output format
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: Format,
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Parse an Entities.xml export and print a summary
    Parse(FileArgs),
    /// Dump parsed objects (zones, rules, hosts, services)
    Dump(DumpArgs),
    /// Search firewall rules by object reference or zone-to-zone path
    Search(SearchArgs),
    /// Run quick correctness / baseline checks
    Check(FileArgs),
    /// Simulate a packet through the firewall for a zone pair
    Trace(TraceArgs),
    /// Find shadowed / unreachable rules
    Verify(FileArgs),
    /// Export the zone reachability graph (DOT, Mermaid, or JSON)
    Graph(GraphArgs),
    /// Fetch live config from a firewall over the XML API and summarise it
    Fetch(FetchArgs),
    /// List the catalogue of API entities the SDK knows about
    Entities,
    /// Get one entity from a live firewall (any XML API tag), as JSON or raw XML
    Get(GetArgs),
    /// Pull the entire configuration from a live firewall (every catalogued entity)
    Export(ExportArgs),
    /// Explain why a destination is reachable from some zones but not others
    Explain(ExplainArgs),
    /// Compare site-to-site IPsec between two or more firewall configs
    S2s(S2sArgs),
    /// Granular per-subsystem state report (summary, VPN tunnels, findings)
    Report(FileArgs),
    /// Emit version-controllable IaC from the config (normalized JSON, or --ansible)
    Iac(IacArgs),
    /// Trace one packet end-to-end: ingress -> DNAT -> route -> firewall -> SNAT
    Path(PathArgs),
    /// Trace a flow across two firewalls and the site-to-site IPsec tunnel
    SitePath(SitePathArgs),
    /// Plan (and optionally --commit) a desired config against a live/saved firewall
    Apply(ApplyArgs),
}

#[derive(Args)]
struct ApplyArgs {
    /// Desired-state config (Entities.xml)
    desired: PathBuf,
    /// Plan against a saved config file instead of a live firewall (offline, dry-run only)
    #[arg(long)]
    live: Option<PathBuf>,
    /// Firewall host to plan/apply against
    #[arg(long)]
    host: Option<String>,
    /// XML API port
    #[arg(long, default_value_t = 4444)]
    port: u16,
    /// Admin username (required with --host)
    #[arg(long)]
    user: Option<String>,
    /// Admin password (or SFOS_PASSWORD)
    #[arg(long)]
    password: Option<String>,
    /// Skip TLS certificate verification
    #[arg(long)]
    insecure: bool,
    /// Also remove live objects not present in the desired config (dangerous)
    #[arg(long)]
    prune: bool,
    /// Actually send the changes (default: dry-run plan only)
    #[arg(long)]
    commit: bool,
}

#[derive(Args)]
struct SitePathArgs {
    /// Site A config (where the source host lives)
    site_a: PathBuf,
    /// Site B config (where the destination host lives)
    site_b: PathBuf,
    /// Source IP at site A
    #[arg(long)]
    src: String,
    /// Destination IP at site B
    #[arg(long)]
    to: String,
    /// Protocol: tcp | udp | icmp
    #[arg(long, default_value = "tcp")]
    proto: String,
    /// Destination port
    #[arg(long, default_value_t = 443)]
    dport: u16,
}

#[derive(Args)]
struct PathArgs {
    /// Path to Entities.xml
    file: PathBuf,
    /// Source IP
    #[arg(long)]
    src: String,
    /// Destination IP, or an IPHost object name to resolve
    #[arg(long)]
    to: String,
    /// Protocol: tcp | udp | icmp
    #[arg(long, default_value = "tcp")]
    proto: String,
    /// Destination port
    #[arg(long, default_value_t = 443)]
    dport: u16,
}

#[derive(Args)]
struct IacArgs {
    /// Path to Entities.xml
    file: PathBuf,
    /// Emit a sophos.sophos_firewall Ansible playbook instead of normalized JSON
    #[arg(long)]
    ansible: bool,
}

#[derive(Args)]
struct ExplainArgs {
    /// Path to Entities.xml
    file: PathBuf,
    /// Destination IP, or an IPHost object name to resolve
    #[arg(long)]
    to: String,
    /// Protocol: tcp | udp | icmp
    #[arg(long, default_value = "tcp")]
    proto: String,
    /// Destination port (ignored for icmp)
    #[arg(long, default_value_t = 443)]
    dport: u16,
    /// Source zone to evaluate (repeatable); default: every zone in the config
    #[arg(long = "from", value_name = "ZONE")]
    from: Vec<String>,
    /// Source IP — infers the source zone from interface addressing (if --from is omitted)
    #[arg(long)]
    src: Option<String>,
}

#[derive(Args)]
struct S2sArgs {
    /// Two or more firewall configs; every unique pair is compared
    #[arg(num_args = 1.., required = true)]
    files: Vec<PathBuf>,
}

/// Shared connection flags for live XML API commands.
#[derive(Args)]
struct ConnArgs {
    /// Firewall host or IP
    #[arg(long)]
    host: String,
    /// XML API port
    #[arg(long, default_value_t = 4444)]
    port: u16,
    /// Admin username
    #[arg(long)]
    user: String,
    /// Admin password (falls back to the SFOS_PASSWORD environment variable)
    #[arg(long)]
    password: Option<String>,
    /// Skip TLS certificate verification (SFOS ships a self-signed cert)
    #[arg(long)]
    insecure: bool,
}

#[derive(Args)]
struct FetchArgs {
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(Args)]
struct GetArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Entity tag to retrieve (e.g. IPHost, FirewallRule, Zone — any XML API tag)
    entity: String,
    /// Print the raw XML response instead of JSON
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
struct ExportArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Write one file per entity into this directory instead of one combined doc
    #[arg(long, value_name = "DIR")]
    out_dir: Option<PathBuf>,
    /// Emit raw XML instead of JSON
    #[arg(long)]
    raw: bool,
}

#[derive(Args)]
struct FileArgs {
    /// Path to Entities.xml (or an XML API <Response> body)
    file: PathBuf,
}

#[derive(Args)]
struct DumpArgs {
    file: PathBuf,
    #[arg(long)]
    zones: bool,
    #[arg(long)]
    rules: bool,
    #[arg(long)]
    hosts: bool,
    #[arg(long)]
    services: bool,
}

#[derive(Args)]
struct SearchArgs {
    file: PathBuf,
    /// Find rules referencing this object (host / network / service / zone)
    #[arg(long, value_name = "OBJECT")]
    referencing: Option<String>,
    /// Source zone (use with --to)
    #[arg(long, value_name = "ZONE")]
    from: Option<String>,
    /// Destination zone (use with --from)
    #[arg(long, value_name = "ZONE")]
    to: Option<String>,
}

#[derive(Args)]
struct TraceArgs {
    file: PathBuf,
    #[arg(long, value_name = "ZONE")]
    from: String,
    #[arg(long, value_name = "ZONE")]
    to: String,
    /// Protocol: tcp | udp | icmp
    #[arg(long, default_value = "tcp")]
    proto: String,
    /// Destination port (ignored for icmp)
    #[arg(long, default_value_t = 0)]
    dport: u16,
    /// Source IP (defaults to 0.0.0.0 — give a real IP to match address-scoped rules)
    #[arg(long)]
    src: Option<String>,
    /// Destination IP (defaults to 0.0.0.0)
    #[arg(long)]
    dst: Option<String>,
}

#[derive(Args)]
struct GraphArgs {
    file: PathBuf,
    /// Emit Mermaid instead of Graphviz DOT (ignored when --format json)
    #[arg(long)]
    mermaid: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sfos-rs: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<ExitCode, String> {
    match &cli.command {
        Command::Parse(a) => {
            cmd_parse(&load(&a.file)?, cli.format);
            Ok(ExitCode::SUCCESS)
        }
        Command::Dump(a) => {
            cmd_dump(&load(&a.file)?, a, cli.format);
            Ok(ExitCode::SUCCESS)
        }
        Command::Search(a) => cmd_search(&load(&a.file)?, a, cli.format),
        Command::Check(a) => Ok(cmd_check(&load(&a.file)?, cli.format)),
        Command::Trace(a) => cmd_trace(&load(&a.file)?, a, cli.format),
        Command::Verify(a) => {
            cmd_verify(&load(&a.file)?, cli.format);
            Ok(ExitCode::SUCCESS)
        }
        Command::Graph(a) => {
            cmd_graph(&load(&a.file)?, a, cli.format);
            Ok(ExitCode::SUCCESS)
        }
        Command::Fetch(a) => cmd_fetch(a, cli.format),
        Command::Explain(a) => cmd_explain(&load(&a.file)?, a, cli.format),
        Command::Path(a) => cmd_path(&load(&a.file)?, a, cli.format),
        Command::SitePath(a) => cmd_site_path(a, cli.format),
        Command::Apply(a) => cmd_apply(a, cli.format),
        Command::S2s(a) => cmd_s2s(a, cli.format),
        Command::Report(a) => {
            let cfg = load(&a.file)?;
            let name = a.file.file_stem().and_then(|s| s.to_str()).unwrap_or("firewall");
            let rep = sfos_sdk::report::build(name, &cfg);
            match cli.format {
                Format::Json => println!("{}", serde_json::to_string_pretty(&rep).unwrap()),
                Format::Text => print!("{}", sfos_sdk::report::render_text(&rep)),
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Iac(a) => {
            let cfg = load(&a.file)?;
            if a.ansible {
                print!("{}", sfos_sdk::iac::to_ansible(&cfg));
            } else {
                println!("{}", serde_json::to_string_pretty(&sfos_sdk::iac::normalize(&cfg)).unwrap());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Entities => {
            cmd_entities(cli.format);
            Ok(ExitCode::SUCCESS)
        }
        Command::Get(a) => cmd_get(a),
        Command::Export(a) => cmd_export(a),
    }
}

fn connect(c: &ConnArgs) -> Result<Client, String> {
    let password = c
        .password
        .clone()
        .or_else(|| std::env::var("SFOS_PASSWORD").ok())
        .ok_or("provide --password or set SFOS_PASSWORD")?;
    Client::new(&c.host, c.port, &c.user, &password, !c.insecure).map_err(|e| e.to_string())
}

fn cmd_fetch(a: &FetchArgs, fmt: Format) -> Result<ExitCode, String> {
    let client = connect(&a.conn)?;
    let cfg = client.export().map_err(|e| e.to_string())?;
    cmd_parse(&cfg, fmt);
    Ok(ExitCode::SUCCESS)
}

// ── explain (differential reachability) ─────────────────────────────────────

fn cmd_explain(cfg: &SophosConfig, a: &ExplainArgs, fmt: Format) -> Result<ExitCode, String> {
    let dst: IpAddr = match a.to.parse() {
        Ok(ip) => ip,
        Err(_) => sfos_sdk::extract::resolve_network(cfg, &a.to)
            .map(|n| n.network())
            .ok_or_else(|| format!("--to '{}' is not an IP and not a resolvable host object", a.to))?,
    };
    let proto = match a.proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        other => return Err(format!("unknown --proto '{other}' (use tcp|udp|icmp)")),
    };
    let zones: Vec<String> = if !a.from.is_empty() {
        a.from.clone()
    } else if let Some(src) = &a.src {
        let sip: IpAddr = src.parse().map_err(|_| format!("invalid --src IP '{src}'"))?;
        match sfos_sdk::extract::zone_of_ip(cfg, sip) {
            Some(z) => vec![z],
            None => return Err(format!("could not infer a zone for --src {src} (no interface covers it)")),
        }
    } else {
        cfg.zones.iter().map(|z| z.name.clone()).collect()
    };
    if zones.is_empty() {
        return Err("no zones to evaluate — config has no zones; pass --from or --src".into());
    }
    let result = reach::explain(cfg, dst, proto, a.dport, &zones);

    match fmt {
        Format::Json => {
            let v = serde_json::json!({
                "destination": a.to,
                "resolved": dst.to_string(),
                "protocol": a.proto,
                "dst_port": a.dport,
                "diverges": result.diverges(),
                "nat": result.nat.as_ref().map(|n| serde_json::json!({
                    "rule": n.rule, "original": n.original, "translated": n.translated,
                })),
                "vantages": result.vantages.iter().map(|v| serde_json::json!({
                    "zone": v.zone,
                    "allowed": v.allowed,
                    "matched_rule": v.matched.as_ref().map(|m| m.name.clone()),
                    "reason": v.reason,
                })).collect::<Vec<_>>(),
                "related_rules": result.related.iter().map(rule_json).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Format::Text => {
            println!("Reachability to {} ({}) {}/{}", a.to, dst, a.proto, a.dport);
            if let Some(n) = &result.nat {
                println!(
                    "  NAT: {} is DNAT'd to {} by rule '{}' — firewall evaluated against the internal host",
                    n.original, n.translated, n.rule
                );
            }
            for v in &result.vantages {
                println!("  {:<12} {:<6} {}", v.zone, if v.allowed { "ALLOW" } else { "BLOCK" }, v.reason);
            }
            if result.diverges() {
                println!("\nDivergence: zones disagree.");
                if let Some(allow) = result.vantages.iter().find(|v| v.allowed && v.matched.is_some()) {
                    let rule = allow.matched.as_ref().unwrap();
                    let blocked: Vec<&str> =
                        result.vantages.iter().filter(|v| !v.allowed).map(|v| v.zone.as_str()).collect();
                    if !blocked.is_empty() {
                        println!(
                            "  {} is allowed by rule '{}' (source zones: {}); {} {} not. \
                             Add the zone(s) to that rule's source zones, or add an equivalent rule.",
                            allow.zone,
                            rule.name,
                            if rule.source_zones.is_empty() { "any".into() } else { rule.source_zones.join(",") },
                            blocked.join(", "),
                            if blocked.len() == 1 { "is" } else { "are" },
                        );
                    }
                }
            } else {
                println!("\nAll evaluated zones agree.");
            }
            if !result.related.is_empty() {
                println!("\nRelated rules (touch {} {}/{}):", dst, a.proto, a.dport);
                for r in &result.related {
                    println!("  {}", rule_line_ref(r));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_path(cfg: &SophosConfig, a: &PathArgs, fmt: Format) -> Result<ExitCode, String> {
    let src: IpAddr = a.src.parse().map_err(|_| format!("invalid --src IP '{}'", a.src))?;
    let dst: IpAddr = match a.to.parse() {
        Ok(ip) => ip,
        Err(_) => sfos_sdk::extract::resolve_network(cfg, &a.to)
            .map(|n| n.network())
            .ok_or_else(|| format!("--to '{}' is not an IP and not a resolvable host object", a.to))?,
    };
    let proto = match a.proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        other => return Err(format!("unknown --proto '{other}' (use tcp|udp|icmp)")),
    };
    let f = reach::forward(cfg, src, dst, proto, a.dport);
    match fmt {
        Format::Json => {
            let v = serde_json::json!({
                "src": a.src, "dst": a.to, "protocol": a.proto, "dst_port": a.dport,
                "ingress_zone": f.ingress_zone,
                "egress_zone": f.egress_zone,
                "egress_interface": f.egress_interface,
                "nat": f.nat.as_ref().map(|n| serde_json::json!({ "rule": n.rule, "original": n.original, "translated": n.translated })),
                "snat": f.snat,
                "firewall": {
                    "allowed": f.verdict.allowed,
                    "matched_rule": f.verdict.matched.as_ref().map(|m| m.name.clone()),
                    "reason": f.verdict.reason,
                },
                "delivered": f.delivered,
                "stages": f.stages,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Format::Text => {
            println!("Path {} -> {} {}/{}", a.src, a.to, a.proto, a.dport);
            for s in &f.stages {
                println!("  {s}");
            }
        }
    }
    Ok(if f.delivered { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn cmd_site_path(a: &SitePathArgs, fmt: Format) -> Result<ExitCode, String> {
    let ca = load(&a.site_a)?;
    let cb = load(&a.site_b)?;
    let an = a.site_a.file_stem().and_then(|s| s.to_str()).unwrap_or("site-a");
    let bn = a.site_b.file_stem().and_then(|s| s.to_str()).unwrap_or("site-b");
    let src: IpAddr = a.src.parse().map_err(|_| format!("invalid --src IP '{}'", a.src))?;
    let dst: IpAddr = a.to.parse().map_err(|_| format!("invalid --to IP '{}'", a.to))?;
    let proto = match a.proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        other => return Err(format!("unknown --proto '{other}' (use tcp|udp|icmp)")),
    };
    let r = reach::site_path(an, &ca, bn, &cb, src, dst, proto, a.dport);
    match fmt {
        Format::Json => {
            let v = serde_json::json!({
                "src": a.src, "dst": a.to, "protocol": a.proto, "dst_port": a.dport,
                "tunnel_a": r.tunnel_a, "tunnel_b": r.tunnel_b, "paired": r.paired,
                "delivered": r.delivered, "stages": r.stages,
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Format::Text => {
            println!("Cross-site path {} -> {} {}/{}", a.src, a.to, a.proto, a.dport);
            for s in &r.stages {
                println!("  {s}");
            }
        }
    }
    Ok(if r.delivered { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

fn cmd_apply(a: &ApplyArgs, fmt: Format) -> Result<ExitCode, String> {
    use sfos_sdk::apply::{plan, Action};

    let desired = load(&a.desired)?;

    // "live" side: a saved file (offline plan) or a live firewall (fetched).
    let (live, client) = if let Some(lf) = &a.live {
        (load(lf)?, None)
    } else if let Some(host) = &a.host {
        let user = a.user.as_deref().ok_or("--user is required with --host")?;
        let password = a
            .password
            .clone()
            .or_else(|| std::env::var("SFOS_PASSWORD").ok())
            .ok_or("provide --password or set SFOS_PASSWORD")?;
        let c = Client::new(host, a.port, user, &password, !a.insecure).map_err(|e| e.to_string())?;
        let live = c.export().map_err(|e| e.to_string())?;
        (live, Some(c))
    } else {
        return Err("specify --live <file> for an offline plan, or --host <fw> to plan against a live firewall".into());
    };

    let items = plan(&desired, &live, a.prune);

    match fmt {
        Format::Json => {
            let arr: Vec<_> = items
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "action": i.action.label(), "tag": i.tag, "name": i.name,
                        "operation": i.action.operation(), "xml": i.xml,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            if items.is_empty() {
                println!("No changes — desired config matches live.");
            }
            for i in &items {
                println!("  {} {:<7} {:<14} {}", i.action.symbol(), i.action.label(), i.tag, i.name);
                if !i.xml.is_empty() {
                    println!("      <Set operation=\"{}\">{}</Set>", i.action.operation(), i.xml);
                }
            }
            if !items.is_empty() {
                let adds = items.iter().filter(|i| i.action == Action::Add).count();
                let upd = items.iter().filter(|i| i.action == Action::Update).count();
                let rem = items.iter().filter(|i| i.action == Action::Remove).count();
                println!("\n{} change(s): {adds} add, {upd} update, {rem} remove", items.len());
            }
        }
    }

    if a.commit {
        let Some(client) = client else {
            return Err("--commit requires --host (cannot write changes to a --live file)".into());
        };
        let mut applied = 0;
        let mut failed = 0;
        for i in &items {
            let res = match i.action {
                Action::Add | Action::Update => client.set(&i.xml, i.action.operation()),
                Action::Remove => client.remove(i.tag, &i.name),
            };
            match res {
                Ok(()) => applied += 1,
                Err(e) => {
                    failed += 1;
                    eprintln!("  ! {} {} failed: {e}", i.action.label(), i.name);
                }
            }
        }
        eprintln!(
            "applied {applied} change(s){}",
            if failed > 0 { format!(", {failed} failed") } else { String::new() }
        );
        Ok(if failed > 0 { ExitCode::FAILURE } else { ExitCode::SUCCESS })
    } else {
        eprintln!("(dry run — re-run with --host … --commit to apply)");
        Ok(ExitCode::SUCCESS)
    }
}

fn rule_json(r: &reach::RuleRef) -> serde_json::Value {
    serde_json::json!({
        "name": r.name, "action": r.action, "enabled": r.enabled,
        "source_zones": r.source_zones, "destination_zones": r.destination_zones,
        "destination_networks": r.destination_networks, "services": r.services,
    })
}

fn rule_line_ref(r: &reach::RuleRef) -> String {
    let st = if r.enabled { "on " } else { "off" };
    format!(
        "[{st}] {:<20} {:<6} src[{}] dst[{}] svc[{}]",
        r.name,
        r.action,
        r.source_zones.join(","),
        r.destination_networks.join(","),
        r.services.join(","),
    )
}

// ── s2s (site-to-site comparison across firewalls) ──────────────────────────

fn cmd_s2s(a: &S2sArgs, fmt: Format) -> Result<ExitCode, String> {
    let mut configs: Vec<(String, SophosConfig)> = Vec::new();
    for f in &a.files {
        let name = f.file_stem().and_then(|s| s.to_str()).unwrap_or("fw").to_string();
        configs.push((name, load(f)?));
    }

    let mut findings: Vec<vpn::VpnFinding> = Vec::new();
    for (name, cfg) in &configs {
        for mut f in vpn::posture(cfg) {
            f.object = format!("{name}/{}", f.object);
            findings.push(f);
        }
    }
    for i in 0..configs.len() {
        for j in (i + 1)..configs.len() {
            let (an, ac) = &configs[i];
            let (bn, bc) = &configs[j];
            findings.extend(vpn::compare_site_to_site(an, ac, bn, bc));
        }
    }

    let fail = findings.iter().any(|f| f.severity == "HIGH" || f.severity == "CRIT");
    match fmt {
        Format::Json => {
            let arr: Vec<_> = findings
                .iter()
                .map(|f| {
                    serde_json::json!({ "severity": f.severity, "check": f.check, "object": f.object, "message": f.message })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            if findings.is_empty() {
                println!("No VPN / site-to-site issues found across {} config(s).", configs.len());
            }
            for f in &findings {
                println!("[{}] {} {} — {}", f.severity, f.check, f.object, f.message);
            }
            if !findings.is_empty() {
                let high = findings.iter().filter(|f| f.severity == "HIGH" || f.severity == "CRIT").count();
                println!("\n{} finding(s), {high} high", findings.len());
            }
        }
    }
    Ok(if fail { ExitCode::FAILURE } else { ExitCode::SUCCESS })
}

fn cmd_entities(fmt: Format) {
    use sfos_sdk::registry::ENTITIES;
    match fmt {
        Format::Json => {
            let arr: Vec<_> = ENTITIES
                .iter()
                .map(|e| serde_json::json!({ "category": e.category, "display": e.display, "tag": e.tag }))
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            let mut current = "";
            for e in ENTITIES {
                if e.category != current {
                    current = e.category;
                    println!("\n# {current}");
                }
                println!("  {:<28} {}", e.tag, e.display);
            }
            println!("\n{} catalogued entities", ENTITIES.len());
        }
    }
}

fn cmd_get(a: &GetArgs) -> Result<ExitCode, String> {
    let client = connect(&a.conn)?;
    if a.raw {
        let xml = client.get_raw(&a.entity).map_err(|e| e.to_string())?;
        println!("{xml}");
    } else {
        let json = client.get_json(&a.entity).map_err(|e| e.to_string())?;
        // Re-parse to pretty-print.
        match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
            Err(_) => println!("{json}"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_export(a: &ExportArgs) -> Result<ExitCode, String> {
    let client = connect(&a.conn)?;
    let results = client.export_all();
    let (mut ok, mut failed) = (0usize, 0usize);

    if let Some(dir) = &a.out_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for (tag, res) in &results {
            match res {
                Ok(xml) => {
                    let (ext, body) =
                        if a.raw { ("xml", xml.clone()) } else { ("json", pretty(&sfos_sdk::xmljson::to_json(xml))) };
                    let path = dir.join(format!("{tag}.{ext}"));
                    std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))?;
                    ok += 1;
                }
                Err(_) => failed += 1,
            }
        }
        eprintln!("exported {ok} entities to {} ({failed} unavailable)", dir.display());
    } else {
        // One combined document on stdout.
        if a.raw {
            for (tag, res) in &results {
                if let Ok(xml) = res {
                    println!("<!-- {tag} -->\n{xml}");
                    ok += 1;
                } else {
                    failed += 1;
                }
            }
        } else {
            let mut obj = serde_json::Map::new();
            for (tag, res) in &results {
                match res {
                    Ok(xml) => {
                        let v: serde_json::Value =
                            serde_json::from_str(&sfos_sdk::xmljson::to_json(xml)).unwrap_or(serde_json::Value::Null);
                        obj.insert(tag.to_string(), v);
                        ok += 1;
                    }
                    Err(e) => {
                        obj.insert(tag.to_string(), serde_json::json!({ "error": e.to_string() }));
                        failed += 1;
                    }
                }
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap());
        }
        eprintln!("exported {ok} entities ({failed} unavailable)");
    }
    Ok(ExitCode::SUCCESS)
}

fn pretty(json: &str) -> String {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .map(|v| serde_json::to_string_pretty(&v).unwrap())
        .unwrap_or_else(|| json.to_string())
}

fn load(path: &std::path::Path) -> Result<SophosConfig, String> {
    let report = load_entities_file(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !report.skipped.is_empty() {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for s in &report.skipped {
            *counts.entry(s.tag.as_str()).or_default() += 1;
        }
        let summary = counts.iter().map(|(tag, n)| format!("{tag} ×{n}")).collect::<Vec<_>>().join(", ");
        eprintln!(
            "sfos-rs: note: skipped {} unmodelled entit{} ({summary}); analysis continues on the rest",
            report.skipped.len(),
            if report.skipped.len() == 1 { "y" } else { "ies" },
        );
        if let Some(first) = report.skipped.first() {
            eprintln!("sfos-rs:   first: <{}> — {}", first.tag, first.error);
        }
    }
    Ok(report.config)
}

// ── parse ───────────────────────────────────────────────────────────────────

fn cmd_parse(cfg: &SophosConfig, fmt: Format) {
    match fmt {
        Format::Json => {
            let v = serde_json::json!({
                "zones": cfg.zones.len(),
                "firewall_rules": cfg.firewall_rules.len(),
                "ip_hosts": cfg.ip_hosts.len(),
                "ip_host_groups": cfg.ip_host_groups.len(),
                "services": cfg.services.len(),
            });
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        Format::Text => {
            println!("Parsed SFOS configuration:");
            println!("  zones            {}", cfg.zones.len());
            println!("  firewall rules   {}", cfg.firewall_rules.len());
            println!("  ip hosts         {}", cfg.ip_hosts.len());
            println!("  ip host groups   {}", cfg.ip_host_groups.len());
            println!("  services         {}", cfg.services.len());
        }
    }
}

// ── dump ──────────────────────────────────────────────────────────────────────

fn cmd_dump(cfg: &SophosConfig, a: &DumpArgs, fmt: Format) {
    let all = !(a.zones || a.rules || a.hosts || a.services);
    match fmt {
        Format::Json => {
            let mut obj = serde_json::Map::new();
            if all || a.zones {
                obj.insert("zones".into(), serde_json::to_value(&cfg.zones).unwrap());
            }
            if all || a.rules {
                obj.insert("firewall_rules".into(), serde_json::to_value(&cfg.firewall_rules).unwrap());
            }
            if all || a.hosts {
                obj.insert("ip_hosts".into(), serde_json::to_value(&cfg.ip_hosts).unwrap());
            }
            if all || a.services {
                obj.insert("services".into(), serde_json::to_value(&cfg.services).unwrap());
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::Value::Object(obj)).unwrap());
        }
        Format::Text => {
            if all || a.zones {
                println!("# Zones ({})", cfg.zones.len());
                for z in &cfg.zones {
                    println!("  {} ({})", z.name, z.zone_type.as_deref().unwrap_or("?"));
                }
            }
            if all || a.rules {
                println!("# Firewall rules ({})", cfg.firewall_rules.len());
                for r in &cfg.firewall_rules {
                    println!("  {}", rule_line(r));
                }
            }
            if all || a.hosts {
                println!("# IP hosts ({})", cfg.ip_hosts.len());
                for h in &cfg.ip_hosts {
                    println!("  {} [{}] {}", h.name, h.host_type.as_deref().unwrap_or("?"), host_addr(h));
                }
            }
            if all || a.services {
                println!("# Services ({})", cfg.services.len());
                for s in &cfg.services {
                    println!("  {} ({})", s.name, s.svc_type.as_deref().unwrap_or("?"));
                }
            }
        }
    }
}

// ── search ────────────────────────────────────────────────────────────────────

fn cmd_search(cfg: &SophosConfig, a: &SearchArgs, fmt: Format) -> Result<ExitCode, String> {
    let hits: Vec<&FirewallRule> = if let Some(obj) = &a.referencing {
        cfg.rules_referencing(obj)
    } else if let (Some(from), Some(to)) = (&a.from, &a.to) {
        cfg.rules_from_to(from, to)
    } else {
        return Err("specify --referencing <object>, or both --from <zone> and --to <zone>".into());
    };

    match fmt {
        Format::Json => {
            let arr: Vec<_> = hits
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "enabled": r.enabled(),
                        "action": r.policy().and_then(|p| p.action.clone()),
                        "source_zones": r.policy().map(|p| p.source_zone_names().to_vec()).unwrap_or_default(),
                        "destination_zones": r.policy().map(|p| p.destination_zone_names().to_vec()).unwrap_or_default(),
                        "services": r.policy().map(|p| p.service_names().to_vec()).unwrap_or_default(),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            if hits.is_empty() {
                println!("no matching rules");
            }
            for r in &hits {
                println!("{}", rule_line(r));
            }
            println!("\n{} matching rule(s)", hits.len());
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ── check ─────────────────────────────────────────────────────────────────────

struct Finding {
    sev: &'static str,
    check: &'static str,
    object: String,
    message: String,
}

fn cmd_check(cfg: &SophosConfig, fmt: Format) -> ExitCode {
    let mut findings: Vec<Finding> = Vec::new();
    let wan_zones: BTreeSet<String> = cfg.zones.iter().filter(|z| z.is_wan()).map(|z| z.name.to_lowercase()).collect();

    for z in cfg.undefined_zone_refs() {
        findings.push(Finding {
            sev: "HIGH",
            check: "SFOS-UNDEFINED-ZONE",
            object: z.clone(),
            message: format!("rule references zone '{z}' which is not defined"),
        });
    }

    for r in &cfg.firewall_rules {
        if !r.enabled() {
            findings.push(Finding {
                sev: "INFO",
                check: "SFOS-DISABLED-RULE",
                object: r.name.clone(),
                message: "rule is disabled — dead configuration".into(),
            });
            continue;
        }
        let Some(p) = r.policy() else { continue };
        let from_wan = p
            .source_zone_names()
            .iter()
            .any(|z| wan_zones.contains(&z.to_lowercase()) || z.eq_ignore_ascii_case("WAN"));

        if from_wan && p.action_accepts() {
            let has_ips =
                p.intrusion_prevention.as_deref().is_some_and(|s| !s.is_empty() && !s.eq_ignore_ascii_case("None"));
            if !has_ips {
                findings.push(Finding {
                    sev: "MEDIUM",
                    check: "SFOS-WAN-INBOUND-NO-IPS",
                    object: r.name.clone(),
                    message: "WAN-sourced accept rule has no intrusion-prevention policy".into(),
                });
            }
        }
        if p.action_accepts() && !matches!(p.log_traffic.as_deref(), Some("Enable")) {
            findings.push(Finding {
                sev: "LOW",
                check: "SFOS-RULE-NO-LOG",
                object: r.name.clone(),
                message: "accept rule does not log traffic".into(),
            });
        }
    }

    let fail = findings.iter().any(|f| f.sev == "HIGH" || f.sev == "CRIT");
    match fmt {
        Format::Json => {
            let arr: Vec<_> = findings
                .iter()
                .map(|f| serde_json::json!({ "severity": f.sev, "check": f.check, "object": f.object, "message": f.message }))
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            if findings.is_empty() {
                println!("No issues found.");
            }
            for f in &findings {
                println!("[{}] {} {} — {}", f.sev, f.check, f.object, f.message);
            }
            let high = findings.iter().filter(|f| f.sev == "HIGH" || f.sev == "CRIT").count();
            let med = findings.iter().filter(|f| f.sev == "MEDIUM").count();
            println!("\n{} finding(s): {high} high, {med} medium", findings.len());
        }
    }
    if fail {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

// ── trace ─────────────────────────────────────────────────────────────────────

fn cmd_trace(cfg: &SophosConfig, a: &TraceArgs, fmt: Format) -> Result<ExitCode, String> {
    let model = extract::to_model(cfg);
    let rule_set = model.rule_sets.get(&(a.from.clone(), a.to.clone()));

    let protocol = match a.proto.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::Icmp,
        other => return Err(format!("unknown --proto '{other}' (use tcp|udp|icmp)")),
    };
    let src: IpAddr = a.src.as_deref().unwrap_or("0.0.0.0").parse().map_err(|_| "invalid --src IP")?;
    let dst: IpAddr = a.dst.as_deref().unwrap_or("0.0.0.0").parse().map_err(|_| "invalid --dst IP")?;
    let packet = Packet { src, dst, protocol, dst_port: a.dport };

    // No synthesised rule set for this zone pair → SFOS implicit default-drop.
    let (action, matched) = match rule_set {
        Some(rs) => {
            let v = evaluate(rs, &packet);
            (v.action, v.matched)
        }
        None => (FilterAction::Drop, None),
    };
    let delivered = action == FilterAction::Accept;

    match fmt {
        Format::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "from": a.from, "to": a.to,
                    "rule_set": rule_set.map(|rs| rs.name.clone()),
                    "protocol": a.proto, "dst_port": a.dport,
                    "action": action.as_str(), "matched_rule": matched, "delivered": delivered,
                }))
                .unwrap()
            );
        }
        Format::Text => {
            println!("{} → {}  (rule set {})", a.from, a.to, rule_set.map(|rs| rs.name.as_str()).unwrap_or("<none>"));
            println!("  packet:  {} dst-port {} {}→{}", a.proto, a.dport, src, dst);
            match matched {
                Some(seq) => println!("  matched: rule seq {seq}"),
                None => println!("  matched: no rule — default action"),
            }
            println!("  verdict: {} → {}", action.as_str(), if delivered { "DELIVERED" } else { "BLOCKED" });
        }
    }
    Ok(if delivered { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

// ── verify (shadow / unreachable rules) ─────────────────────────────────────

fn cmd_verify(cfg: &SophosConfig, fmt: Format) {
    let model = extract::to_model(cfg);
    let mut rows: Vec<(String, shadow::ShadowFinding)> = Vec::new();
    for rs in model.rule_sets.values() {
        for f in shadow::detect(rs) {
            rows.push((rs.name.clone(), f));
        }
    }

    match fmt {
        Format::Json => {
            let arr: Vec<_> = rows
                .iter()
                .map(|(name, f)| {
                    serde_json::json!({
                        "rule_set": name, "shadowed_seq": f.shadowed, "shadowing_seq": f.shadowing,
                        "kind": if f.same_action { "unreachable" } else { "overridden" },
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&arr).unwrap());
        }
        Format::Text => {
            if rows.is_empty() {
                println!("No shadowed or unreachable rules found.");
            }
            for (name, f) in &rows {
                let kind = if f.same_action { "unreachable" } else { "overridden" };
                println!("[SHADOW] rule set {}: rule {} {} by rule {}", name, f.shadowed, kind, f.shadowing);
            }
            if !rows.is_empty() {
                println!("\n{} shadow finding(s)", rows.len());
            }
        }
    }
}

// ── graph (zone reachability) ───────────────────────────────────────────────

fn cmd_graph(cfg: &SophosConfig, a: &GraphArgs, fmt: Format) {
    let g = sfos_sdk::graph::build(cfg);
    match fmt {
        Format::Json => println!("{}", serde_json::to_string_pretty(&g.edges_json()).unwrap()),
        Format::Text if a.mermaid => print!("{}", g.to_mermaid()),
        Format::Text => print!("{}", g.to_dot()),
    }
}

// ── shared rendering ────────────────────────────────────────────────────────

fn rule_line(r: &FirewallRule) -> String {
    let st = if r.enabled() { "on " } else { "off" };
    match r.policy() {
        Some(p) => format!(
            "[{st}] {:<24} {:<6} {}→{} svc:[{}]",
            r.name,
            p.action.as_deref().unwrap_or("?"),
            zlist(p.source_zone_names()),
            zlist(p.destination_zone_names()),
            p.service_names().join(","),
        ),
        None => format!("[{st}] {:<24} (no network/user policy)", r.name),
    }
}

fn zlist(zones: &[String]) -> String {
    if zones.is_empty() {
        "any".to_string()
    } else {
        zones.join(",")
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
