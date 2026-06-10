# SDK guide (`sfos-sdk`)

The library behind the CLI. Use it to build your own tooling: pull config from
live firewalls, parse offline exports, run the same analyses, and write
changes programmatically.

```toml
[dependencies]
sfos-sdk = { git = "https://github.com/TWN-Systems/sfos-rs", package = "sfos-sdk" }
```

Module map (`sfos_sdk::…`):

| Module | Purpose |
|---|---|
| `client` | live XML API client: auth, get/set/remove, filtered get, full export |
| `sophos` | typed config model + `Entities.xml` / API-response parser + object search |
| `entity` | `SophosEntity` trait + typed constructors (the create/update/delete layer) |
| `registry` | catalogue of 66 XML API entities across the SFOS menu categories |
| `xmljson` | generic XML→JSON conversion (any entity without a typed struct) |
| `apply` | pure plan/diff engine (desired vs live → add/update/remove items) |
| `ir` / `extract` | vendor-neutral firewall IR + the Sophos→IR bridge |
| `acl` | packet-vs-ruleset evaluation |
| `reach` | reachability: `explain` (differential), `forward` (path), `site_path` |
| `route` | longest-prefix-match route table |
| `shadow` | shadowed / unreachable rule detection |
| `vpn` | VPN posture + cross-firewall site-to-site comparison |
| `report` | per-subsystem state report builder |
| `iac` | normalized declarative JSON + Ansible emitter |

## The client

```rust
use sfos_sdk::client::{Client, FilterCriteria};

// verify_certs = false accepts the default self-signed SFOS certificate.
let fw = Client::new("fw.example.com", 4444, "admin", &password, false)?;
```

`Client::new(host, port, username, password, verify_certs)` builds a blocking
HTTPS client (30 s timeout) for `https://{host}:{port}/webconsole/APIController`.
Every request carries the `<Login>` block; credentials are XML-escaped.

### Reading

| Method | Returns | Notes |
|---|---|---|
| `get_entities(tag)` | `SophosConfig` | one entity type, parsed into the typed model |
| `get_raw(tag)` | `String` (XML) | **any** tag, catalogued or not |
| `get_json(tag)` | `String` (JSON) | `get_raw` + generic XML→JSON |
| `get_entities_filtered(tag, key, criteria, value)` | `SophosConfig` | server-side `<Filter>` |
| `get_raw_filtered(tag, key, criteria, value)` | `String` (XML) | server-side `<Filter>` |
| `export()` | `SophosConfig` | the 5 modelled types merged into one config — the live equivalent of parsing a backup |
| `export_all()` | `Vec<(&str, Result<String, SdkError>)>` | raw XML for **all 66** catalogued entities, per-entity errors captured |

Filters map to the SFOS `<Filter><key name=… criteria=…>` request shape:

```rust
// every IPHost whose Name contains "web"
let cfg = fw.get_entities_filtered("IPHost", "Name", FilterCriteria::Like, "web")?;
```

`FilterCriteria::Eq` → `criteria="="`, `Neq` → `"!="`, `Like` → `"like"`.

### Writing (see [safety.md](safety.md) first)

Low-level — you supply the XML body:

```rust
fw.set("<IPHost><Name>web</Name>…</IPHost>", "add")?;   // or "update"
fw.remove("IPHost", "old-host")?;                       // remove by name
```

Typed — entities serialize themselves (parity with the Python SDK's
`create_*` methods):

```rust
use sfos_sdk::sophos::{FirewallRule, IpHost, IpHostGroup, ServiceObj, Zone};

fw.create(&IpHost::ip("web", "10.0.10.5"))?;
fw.create(&IpHost::network("lan-net", "10.0.0.0", "255.255.0.0"))?;
fw.create(&IpHost::range("dhcp-pool", "10.0.20.10", "10.0.20.99"))?;
fw.create(&IpHostGroup::new("servers", &["web", "db"]))?;
fw.create(&Zone::new("DMZ", "DMZ"))?;
fw.create(&ServiceObj::tcp("HTTPS-8443", "8443"))?;     // SourcePort 1:65535
fw.create(&ServiceObj::udp("Syslog", "514"))?;
fw.create(&FirewallRule::allow("LAN-to-DMZ-web", &["LAN"], &["DMZ"], &["HTTPS-8443"]))?;
fw.create(&FirewallRule::deny("Block-guest-to-LAN", &["Guest"], &["LAN"], &[]))?;

fw.update(&IpHost::ip("web", "10.0.10.6"))?;            // Set operation="update"
fw.delete(&IpHost::ip("web", "10.0.10.6"))?;            // Remove by T::TAG + name()
```

Constructor defaults worth knowing:
- `ServiceObj::tcp/udp` → `Type=TCPorUDP`, `SourcePort=1:65535`
- `FirewallRule::allow/deny` → `Status=Enable`, `LogTraffic=Enable`,
  `IPFamily=IPv4`, `PolicyType=Network`; empty zone/service slices simply omit
  that list (SFOS treats it as "Any")

To support a new writable type, implement `SophosEntity` (three items:
`TAG`, `name()`, `to_xml()`) — `create`/`update`/`delete` and the `apply`
planner then work with it.

## Offline parsing & analysis

```rust
use sfos_sdk::sophos::{parse_entities, parse_entities_file};

let cfg = parse_entities_file("Entities.xml")?;          // or parse_entities(&xml_string)
```

`parse_entities` accepts both a backup `<Configuration>` document and an XML
API `<Response>` body — entity elements parse identically. Then:

```rust
// search
let hits = cfg.rules_referencing("WebServer");
let lan_wan = cfg.rules_from_to("LAN", "WAN");

// analyses (exactly what the CLI commands run)
let posture  = sfos_sdk::vpn::posture(&cfg);
let findings = sfos_sdk::vpn::compare_site_to_site("a", &cfg_a, "b", &cfg_b);
let result   = sfos_sdk::reach::explain(&cfg, dst_ip, proto, 443, &zones);
let flow     = sfos_sdk::reach::forward(&cfg, src_ip, dst_ip, proto, 443);
let xsite    = sfos_sdk::reach::site_path("a", &cfg_a, "b", &cfg_b, src, dst, proto, 443);
let report   = sfos_sdk::report::build("site-a", &cfg);
let iac      = sfos_sdk::iac::normalize(&cfg);
let plan     = sfos_sdk::apply::plan(&desired, &live, /*prune*/ false);
```

## XML→JSON conventions (`xmljson::to_json`)

Generic conversion used by `get`/`export` for entities without typed structs:
XML attributes become `"@attr"` keys, text content becomes `"#text"` (or a
plain string when the element has no attributes/children), and repeated
sibling elements become arrays.

## Entity registry

`registry::ENTITIES` — 66 entities across 15 categories, mirroring the SFOS
menu structure (derived from the SFOS 21.5 API reference). The XML API is
uniform (`<Get><Tag></Tag></Get>`), so this table plus the generic client is
enough to pull the entire configuration. Tags are best-effort from the docs
and self-validate against a live box via `export_all`'s per-entity results;
`get_raw` accepts any tag string for entities not catalogued.

| Category | Tags |
|---|---|
| Hosts and services | `IPHost`, `IPHostGroup`, `MACHost`, `FQDNHost`, `FQDNHostGroup`, `CountryGroup`, `Services`, `ServiceGroup` |
| Firewall | `FirewallRule`, `FirewallRuleGroup`, `NATRule`, `SSLTLSInspectionRule`, `LocalServiceACL` |
| Intrusion prevention | `IPSPolicy`, `CustomIPSSignatures`, `DoSSettings` |
| Web | `WebFilterPolicy`, `WebFilterURLGroup`, `WebFilterException`, `FileType`, `UserActivity` |
| Applications | `ApplicationFilterPolicy`, `ApplicationFilter` |
| Email | `SMTPPolicy`, `TrustedDomain` |
| VPN | `VPNIPSecConnection`, `L2TP` |
| Network | `Interface`, `VLAN`, `Alias`, `BridgePair`, `LAG`, `Zone`, `Gateway`, `DNS`, `DNSHostEntry`, `DHCPServer`, `DHCPRelay`, `IPTunnel`, `GRETunnel`, `DynamicDNS` |
| Routing | `UnicastRoute`, `SDWANPolicyRoute`, `GatewayConfiguration` |
| Authentication | `AuthenticationServer`, `LDAPServer`, `RADIUSServer`, `User`, `UserGroup`, `GuestUser`, `OTPToken` |
| System services | `HAConfiguration`, `SyslogServers`, `QoSPolicy`, `Notification` |
| Profiles | `Schedule`, `AccessTime`, `DecryptionProfile` |
| Administration | `AdminSettings`, `WebAdminSettings`, `SNMPCommunity`, `LoginSecurity` |
| Certificates | `Certificate`, `CertificateAuthority` |
| System | `Hotfix`, `CentralManagement` |

Writable (typed, `apply`-managed) subset — `client::EXPORTABLE_ENTITIES`, in
dependency order: `Zone`, `IPHost`, `IPHostGroup`, `Services`, `FirewallRule`.

## Parity with the Python SDK (`sophosfirewall-python`)

| Python | sfos-rs |
|---|---|
| `SophosFirewall(username, password, hostname, port)` | `Client::new(host, port, user, pass, verify_certs)` |
| `get_tag("IPHost")` | `get_raw("IPHost")` / `get_entities("IPHost")` |
| `get_tag_with_filter(tag, key, value, operator)` | `get_raw_filtered` / `get_entities_filtered` |
| `create_ip_host(...)` etc. | `client.create(&IpHost::ip(...))` etc. |
| `submit_xml` / template-driven `Set` | `set(entity_xml, op)` |
| `remove(xml_tag, name)` | `remove(tag, name)` |
| raises `SophosFirewallZeroRecords` on empty result | **returns an empty `SophosConfig`** — check `.is_empty()` / lengths yourself |
| raises `SophosFirewallAuthFailure` | `Err(SdkError::Auth(_))` |
| raises `SophosFirewallAPIError` | `Err(SdkError::Api { code })` |

See [errors.md](errors.md) for the full error taxonomy.
