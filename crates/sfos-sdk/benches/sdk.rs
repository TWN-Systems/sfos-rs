//! CodSpeed performance benchmarks for the sfos-sdk crate.
//!
//! These cover the core offline pipeline: parsing a Sophos `Entities.xml`
//! export, bridging it to the vendor-neutral IR, building the zone graph,
//! rendering it, running reachability analysis, and detecting shadowed rules.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::IpAddr;

use sfos_sdk::extract::to_model;
use sfos_sdk::graph;
use sfos_sdk::ir::Protocol;
use sfos_sdk::reach::{explain, forward};
use sfos_sdk::shadow;
use sfos_sdk::sophos::parse_entities;

const SAMPLE: &str = include_str!("../tests/fixtures/entities-sample.xml");
const NAT: &str = include_str!("../tests/fixtures/entities-nat.xml");
const VPN: &str = include_str!("../tests/fixtures/entities-vpn.xml");

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_entities");
    group.bench_function("sample", |b| b.iter(|| parse_entities(black_box(SAMPLE)).unwrap()));
    group.bench_function("nat", |b| b.iter(|| parse_entities(black_box(NAT)).unwrap()));
    group.bench_function("vpn", |b| b.iter(|| parse_entities(black_box(VPN)).unwrap()));
    group.finish();
}

fn bench_to_model(c: &mut Criterion) {
    let cfg = parse_entities(SAMPLE).unwrap();
    c.bench_function("to_model/sample", |b| b.iter(|| to_model(black_box(&cfg))));
}

fn bench_graph(c: &mut Criterion) {
    let cfg = parse_entities(SAMPLE).unwrap();
    c.bench_function("graph/build", |b| b.iter(|| graph::build(black_box(&cfg))));

    let g = graph::build(&cfg);
    c.bench_function("graph/to_dot", |b| b.iter(|| black_box(&g).to_dot()));
    c.bench_function("graph/to_mermaid", |b| b.iter(|| black_box(&g).to_mermaid()));
}

fn bench_reach(c: &mut Criterion) {
    let cfg = parse_entities(NAT).unwrap();
    let public: IpAddr = "203.0.113.10".parse().unwrap();
    c.bench_function("reach/explain_dnat", |b| {
        b.iter(|| explain(black_box(&cfg), black_box(public), Protocol::Tcp, 443, &["WAN".to_string()]))
    });

    let src: IpAddr = "203.0.113.50".parse().unwrap();
    c.bench_function("reach/forward_dnat", |b| {
        b.iter(|| forward(black_box(&cfg), black_box(src), black_box(public), Protocol::Tcp, 443))
    });
}

fn bench_shadow(c: &mut Criterion) {
    let cfg = parse_entities(SAMPLE).unwrap();
    let model = to_model(&cfg);
    c.bench_function("shadow/detect_all", |b| {
        b.iter(|| {
            let mut total = 0usize;
            for rs in model.rule_sets.values() {
                total += shadow::detect(black_box(rs)).len();
            }
            total
        })
    });
}

criterion_group!(benches, bench_parse, bench_to_model, bench_graph, bench_reach, bench_shadow);
criterion_main!(benches);
