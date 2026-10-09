//! Resolver query log (Unbound), as JSON with a duplicated ECS `dns` object.

use sluice_core::logsource::LogSource;

use crate::fields::{Fields, object, rfc3339};
use crate::sources::{Ctx, Spec, json_format};
use crate::world::{BAD_DOMAIN, DOMAINS, EXTERNAL_IPS, INTERNAL_IPS};

pub(crate) const SPEC: Spec = Spec {
    id: "dns",
    generate,
    logsource: || LogSource {
        product: Some("unbound".into()),
        service: None,
        category: Some("dns".into()),
    },
    format: json_format,
};

pub(crate) const BAD_DOMAIN_LOOKUP: &str = "bad-domain-lookup";

fn generate(ctx: &mut Ctx) {
    for _ in 0..ctx.volume(6_000) {
        let ts = ctx.any_time();
        let client = *ctx.rng.pick(&INTERNAL_IPS);
        let name = *ctx.rng.pick(&DOMAINS);
        let qtype = *ctx.rng.pick(&["A", "A", "AAAA", "HTTPS"]);
        let fields = query(ctx, ts, client, name, qtype);
        ctx.emit(ts, fields);
    }
    let ts = ctx.at_percent(50);
    let fields = query(ctx, ts, "10.10.1.22", BAD_DOMAIN, "A");
    ctx.emit_attack(BAD_DOMAIN_LOOKUP, ts, fields);
}

fn query(ctx: &mut Ctx, ts: i64, client: &str, name: &str, qtype: &str) -> Fields {
    let answer = *ctx.rng.pick(&EXTERNAL_IPS);
    let id = ctx.rng.between(1, 65_535);
    let ttl = ctx.rng.between(30, 3_600);
    let question = || {
        object([
            ("name", name.into()),
            ("type", qtype.into()),
            ("class", "IN".into()),
        ])
    };
    Fields::new()
        .set("@timestamp", rfc3339(ts))
        .set("resolver", "unbound")
        .set(
            "client",
            object([
                ("ip", client.into()),
                ("port", ctx.rng.between(1_024, 65_535).into()),
            ]),
        )
        .set("query", question())
        .set("response_code", "NOERROR")
        .set(
            "answers",
            vec![object([("data", answer.into()), ("ttl", ttl.into())])],
        )
        .set(
            "dns",
            object([
                ("id", id.into()),
                ("question", question()),
                ("response_code", "NOERROR".into()),
                ("header_flags", vec!["RD", "RA"].into()),
                ("resolved_ip", vec![answer].into()),
            ]),
        )
        .set("dnssec", "")
        .set("edns", serde_json::Value::Null)
}
