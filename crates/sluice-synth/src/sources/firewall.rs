//! Firewall decisions from `OPNsense` (`filterlog`), parsed into JSON with the raw CSV line kept
//! alongside.

use sluice_core::logsource::LogSource;

use crate::fields::{Fields, object, rfc3339};
use crate::sources::{Ctx, Spec, json_format};
use crate::world::{ATTACKER_IP, EXTERNAL_IPS, INTERNAL_IPS, SCANNER_IP};

pub(crate) const SPEC: Spec = Spec {
    id: "firewall",
    generate,
    logsource: || LogSource {
        product: Some("opnsense".into()),
        service: Some("filterlog".into()),
        category: Some("firewall".into()),
        complete: false,
    },
    format: json_format,
};

const BASTION_IP: &str = "10.10.3.5";

/// One filter decision.
struct Packet<'a> {
    action: &'a str,
    direction: &'a str,
    interface: &'a str,
    proto: &'a str,
    src: &'a str,
    dst: &'a str,
    dst_port: u64,
}

fn generate(ctx: &mut Ctx) {
    for _ in 0..ctx.volume(8_000) {
        let ts = ctx.any_time();
        let (port, proto) = *ctx.rng.pick(&[
            (443, "tcp"),
            (443, "tcp"),
            (80, "tcp"),
            (53, "udp"),
            (123, "udp"),
        ]);
        let packet = Packet {
            action: "pass",
            direction: "out",
            interface: "igb1",
            proto,
            src: ctx.rng.pick(&INTERNAL_IPS),
            dst: ctx.rng.pick(&EXTERNAL_IPS),
            dst_port: port,
        };
        let fields = filterlog(ctx, ts, &packet);
        ctx.emit(ts, fields);
    }
    // Internet background noise: blocked inbound probes. The scanner contributes a share.
    for _ in 0..ctx.volume(2_000) {
        let ts = ctx.any_time();
        let src = if ctx.rng.chance(20) {
            SCANNER_IP.to_owned()
        } else {
            format!(
                "45.155.{}.{}",
                ctx.rng.between(0, 255),
                ctx.rng.between(1, 254)
            )
        };
        let port = *ctx.rng.pick(&[22, 23, 445, 3389, 8080, 5900]);
        let packet = Packet {
            action: "block",
            direction: "in",
            interface: "igb0",
            proto: "tcp",
            src: &src,
            dst: "192.0.2.10",
            dst_port: port,
        };
        let fields = filterlog(ctx, ts, &packet);
        ctx.emit(ts, fields);
    }
    // The SSH brute force, seen by the firewall: allowed through to the bastion.
    let start = ctx.at_percent(60);
    for i in 0..31 {
        let ts = start + i * 2;
        let packet = Packet {
            action: "pass",
            direction: "in",
            interface: "igb0",
            proto: "tcp",
            src: ATTACKER_IP,
            dst: BASTION_IP,
            dst_port: 22,
        };
        let fields = filterlog(ctx, ts, &packet);
        ctx.emit(ts, fields);
    }
}

fn filterlog(ctx: &mut Ctx, ts: i64, packet: &Packet<'_>) -> Fields {
    let rule = if packet.action == "pass" { 12 } else { 4 };
    let tracker = 1_000_000_000 + ctx.rng.below(100);
    let src_port = ctx.rng.between(1_024, 65_535);
    let length = ctx.rng.between(40, 1_500);
    let ttl = ctx.rng.between(48, 128);
    let flags = if packet.proto == "tcp" { "S" } else { "" };
    let proto_number = if packet.proto == "tcp" { 6 } else { 17 };
    let raw = format!(
        "{rule},,,{tracker},{iface},match,{action},{dir},4,0x0,,{ttl},{id},0,DF,{proto_number},{proto},{length},{src},{dst},{src_port},{dst_port},{payload},{flags},,,,",
        iface = packet.interface,
        action = packet.action,
        dir = packet.direction,
        id = ctx.rng.between(1, 65_535),
        proto = packet.proto,
        src = packet.src,
        dst = packet.dst,
        dst_port = packet.dst_port,
        payload = length.saturating_sub(40),
    );
    Fields::new()
        .set("@timestamp", rfc3339(ts))
        .set(
            "observer",
            object([
                ("hostname", "fw01".into()),
                ("vendor", "Deciso".into()),
                ("product", "OPNsense".into()),
                ("version", "24.7.5".into()),
            ]),
        )
        .set(
            "event",
            object([
                ("dataset", "opnsense.filterlog".into()),
                ("original", raw.clone().into()),
            ]),
        )
        .set("interface", packet.interface)
        .set("action", packet.action)
        .set("direction", packet.direction)
        .set("reason", "match")
        .set("rule_number", rule)
        .set("tracker", tracker.to_string())
        .set("ip_version", 4)
        .set("tos", "0x0")
        .set("ecn", "")
        .set("ttl", ttl)
        .set("proto", packet.proto)
        .set("length", length)
        .set("src_ip", packet.src)
        .set("src_port", src_port)
        .set("dst_ip", packet.dst)
        .set("dst_port", packet.dst_port)
        .set("tcp_flags", flags)
        .set("message", raw)
}
