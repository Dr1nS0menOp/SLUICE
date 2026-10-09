//! The Winlogbeat envelope shared by every Windows event-log channel.

use crate::fields::{Fields, object, rfc3339, windows_time};
use crate::sources::{Ctx, beats_envelope};
use crate::world::{DNS_SUFFIX, WindowsHost};

/// The channel an event comes from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Channel {
    pub(crate) name: &'static str,
    pub(crate) provider: &'static str,
}

pub(crate) const SECURITY: Channel = Channel {
    name: "Security",
    provider: "Microsoft-Windows-Security-Auditing",
};

pub(crate) const SYSMON: Channel = Channel {
    name: "Microsoft-Windows-Sysmon/Operational",
    provider: "Microsoft-Windows-Sysmon",
};

pub(crate) fn fqdn(host: &WindowsHost) -> String {
    format!("{}.{DNS_SUFFIX}", host.name.to_lowercase())
}

/// Envelope and system fields of one event: agent, host, both timestamps, and record metadata.
pub(crate) fn envelope(
    ctx: &mut Ctx,
    channel: Channel,
    host: &WindowsHost,
    ts: i64,
    event_id: u32,
) -> Fields {
    let fraction = ctx.rng.below(10_000_000);
    beats_envelope("winlogbeat", host.name, host.agent_id)
        .set(
            "host",
            object([
                ("name", fqdn(host).into()),
                ("hostname", host.name.into()),
                ("ip", host.ip.into()),
                (
                    "os",
                    object([
                        ("family", "windows".into()),
                        ("name", host.os_name.into()),
                        ("build", host.os_build.into()),
                        ("kernel", "10.0".into()),
                        ("platform", "windows".into()),
                    ]),
                ),
            ]),
        )
        .set("@timestamp", rfc3339(ts))
        .set("TimeCreated", windows_time(ts, fraction))
        .set("EventID", event_id)
        .set("Channel", channel.name)
        .set("Provider", channel.provider)
        .set("Computer", fqdn(host))
        .set("Level", "Information")
        .set("RecordNumber", ctx.rng.between(100_000, 9_999_999))
        .set("ThreadID", ctx.rng.between(1_000, 9_000))
}
