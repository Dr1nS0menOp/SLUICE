//! `/var/log/auth.log` from Linux servers, shipped by Filebeat as raw lines.

use crate::fields::{Fields, object, rfc3339, syslog_time};
use crate::sources::{Ctx, Spec, beats_envelope, logsource, text_format};
use crate::world::{ATTACKER_IP, INTERNAL_IPS, LINUX_HOSTS, LINUX_USERS};

pub(crate) const SPEC: Spec = Spec {
    id: "linux-auth",
    generate,
    logsource: || logsource("linux", Some("auth")),
    format: text_format,
};

pub(crate) const SSH_BRUTE_FORCE: &str = "ssh-brute-force";

fn generate(ctx: &mut Ctx) {
    for _ in 0..ctx.volume(1_500) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&LINUX_HOSTS);
        for state in ["opened", "closed"] {
            let line = format!(
                "pam_unix(cron:session): session {state} for user root{}",
                if state == "opened" {
                    "(uid=0) by (uid=0)"
                } else {
                    ""
                }
            );
            let fields = syslog(ctx, ts, host, "CRON", &line);
            ctx.emit(ts, fields);
        }
    }
    for _ in 0..ctx.volume(300) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&LINUX_HOSTS);
        let user = *ctx.rng.pick(&LINUX_USERS);
        let ip = *ctx.rng.pick(&INTERNAL_IPS);
        let port = ctx.rng.between(40_000, 65_000);
        let key = ctx.rng.hex(43);
        let accepted = format!(
            "Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 SHA256:{key}"
        );
        let fields = syslog(ctx, ts, host, "sshd", &accepted);
        ctx.emit(ts, fields);
        let session =
            format!("pam_unix(sshd:session): session opened for user {user}(uid=1000) by (uid=0)");
        let fields = syslog(ctx, ts, host, "sshd", &session);
        ctx.emit(ts, fields);
        let logind = format!(
            "New session {} of user {user}.",
            ctx.rng.between(100, 9_999)
        );
        let fields = syslog(ctx, ts + 1, host, "systemd-logind", &logind);
        ctx.emit(ts + 1, fields);
    }
    for _ in 0..ctx.volume(150) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&LINUX_HOSTS);
        let user = *ctx.rng.pick(&LINUX_USERS);
        let command = *ctx.rng.pick(&[
            "/usr/bin/systemctl restart nginx",
            "/usr/bin/apt-get update",
            "/usr/bin/journalctl -u nginx --since today",
        ]);
        let line = format!("{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}");
        let fields = syslog(ctx, ts, host, "sudo", &line);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(40) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&LINUX_HOSTS);
        let user = *ctx.rng.pick(&LINUX_USERS);
        let ip = *ctx.rng.pick(&INTERNAL_IPS);
        let port = ctx.rng.between(40_000, 65_000);
        let line = format!("Failed password for {user} from {ip} port {port} ssh2");
        let fields = syslog(ctx, ts, host, "sshd", &line);
        ctx.emit(ts, fields);
    }
    ssh_brute_force(ctx);
}

/// Scenario: 30 failed passwords from one external IP, then a root login from it.
fn ssh_brute_force(ctx: &mut Ctx) {
    let start = ctx.at_percent(60);
    let names = ["admin", "root", "test", "oracle", "ubuntu", "postgres"];
    for i in 0..30 {
        let ts = start + i * 2;
        let name = names[usize::try_from(i).unwrap_or(0) % names.len()];
        let port = ctx.rng.between(30_000, 60_000);
        let line =
            format!("Failed password for invalid user {name} from {ATTACKER_IP} port {port} ssh2");
        let fields = syslog(ctx, ts, "bastion01", "sshd", &line);
        ctx.emit_attack(SSH_BRUTE_FORCE, ts, fields);
    }
    let ts = start + 62;
    let port = ctx.rng.between(30_000, 60_000);
    let line = format!("Accepted password for root from {ATTACKER_IP} port {port} ssh2");
    let fields = syslog(ctx, ts, "bastion01", "sshd", &line);
    ctx.emit_attack(SSH_BRUTE_FORCE, ts, fields);
}

fn syslog(ctx: &mut Ctx, ts: i64, host: &str, program: &str, text: &str) -> Fields {
    let pid = ctx.rng.between(300, 65_000);
    let line = format!("{} {host} {program}[{pid}]: {text}", syslog_time(ts));
    let agent_id = format!("filebeat-{host}");
    beats_envelope("filebeat", host, &agent_id)
        .set("@timestamp", rfc3339(ts))
        .set(
            "host",
            object([("name", host.into()), ("hostname", host.into())]),
        )
        .set(
            "log",
            object([
                ("offset", ctx.rng.between(0, 50_000_000).into()),
                ("file", object([("path", "/var/log/auth.log".into())])),
            ]),
        )
        .set("input", object([("type", "filestream".into())]))
        .set("event", object([("original", line.clone().into())]))
        .set("message", line)
}
