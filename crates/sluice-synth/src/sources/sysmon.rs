//! Sysmon operational log, as shipped by Winlogbeat.
//!
//! Like the real thing, every event's rendered `Message` repeats all of its data fields, so the
//! body carries nearly everything twice.

use crate::fields::{Fields, datetime};
use crate::sources::{Ctx, Spec, json_format, logsource, winlog};
use crate::world::{
    DLLS, DOMAIN, DOMAINS, EXTERNAL_IPS, PROCESSES, USERS, WINDOWS_HOSTS, WindowsHost,
};

pub(crate) const SPEC: Spec = Spec {
    id: "sysmon",
    generate,
    logsource: || logsource("windows", Some("sysmon")),
    format: json_format,
};

pub(crate) const LSASS_ACCESS: &str = "lsass-access";
pub(crate) const ENCODED_POWERSHELL: &str = "encoded-powershell";

const LSASS: &str = r"C:\Windows\system32\lsass.exe";

/// (source image, target image, granted access) for benign process access. Defender reading
/// LSASS with 0x1410 is the classic exclusion that LSASS-access rules filter out.
const ACCESS_PAIRS: [(&str, &str, &str); 6] = [
    (
        r"C:\Windows\system32\svchost.exe",
        r"C:\Windows\system32\svchost.exe",
        "0x1000",
    ),
    (
        r"C:\Windows\system32\csrss.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "0x1400",
    ),
    (
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090-0\MsMpEng.exe",
        LSASS,
        "0x1410",
    ),
    (
        r"C:\Windows\system32\wbem\wmiprvse.exe",
        r"C:\Windows\system32\svchost.exe",
        "0x1400",
    ),
    (
        r"C:\Windows\explorer.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        "0x1000",
    ),
    (r"C:\Windows\system32\svchost.exe", LSASS, "0x1000"),
];

/// Builds one benign event of a given type.
type Make = fn(&mut Ctx, &WindowsHost, i64) -> Fields;

fn generate(ctx: &mut Ctx) {
    let volumes: [(u64, Make); 6] = [
        (1_500, process_create),
        (4_000, network_connect),
        (15_000, image_load),
        (3_000, process_access),
        (2_000, file_create),
        (3_000, dns_query),
    ];
    for (per_hour, make) in volumes {
        for _ in 0..ctx.volume(per_hour) {
            let ts = ctx.any_time();
            let host = *ctx.rng.pick(&WINDOWS_HOSTS);
            let fields = make(ctx, &host, ts);
            ctx.emit(ts, fields);
        }
    }
    encoded_powershell(ctx);
    lsass_access(ctx);
}

/// Scenario: discovery, then an encoded PowerShell command, on Carol's workstation.
fn encoded_powershell(ctx: &mut Ctx) {
    let host = WINDOWS_HOSTS[4];
    let ts = ctx.at_percent(30);
    let cmd = r"C:\Windows\System32\cmd.exe";
    let whoami = process(
        ctx,
        &host,
        ts,
        "carol",
        r"C:\Windows\System32\whoami.exe",
        "whoami.exe",
        "whoami  /all",
        cmd,
    );
    ctx.emit_attack(ENCODED_POWERSHELL, ts, whoami);
    let powershell = process(
        ctx,
        &host,
        ts + 5,
        "carol",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "PowerShell.EXE",
        "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA",
        cmd,
    );
    ctx.emit_attack(ENCODED_POWERSHELL, ts + 5, powershell);
}

/// Scenario: a renamed procdump dumps LSASS on Bob's workstation.
fn lsass_access(ctx: &mut Ctx) {
    let host = WINDOWS_HOSTS[3];
    let ts = ctx.at_percent(45);
    let tool = r"C:\Users\Public\svc-helper.exe";
    let launch = process(
        ctx,
        &host,
        ts,
        "bob",
        tool,
        "procdump",
        r"svc-helper.exe -accepteula -ma lsass.exe C:\Users\Public\lsass.dmp",
        r"C:\Windows\System32\cmd.exe",
    );
    ctx.emit_attack(LSASS_ACCESS, ts, launch);
    let access = access(ctx, &host, ts + 1, tool, LSASS, "0x1010");
    ctx.emit_attack(LSASS_ACCESS, ts + 1, access);
    let dump = file(ctx, &host, ts + 3, tool, r"C:\Users\Public\lsass.dmp");
    ctx.emit_attack(LSASS_ACCESS, ts + 3, dump);
}

/// A Sysmon event whose `Message` renders every data field, as Windows does.
fn event(
    ctx: &mut Ctx,
    host: &WindowsHost,
    ts: i64,
    event_id: u32,
    title: &str,
    data: Vec<(&str, String)>,
) -> Fields {
    let millis = ctx.rng.below(1_000);
    let utc = format!("{}.{millis:03}", datetime(ts).format("%Y-%m-%d %H:%M:%S"));
    let mut message = format!("{title}:\nRuleName: -\nUtcTime: {utc}");
    let mut fields = winlog::envelope(ctx, winlog::SYSMON, host, ts, event_id)
        .set("RuleName", "-")
        .set("UtcTime", utc);
    for (key, value) in data {
        message.push('\n');
        message.push_str(key);
        message.push_str(": ");
        message.push_str(&value);
        fields = fields.set(key, value);
    }
    fields.set("Message", message)
}

fn guid(ctx: &mut Ctx) -> String {
    format!(
        "{{{}-{}-{}-{}-{}}}",
        ctx.rng.hex(8),
        ctx.rng.hex(4),
        ctx.rng.hex(4),
        ctx.rng.hex(4),
        ctx.rng.hex(12)
    )
}

fn hashes(ctx: &mut Ctx) -> String {
    format!(
        "SHA1={},MD5={},SHA256={},IMPHASH={}",
        ctx.rng.hex(40).to_uppercase(),
        ctx.rng.hex(32).to_uppercase(),
        ctx.rng.hex(64).to_uppercase(),
        ctx.rng.hex(32).to_uppercase()
    )
}

fn pid(ctx: &mut Ctx) -> String {
    ctx.rng.between(400, 16_000).to_string()
}

fn domain_user(user: &str) -> String {
    format!("{DOMAIN}\\{user}")
}

fn process_create(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (image, parent, command_line) = *ctx.rng.pick(&PROCESSES);
    let user = *ctx.rng.pick(&USERS);
    let original = image.rsplit('\\').next().unwrap_or(image).to_owned();
    process(ctx, host, ts, user, image, &original, command_line, parent)
}

#[allow(clippy::too_many_arguments)] // Mirrors the Sysmon schema; a struct would only rename them.
fn process(
    ctx: &mut Ctx,
    host: &WindowsHost,
    ts: i64,
    user: &str,
    image: &str,
    original_file_name: &str,
    command_line: &str,
    parent: &str,
) -> Fields {
    let data = vec![
        ("ProcessGuid", guid(ctx)),
        ("ProcessId", pid(ctx)),
        ("Image", image.to_owned()),
        (
            "FileVersion",
            "10.0.26100.1 (WinBuild.160101.0800)".to_owned(),
        ),
        ("Description", String::new()),
        ("Product", "Microsoft® Windows® Operating System".to_owned()),
        ("Company", "Microsoft Corporation".to_owned()),
        ("OriginalFileName", original_file_name.to_owned()),
        ("CommandLine", command_line.to_owned()),
        ("CurrentDirectory", r"C:\Windows\system32\".to_owned()),
        ("User", domain_user(user)),
        ("LogonGuid", guid(ctx)),
        ("LogonId", format!("0x{}", ctx.rng.hex(6))),
        ("TerminalSessionId", "1".to_owned()),
        ("IntegrityLevel", "Medium".to_owned()),
        ("Hashes", hashes(ctx)),
        ("ParentProcessGuid", guid(ctx)),
        ("ParentProcessId", pid(ctx)),
        ("ParentImage", parent.to_owned()),
        ("ParentCommandLine", parent.to_owned()),
        ("ParentUser", domain_user(user)),
    ];
    event(ctx, host, ts, 1, "Process Create", data)
}

fn network_connect(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (image, _, _) = *ctx.rng.pick(&PROCESSES);
    let (port, name) = *ctx.rng.pick(&[
        ("443", "https"),
        ("443", "https"),
        ("80", "http"),
        ("445", "microsoft-ds"),
    ]);
    let data = vec![
        ("ProcessGuid", guid(ctx)),
        ("ProcessId", pid(ctx)),
        ("Image", image.to_owned()),
        ("User", domain_user(ctx.rng.pick(&USERS))),
        ("Protocol", "tcp".to_owned()),
        ("Initiated", "true".to_owned()),
        ("SourceIsIpv6", "false".to_owned()),
        ("SourceIp", host.ip.to_owned()),
        ("SourceHostname", String::new()),
        ("SourcePort", ctx.rng.between(49_152, 65_535).to_string()),
        ("SourcePortName", String::new()),
        ("DestinationIsIpv6", "false".to_owned()),
        ("DestinationIp", (*ctx.rng.pick(&EXTERNAL_IPS)).to_owned()),
        ("DestinationHostname", String::new()),
        ("DestinationPort", port.to_owned()),
        ("DestinationPortName", name.to_owned()),
    ];
    event(ctx, host, ts, 3, "Network connection detected", data)
}

fn image_load(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (image, _, _) = *ctx.rng.pick(&PROCESSES);
    let loaded = *ctx.rng.pick(&DLLS);
    let data = vec![
        ("ProcessGuid", guid(ctx)),
        ("ProcessId", pid(ctx)),
        ("Image", image.to_owned()),
        ("ImageLoaded", loaded.to_owned()),
        (
            "FileVersion",
            "10.0.26100.1882 (WinBuild.160101.0800)".to_owned(),
        ),
        ("Description", "Windows NT BASE API Client DLL".to_owned()),
        ("Product", "Microsoft® Windows® Operating System".to_owned()),
        ("Company", "Microsoft Corporation".to_owned()),
        (
            "OriginalFileName",
            loaded.rsplit('\\').next().unwrap_or(loaded).to_owned(),
        ),
        ("Hashes", hashes(ctx)),
        ("Signed", "true".to_owned()),
        ("Signature", "Microsoft Windows".to_owned()),
        ("SignatureStatus", "Valid".to_owned()),
        ("User", domain_user(ctx.rng.pick(&USERS))),
    ];
    event(ctx, host, ts, 7, "Image loaded", data)
}

fn process_access(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (source, target, granted) = *ctx.rng.pick(&ACCESS_PAIRS);
    access(ctx, host, ts, source, target, granted)
}

fn access(
    ctx: &mut Ctx,
    host: &WindowsHost,
    ts: i64,
    source: &str,
    target: &str,
    granted: &str,
) -> Fields {
    let data = vec![
        ("SourceProcessGUID", guid(ctx)),
        ("SourceProcessId", pid(ctx)),
        ("SourceThreadId", pid(ctx)),
        ("SourceImage", source.to_owned()),
        ("TargetProcessGUID", guid(ctx)),
        ("TargetProcessId", pid(ctx)),
        ("TargetImage", target.to_owned()),
        ("GrantedAccess", granted.to_owned()),
        (
            "CallTrace",
            r"C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|UNKNOWN(00000000)".to_owned(),
        ),
        ("SourceUser", r"NT AUTHORITY\SYSTEM".to_owned()),
        ("TargetUser", r"NT AUTHORITY\SYSTEM".to_owned()),
    ];
    event(ctx, host, ts, 10, "Process accessed", data)
}

fn file_create(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (image, _, _) = *ctx.rng.pick(&PROCESSES);
    let name = format!(
        r"C:\Users\{}\AppData\Local\Temp\{}.tmp",
        ctx.rng.pick(&USERS),
        ctx.rng.hex(8)
    );
    file(ctx, host, ts, image, &name)
}

fn file(ctx: &mut Ctx, host: &WindowsHost, ts: i64, image: &str, target: &str) -> Fields {
    let created = datetime(ts).format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    let data = vec![
        ("ProcessGuid", guid(ctx)),
        ("ProcessId", pid(ctx)),
        ("Image", image.to_owned()),
        ("TargetFilename", target.to_owned()),
        ("CreationUtcTime", created),
        ("User", domain_user(ctx.rng.pick(&USERS))),
    ];
    event(ctx, host, ts, 11, "File created", data)
}

fn dns_query(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let (image, _, _) = *ctx.rng.pick(&PROCESSES);
    let domain = *ctx.rng.pick(&DOMAINS);
    let answer = *ctx.rng.pick(&EXTERNAL_IPS);
    let data = vec![
        ("ProcessGuid", guid(ctx)),
        ("ProcessId", pid(ctx)),
        ("QueryName", domain.to_owned()),
        ("QueryStatus", "0".to_owned()),
        ("QueryResults", format!("::ffff:{answer};")),
        ("Image", image.to_owned()),
        ("User", domain_user(ctx.rng.pick(&USERS))),
    ];
    event(ctx, host, ts, 22, "Dns query", data)
}
