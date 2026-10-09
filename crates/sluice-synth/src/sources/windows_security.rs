//! Windows Security event log, as shipped by Winlogbeat with event data flattened.

use crate::fields::Fields;
use crate::sources::{Ctx, Spec, json_format, logsource, winlog};
use crate::world::{DOMAIN, EXTERNAL_IPS, USERS, WINDOWS_HOSTS, WindowsHost};

pub(crate) const SPEC: Spec = Spec {
    id: "windows-security",
    generate,
    logsource: || logsource("windows", Some("security")),
    format: json_format,
};

pub(crate) const FAILED_LOGON_BURST: &str = "failed-logon-burst";

const SID_PREFIX: &str = "S-1-5-21-3623811015-3361044348-30300820";

/// The explanatory tail Windows appends to every rendered 4624 message.
const LOGON_EXPLANATION: &str = "This event is generated when a logon session is created. It is \
generated on the computer that was accessed.\n\nThe subject fields indicate the account on the \
local system which requested the logon. This is most commonly a service such as the Server \
service, or a local process such as Winlogon.exe or Services.exe.\n\nThe logon type field \
indicates the kind of logon that occurred. The most common types are 2 (interactive) and 3 \
(network).\n\nThe New Logon fields indicate the account for whom the new logon was created, i.e. \
the account that was logged on.\n\nThe network fields indicate where a remote logon request \
originated. Workstation name is not always available and may be left blank in some cases.\n\nThe \
impersonation level field indicates the extent to which a process in the logon session can \
impersonate.\n\nThe authentication information fields provide detailed information about this \
specific logon request.\n\t- Logon GUID is a unique identifier that can be used to correlate this \
event with a KDC event.\n\t- Transited services indicate which intermediate services have \
participated in this logon request.\n\t- Package name indicates which sub-protocol was used among \
the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will \
be 0 if no session key was requested.";

const FAILURE_EXPLANATION: &str = "This event is generated when a logon request fails. It is \
generated on the computer where access was attempted.\n\nThe Subject fields indicate the account \
on the local system which requested the logon. This is most commonly a service such as the Server \
service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field \
indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 \
(network).\n\nThe Process Information fields indicate which account and process on the system \
requested the logon.\n\nThe Network Information fields indicate where a remote logon request \
originated. Workstation name is not always available and may be left blank in some cases.\n\nThe \
authentication information fields provide detailed information about this specific logon \
request.\n\t- Transited services indicate which intermediate services have participated in this \
logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM \
protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if \
no session key was requested.";

fn generate(ctx: &mut Ctx) {
    for _ in 0..ctx.volume(6_000) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&WINDOWS_HOSTS);
        let user = *ctx.rng.pick(&USERS);
        let logon_type = *ctx.rng.pick(&[3, 3, 3, 3, 5, 5, 2, 10]);
        let fields = logon_success(ctx, &host, ts, user, logon_type);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(5_000) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&WINDOWS_HOSTS);
        let user = *ctx.rng.pick(&USERS);
        let fields = logoff(ctx, &host, ts, user);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(800) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&WINDOWS_HOSTS);
        let user = *ctx.rng.pick(&["svc_backup", "svc_sql", "administrator"]);
        let fields = special_privileges(ctx, &host, ts, user);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(12_000) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&WINDOWS_HOSTS);
        let fields = wfp_permitted(ctx, &host, ts);
        ctx.emit(ts, fields);
    }
    for _ in 0..ctx.volume(60) {
        let ts = ctx.any_time();
        let host = *ctx.rng.pick(&WINDOWS_HOSTS);
        let user = *ctx.rng.pick(&USERS);
        let source = *ctx.rng.pick(&WINDOWS_HOSTS);
        let fields = logon_failure(ctx, &host, ts, user, source);
        ctx.emit(ts, fields);
    }
    // Rare and benign: two accounts created by an admin. Exercises the rarity floor.
    for (percent, user) in [(20, "eve"), (70, "frank")] {
        let ts = ctx.at_percent(percent);
        let fields = account_created(ctx, &WINDOWS_HOSTS[0], ts, user);
        ctx.emit(ts, fields);
    }
    failed_logon_burst(ctx);
}

/// Scenario: one account fails 12 times from one workstation within a minute.
fn failed_logon_burst(ctx: &mut Ctx) {
    let start = ctx.at_percent(40);
    let dc = WINDOWS_HOSTS[0];
    let attacker = WINDOWS_HOSTS[3];
    for i in 0..12 {
        let ts = start + i * 4;
        let fields = logon_failure(ctx, &dc, ts, "svc_sql", attacker);
        ctx.emit_attack(FAILED_LOGON_BURST, ts, fields);
    }
}

fn sid(user: &str) -> String {
    let rid = 1100 + USERS.iter().position(|u| *u == user).unwrap_or(USERS.len());
    format!("{SID_PREFIX}-{rid}")
}

fn base(ctx: &mut Ctx, host: &WindowsHost, ts: i64, event_id: u32, task: &str) -> Fields {
    winlog::envelope(ctx, winlog::SECURITY, host, ts, event_id)
        .set("Task", task)
        .set("Keywords", "Audit Success")
        .set("Opcode", "Info")
        .set("ProcessID", 812)
}

fn logon_id(ctx: &mut Ctx) -> String {
    format!("0x{}", ctx.rng.hex(7))
}

fn logon_success(
    ctx: &mut Ctx,
    host: &WindowsHost,
    ts: i64,
    user: &str,
    logon_type: u32,
) -> Fields {
    let source = *ctx.rng.pick(&WINDOWS_HOSTS);
    let (ip, port, workstation) = if logon_type == 3 || logon_type == 10 {
        (
            source.ip,
            ctx.rng.between(49_152, 65_535).to_string(),
            source.name,
        )
    } else {
        ("-", "-".to_owned(), "-")
    };
    let id = logon_id(ctx);
    let (process, package) = if logon_type == 3 {
        ("NtLmSsp ", "NTLM")
    } else {
        ("Advapi  ", "Negotiate")
    };
    let message = format!(
        "An account was successfully logged on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount \
         Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Information:\n\tLogon \
         Type:\t\t{logon_type}\n\tRestricted Admin Mode:\t-\n\tVirtual Account:\t\tNo\n\tElevated \
         Token:\t\tYes\n\nImpersonation Level:\t\tImpersonation\n\nNew Logon:\n\tSecurity \
         ID:\t\t{sid}\n\tAccount Name:\t\t{user}\n\tAccount Domain:\t\t{DOMAIN}\n\tLogon \
         ID:\t\t{id}\n\tLinked Logon ID:\t\t0x0\n\tNetwork Account Name:\t-\n\tNetwork Account \
         Domain:\t-\n\tLogon GUID:\t\t{{00000000-0000-0000-0000-000000000000}}\n\nProcess \
         Information:\n\tProcess ID:\t\t0x0\n\tProcess Name:\t\t-\n\nNetwork \
         Information:\n\tWorkstation Name:\t{workstation}\n\tSource Network Address:\t{ip}\n\tSource \
         Port:\t\t{port}\n\nDetailed Authentication Information:\n\tLogon Process:\t\t{process}\n\t\
         Authentication Package:\t{package}\n\tTransited Services:\t-\n\tPackage Name (NTLM \
         only):\t-\n\tKey Length:\t\t0\n\n{LOGON_EXPLANATION}",
        sid = sid(user),
    );
    base(ctx, host, ts, 4624, "Logon")
        .set("SubjectUserSid", "S-1-0-0")
        .set("SubjectUserName", "-")
        .set("SubjectDomainName", "-")
        .set("SubjectLogonId", "0x0")
        .set("TargetUserSid", sid(user))
        .set("TargetUserName", user)
        .set("TargetDomainName", DOMAIN)
        .set("TargetLogonId", id)
        .set("LogonType", logon_type)
        .set("LogonProcessName", process)
        .set("AuthenticationPackageName", package)
        .set("WorkstationName", workstation)
        .set("LogonGuid", "{00000000-0000-0000-0000-000000000000}")
        .set("TransmittedServices", "-")
        .set("LmPackageName", "-")
        .set("KeyLength", 0)
        .set("ProcessId", "0x0")
        .set("ProcessName", "-")
        .set("IpAddress", ip)
        .set("IpPort", port)
        .set("ImpersonationLevel", "%%1833")
        .set("RestrictedAdminMode", "-")
        .set("TargetOutboundUserName", "-")
        .set("TargetOutboundDomainName", "-")
        .set("VirtualAccount", "%%1843")
        .set("TargetLinkedLogonId", "0x0")
        .set("ElevatedToken", "%%1842")
        .set("RemoteCredentialGuard", serde_json::Value::Null)
        .set("Message", message)
}

fn logon_failure(
    ctx: &mut Ctx,
    host: &WindowsHost,
    ts: i64,
    user: &str,
    source: WindowsHost,
) -> Fields {
    let port = ctx.rng.between(49_152, 65_535).to_string();
    let message = format!(
        "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount \
         Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount \
         For Which Logon Failed:\n\tSecurity ID:\t\tS-1-0-0\n\tAccount Name:\t\t{user}\n\tAccount \
         Domain:\t\t{DOMAIN}\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad \
         password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC000006A\n\nProcess \
         Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork \
         Information:\n\tWorkstation Name:\t{ws}\n\tSource Network Address:\t{ip}\n\tSource \
         Port:\t\t{port}\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \
         \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM \
         only):\t-\n\tKey Length:\t\t0\n\n{FAILURE_EXPLANATION}",
        ws = source.name,
        ip = source.ip,
    );
    base(ctx, host, ts, 4625, "Logon")
        .set("Keywords", "Audit Failure")
        .set("SubjectUserSid", "S-1-0-0")
        .set("SubjectUserName", "-")
        .set("SubjectDomainName", "-")
        .set("SubjectLogonId", "0x0")
        .set("TargetUserSid", "S-1-0-0")
        .set("TargetUserName", user)
        .set("TargetDomainName", DOMAIN)
        .set("Status", "0xc000006d")
        .set("FailureReason", "%%2313")
        .set("SubStatus", "0xc000006a")
        .set("LogonType", 3)
        .set("LogonProcessName", "NtLmSsp ")
        .set("AuthenticationPackageName", "NTLM")
        .set("WorkstationName", source.name)
        .set("TransmittedServices", "-")
        .set("LmPackageName", "-")
        .set("KeyLength", 0)
        .set("ProcessId", "0x0")
        .set("ProcessName", "-")
        .set("IpAddress", source.ip)
        .set("IpPort", port)
        .set("Message", message)
}

fn logoff(ctx: &mut Ctx, host: &WindowsHost, ts: i64, user: &str) -> Fields {
    let id = logon_id(ctx);
    let message = format!(
        "An account was logged off.\n\nSubject:\n\tSecurity ID:\t\t{sid}\n\tAccount \
         Name:\t\t{user}\n\tAccount Domain:\t\t{DOMAIN}\n\tLogon ID:\t\t{id}\n\nLogon \
         Type:\t\t\t3\n\nThis event is generated when a logon session is destroyed. It may be \
         positively correlated with a logon event using the Logon ID value. Logon IDs are only \
         unique between reboots on the same computer.",
        sid = sid(user),
    );
    base(ctx, host, ts, 4634, "Logoff")
        .set("TargetUserSid", sid(user))
        .set("TargetUserName", user)
        .set("TargetDomainName", DOMAIN)
        .set("TargetLogonId", id)
        .set("LogonType", 3)
        .set("Message", message)
}

fn special_privileges(ctx: &mut Ctx, host: &WindowsHost, ts: i64, user: &str) -> Fields {
    let id = logon_id(ctx);
    let privileges = "SeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeDebugPrivilege\n\t\t\t\
                      SeImpersonatePrivilege";
    let message = format!(
        "Special privileges assigned to new logon.\n\nSubject:\n\tSecurity ID:\t\t{sid}\n\t\
         Account Name:\t\t{user}\n\tAccount Domain:\t\t{DOMAIN}\n\tLogon ID:\t\t{id}\n\n\
         Privileges:\t\t{privileges}",
        sid = sid(user),
    );
    base(ctx, host, ts, 4672, "Special Logon")
        .set("SubjectUserSid", sid(user))
        .set("SubjectUserName", user)
        .set("SubjectDomainName", DOMAIN)
        .set("SubjectLogonId", id)
        .set("PrivilegeList", privileges)
        .set("Message", message)
}

fn wfp_permitted(ctx: &mut Ctx, host: &WindowsHost, ts: i64) -> Fields {
    let application = *ctx.rng.pick(&[
        r"\device\harddiskvolume3\windows\system32\svchost.exe",
        r"\device\harddiskvolume3\program files\google\chrome\application\chrome.exe",
        r"\device\harddiskvolume3\windows\system32\lsass.exe",
        r"\device\harddiskvolume3\program files\microsoft office\root\office16\outlook.exe",
    ]);
    let destination = *ctx.rng.pick(&EXTERNAL_IPS);
    let (port, protocol) = *ctx
        .rng
        .pick(&[(443, 6), (443, 6), (53, 17), (80, 6), (445, 6)]);
    let source_port = ctx.rng.between(49_152, 65_535);
    let message = format!(
        "The Windows Filtering Platform has permitted a connection.\n\nApplication \
         Information:\n\tProcess ID:\t\t{pid}\n\tApplication Name:\t{application}\n\nNetwork \
         Information:\n\tDirection:\t\tOutbound\n\tSource Address:\t\t{src}\n\tSource \
         Port:\t\t{source_port}\n\tDestination Address:\t{destination}\n\tDestination \
         Port:\t\t{port}\n\tProtocol:\t\t{protocol}\n\nFilter Information:\n\tFilter Run-Time \
         ID:\t{filter}\n\tLayer Name:\t\tConnect\n\tLayer Run-Time ID:\t48",
        pid = ctx.rng.between(400, 12_000),
        src = host.ip,
        filter = ctx.rng.between(60_000, 70_000),
    );
    base(ctx, host, ts, 5156, "Filtering Platform Connection")
        .set("Application", application)
        .set("Direction", "%%14593")
        .set("SourceAddress", host.ip)
        .set("SourcePort", source_port.to_string())
        .set("DestAddress", destination)
        .set("DestPort", port.to_string())
        .set("Protocol", protocol)
        .set("FilterRTID", ctx.rng.between(60_000, 70_000))
        .set("LayerName", "%%14611")
        .set("LayerRTID", 48)
        .set("RemoteUserID", "S-1-0-0")
        .set("RemoteMachineID", "S-1-0-0")
        .set("Message", message)
}

fn account_created(ctx: &mut Ctx, host: &WindowsHost, ts: i64, user: &str) -> Fields {
    let message = format!(
        "A user account was created.\n\nSubject:\n\tAccount Name:\t\tadministrator\n\tAccount \
         Domain:\t\t{DOMAIN}\n\nNew Account:\n\tAccount Name:\t\t{user}\n\tAccount \
         Domain:\t\t{DOMAIN}"
    );
    base(ctx, host, ts, 4720, "User Account Management")
        .set("SubjectUserName", "administrator")
        .set("SubjectDomainName", DOMAIN)
        .set("TargetUserName", user)
        .set("TargetDomainName", DOMAIN)
        .set("SamAccountName", user)
        .set("DisplayName", "")
        .set("UserPrincipalName", "")
        .set("HomeDirectory", "")
        .set("Message", message)
}
