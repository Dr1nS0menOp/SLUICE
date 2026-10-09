//! The fictional environment every source draws from: one small company network.
//!
//! Sources share these fixtures, so a user who logs on in Windows Security also shows up in
//! Sysmon, and an IP that brute-forces SSH also appears in the firewall log. That coherence is
//! what makes the demo believable and lets rules correlate across sources.

/// A Windows machine with a Beats agent.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowsHost {
    pub(crate) name: &'static str,
    pub(crate) ip: &'static str,
    pub(crate) agent_id: &'static str,
    pub(crate) os_name: &'static str,
    pub(crate) os_build: &'static str,
}

pub(crate) const DOMAIN: &str = "CORP";
pub(crate) const DNS_SUFFIX: &str = "corp.example";

pub(crate) const WINDOWS_HOSTS: [WindowsHost; 5] = [
    WindowsHost {
        name: "DC01",
        ip: "10.10.0.10",
        agent_id: "6f1c2a9e-0d41-4a8e-9a51-1b0c7d2e3f01",
        os_name: "Windows Server 2022 Datacenter",
        os_build: "20348.2700",
    },
    WindowsHost {
        name: "FS01",
        ip: "10.10.0.20",
        agent_id: "0b7e4f3a-5c2d-4e19-8f60-2a1d9c8b7e02",
        os_name: "Windows Server 2022 Standard",
        os_build: "20348.2700",
    },
    WindowsHost {
        name: "WS-ALICE",
        ip: "10.10.1.21",
        agent_id: "9a3d5e7f-1b2c-4d6e-8f90-3c4b5a6d7e03",
        os_name: "Windows 11 Enterprise",
        os_build: "26100.2033",
    },
    WindowsHost {
        name: "WS-BOB",
        ip: "10.10.1.22",
        agent_id: "2c4e6a8b-0d1f-4a3c-9e5b-4d6f8a0c2e04",
        os_name: "Windows 11 Enterprise",
        os_build: "26100.2033",
    },
    WindowsHost {
        name: "WS-CAROL",
        ip: "10.10.1.23",
        agent_id: "7e9a1c3d-5f2b-4e8d-a6c0-5e7a9c1e3f05",
        os_name: "Windows 11 Enterprise",
        os_build: "26100.2033",
    },
];

/// Linux servers sending auth logs and running nginx.
pub(crate) const LINUX_HOSTS: [&str; 3] = ["web01", "web02", "bastion01"];

pub(crate) const USERS: [&str; 6] = ["alice", "bob", "carol", "dave", "svc_backup", "svc_sql"];

pub(crate) const LINUX_USERS: [&str; 3] = ["deploy", "alice", "ansible"];

/// Internal clients, for firewall and DNS traffic.
pub(crate) const INTERNAL_IPS: [&str; 6] = [
    "10.10.1.21",
    "10.10.1.22",
    "10.10.1.23",
    "10.10.0.10",
    "10.10.0.20",
    "10.10.2.15",
];

/// Benign external destinations.
pub(crate) const EXTERNAL_IPS: [&str; 6] = [
    "142.250.74.110",
    "13.107.42.14",
    "151.101.1.69",
    "104.16.132.229",
    "52.97.146.162",
    "185.199.108.153",
];

pub(crate) const DOMAINS: [&str; 10] = [
    "www.google.com",
    "outlook.office365.com",
    "login.microsoftonline.com",
    "github.com",
    "api.github.com",
    "update.microsoft.com",
    "ctldl.windowsupdate.com",
    "dc01.corp.example",
    "fs01.corp.example",
    "teams.microsoft.com",
];

/// Benign processes with plausible parents and command lines.
pub(crate) const PROCESSES: [(&str, &str, &str); 8] = [
    (
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\services.exe",
        r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule",
    ),
    (
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Windows\explorer.exe",
        r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer"#,
    ),
    (
        r"C:\Windows\System32\conhost.exe",
        r"C:\Windows\System32\cmd.exe",
        r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
    ),
    (
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r"C:\Windows\explorer.exe",
        r#""C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE""#,
    ),
    (
        r"C:\Windows\System32\taskhostw.exe",
        r"C:\Windows\System32\svchost.exe",
        r"taskhostw.exe -RegisterDevice -ProtectionStateChanged",
    ),
    (
        r"C:\Windows\System32\backgroundTaskHost.exe",
        r"C:\Windows\System32\svchost.exe",
        r#""C:\Windows\system32\backgroundTaskHost.exe" -ServerName:App.AppXmtcan0h2tfbfy7k9kn8hbxb6dmzz1zh0.mca"#,
    ),
    (
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\explorer.exe",
        r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File C:\Scripts\inventory.ps1"#,
    ),
    (
        r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
        r"C:\Windows\explorer.exe",
        r#""C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background"#,
    ),
];

/// DLLs loaded by everything, all the time: the bulk of Sysmon event 7.
pub(crate) const DLLS: [&str; 8] = [
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\KernelBase.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\advapi32.dll",
    r"C:\Windows\System32\combase.dll",
    r"C:\Windows\System32\bcrypt.dll",
    r"C:\Windows\System32\msvcrt.dll",
];

/// URL paths of the internal web application.
pub(crate) const WEB_PATHS: [&str; 6] = [
    "/",
    "/login",
    "/api/v1/orders",
    "/api/v1/orders/1042",
    "/static/app.js",
    "/static/style.css",
];

pub(crate) const USER_AGENTS: [&str; 3] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "curl/8.5.0",
];

/// Attacker infrastructure (documentation ranges, RFC 5737).
pub(crate) const ATTACKER_IP: &str = "198.51.100.23";
pub(crate) const SCANNER_IP: &str = "203.0.113.77";
pub(crate) const BAD_DOMAIN: &str = "cdn-update.badcdn.example";
