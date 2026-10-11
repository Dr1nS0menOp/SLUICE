# Vector on Windows: the `windows_event_log` source

Verified 2026-10-11 with the official Vector 0.59.0 Windows build
(`vector-0.59.0-x86_64-pc-windows-msvc.zip`, SHA-256 `c1db44a0…dddb8` as published in
`vector-0.59.0-SHA256SUMS`) on Windows 11 Pro 10.0.26200. The binary is not Authenticode-signed,
yet Smart App Control let it run. The source is marked beta.

## Access

Without elevation the Security channel is skipped with a warning (`Skipping channel due to
access denied. channel=Security`); System, Application and
`Microsoft-Windows-PowerShell/Operational` are readable by a normal user. Collecting Security
events needs Vector to run as an administrator, as `LocalSystem` (a service), or as an account
in the Event Log Readers group with access to the Security log.

## Event shape

One JSON object per event. Fields seen on 116 events from System, Application and PowerShell
(`render_message: true`, defaults otherwise):

| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | RFC 3339 with 100 ns precision, UTC (`2026-10-11T05:49:33.501855300Z`) |
| `channel`, `computer`, `host`, `provider_name`, `provider_guid` | string | |
| `event_id`, `record_id`, `version`, `process_id`, `thread_id` | integer | |
| `level` | string | `Information`, `Warning`, … |
| `level_value` | integer | 4 = Information |
| `task`, `opcode` | integer | with `task_name`, `opcode_name` when the provider defines them |
| `keywords` | string | hex mask (`0x8000000000000604`); `keyword_names` (list) on some |
| `user_id`, `user_name` | string | SID and `DOMAIN\user` |
| `activity_id` | string | GUID |
| `qualifiers` | integer | classic providers only |
| `message` | string | the rendered message, `\r\n` line ends |
| `event_data` | object | named `<Data Name="…">` values, **all strings** (`"BootId": "151"`) |
| `string_inserts` | list | unnamed `<Data>` values of classic events, instead of `event_data` |
| `source_type` | string | always `windows_event_log` |

So the EventData names Sigma and Sentinel use (`TargetUserName`, `LogonType`, …) are one level
down, under `event_data`, and numbers inside it are strings.

## Shaped as `SecurityEvent` (`sluice agent windows`)

`sluice_vector::windows::security_event_program` maps this shape to Sentinel's `SecurityEvent`
columns (ADR 0014). Checked on this machine, same day: the generated agent configuration passes
`vector validate` with the Windows build, and run on the last two hours of System, Application
and PowerShell events it shaped 193 events with no error or warning; every output column was a
`SecurityEvent` column of the right type, and every `EventData` value parsed as XML. Data
columns such as `TargetUserName` only appear for Security channel events, which this run could
not read without elevation: the Security path is so far covered by the unit tests only.

The shaping runs centrally, in the `sluice up` source (`shape:`), after the archive keeps the
original; the agent only routes the Security channel and the others to two sources.

**Security channel, elevated run (2026-10-11):** run as administrator, the source read the
Security channel without warnings: 154 events of the last two hours (4624, 4672, 4798, 5379).
Shaped with the real Vector (Linux) using the program `sluice up` generates, all 154 were valid
`SecurityEvent` records: 44 distinct columns, data columns filled where the events carry them
(`TargetUserName` on 77, `LogonType`, `IpAddress` and `ProcessName` on the 43 logons), every
`EventData` value parsed as XML (5 to 28 items), and `Activity` in the agent's form
(`4624 - An account was successfully logged on.`).

`SecurityEvent` is the table for the **Security** channel. System, Application and other
channels go to `WindowsEvent` (`windows_event_program`): 267 real events from System,
Application and PowerShell shaped with every column valid, and an end-to-end run through
`sluice up` delivered 705 events to the `WindowsEvent` destination only (ADR 0014).
