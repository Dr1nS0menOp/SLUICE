# Credits

Sluice builds on work other people did first. This page names them and says what Sluice took.
Where a recipe or a decision rests on one of these sources, it links here or to the source.

## Research and guidance

| Source | By | What Sluice uses |
|---|---|---|
| NIST SP 800-92, *Guide to Computer Security Log Management* (2006) | Karen Kent, Murugiah Souppaya | The term *event reduction*, and pairing reduction with an archive (safety contract rule 2). |
| Windows security auditing reference (events 4624, 4688 and others) | Microsoft | What each field of an event holds, and which values are placeholders implied by other fields ([field value study](notes/field-value.md)). |
| Windows security event sets for Microsoft Sentinel; Appendix L, *Events to Monitor* | Microsoft | Which kinds of Windows event matter for breach detection. |
| *Detecting Lateral Movement through Tracking Event Logs* (2017) | JPCERT/CC | Which events attacker tools leave behind. |
| Event Forwarding Guidance | NSA | The same, as forwarding guidance. |
| Windows Event Forwarding for Network Defense | Palantir | The same, as open-source subscriptions. |
| Windows Logging Cheat Sheets | Michael Gough (Malware Archaeology) | The same, as audit settings. |
| Cribl Stream guidance on Windows XML events; the cribl-windows-events pack | Cribl; David Maislin | How much of a Windows event is placeholders and rendered text, and why a blanket rule is unsafe. |
| *Top 4 tricks to reduce SIEM data volume* (2025) | Balázs Scheidler (Axoflow) | The rendered text repeats the event. |
| Security-Datasets (formerly Mordor), `compound/apt29` day 1, MIT | Open Threat Research Forge (Roberto Rodriguez, Jose Rodriguez) | A sample from four machines, to measure implied values beyond one PC (`docs/notes/field-value.md`), and the data of the [example report](example-report.html). The dataset is kept in a user cache, not in the repository; the report quotes excerpts of it (see below). |
| Pre-SIEM log filtering and log reduction | NXLog | Drop only what no detection, investigation or compliance need depends on. |
| SigmaHQ, *Pass the Hash Activity 2* | Dave Kennedy, Jeff Warren, David Vassallo | The counterexample that a placeholder can be a detection signal. |
| Sysmon documentation | Mark Russinovich, Thomas Garnier | `ProcessGuid` as the correlation key. |
| systemd.journal-fields | systemd project | Which journal fields are fixed per host or boot. |
| *Understanding Audit Log Files* | Red Hat | The audit record fields. |
| LAUREL | Hilko Bengen, Sergej Schmidt | Shaping auditd records into one event. |
| Neo23x0/auditd | Florian Roth and contributors | Filtering auditd noise at the source. |
| Drain, ICWS 2017 | Pinjia He, Jieming Zhu, Zibin Zheng, Michael R. Lyu | Sluice's template discovery for text logs ([notes](notes/drain.md)). |
| Logzip, ASE 2019 | Jinyang Liu, Jieming Zhu, Shilin He, Pinjia He, Zibin Zheng, Michael R. Lyu | A template's text is a constant of the template. |
| CLP, OSDI 2021 | Kirk Rodrigues, Yu Luo, Ding Yuan | Template plus variables, for archives. |

Links to each source are in the [field value study](notes/field-value.md).

## Data in the example report

[The example report](example-report.html) quotes events from Security-Datasets
(`compound/apt29/day1/apt29_evals_day1_manual.zip`), which `scripts/example-report.sh`
downloads and checks by its SHA-256. Those excerpts are under the dataset's license:

```text
MIT License

Copyright (c) 2021 Open Threat Research Forge

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

The eight rules in `examples/apt29/rules/` are Sluice's own, written for this example after
the techniques the dataset's emulation plan names; they are not SigmaHQ rules.

## Software

The engines Sluice runs or generates code for, and the libraries it is built on, are listed with
their licenses in [architecture](architecture.md#technologies) and checked by `cargo deny`.
