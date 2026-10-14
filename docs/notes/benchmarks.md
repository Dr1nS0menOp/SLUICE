# Benchmarks

Measured with `scripts/bench.sh`: one demo source's events from stdin through the transforms
Sluice generates (parse, classify, reduce, route, summarize) into a blackhole sink, with the real
Vector. Times include Vector's start-up, so short runs understate throughput. The script fails if
Vector logs an error, so every number is the normal path.

## 2026-10-10, Vector 0.59.0, Sluice 0.1.0

Machine: Intel Core i9-11900 (16 threads), WSL2 on Windows 11, demo scale 300.

| Source | Events | Size | Time | Events/s | MB/s |
|--------|-------:|-----:|-----:|---------:|-----:|
| windows-security | 71,594 | 148.8 MB | 1.22 s | 58,635 | 121.8 |
| sysmon | 85,505 | 166.0 MB | 1.65 s | 51,846 | 100.7 |
| linux-auth (text, Drain classifier) | 12,301 | 7.0 MB | 0.23 s | 54,395 | 31.0 |

### Scaling with Vector worker threads

`THREADS=n scripts/bench.sh windows-security 600` (143,174 events, 297.5 MB):

| Threads | Time | Events/s | Events/s per thread |
|--------:|-----:|---------:|--------------------:|
| 1 | 8.73 s | 16,409 | 16,409 |
| 2 | 4.96 s | 28,851 | 14,426 |
| 4 | 2.90 s | 49,294 | 12,324 |
| 8 | 1.97 s | 72,768 | 9,096 |

Roughly 16,000 events per second per vCPU for this source, scaling close to linearly up to four
threads.

## Load test of a generated configuration, 2026-10-14

`scripts/load-test.sh` (ADR 0022) on the demo's own `vector.yaml` at scale 300: every source
through its transforms in that file, Vector 0.59.0, same machine, all threads.

| Source | Events | MB | Time | Events/s | MB/s |
|--------|-------:|---:|-----:|---------:|-----:|
| dns | 18,001 | 7.9 | 0.27 s | 66,916 | 29.3 |
| firewall | 30,031 | 21.0 | 0.32 s | 92,967 | 65.0 |
| linux-auth | 12,301 | 7.0 | 0.27 s | 46,199 | 26.4 |
| nginx | 24,004 | 12.4 | 0.30 s | 79,098 | 40.9 |
| sysmon | 85,505 | 166.0 | 1.15 s | 74,157 | 144.0 |
| windows-security | 71,594 | 148.8 | 0.84 s | 85,423 | 177.5 |

The same configuration saves 73.8 % of 362.8 MB with 43 = 43 alerts (`sluice prove`).

## Soak run, 2026-10-10/11: 19 hours live

`sluice up --config examples/up/sluice-dual.yaml --demo-traffic` (six demo sources, two rule
profiles, 30-second cycles, demo promotion settings: 60 s shadow, 2 proofs), WSL2, Vector 0.59.0:

- 2,086 cycles per profile, every one proven (last: 12,574 = 12,574 alerts), no failed cycle.
- The `sigma` destination received 2.3 GB, the `wazuh` destination 7.4 GB (unchanged): 69% less
  over the run; the last window, 135.4 → 49.1 MB.
- Recipes flapped on three `sudo` templates holding 105–109 events in the window, right at the
  rarity floor of 100: 44 "rollbacks" and 34 demotions, every one caused by contract rule 4, not
  by a failed proof. Fixed since: such a stop is now `paused`, logged at info, and a new recipe
  needs 125% of the floor (`ENTRY_MARGIN_PERCENT`) to enter shadow.
- Memory: the control plane held 3.1 GB resident (6 sources × 20,000 events in the window, two
  profiles), flat over the last five minutes sampled (+2 MB); Vector 208 MB. Size the window
  (`window.max_events_per_source`) to the memory available; profiling the analysis' peak
  allocation is open.
- Disk: 632 MB of gzip archive for 19 hours of demo traffic.

**Memory, after two fixes (2026-10-11).** A cycle used to copy the whole window, and the proof
copied every forwarded event even when the data plane left it unchanged. Now a cycle takes the
events out of the window and gives them back (events tapped meanwhile stay newest), and the
proof borrows unchanged events. Same run, 32 minutes: 1,196 MB resident at 94,587 events in
the window, 12.6 KB per event, growing linearly; about 1.5 GB for a full window of 120,000,
half of the 3.1 GB before. `sluice demo` alone (no window): 1,372 → 1,291 MB at 120,761 events.
What remains is mostly the event itself as a `serde_json` map (each key and value its own
allocation) plus the analysis and proof of each profile.

For scale: the demo's hour of traffic for a small company network (80,536 events at scale 100)
is about 22 events per second, so one Vector process has three orders of magnitude of headroom
for a network of that kind.
