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

For scale: the demo's hour of traffic for a small company network (80,536 events at scale 100)
is about 22 events per second, so one Vector process has three orders of magnitude of headroom
for a network of that kind.
