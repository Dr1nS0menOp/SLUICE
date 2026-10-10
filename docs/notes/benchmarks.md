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

For scale: the demo's hour of traffic for a small company network (80,536 events at scale 100)
is about 22 events per second, so one Vector process has three orders of magnitude of headroom
for a network of that kind.
