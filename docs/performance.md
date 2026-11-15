# Performance

Measured with `python scripts/perf.py` on EgressVeil 0.7.0 (Windows 11, Python 3.12, loopback, mock upstream). The gateway and upstream run on the same machine, so the numbers show the overhead EgressVeil adds, not network latency. Re-run the script to measure your own machine.

## Added latency per request

| Request body | Direct p50 | Through gateway p50 | Added p50 | Gateway p95 |
| --- | --- | --- | --- | --- |
| 1 KB | 0.21 ms | 1.23 ms | **1.02 ms** | 1.96 ms |
| 100 KB | 0.39 ms | 8.82 ms | **8.43 ms** | 15.22 ms |
| 1 MB | 2.96 ms | 89.1 ms | **86.15 ms** | 112.77 ms |

- Streaming throughput: **581.0 MB/s** with response inspection off, **13.5 MB/s** with it on (134.2 MB stream).
- Peak Python memory while streaming 134.2 MB with inspection on: **0.9 MB** (bounded by the chunk size and scan window, not by the stream length).


Inspection time grows with request size (every string is scanned by every detector). LLM requests take seconds, and a typical coding-agent request is tens to a few hundred KB, so the added time is a few to tens of milliseconds.

## Memory

`tests/test_soak.py` runs on every CI build. It streams 24 MB through the gateway with response inspection on, checks that the bytes arrive unchanged, and fails if peak Python memory reaches 16 MB.
