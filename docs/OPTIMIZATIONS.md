# Optimizations & Debugging

Performance, resource-safety, and debuggability backlog. Several items overlap
with the security tracker (an unbounded resource is both a DoS surface and a
perf problem) — those cross-reference [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md).

## 1. Algorithmic / hot paths

### 1.1 AXFR name-walker is O(n^2) (`C-5`)
- Where: `extractDNSNames` in [internal/modules/dnsextra.go](../internal/modules/dnsextra.go).
- Symptom: on large/hostile zone-transfer data the name walk is quadratic;
  fuzzing showed slow-input windows (audit Part III).
- Fix: single-pass structural parse that tracks offsets instead of re-scanning;
  keep the existing compression-pointer cap (10 jumps) and size/count caps.
- Verify: add `BenchmarkExtractDNSNames` over small/medium/large synthetic zones
  and assert near-linear scaling; keep the fuzz target for safety.

### 1.2 DNS engine throughput
- Where: raw-UDP engine (`dnsengine.go`) used when `-resolvers` is set.
- Levers: resolver-pool rotation, in-flight window sizing, and `-rate` governing
  DNS. Add a benchmark for query/sec vs pool size; ensure `-rate 0` doesn't
  starve or flood.

## 2. Unbounded accumulation (memory) — `C-6` / `C-9`

- Discovered-host set from passive/CT/permute can grow without bound on hostile
  input, and each host may drive active probes (amplification).
- Crawler external-link and JS-file collections (`crawler.go`, `content.go`)
  accumulate over large pages.
- Fix: hard caps with clear "truncated" findings. Note the caps already exist as
  knobs — `WaybackLimit`, `CrawlMaxPages`, `MaxJSFiles` (`core.Config`) — so:
  (a) confirm every collector actually honors them, (b) add a host-set cap and
  a per-host active-probe cap, and (c) expose the knobs in the GUI (see
  [CLI_PARITY.md](CLI_PARITY.md)).
- Verify: memory profile a scan against a synthetic "huge hostile page" fixture.

## 3. webui resource & latency

### 3.1 File I/O under lock (`F-10`)
- Where: `appendLog` in [webui/jobs.go](../webui/jobs.go) writes to the `.log`
  file while holding `j.mu`.
- Fix: buffer/writer that flushes outside the critical section, or a dedicated
  writer goroutine; keep the in-memory ring buffer append under lock only.
- Verify: `-race` clean; measure log-append latency under a chatty scan.

### 3.2 Job-map growth / log cap (`F-9`)
- Where: `Manager.jobs` map ([webui/jobs.go](../webui/jobs.go)) never evicts;
  `logBuf` is ring-capped at `maxLogLines=5000` but the on-disk `.log` is
  unbounded.
- Fix: evict finished jobs after a TTL/count; cap or rotate the `.log`.

### 3.3 SSE backpressure
- Current design is already non-blocking: `appendLog` does a `select { case ch<-:
  default }` so a slow subscriber drops lines rather than stalling the worker;
  subscriber channels are buffered (256). The frontend caps the terminal DOM at
  ~6000 nodes.
- Improve: surface a "lines dropped" marker when a subscriber falls behind, and
  make the buffer size a named constant; benchmark a fast-producing scan with a
  throttled reader.

### 3.4 HTTP server timeouts (`F-4`, perf+DoS)
- Adding `ReadHeaderTimeout`/`ReadTimeout`/`IdleTimeout` (with the SSE route
  split out) also bounds resource use under slowloris-style clients.

## 4. HTTP client efficiency (engine)
- Where: the shared client/transport in [internal/core/core.go](../internal/core/core.go).
- Check: connection reuse/keep-alives, per-host connection caps, sane
  `MaxIdleConnsPerHost`, and that the rate limiter (`RateLimiter`) is the single
  choke point rather than per-module ad-hoc sleeps.
- Verify: benchmark a crawl against a local server; watch goroutine count and
  socket churn.

## 5. Concurrency correctness (keep it fast *and* safe)
- Fan-out is semaphore-bounded and shared writes are mutex-guarded; `go test
  -race ./...` is currently clean. Any optimization here must re-run `-race`.
- Watch the cancel/run race (`F-7`) when refactoring the worker.

## 6. Profiling & debugging toolkit

- `pprof`: add a **build-tag or env-gated**, loopback-only `net/http/pprof`
  endpoint to the webui for CPU/heap/goroutine profiles during a scan (never
  enabled in normal builds; document the flag). Alternatively profile the CLI
  directly with `-cpuprofile`/`-memprofile` added behind a debug flag.
- `go test -bench=. -benchmem` for the hot paths in §1 (DNS parse, report gen,
  `buildArgs`).
- `go test -race` for concurrency; `GODEBUG=gctrace=1` to watch GC under a large
  scan; `GODEBUG=inittrace=1` for startup.
- `dlv` (Delve) for stepping the worker/SSE lifecycle when chasing `F-7`/`F-10`.
- Verbose engine logging (`-v`) plus the webui live log to correlate module
  timing during an end-to-end run.

## 7. Suggested benchmark set (later phase)
- `BenchmarkExtractDNSNames` (small/medium/large, incl. compression pointers).
- `BenchmarkGenerateReport` (many findings).
- `BenchmarkBuildArgs` (full option set — also guards parity).
- A crawler throughput benchmark against a local fixture server.
- An SSE fan-out benchmark (fast producer, throttled consumer) to validate the
  drop-not-block behavior and any "lines dropped" marker.

## 8. Priorities
1. `F-10` (I/O under lock) and `F-4` (timeouts) — small, high value for the webui.
2. `C-5` (AXFR O(n^2)) — correctness-adjacent, fuzz-corroborated.
3. Accumulation caps `C-6`/`C-9` + honor existing knobs, then expose them (parity).
4. Client tuning + benchmarks as ongoing hygiene.
