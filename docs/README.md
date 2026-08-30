# w1r3hound — QA, Security & Parity Documentation

This folder is the working documentation set for the next phase of w1r3hound
(the reskinned dashboard build). It captures the **current state**, the
**work to do**, and **how to verify it** — so the actual implementation and
testing phases are turnkey.

> Status of this set: **implemented.** The work described in these documents has
> been completed. Tests and CI are in place.

## Documents

| Doc | Purpose |
|-----|---------|
| [PROJECT_STATE.md](PROJECT_STATE.md) | Snapshot of what is built: architecture, modules, build health, and current automated-test coverage (with the gaps). |
| [CLI_PARITY.md](CLI_PARITY.md) | The capability gap: CLI flags the web GUI does not expose yet, and a security-aware design to close it. |
| [TEST_PLAN.md](TEST_PLAN.md) | The QA + automated-test plan: CLI matrix, webui backend tests, frontend QA matrix, end-to-end scenarios, CI. |
| [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md) | Security posture, the open-items tracker (from the prior audit + reskin/parity), and a re-verification checklist. |
| [FALSE_POSITIVES_NEGATIVES.md](FALSE_POSITIVES_NEGATIVES.md) | Detection-accuracy methodology: curated corpus, per-module expected findings, and regression snapshots. |
| [OPTIMIZATIONS.md](OPTIMIZATIONS.md) | Performance and debugging targets, plus a profiling approach. |

## The one-line takeaway

The engine (CLI) is feature-complete and well tested; the **web GUI currently
exposes fewer capabilities than the CLI** and has **no automated tests**.
Closing the parity gap and adding webui/frontend tests are the top priorities.

## Prioritized roadmap

Priority legend: **P0** = do first (correctness/parity/high-risk security),
**P1** = important, **P2** = valuable, **P3** = polish.

### P0 — Parity & high/medium-severity security
- Close the CLI-to-GUI capability gap so the app has the same power as the CLI
  (see [CLI_PARITY.md](CLI_PARITY.md)): `-dir-wordlist`, `-dir-ext`,
  `-header/-H`, `-skip-tls-verify`, `-block-private-egress`, `-resolver`,
  `-resolvers`, `-wayback-limit`, `-crawl-pages`, `-js-files`.
- Add `http.Server` timeouts to the webui (open audit item `F-4`).
- Decide TLS-verification default for the GUI (`C-3`/`F-15`): the CLI defaults
  to skip-verify; the GUI should be able to turn it back on.

### P1 — Test coverage where there is none
- webui backend tests (`buildArgs` validation table, `originGuard`/CSP/token,
  `confinedResultFile`, jobs queue/cancel/SSE) — see [TEST_PLAN.md](TEST_PLAN.md).
- Frontend QA matrix and a minimal headless smoke test (SSE stream, findings
  mapping, CSP-clean load, triage persistence, CSV export).
- Wire CI: `go vet`, `go test -race ./...`, `gofmt -l`, `govulncheck`, `gosec`.

### P2 — Optimizations & debugging
- AXFR name-walker O(n^2) (`C-5`), unbounded accumulation caps (`C-6/C-9`),
  file I/O under locks (`F-10`), job-map growth / log eviction (`F-9`),
  SSE backpressure. See [OPTIMIZATIONS.md](OPTIMIZATIONS.md).

### P3 — Accuracy tuning & hygiene
- False-positive / false-negative review per module against a curated corpus
  ([FALSE_POSITIVES_NEGATIVES.md](FALSE_POSITIVES_NEGATIVES.md)).
- CSP tightening (`base-uri`, `object-src`, remove style `unsafe-inline`),
  info-disclosure polish (`F-6`), directory perms `0700` (`F-8`), toolchain
  bump (`C-11`).

## How to use this set

1. Start with [PROJECT_STATE.md](PROJECT_STATE.md) for the lay of the land.
2. Implement P0 parity from [CLI_PARITY.md](CLI_PARITY.md).
3. Build out tests from [TEST_PLAN.md](TEST_PLAN.md) and track security items in
   [SECURITY_ASSESSMENT.md](SECURITY_ASSESSMENT.md).
4. Use [FALSE_POSITIVES_NEGATIVES.md](FALSE_POSITIVES_NEGATIVES.md) and
   [OPTIMIZATIONS.md](OPTIMIZATIONS.md) as the accuracy/perf backlog.

All file/line references are to the canonical project at `~/Desktop/w1r3hound/`.
