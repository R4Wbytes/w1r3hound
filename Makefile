# w1r3hound — build, test and QA targets.
# Zero runtime deps; the optional tools (govulncheck, gosec) degrade to a
# skip when not installed. See docs/TEST_PLAN.md for the full plan.

GO      ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)
CLI_BIN := w1r3hound
GUI_BIN := webui/w1r3hound-webui

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "w1r3hound make targets:"
	@echo "  build       build the CLI and the webui binaries"
	@echo "  vet         go vet ./..."
	@echo "  fmt-check   fail if any file is not gofmt-clean"
	@echo "  fmt         gofmt -w the tree"
	@echo "  test        go test ./..."
	@echo "  test-race   go test -race ./..."
	@echo "  csp         CSP-hygiene check for webui/static"
	@echo "  golden      FP/FN golden-snapshot check (golden-update to refresh)"
	@echo "  fuzz        re-run the fuzz seed corpora"
	@echo "  bench       micro-benchmarks for the hot paths (OPTIMIZATIONS.md)"
	@echo "  vuln        govulncheck ./...   (informational; skipped if absent)"
	@echo "  sec         gosec ./...         (informational; skipped if absent)"
	@echo "  smoke       build + contained loopback portscan of 127.0.0.1"
	@echo "  e2e-juiceshop  Docker Juice Shop end-to-end (TEST_PLAN.md 4.2)"
	@echo "  e2e-ui      dev-only Playwright headless smoke of the web console"
	@echo "  ci          vet + fmt-check + test-race + csp (the gate)"
	@echo "  clean       remove built binaries"

.PHONY: build
build:
	$(GO) build -ldflags='$(LDFLAGS)' -o $(CLI_BIN) .
	$(GO) build -o $(GUI_BIN) ./webui

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "gofmt required on:"; echo "$$out"; exit 1; \
	else \
		echo "gofmt: clean"; \
	fi

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: test
test:
	$(GO) test ./...

.PHONY: test-race
test-race:
	$(GO) test -race ./...

.PHONY: csp
csp:
	$(GO) test -run TestStaticAssetsAreCSPClean ./webui/

.PHONY: vuln
vuln:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed; skipping (go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

.PHONY: sec
sec:
	@if command -v gosec >/dev/null 2>&1; then \
		gosec -quiet ./...; \
	else \
		echo "gosec not installed; skipping (go install github.com/securego/gosec/v2/cmd/gosec@latest)"; \
	fi

# Contained end-to-end smoke: a loopback portscan must produce a JSON report.
# Purely local (127.0.0.1); no traffic leaves the host.
.PHONY: smoke
smoke: build
	@tmp=$$(mktemp -d); \
	echo "[smoke] loopback portscan of 127.0.0.1 -> $$tmp/smoke.json"; \
	./$(CLI_BIN) -t 127.0.0.1 -m portscan -p top100 -o $$tmp/smoke >/dev/null 2>&1; \
	rc=$$?; \
	if [ $$rc -ne 0 ]; then echo "[smoke] CLI exit $$rc"; rm -rf $$tmp; exit 1; fi; \
	if [ -f $$tmp/smoke.json ] && [ -f $$tmp/smoke.md ]; then \
		echo "[smoke] OK: JSON + Markdown report written"; rm -rf $$tmp; \
	else \
		echo "[smoke] FAILED: report not produced"; rm -rf $$tmp; exit 1; \
	fi

# FP/FN golden snapshots (hermetic; also run by `test`/`test-race`).
.PHONY: golden
golden:
	$(GO) test ./internal/modules/ -run TestGoldenFindings

.PHONY: golden-update
golden-update:
	$(GO) test ./internal/modules/ -run TestGoldenFindings -update-golden

# Re-run the fuzz seed corpora (parser hardening; SECURITY_ASSESSMENT §5).
.PHONY: fuzz
fuzz:
	$(GO) test -run=Fuzz ./internal/core/ ./internal/modules/

# Micro-benchmarks for the hot paths (OPTIMIZATIONS.md §7): the AXFR
# name-walker, the report builder, and the GUI buildArgs/parity path.
.PHONY: bench
bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/modules/ ./internal/report/ ./webui/

# OWASP Juice Shop end-to-end (TEST_PLAN.md §4.2). Needs Docker; pulls the image
# once, runs the tagged test, and always tears down. Uses --network host so the
# app is reachable on 127.0.0.1:3000 even where Docker's bridge port-publishing
# (-p) is broken by the host iptables/nftables setup; the container is short-
# lived and always stopped afterward.
.PHONY: e2e-juiceshop
e2e-juiceshop: build
	@echo "[e2e] starting OWASP Juice Shop on 127.0.0.1:3000..."
	@docker rm -f w1r3-juice >/dev/null 2>&1 || true
	@docker run --rm -d --name w1r3-juice --network host bkimminich/juice-shop >/dev/null
	@echo "[e2e] waiting for readiness (up to ~3m)..."
	@ok=0; for i in $$(seq 1 90); do if curl -sf -o /dev/null http://127.0.0.1:3000/; then ok=1; break; fi; sleep 2; done; \
	 if [ $$ok -ne 1 ]; then echo "[e2e] Juice Shop did not become ready"; docker stop w1r3-juice >/dev/null 2>&1 || true; exit 1; fi; \
	 echo "[e2e] running tagged integration test..."; \
	 W1R3HOUND_JUICE_URL=http://127.0.0.1:3000 $(GO) test -tags juiceshop -run TestJuiceShopPhaseC -v ./internal/modules/; rc=$$?; \
	 docker stop w1r3-juice >/dev/null 2>&1 || true; \
	 exit $$rc

# Dev-only Playwright headless smoke of the web console. Needs Node and a
# running webui (start it first: ./webui/run.sh). Installs its own deps and a
# headless Chromium; nothing here ships in the zero-dependency build.
.PHONY: e2e-ui
e2e-ui:
	cd webui/e2e && npm install && npx playwright install chromium && npx playwright test

.PHONY: ci
ci: vet fmt-check test-race csp
	@echo "ci: passed (vet, fmt-check, test-race, csp)"

.PHONY: clean
clean:
	rm -f $(CLI_BIN) $(GUI_BIN)
