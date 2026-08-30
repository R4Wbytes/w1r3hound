# Contributing to w1r3hound

Thanks for your interest in contributing.

## Building

```bash
git clone https://github.com/R4Wbytes/w1r3hound.git
cd w1r3hound
make build
```

Requires Go 1.22 or later.

## Running tests

```bash
make ci          # vet + gofmt check + test-race + CSP (the gate)
make test        # go test ./...
make test-race   # go test -race ./...
make golden      # FP/FN golden-snapshot check
make fuzz        # fuzz seed corpora
make smoke       # build + loopback portscan of 127.0.0.1
```

## Code style

- All code must pass `gofmt`. Run `make fmt` before committing.
- No external dependencies. w1r3hound is built entirely on the Go standard library.
- No TODO/FIXME comments in source. Track work items in `docs/`.

## Pull requests

1. Fork the repo and create a feature branch from `main`.
2. Write tests for new functionality.
3. Ensure `make ci` passes.
4. Open a PR with a clear description of the change.

## Responsible disclosure

Security vulnerabilities should be reported privately. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
