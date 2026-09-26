# w1r3hound — reproducible, static, non-root container image for the CLI.
#
# Scope: this image ships the single-binary recon CLI (the "zero dependencies,
# single binary" artifact). The web GUI is intentionally NOT containerised here:
# it locates the repo root at runtime and drives the CLI as a subprocess, so it
# expects the source tree layout rather than a lone binary. Containerising the
# GUI is tracked as a follow-up.
#
# Build:  docker build --build-arg VERSION=$(git describe --tags --always) -t w1r3hound .
# Run:    docker run --rm w1r3hound -t example.com
#         docker run --rm -v "$PWD/out:/work" w1r3hound -t example.com -o /work/report

# ---- build stage ----
FROM golang:1.26 AS build
WORKDIR /src

# The module has zero external dependencies, so there is nothing to pre-fetch;
# copy the tree and build straight away. CGO is disabled so the resulting binary
# is fully static (no libc), and -trimpath strips build-host paths for a
# reproducible artifact.
COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 GOFLAGS=-mod=mod \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/w1r3hound .

# ---- runtime stage ----
# distroless/static: no shell, no package manager, minimal attack surface; the
# :nonroot tag runs as an unprivileged UID by default. CA certificates are
# included so the CLI's HTTPS calls to intel APIs (crt.sh, Wayback, …) work.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/w1r3hound /usr/local/bin/w1r3hound
USER nonroot:nonroot
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/w1r3hound"]
