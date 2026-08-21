# RuleForge — minimal production image.
# Build:  docker build -t ruleforge .
# Run:    docker run -d -p 127.0.0.1:8428:8428 -v ruleforge-data:/data ruleforge

FROM golang:1.24 AS build
WORKDIR /src
# Dependencies first, so a source-only change does not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# CGO is required by the mattn/go-sqlite3 driver (see go.mod).
# ISSUER_PUBKEY empty => every licence key invalid => permanent free edition.
ARG ISSUER_PUBKEY=""
ARG VERSION=0.1.0
RUN CGO_ENABLED=1 go build -trimpath \
    -ldflags "-s -w -X main.issuerPublicKeyB64=${ISSUER_PUBKEY} -X main.version=${VERSION}" \
    -o /out/ruleforge ./cmd/ruleforge

FROM debian:bookworm-slim
# Runs unprivileged. /data is created and chowned here so a named volume
# inherits the right ownership instead of defaulting to root.
RUN useradd -r -u 10001 ruleforge \
 && mkdir -p /data \
 && chown ruleforge:ruleforge /data
# No ca-certificates on purpose: RuleForge makes no outbound connections.
COPY --from=build /out/ruleforge /usr/local/bin/ruleforge
USER ruleforge
WORKDIR /data
VOLUME /data
EXPOSE 8428
ENTRYPOINT ["ruleforge", "-listen", "0.0.0.0:8428", "-db", "/data/ruleforge.db"]
