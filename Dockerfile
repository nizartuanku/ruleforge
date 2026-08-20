FROM golang:1.24 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o /out/ruleforge ./cmd/ruleforge

FROM debian:bookworm-slim
COPY --from=build /out/ruleforge /usr/local/bin/ruleforge
EXPOSE 8428
VOLUME /data
WORKDIR /data
ENTRYPOINT ["ruleforge", "-listen", "0.0.0.0:8428", "-db", "/data/ruleforge.db"]
