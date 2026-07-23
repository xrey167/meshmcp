# meshmcp — identity-native control plane for agent-to-tool (MCP) traffic.
#
# The mesh layer is USERSPACE WireGuard (NetBird embed / netstack), so this
# container needs no TUN device, no NET_ADMIN, no privileges at all — it runs
# as nonroot on a distroless base. State (mesh identity, config, audit ledger)
# lives under /data; mount a volume there or the peer re-enrolls fresh on every
# container replacement.
#
#   docker build -t meshmcp .
#   docker run -e NB_SETUP_KEY=<key> -v meshmcp-data:/data meshmcp
#
# See examples/docker-compose.yml for the compose form.

FROM golang:1.26 AS build
WORKDIR /src
# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /meshmcp ./cmd/meshmcp

# distroless/static ships CA certificates (needed for the management TLS
# connection and ACME) and nothing else — no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /meshmcp /usr/local/bin/meshmcp
ENV MESHMCP_HOME=/data
VOLUME /data
ENTRYPOINT ["meshmcp"]
# One command from container to gateway: scaffolds a safe-by-default config on
# first run, then joins and serves. Override the command for other verbs.
CMD ["air", "up"]
