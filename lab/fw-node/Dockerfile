# syntax=docker/dockerfile:1
# fw-node: router + firewall. Stage 1 build xdpfw (C -> BPF bytecode -> nhúng vào Go),
# stage 2 chỉ chứa binary + công cụ mạng cần cho demo/benchmark.

FROM golang:1.23.4-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang llvm libbpf-dev \
    && rm -rf /var/lib/apt/lists/*
ENV GOTOOLCHAIN=local CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY bpf ./bpf
COPY internal ./internal
COPY cmd ./cmd
ARG VERSION=dev
RUN go generate ./... \
    && go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/xdpfw ./cmd/xdpfw

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iptables nftables bpftool iputils-ping curl tcpdump procps ethtool \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/xdpfw /usr/local/bin/xdpfw
COPY lab/fw-node/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
