FROM --platform=linux/amd64 golang:1.21-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-amd64 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go generate ./pkg/ebpf/...

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ebpf-apm ./cmd/main.go

FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /ebpf-apm /usr/local/bin/ebpf-apm
COPY config.yaml /app/config.yaml
COPY scripts/init_clickhouse.sql /app/scripts/init_clickhouse.sql

RUN chmod +x /usr/local/bin/ebpf-apm

EXPOSE 8080

ENV GIN_MODE=release

ENTRYPOINT ["/usr/local/bin/ebpf-apm"]
CMD ["--config", "/app/config.yaml"]
