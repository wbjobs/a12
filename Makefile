.PHONY: all build generate run clean docker-build docker-up docker-down help

BIN_DIR := bin
CMD_DIR := cmd
MAIN_FILE := $(CMD_DIR)/main.go
BINARY_NAME := ebpf-apm

all: generate build

help:
	@echo "Available targets:"
	@echo "  make generate     - Generate eBPF Go bindings"
	@echo "  make build        - Build the binary"
	@echo "  make run          - Run the agent (requires root)"
	@echo "  make init-schema  - Initialize ClickHouse schema"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-up    - Start services with Docker Compose"
	@echo "  make docker-down  - Stop services"
	@echo "  make clean        - Clean build artifacts"

generate:
	@echo "Generating eBPF Go bindings..."
	go generate ./pkg/ebpf/...

build: generate
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) $(MAIN_FILE)
	@echo "Build completed: $(BIN_DIR)/$(BINARY_NAME)"

run: build
	@echo "Running $(BINARY_NAME)..."
	@sudo $(BIN_DIR)/$(BINARY_NAME) --config config.yaml

init-schema: build
	@echo "Initializing ClickHouse schema..."
	@sudo $(BIN_DIR)/$(BINARY_NAME) --config config.yaml --init-schema

docker-build:
	@echo "Building Docker image..."
	docker build -t ebpf-apm:latest .

docker-up: docker-build
	@echo "Starting services..."
	docker-compose up -d

docker-down:
	@echo "Stopping services..."
	docker-compose down

clean:
	@echo "Cleaning..."
	@rm -rf $(BIN_DIR)
	@rm -f pkg/ebpf/bpf_bpf*.go
	@go clean
	@echo "Clean completed"

test:
	go test -v ./...

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
