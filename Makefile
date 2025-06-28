# Makefile for tinkrotate project

# Variables
PROTOC = protoc
GO_PLUGIN = protoc-gen-go
PROTO_DIR = proto
TINKROTATE_PROTO = $(PROTO_DIR)/tinkrotate/v1/tinkrotate.proto
OUTPUT_DIR = .

# Find tink-go proto directory
# If this fails, ensure 'github.com/tink-crypto/tink-go/v2' is in your go.mod
TINK_GO_DIR := $(shell go list -m -f '{{.Dir}}' github.com/tink-crypto/tink-go/v2)
TINK_PROTO_DIR = $(TINK_GO_DIR)/proto

.PHONY: proto check-tools

# Default target
all: proto

# Generate Go code from protobuf definitions
proto: check-tools $(TINKROTATE_PROTO)
	@echo "Generating Go code from $(TINKROTATE_PROTO)..."
	@$(PROTOC) \
		-I=$(PROTO_DIR) \
		-I=$(TINK_PROTO_DIR) \
		--go_out=$(OUTPUT_DIR) --go_opt=paths=source_relative \
		$(TINKROTATE_PROTO)
	@echo "Done."

# Check for required tools
check-tools:
	@command -v $(PROTOC) >/dev/null 2>&1 || (echo "Error: protoc is not installed or not in PATH."; echo "See: https://grpc.io/docs/protoc-installation/"; exit 1)
	@command -v $(GO_PLUGIN) >/dev/null 2>&1 || (echo "Error: $(GO_PLUGIN) is not installed or not in PATH."; echo "Install with: go install google.golang.org/protobuf/cmd/protoc-gen-go@latest"; exit 1)
	@if [ -z "$(TINK_GO_DIR)" ]; then echo "Error: Could not find tink-go directory. Ensure 'github.com/tink-crypto/tink-go/v2' is in go.mod and run 'go mod download'."; exit 1; fi
	@if [ ! -d "$(TINK_PROTO_DIR)" ]; then echo "Error: Tink proto directory not found at $(TINK_PROTO_DIR). Check tink-go installation."; exit 1; fi

# Clean generated files (optional)
clean:
	@echo "Cleaning generated proto files..."
	@rm -f $(PROTO_DIR)/tinkrotate/v1/*.pb.go
	@echo "Done."
