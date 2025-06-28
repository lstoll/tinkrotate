#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
PROJECT_ROOT=$(cd -- "$SCRIPT_DIR/.." &> /dev/null && pwd)

PATH="$PROJECT_ROOT/bin:$PATH"

PROTOC="protoc"
PROTO_DIR="$PROJECT_ROOT/proto"
TINKROTATE_PROTO="$PROTO_DIR/tinkrotate/v1/tinkrotate.proto"
OUTPUT_DIR="$PROJECT_ROOT"/proto

# Temporary directory for fixing include paths
TEMP_INCLUDE_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
  echo "Cleaning up temporary directory: $TEMP_INCLUDE_DIR"
  rm -rf "$TEMP_INCLUDE_DIR"
}

# Register cleanup function to run on script exit (normal or error)
trap cleanup EXIT

# --- Dependency Checks ---

# Check for protoc
if ! command -v $PROTOC &> /dev/null; then
    echo "Error: protoc is not installed or not in PATH." >&2
    exit 1
fi

# Find tink-go proto directory
# Change to project root to ensure go list works correctly
cd "$PROJECT_ROOT"
TINK_GO_DIR=$(go list -m -f '{{.Dir}}' github.com/tink-crypto/tink-go/v2 2>/dev/null)
if [ -z "$TINK_GO_DIR" ]; then
    echo "Error: Could not find tink-go directory using 'go list'." >&2
    echo "Ensure 'github.com/tink-crypto/tink-go/v2' is in go.mod and run 'go mod download'." >&2
    exit 1
fi

TINK_PROTO_SRC_DIR="$TINK_GO_DIR/proto" # Where tink's protos actually are
if [ ! -d "$TINK_PROTO_SRC_DIR" ]; then
    echo "Error: Tink proto source directory not found at $TINK_PROTO_SRC_DIR. Check tink-go installation." >&2
    exit 1
fi

# --- Prepare Temporary Include Structure ---

# Create the expected directory structure within the temp dir
TINK_EXPECTED_SUBDIR="google/crypto/tink"
mkdir -p "$TEMP_INCLUDE_DIR/$TINK_EXPECTED_SUBDIR"

echo "Copying Tink protos from $TINK_PROTO_SRC_DIR to temporary structure in $TEMP_INCLUDE_DIR/$TINK_EXPECTED_SUBDIR ..."
# Copy *all* .proto files, as tink.proto might import others (like common.proto)
# from the same directory, which protoc will expect in the relative path.
cp "$TINK_PROTO_SRC_DIR"/*.proto "$TEMP_INCLUDE_DIR/$TINK_EXPECTED_SUBDIR/"

# --- Code Generation ---

echo "Generating Go code from $TINKROTATE_PROTO..."

$PROTOC \
    -I="$PROTO_DIR" \
    -I="$TEMP_INCLUDE_DIR" \
    --go_out="$OUTPUT_DIR" --go_opt=paths=source_relative \
    "$TINKROTATE_PROTO"

echo "Done."

