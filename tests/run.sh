#!/bin/bash
# Astraea Formal Test Runner

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "--- Astraea Security Mesh Test Suite ---"

if [ "${SKIP_BUILD}" != "1" ]; then
    echo "Building Astraea..."
    rm -rf zig-out/ zig-cache/
    zig build -j2
fi

# Create outside file and symlink for traversal testing
echo "secret outside" > /data/data/com.termux/files/home/secret_outside.txt
ln -sf /data/data/com.termux/files/home/secret_outside.txt tests/symlink_outside

cleanup() {
    rm -f /data/data/com.termux/files/home/secret_outside.txt
    rm -f tests/symlink_outside
}
trap cleanup EXIT

# Execution Stage
for test_file in tests/suite/*.test.js; do
    name=$(basename "$test_file")
    echo "Running $name..."
    if ! LD_PRELOAD=./zig-out/lib/libastraea.so node "$test_file"; then
        echo -e "${RED}FAILED: $test_file${NC}"
        exit 1
    fi
done

echo -e "\n${GREEN}--- All Tests Passed Successfully ---${NC}"
