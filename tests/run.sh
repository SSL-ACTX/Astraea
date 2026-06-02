#!/bin/bash
# Astraea Formal Test Runner

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "--- Astraea Security Mesh Test Suite ---"

# Compilation Stage
echo "Skipping build, reusing existing libastraea.so..."

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
