#!/bin/bash
# Astraea Formal Test Runner

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "--- Astraea Test Suite ---"

# Build the project first
echo "Building Astraea..."
zig build > /dev/null

# Helper function to run a test
run_test() {
    local test_file=$1
    local test_name=$2
    echo -n "Running $test_name... "
    if LD_PRELOAD=./zig-out/lib/libastraea.so node "$test_file" > /dev/null 2>&1; then
        echo -e "${GREEN}PASSED${NC}"
    else
        echo -e "${RED}FAILED${NC}"
        return 1
    fi
}

# Run Tests
run_test "tests/exploit_fs_access.js" "FS Access Control"
run_test "tests/exploit_eval.js" "Eval Sandbox Escape"

# Benchmarks (Optional/Informational)
echo -n "Running Performance Benchmark... "
if LD_PRELOAD=./zig-out/lib/libastraea.so node tests/bench_performance.js > /dev/null 2>&1; then
    echo -e "${GREEN}DONE${NC}"
else
    echo -e "${RED}ERROR${NC}"
fi

echo "--- All Tests Completed ---"
