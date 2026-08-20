#!/bin/sh

PROFILE_BIN="$PROFILE_DIR/profile_stack"
DURATION=10
FREQ=99

./test_profile &
TEST_PID=$!
echo "test_profile PID = $TEST_PID"

# 等它跑起来
sleep 1

timeout "$DURATION" "$PROFILE_BIN" -p "$TEST_PID" -f "$FREQ" 2>&1 || true

kill "$TEST_PID" 2>/dev/null || true
wait "$TEST_PID" 2>/dev/null || true
