#!/bin/bash
set -e

./test_profile &
PID=$!
echo "PID=$PID"
sleep 1

echo "Starting profiler..."
sudo ./bpftrace -p $PID -f 99 > out.folded &
BPF_PID=$!

echo "Profiling for 10 seconds..."
sleep 10

sudo kill -INT $BPF_PID 2>/dev/null
wait $BPF_PID 2>/dev/null

echo "Done. Check out.folded"
kill $PID 2>/dev/null