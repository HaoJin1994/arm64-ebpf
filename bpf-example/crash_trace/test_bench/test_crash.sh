#!/bin/bash
# run_with_tracer.sh

sudo ./test_crash_trace &
TRACER_PID=$!
sleep 0.3          # 等 BPF 程序挂载好

cat /proc/$TRACER_PID/maps >> maps.txt

/home/jin/test/bpf-developer-tutorial/src/12-profile/crash_trace      # 跑你的程序
EXIT_CODE=$?

sudo kill $TRACER_PID 2>/dev/null
wait $TRACER_PID 2>/dev/null

exit $EXIT_CODE