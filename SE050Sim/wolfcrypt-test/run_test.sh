#!/bin/bash
set -e

export SE050_SIM_HOST=127.0.0.1
export SE050_SIM_PORT=8050
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Platform SCP03 variant: provision the simulator and the SDK from the same
# key file so the two sides derive identical session keys.
if [ "$SE05X_AUTH" = "PlatfSCP03" ]; then
    echo "=== Platform SCP03 variant: provisioning keys from /app/scp03_keys.txt ==="
    export SE050_SIM_SCP03_ENC=$(awk '/^ENC /{print $2}' /app/scp03_keys.txt)
    export SE050_SIM_SCP03_MAC=$(awk '/^MAC /{print $2}' /app/scp03_keys.txt)
    export EX_SSS_BOOT_SCP03_PATH=/app/scp03_keys.txt
fi

echo "=== Starting SE050 Simulator ==="
/app/se050-sim-server &
SIM_PID=$!

# Wait for server to be ready
sleep 1

# Verify server is listening
if ! kill -0 $SIM_PID 2>/dev/null; then
    echo "ERROR: Simulator failed to start"
    exit 1
fi

echo "=== Running wolfCrypt Test Suite ==="

/app/wolfcrypt_se050_test
TEST_RESULT=$?

echo ""
echo "=== Test Result: $([ $TEST_RESULT -eq 0 ] && echo 'PASS' || echo 'FAIL') ==="

# Stop simulator
kill $SIM_PID 2>/dev/null || true
wait $SIM_PID 2>/dev/null || true

exit $TEST_RESULT
