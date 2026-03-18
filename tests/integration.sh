#!/bin/bash
#
# Integration tests for ironbox container runtime.
# Requires: root, running containerd, alpine image pulled.
#
# Usage: sudo ./tests/integration.sh
#

set -euo pipefail

RUNTIME="io.containerd.ironbox.v1"
IMAGE="docker.io/library/alpine:latest"
PASS=0
FAIL=0
TOTAL=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

cleanup_container() {
    local name="$1"
    sudo ctr task kill "$name" 2>/dev/null || true
    sudo ctr task rm "$name" 2>/dev/null || true
    sudo ctr container rm "$name" 2>/dev/null || true
    sudo ctr snapshot rm "$name" 2>/dev/null || true
}

# Run a short-lived container and check output contains expected string
run_test() {
    local name="$1"; shift
    local expected="$1"; shift
    local cname="test-${name}-$$"
    ((TOTAL++))
    printf "  %-40s" "$name"

    cleanup_container "$cname" 2>/dev/null

    local output
    if output=$(sudo ctr run --runtime "$RUNTIME" --rm "$IMAGE" "$cname" "$@" 2>&1); then
        if echo "$output" | grep -qE "$expected"; then
            echo -e "${GREEN}PASS${NC}"
            ((PASS++))
        else
            echo -e "${RED}FAIL${NC} (expected /$expected/, got: $output)"
            ((FAIL++))
        fi
    else
        echo -e "${RED}FAIL${NC} (exit error: $output)"
        ((FAIL++))
    fi

    cleanup_container "$cname" 2>/dev/null
}

echo "=== ironbox integration tests ==="
echo ""

# Ensure image is available
echo "Pulling image (if needed)..."
sudo ctr image pull "$IMAGE" >/dev/null 2>&1 || true
echo ""

# --- Basic ---
echo "Basic:"
run_test "echo"          "hello"       echo hello
run_test "sh-echo"       "works"       sh -c "echo works"
run_test "exit-code"     ""            true

# --- PID namespace ---
echo ""
echo "PID namespace:"
run_test "pid-1"         "^1$"         sh -c "echo \$\$"
run_test "pipe-fork"     "hello"       sh -c "echo hello | cat"

# --- Cgroup ---
echo ""
echo "Cgroup:"
run_test "cgroup-path"   "/ironbox/"   sh -c "cat /proc/self/cgroup"

# --- Filesystem ---
echo ""
echo "Filesystem:"
run_test "rootfs"        "bin"         ls /
run_test "proc"          "self"        ls /proc
run_test "dev-null"      "/dev/null"   ls /dev/null

# --- Network ---
echo ""
echo "Network:"
run_test "loopback"      "LOOPBACK,UP" ip link show lo

# --- Environment ---
echo ""
echo "Environment:"
run_test "env-path"      "PATH="       sh -c "env | grep PATH"
run_test "hostname"      ""            sh -c "hostname"  # just verify it doesn't crash

# --- Capabilities ---
echo ""
echo "Capabilities:"
run_test "cap-status"    "CapBnd"      sh -c "cat /proc/self/status | grep Cap"

# --- Long-running + kill ---
echo ""
echo "Lifecycle:"
LONG_NAME="test-long-$$"
((TOTAL++))
printf "  %-40s" "long-running-kill"
cleanup_container "$LONG_NAME" 2>/dev/null
if sudo ctr run -d --runtime "$RUNTIME" "$IMAGE" "$LONG_NAME" sleep 300 2>&1; then
    # Verify it's running
    if sudo ctr task ls 2>/dev/null | grep -q "$LONG_NAME"; then
        sudo ctr task kill "$LONG_NAME" 2>/dev/null || true
        sleep 1
        cleanup_container "$LONG_NAME" 2>/dev/null
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAIL${NC} (not in task list)"
        ((FAIL++))
        cleanup_container "$LONG_NAME" 2>/dev/null
    fi
else
    echo -e "${RED}FAIL${NC} (couldn't start)"
    ((FAIL++))
    cleanup_container "$LONG_NAME" 2>/dev/null
fi

# --- Exec ---
EXEC_NAME="test-exec-$$"
((TOTAL++))
printf "  %-40s" "exec"
cleanup_container "$EXEC_NAME" 2>/dev/null
if sudo ctr run -d --runtime "$RUNTIME" "$IMAGE" "$EXEC_NAME" sleep 300 2>&1; then
    sleep 1
    exec_out=$(sudo ctr task exec --exec-id e1 "$EXEC_NAME" echo "exec works" 2>&1) || true
    if echo "$exec_out" | grep -q "exec works"; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
    else
        echo -e "${RED}FAIL${NC} ($exec_out)"
        ((FAIL++))
    fi
    sudo ctr task kill "$EXEC_NAME" 2>/dev/null || true
    sleep 1
    cleanup_container "$EXEC_NAME" 2>/dev/null
else
    echo -e "${RED}FAIL${NC} (couldn't start)"
    ((FAIL++))
    cleanup_container "$EXEC_NAME" 2>/dev/null
fi

# --- Summary ---
echo ""
echo "================================="
echo -e "Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
echo "================================="

[ "$FAIL" -eq 0 ] || exit 1
