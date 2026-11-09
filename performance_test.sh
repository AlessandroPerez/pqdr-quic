#!/bin/bash
#
# Performance test: PQDR-QUIC vs vanilla QUIC, end-to-end file transfer over
# loopback with the quiche-server and quiche-client apps.
#
# No test data is stored, on disk or in memory:
#
# - Timed runs serve a sparse file (created instantly with `truncate`, which
#   takes no disk space and reads back as zeros at memory speed), streamed by
#   the server as the connection takes it. The client's output is only
#   counted, so nothing else competes for CPU during the measurement.
#
# - Before the timed runs, one untimed run per configuration checks data
#   integrity: random data from /dev/urandom is streamed through a named
#   pipe and hashed on both sides. (Hashing during the timed runs would slow
#   them down noticeably on machines with few cores.)
#
# Both configurations use ChaCha20-Poly1305 (the apps prefer it by default),
# so the comparison isolates the cost of PQDR-QUIC's per-packet ratchet.

set -uo pipefail

cd "$(dirname "$0")"

FILE_SIZE_GB=20
RUNS=1
VERIFY=1
PORT=4433

usage() {
    echo "Usage: $0 [--runs N] [--size GB] [--no-verify] [--port PORT]"
    echo "  --runs N     Number of timed runs per configuration (default: 1)"
    echo "  --size GB    Transfer size in GiB (default: 20)"
    echo "  --no-verify  Skip the data integrity check"
    echo "  --port PORT  UDP port for the server (default: 4433)"
    echo "  --help       Show this help message"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --runs)
            RUNS="$2"
            shift 2
            ;;
        --size)
            FILE_SIZE_GB="$2"
            shift 2
            ;;
        --no-verify)
            VERIFY=0
            shift
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

SERVER_BIN=./target/release/quiche-server
CLIENT_BIN=./target/release/quiche-client
RESULTS_FILE="performance_results.txt"
FILE_SIZE_BYTES=$((FILE_SIZE_GB * 1024 * 1024 * 1024))

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

for tool in bc mkfifo truncate timeout; do
    if ! command -v "$tool" > /dev/null; then
        echo -e "${RED}Error: '$tool' is required but not installed${NC}"
        exit 1
    fi
done

if [ ! -x "$SERVER_BIN" ] || [ ! -x "$CLIENT_BIN" ]; then
    echo -e "${RED}Error: $SERVER_BIN and $CLIENT_BIN not found${NC}"
    echo "Build them first with: cargo build --release --package=quiche_apps"
    exit 1
fi

if command -v b3sum > /dev/null; then
    HASH_TOOL=b3sum
else
    HASH_TOOL=md5sum
fi

# Test data lives in a temporary directory (the sparse file takes no space).
WWW=$(mktemp -d)
SERVER_LOG="$WWW/server.log"
SERVER_PID=

GENERATOR_PID=

# Stops the random data generator, which may be blocked on the named pipe.
stop_generator() {
    if [ -n "$GENERATOR_PID" ]; then
        # Opening the pipe for reading unblocks a writer waiting to open it;
        # closing it makes the writer fail.
        if [ -p "$WWW/random.bin" ]; then
            timeout 1 cat "$WWW/random.bin" > /dev/null 2>&1 || true
        fi

        wait "$GENERATOR_PID" 2> /dev/null || true
        GENERATOR_PID=
    fi

    rm -f "$WWW/random.bin"
}

cleanup() {
    stop_server
    stop_generator
    rm -rf "$WWW"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

truncate -s "$FILE_SIZE_BYTES" "$WWW/zeros.bin"

COMMON_ARGS=(
    --max-data 25000000000
    --max-stream-data 25000000000
    --idle-timeout 300000
)

echo "=============================================="
echo "QUIC Performance Test - ${FILE_SIZE_GB}GB File Transfer"
echo "Runs per configuration: $RUNS"
echo "=============================================="
echo ""

# start_server <pqdr: true|false>
start_server() {
    local extra=()

    if [ "$1" != "true" ]; then
        extra+=(--disable-pqdr)
    fi

    "$SERVER_BIN" \
        --listen "127.0.0.1:$PORT" \
        --cert apps/src/bin/cert.crt \
        --key apps/src/bin/cert.key \
        --root "$WWW" \
        "${COMMON_ARGS[@]}" \
        "${extra[@]}" > "$SERVER_LOG" 2>&1 &
    SERVER_PID=$!

    sleep 2

    if ! kill -0 "$SERVER_PID" 2> /dev/null; then
        echo -e "${RED}Server failed to start!${NC}" >&2
        cat "$SERVER_LOG" >&2
        exit 1
    fi
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2> /dev/null || true
        wait "$SERVER_PID" 2> /dev/null || true
        SERVER_PID=
    fi
}

# download <pqdr: true|false> <file>: writes the response body to stdout.
download() {
    local extra=()

    if [ "$1" != "true" ]; then
        extra+=(--disable-pqdr)
    fi

    "$CLIENT_BIN" \
        --no-verify \
        "${COMMON_ARGS[@]}" \
        "${extra[@]}" \
        "https://127.0.0.1:$PORT/$2" 2> /dev/null
}

# verify_integrity <name> <pqdr: true|false>: sets INTEGRITY to PASS or FAIL.
verify_integrity() {
    local test_name=$1
    local pqdr_enabled=$2

    echo -e "${BLUE}Checking data integrity: $test_name (${FILE_SIZE_GB}GB of random data)...${NC}"

    rm -f "$WWW/random.bin" "$WWW/sent.hash"
    mkfifo "$WWW/random.bin"

    # The generator blocks until the server opens the pipe, and its output
    # is hashed as the server reads it.
    head -c "$FILE_SIZE_BYTES" /dev/urandom |
        tee "$WWW/random.bin" |
        "$HASH_TOOL" | awk '{print $1}' > "$WWW/sent.hash" &
    GENERATOR_PID=$!

    start_server "$pqdr_enabled"

    local received
    received=$(download "$pqdr_enabled" random.bin | "$HASH_TOOL" | awk '{print $1}')

    # If the transfer was cut short, the generator only stops once the
    # server has closed the pipe.
    stop_server
    stop_generator

    local sent
    sent=$(cat "$WWW/sent.hash" 2> /dev/null)

    if [ -n "$sent" ] && [ "$sent" = "$received" ]; then
        echo -e "${GREEN}✓ Hashes match ($HASH_TOOL $sent)${NC}"
        INTEGRITY=PASS
    else
        echo -e "${RED}✗ Hashes do not match!${NC}"
        echo "  Sent:     $sent"
        echo "  Received: $received"
        INTEGRITY=FAIL
    fi
}

# Function to calculate statistics
calculate_stats() {
    local values=("$@")
    local count=${#values[@]}

    if [ $count -eq 0 ]; then
        echo "0 0 0 0 0 0"
        return
    fi

    # Sort values for median calculation
    IFS=$'\n' sorted=($(sort -n <<<"${values[*]}"))
    unset IFS

    # Calculate mean
    local sum=0
    for val in "${values[@]}"; do
        sum=$(echo "$sum + $val" | bc)
    done
    local mean=$(echo "scale=2; $sum / $count" | bc)

    # Calculate median
    local median
    if [ $((count % 2)) -eq 0 ]; then
        local mid1=$((count / 2 - 1))
        local mid2=$((count / 2))
        median=$(echo "scale=2; (${sorted[$mid1]} + ${sorted[$mid2]}) / 2" | bc)
    else
        local mid=$((count / 2))
        median=${sorted[$mid]}
    fi

    # Calculate standard deviation
    local variance=0
    for val in "${values[@]}"; do
        local diff=$(echo "$val - $mean" | bc)
        local sq=$(echo "$diff * $diff" | bc)
        variance=$(echo "$variance + $sq" | bc)
    done
    variance=$(echo "scale=10; $variance / $count" | bc)
    local stddev=$(echo "scale=2; sqrt($variance)" | bc)

    # Min and max
    local min=${sorted[0]}
    local max=${sorted[$((count - 1))]}

    # Coefficient of variation (CV%)
    local cv=$(echo "scale=2; $stddev * 100 / $mean" | bc)

    echo "$mean $median $stddev $min $max $cv"
}

# run_test <name> <pqdr: true|false> <run number>: sets DOWNLOAD_TIME,
# THROUGHPUT and BYTES_RECEIVED.
run_test() {
    local test_name=$1
    local pqdr_enabled=$2
    local run_number=$3

    echo "=============================================="
    echo -e "${GREEN}Test: $test_name (Run $run_number/$RUNS)${NC}"
    echo "=============================================="

    start_server "$pqdr_enabled"

    echo -e "${BLUE}Downloading ${FILE_SIZE_GB}GB...${NC}"
    echo "Started at: $(date '+%Y-%m-%d %H:%M:%S')"

    local start_time end_time
    start_time=$(date +%s.%N)
    BYTES_RECEIVED=$(download "$pqdr_enabled" zeros.bin | wc -c)
    end_time=$(date +%s.%N)

    stop_server

    echo "Download completed at: $(date '+%Y-%m-%d %H:%M:%S')"

    DOWNLOAD_TIME=$(echo "$end_time - $start_time" | bc)

    # Megabits computed as GiB * 1024 * 8, as in the published results.
    THROUGHPUT=$(echo "scale=2; (${FILE_SIZE_GB} * 1024 * 8) / $DOWNLOAD_TIME" | bc)

    if [ "$BYTES_RECEIVED" != "$FILE_SIZE_BYTES" ]; then
        echo -e "${RED}✗ Received $BYTES_RECEIVED bytes, expected $FILE_SIZE_BYTES${NC}"
        INCOMPLETE_TRANSFERS=$((INCOMPLETE_TRANSFERS + 1))
    fi

    echo ""
    echo "=== Run $run_number Results ==="
    echo "Download time:      ${DOWNLOAD_TIME}s"
    echo "Throughput:         ${THROUGHPUT} Mbps"
    echo "Bytes received:     ${BYTES_RECEIVED}"
    echo ""

    sleep 2
}

# Clear previous results
echo "Performance Test Results - $(date)" > "$RESULTS_FILE"
echo "Number of runs per configuration: $RUNS" >> "$RESULTS_FILE"
echo "Transfer size: ${FILE_SIZE_GB}GB" >> "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Integrity checks
vanilla_integrity="SKIPPED"
pqdr_integrity="SKIPPED"

if [ "$VERIFY" = "1" ]; then
    verify_integrity "Vanilla QUIC" "false"
    vanilla_integrity=$INTEGRITY

    verify_integrity "PQDR-QUIC" "true"
    pqdr_integrity=$INTEGRITY
    echo ""

    echo "Integrity check (random data, $HASH_TOOL):" >> "$RESULTS_FILE"
    echo "  Vanilla QUIC: $vanilla_integrity" >> "$RESULTS_FILE"
    echo "  PQDR-QUIC:    $pqdr_integrity" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
fi

INCOMPLETE_TRANSFERS=0

# Arrays to store results
declare -a vanilla_download_times
declare -a vanilla_throughputs
declare -a pqdr_download_times
declare -a pqdr_throughputs

# run_config <name> <pqdr: true|false> <array prefix>
run_config() {
    local name=$1
    local pqdr_enabled=$2
    local prefix=$3

    echo ""
    echo "=============================================="
    echo -e "${YELLOW}Running $name Tests${NC}"
    echo "=============================================="
    echo ""

    for i in $(seq 1 "$RUNS"); do
        run_test "$name" "$pqdr_enabled" "$i"

        eval "${prefix}_download_times+=(\"$DOWNLOAD_TIME\")"
        eval "${prefix}_throughputs+=(\"$THROUGHPUT\")"

        # Save individual result
        echo "=== $name - Run $i ===" >> "$RESULTS_FILE"
        echo "Download time:      ${DOWNLOAD_TIME}s" >> "$RESULTS_FILE"
        echo "Throughput:         ${THROUGHPUT} Mbps" >> "$RESULTS_FILE"
        echo "Bytes received:     ${BYTES_RECEIVED}" >> "$RESULTS_FILE"
        echo "" >> "$RESULTS_FILE"
    done
}

run_config "Vanilla QUIC" "false" vanilla
run_config "PQDR-QUIC" "true" pqdr

# print_stats <name> <throughputs...> -- <download times...>
print_stats() {
    local name=$1
    shift

    local throughputs=()
    while [ "$1" != "--" ]; do
        throughputs+=("$1")
        shift
    done
    shift

    local mean median stddev min max cv
    read -r mean median stddev min max cv <<< "$(calculate_stats "${throughputs[@]}")"

    local dl_mean dl_median dl_stddev dl_min dl_max dl_cv
    read -r dl_mean dl_median dl_stddev dl_min dl_max dl_cv <<< "$(calculate_stats "$@")"

    {
        echo "Throughput:"
        echo "  Mean:     ${mean} Mbps"
        echo "  Median:   ${median} Mbps"
        echo "  StdDev:   ${stddev} Mbps"
        echo "  Min:      ${min} Mbps"
        echo "  Max:      ${max} Mbps"
        echo "  CV:       ${cv}%"
        echo ""
        echo "Download Time:"
        echo "  Mean:     ${dl_mean}s"
        echo "  Median:   ${dl_median}s"
        echo "  StdDev:   ${dl_stddev}s"
        echo "  Min:      ${dl_min}s"
        echo "  Max:      ${dl_max}s"
        echo ""
    } > "$WWW/stats.txt"

    echo -e "${BLUE}$name Statistics:${NC}"
    sed 's/^/  /' "$WWW/stats.txt"

    {
        echo "=================================="
        echo "$name - Aggregate Statistics"
        echo "=================================="
        cat "$WWW/stats.txt"
    } >> "$RESULTS_FILE"

    LAST_MEAN=$mean
    LAST_DL_MEAN=$dl_mean
}

# Calculate and display aggregate statistics
echo ""
echo "=============================================="
echo -e "${GREEN}Aggregate Statistics${NC}"
echo "=============================================="
echo ""

print_stats "Vanilla QUIC" "${vanilla_throughputs[@]}" -- "${vanilla_download_times[@]}"
mean=$LAST_MEAN
dl_mean=$LAST_DL_MEAN

print_stats "PQDR-QUIC" "${pqdr_throughputs[@]}" -- "${pqdr_download_times[@]}"
pqdr_mean=$LAST_MEAN
pqdr_dl_mean=$LAST_DL_MEAN

# Performance comparison
echo -e "${BLUE}Performance Comparison:${NC}"
# Multiply before dividing: bc truncates every intermediate result to `scale`
# decimal places.
overhead=$(echo "scale=2; ($pqdr_dl_mean - $dl_mean) * 100 / $dl_mean" | bc)
throughput_diff=$(echo "scale=2; ($mean - $pqdr_mean) * 100 / $mean" | bc)

echo "  PQDR vs Vanilla:"
echo "    Throughput difference: ${throughput_diff}%"
echo "    Download time overhead: ${overhead}%"

{
    echo ""
    echo "=================================="
    echo "Performance Comparison"
    echo "=================================="
    echo "PQDR vs Vanilla:"
    echo "  Throughput difference: ${throughput_diff}%"
    echo "  Download time overhead: ${overhead}%"
} >> "$RESULTS_FILE"
echo ""

echo "=============================================="
echo -e "${GREEN}Performance testing complete!${NC}"
echo "=============================================="
echo ""
echo "Results saved to: $RESULTS_FILE"

if [ "$vanilla_integrity" = "FAIL" ] || [ "$pqdr_integrity" = "FAIL" ]; then
    echo -e "${RED}Data integrity check FAILED (see above)${NC}"
    exit 1
fi

if [ "$INCOMPLETE_TRANSFERS" -gt 0 ]; then
    echo -e "${RED}$INCOMPLETE_TRANSFERS timed transfer(s) were incomplete (see above)${NC}"
    exit 1
fi
