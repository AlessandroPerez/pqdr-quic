#!/bin/bash
set -e

# Performance test script for PQDR-QUIC vs Vanilla QUIC
# Tests 20GB file transfer end-to-end

cd "$(dirname "$0")"

# Default file size in GB
FILE_SIZE_GB=20

# Default number of runs
RUNS=1

# Parse command-line arguments
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
        -h|--help)
            echo "Usage: $0 [--runs N] [--size SIZE]"
            echo "  --runs N    Number of test runs per configuration (default: 1)"
            echo "  --size SIZE File size in GB (default: 20)"
            echo "  --help      Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Update file name based on size
FILE="test_${FILE_SIZE_GB}gb.bin"
SERVER_FILE="test-www/$FILE"
CLIENT_FILE="/tmp/quic_download_$FILE"
RESULTS_FILE="performance_results.txt"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "QUIC Performance Test - ${FILE_SIZE_GB}GB File Transfer"
echo "Runs per configuration: $RUNS"
echo "=============================================="
echo ""

# Ensure the test file exists, or create it if missing
if [ ! -f "$SERVER_FILE" ]; then
    echo -e "${YELLOW}Creating $SERVER_FILE (${FILE_SIZE_GB}GB)...${NC}"
    mkdir -p "$(dirname "$SERVER_FILE")"
    dd if=/dev/urandom of="$SERVER_FILE" bs=1M count=$((FILE_SIZE_GB * 1024))
fi

# Check if file exists
if [ ! -f "$SERVER_FILE" ]; then
    echo -e "${RED}Error: $SERVER_FILE does not exist${NC}"
    echo "Please create it first with: dd if=/dev/urandom of=$SERVER_FILE bs=1M count=20480"
    exit 1
fi

# Calculate or load server-side hash
HASH_FILE="$SERVER_FILE.blake3"
if [ -f "$HASH_FILE" ]; then
    echo -e "${BLUE}Loading cached server-side BLAKE3 hash...${NC}"
    SERVER_HASH=$(cat "$HASH_FILE")
    echo "Server BLAKE3: $SERVER_HASH"
else
    echo -e "${BLUE}Calculating server-side BLAKE3 hash (this will take a minute)...${NC}"
    if command -v b3sum &> /dev/null; then
        SERVER_HASH=$(b3sum "$SERVER_FILE" | awk '{print $1}')
    else
        echo "BLAKE3 not found, using MD5..."
        SERVER_HASH=$(md5sum "$SERVER_FILE" | awk '{print $1}')
        HASH_FILE="$SERVER_FILE.md5"
    fi
    echo "$SERVER_HASH" > "$HASH_FILE"
    echo "Server hash: $SERVER_HASH (saved to $HASH_FILE)"
fi
echo ""

# Function to calculate statistics
calculate_stats() {
    local values=("$@")
    local count=${#values[@]}

    if [ $count -eq 0 ]; then
        echo "0 0 0 0 0"
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
    local cv=$(echo "scale=2; ($stddev / $mean) * 100" | bc)

    echo "$mean $median $stddev $min $max $cv"
}

# Function to run a single test
run_test() {
    local test_name=$1
    local pqdr_enabled=$2
    local run_number=$3

    echo "==============================================" >&2
    echo -e "${GREEN}Test: $test_name (Run $run_number/$RUNS)${NC}" >&2
    echo "==============================================" >&2

    # Clean up previous download
    rm -f "$CLIENT_FILE"

    # Start server (idle-timeout set to 300s = 5 minutes for large file transfers)
    echo -e "${BLUE}Starting server...${NC}" >&2
    if [ "$pqdr_enabled" = "true" ]; then
        ./target/release/quiche-server \
            --listen 127.0.0.1:4433 \
            --cert apps/src/bin/cert.crt \
            --key apps/src/bin/cert.key \
            --root test-www \
            --max-data 25000000000 \
            --max-stream-data 25000000000 \
            --idle-timeout 300000 > /tmp/server_perf.log 2>&1 &
    else
        ./target/release/quiche-server \
            --listen 127.0.0.1:4433 \
            --cert apps/src/bin/cert.crt \
            --key apps/src/bin/cert.key \
            --root test-www \
            --max-data 25000000000 \
            --max-stream-data 25000000000 \
            --idle-timeout 300000 \
            --disable-pqdr > /tmp/server_perf.log 2>&1 &
    fi
    SERVER_PID=$!
    sleep 3

    if ! ps -p $SERVER_PID > /dev/null 2>&1; then
        echo -e "${RED}Server failed to start!${NC}" >&2
        cat /tmp/server_perf.log >&2
        return 1
    fi

    echo -e "${BLUE}Downloading ${FILE_SIZE_GB}GB file...${NC}" >&2
    echo "Started at: $(date '+%Y-%m-%d %H:%M:%S')" >&2

    # Measure total time including download and hash verification
    START_TIME=$(date +%s.%N)

    # Download file (with 5-minute idle timeout for large files)
    if [ "$pqdr_enabled" = "true" ]; then
        ./target/release/quiche-client \
            --no-verify \
            --max-data 25000000000 \
            --max-stream-data 25000000000 \
            --idle-timeout 300000 \
            https://127.0.0.1:4433/$FILE > "$CLIENT_FILE" 2>/dev/null
    else
        ./target/release/quiche-client \
            --no-verify \
            --max-data 25000000000 \
            --max-stream-data 25000000000 \
            --idle-timeout 300000 \
            --disable-pqdr \
            https://127.0.0.1:4433/$FILE > "$CLIENT_FILE" 2>/dev/null
    fi

    DOWNLOAD_END=$(date +%s.%N)

    echo "Download completed at: $(date '+%Y-%m-%d %H:%M:%S')" >&2

    # Calculate client-side hash
    echo -e "${BLUE}Calculating client-side hash...${NC}" >&2
    if command -v b3sum &> /dev/null; then
        CLIENT_HASH=$(b3sum "$CLIENT_FILE" | awk '{print $1}')
    else
        CLIENT_HASH=$(md5sum "$CLIENT_FILE" | awk '{print $1}')
    fi

    HASH_END=$(date +%s.%N)

    echo "Hash verification completed at: $(date '+%Y-%m-%d %H:%M:%S')" >&2

    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true

    # Calculate times
    DOWNLOAD_TIME=$(echo "$DOWNLOAD_END - $START_TIME" | bc)
    TOTAL_TIME=$(echo "$HASH_END - $START_TIME" | bc)
    HASH_TIME=$(echo "$HASH_END - $DOWNLOAD_END" | bc)

    # Calculate throughput (20GB in bytes / time in seconds = bytes/sec, convert to Mbps)
    THROUGHPUT=$(echo "scale=2; (${FILE_SIZE_GB} * 1024 * 8) / $DOWNLOAD_TIME" | bc)

    # Verify integrity
    if [ "$SERVER_HASH" = "$CLIENT_HASH" ]; then
        echo -e "${GREEN}✓ SUCCESS: Hashes match!${NC}" >&2
        INTEGRITY="PASS"
    else
        echo -e "${RED}✗ FAILURE: Hashes do not match!${NC}" >&2
        echo "Server: $SERVER_HASH" >&2
        echo "Client: $CLIENT_HASH" >&2
        INTEGRITY="FAIL"
    fi

    echo "" >&2
    echo "=== Run $run_number Results ===" >&2
    echo "Download time:      ${DOWNLOAD_TIME}s" >&2
    echo "Hash time:          ${HASH_TIME}s" >&2
    echo "Total time:         ${TOTAL_TIME}s" >&2
    echo "Throughput:         ${THROUGHPUT} Mbps" >&2
    echo "Integrity check:    $INTEGRITY" >&2
    echo "" >&2

    # Cleanup
    rm -f "$CLIENT_FILE"

    # Return values as space-separated string
    echo "$DOWNLOAD_TIME $TOTAL_TIME $HASH_TIME $THROUGHPUT $INTEGRITY"

    sleep 2
}

# Clear previous results
echo "Performance Test Results - $(date)" > "$RESULTS_FILE"
echo "Number of runs per configuration: $RUNS" >> "$RESULTS_FILE"
echo "========================================" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Arrays to store results
declare -a vanilla_download_times
declare -a vanilla_total_times
declare -a vanilla_hash_times
declare -a vanilla_throughputs
declare -a pqdr_download_times
declare -a pqdr_total_times
declare -a pqdr_hash_times
declare -a pqdr_throughputs

# Run Vanilla QUIC tests
echo ""
echo "=============================================="
echo -e "${YELLOW}Running Vanilla QUIC Tests${NC}"
echo "=============================================="
echo ""

for i in $(seq 1 $RUNS); do
    result=$(run_test "Vanilla QUIC (Standard)" "false" "$i")
    read -r dl_time tot_time hash_time throughput integrity <<< "$result"
    vanilla_download_times+=("$dl_time")
    vanilla_total_times+=("$tot_time")
    vanilla_hash_times+=("$hash_time")
    vanilla_throughputs+=("$throughput")

    # Save individual result
    echo "=== Vanilla QUIC - Run $i ===" >> "$RESULTS_FILE"
    echo "Download time:      ${dl_time}s" >> "$RESULTS_FILE"
    echo "Hash time:          ${hash_time}s" >> "$RESULTS_FILE"
    echo "Total time:         ${tot_time}s" >> "$RESULTS_FILE"
    echo "Throughput:         ${throughput} Mbps" >> "$RESULTS_FILE"
    echo "Integrity check:    $integrity" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
done

# Run PQDR-QUIC tests
echo ""
echo "=============================================="
echo -e "${YELLOW}Running PQDR-QUIC Tests${NC}"
echo "=============================================="
echo ""

for i in $(seq 1 $RUNS); do
    result=$(run_test "PQDR-QUIC (Post-Quantum Double-Ratchet)" "true" "$i")
    read -r dl_time tot_time hash_time throughput integrity <<< "$result"
    pqdr_download_times+=("$dl_time")
    pqdr_total_times+=("$tot_time")
    pqdr_hash_times+=("$hash_time")
    pqdr_throughputs+=("$throughput")

    # Save individual result
    echo "=== PQDR-QUIC - Run $i ===" >> "$RESULTS_FILE"
    echo "Download time:      ${dl_time}s" >> "$RESULTS_FILE"
    echo "Hash time:          ${hash_time}s" >> "$RESULTS_FILE"
    echo "Total time:         ${tot_time}s" >> "$RESULTS_FILE"
    echo "Throughput:         ${throughput} Mbps" >> "$RESULTS_FILE"
    echo "Integrity check:    $integrity" >> "$RESULTS_FILE"
    echo "" >> "$RESULTS_FILE"
done

# Calculate and display aggregate statistics
echo ""
echo "=============================================="
echo -e "${GREEN}Aggregate Statistics${NC}"
echo "=============================================="
echo ""

# Vanilla QUIC stats
echo -e "${BLUE}Vanilla QUIC Statistics:${NC}"
read -r mean median stddev min max cv <<< $(calculate_stats "${vanilla_throughputs[@]}")
echo "  Throughput:"
echo "    Mean:     ${mean} Mbps"
echo "    Median:   ${median} Mbps"
echo "    StdDev:   ${stddev} Mbps"
echo "    Min:      ${min} Mbps"
echo "    Max:      ${max} Mbps"
echo "    CV:       ${cv}%"
echo ""

read -r dl_mean dl_median dl_stddev dl_min dl_max dl_cv <<< $(calculate_stats "${vanilla_download_times[@]}")
echo "  Download Time:"
echo "    Mean:     ${dl_mean}s"
echo "    Median:   ${dl_median}s"
echo "    StdDev:   ${dl_stddev}s"
echo "    Min:      ${dl_min}s"
echo "    Max:      ${dl_max}s"
echo ""

# Save vanilla stats to file
echo "==================================" >> "$RESULTS_FILE"
echo "Vanilla QUIC - Aggregate Statistics" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"
echo "Throughput:" >> "$RESULTS_FILE"
echo "  Mean:     ${mean} Mbps" >> "$RESULTS_FILE"
echo "  Median:   ${median} Mbps" >> "$RESULTS_FILE"
echo "  StdDev:   ${stddev} Mbps" >> "$RESULTS_FILE"
echo "  Min:      ${min} Mbps" >> "$RESULTS_FILE"
echo "  Max:      ${max} Mbps" >> "$RESULTS_FILE"
echo "  CV:       ${cv}%" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Download Time:" >> "$RESULTS_FILE"
echo "  Mean:     ${dl_mean}s" >> "$RESULTS_FILE"
echo "  Median:   ${dl_median}s" >> "$RESULTS_FILE"
echo "  StdDev:   ${dl_stddev}s" >> "$RESULTS_FILE"
echo "  Min:      ${dl_min}s" >> "$RESULTS_FILE"
echo "  Max:      ${dl_max}s" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# PQDR-QUIC stats
echo -e "${BLUE}PQDR-QUIC Statistics:${NC}"
read -r pqdr_mean pqdr_median pqdr_stddev pqdr_min pqdr_max pqdr_cv <<< $(calculate_stats "${pqdr_throughputs[@]}")
echo "  Throughput:"
echo "    Mean:     ${pqdr_mean} Mbps"
echo "    Median:   ${pqdr_median} Mbps"
echo "    StdDev:   ${pqdr_stddev} Mbps"
echo "    Min:      ${pqdr_min} Mbps"
echo "    Max:      ${pqdr_max} Mbps"
echo "    CV:       ${pqdr_cv}%"
echo ""

read -r pqdr_dl_mean pqdr_dl_median pqdr_dl_stddev pqdr_dl_min pqdr_dl_max pqdr_dl_cv <<< $(calculate_stats "${pqdr_download_times[@]}")
echo "  Download Time:"
echo "    Mean:     ${pqdr_dl_mean}s"
echo "    Median:   ${pqdr_dl_median}s"
echo "    StdDev:   ${pqdr_dl_stddev}s"
echo "    Min:      ${pqdr_dl_min}s"
echo "    Max:      ${pqdr_dl_max}s"
echo ""

# Save PQDR stats to file
echo "==================================" >> "$RESULTS_FILE"
echo "PQDR-QUIC - Aggregate Statistics" >> "$RESULTS_FILE"
echo "==================================" >> "$RESULTS_FILE"
echo "Throughput:" >> "$RESULTS_FILE"
echo "  Mean:     ${pqdr_mean} Mbps" >> "$RESULTS_FILE"
echo "  Median:   ${pqdr_median} Mbps" >> "$RESULTS_FILE"
echo "  StdDev:   ${pqdr_stddev} Mbps" >> "$RESULTS_FILE"
echo "  Min:      ${pqdr_min} Mbps" >> "$RESULTS_FILE"
echo "  Max:      ${pqdr_max} Mbps" >> "$RESULTS_FILE"
echo "  CV:       ${pqdr_cv}%" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "Download Time:" >> "$RESULTS_FILE"
echo "  Mean:     ${pqdr_dl_mean}s" >> "$RESULTS_FILE"
echo "  Median:   ${pqdr_dl_median}s" >> "$RESULTS_FILE"
echo "  StdDev:   ${pqdr_dl_stddev}s" >> "$RESULTS_FILE"
echo "  Min:      ${pqdr_dl_min}s" >> "$RESULTS_FILE"
echo "  Max:      ${pqdr_dl_max}s" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Performance comparison
echo -e "${BLUE}Performance Comparison:${NC}"
if [ "$RUNS" -gt 1 ]; then
    overhead=$(echo "scale=2; (($dl_mean - $pqdr_dl_mean) / $dl_mean) * 100" | bc)
    throughput_diff=$(echo "scale=2; (($mean - $pqdr_mean) / $mean) * 100" | bc)

    echo "  PQDR vs Vanilla:"
    echo "    Throughput difference: ${throughput_diff}%"
    echo "    Download time overhead: ${overhead}%"

    echo "" >> "$RESULTS_FILE"
    echo "==================================" >> "$RESULTS_FILE"
    echo "Performance Comparison" >> "$RESULTS_FILE"
    echo "==================================" >> "$RESULTS_FILE"
    echo "PQDR vs Vanilla:" >> "$RESULTS_FILE"
    echo "  Throughput difference: ${throughput_diff}%" >> "$RESULTS_FILE"
    echo "  Download time overhead: ${overhead}%" >> "$RESULTS_FILE"
fi
echo ""

echo "=============================================="
echo -e "${GREEN}Performance testing complete!${NC}"
echo "=============================================="
echo ""
echo "Results saved to: $RESULTS_FILE"
