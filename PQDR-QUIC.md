# PQDR-QUIC Implementation Status

This document describes the PQDR-QUIC (Post-Quantum Double-Ratchet QUIC) implementation in quiche.

## Overview

PQDR-QUIC extends QUIC with post-quantum cryptography and advanced security properties through double-ratcheting, providing:

- **Post-quantum security**: ML-KEM-768 (Module-Lattice-Based KEM, NIST Level 3) for key exchange
- **Forward secrecy**: Each packet encrypted with a unique key derived via BLAKE3 KDF chain
- **Post-compromise recovery**: Automatic ML-KEM ratchets every 60 seconds restore security after compromise
- **Signal-style double ratchet**: Combines symmetric (BLAKE3 chain) and asymmetric (ML-KEM) ratchets
- **Minimal overhead**: Only ~2% performance impact for 20GB transfers

### Key Security Properties

**Forward Secrecy (via BLAKE3 Symmetric Ratchet)**
- Protects the *past*: Even if an attacker compromises key K_n, they cannot decrypt packets 1 through n-1
- Achieved through one-way BLAKE3 key derivation: each packet key is derived from a chain key that is immediately replaced
- Operates on every packet with ~64ns overhead per packet

**Post-Compromise Recovery (via ML-KEM Asymmetric Ratchet)**
- Protects the *future*: Even if an attacker fully compromises the system at time T, they can only decrypt messages for at most 60 seconds
- Achieved through periodic ML-KEM-768 key exchanges that introduce fresh entropy
- Also called "future secrecy" or "break-in recovery"
- Operates every 60 seconds with ~50μs overhead per ratchet

Together, these properties provide **continuous security**: compromise of any single key or state does not permanently break confidentiality.

## Implementation Status

### ✅ Completed Components

1. **ML-KEM-768 Bindings** (`quiche/src/crypto/boringssl.rs`)
   - FFI bindings to BoringSSL's ML-KEM implementation
   - Key generation, encapsulation, and decapsulation
   - Uses vendored BoringSSL with ML-KEM support

2. **BLAKE3 Key Derivation** (`quiche/src/crypto/blake3_kdf.rs`)
   - HKDF-style extract and expand operations
   - Signal protocol-compatible key derivation
   - Root key and chain key derivation functions
   - All tests passing ✓

3. **Double-Ratchet State Machine** (`quiche/src/crypto/ratchet.rs`)
   - Complete ratchet state with symmetric and asymmetric ratchets
   - Timer-based ratchet initiation (every 60 seconds)
   - Server-always-initiates ratchet model (`we_initiate_next = is_server`)
   - Out-of-order packet handling with skipped keys cache
   - Epoch-transition `recv_chain_pn` sync fix (Bug 4: in-flight packet misalignment)
   - 8/8 tests passing ✓ (includes regression test for Bug 4)

4. **KEM Material Transport**
   - Server ML-KEM pubkey: sent as 64-byte plaintext prefix embedded in first 19 application packets per epoch (assembled in-order by packet number)
   - Client KEM ciphertext: sent as raw bytes via QUIC CRYPTO stream at t≈55s
   - `KEY_RATCHET` frame type 0x40 exists in `frame.rs` but is deprecated and ignored; reception is silently dropped for backwards compatibility

5. **Connection Integration** (`quiche/src/lib.rs`)
   - Ratchet state initialized after TLS handshake
   - Timer-based ratchet initiation in send path
   - KEY_RATCHET frame processing in receive path
   - Packet encryption using ratchet-derived keys
   - Packet decryption with ratchet state

6. **Transport Parameter Negotiation** (`quiche/src/transport_params.rs`)
   - PQDR-QUIC support parameter (0xFF00)
   - Only enables when both peers support it
   - Proper negotiation and logging

7. **Configuration API** (`quiche/src/lib.rs`)
   - `Config::enable_pqdr_quic(bool)` method
   - Disabled by default for compatibility

## Architecture

### Packet Encryption Flow

```
┌─────────────────────────────────────────────────────────┐
│                  Application Packet                      │
└───────────────────────┬─────────────────────────────────┘
                        │
                        v
           ┌────────────────────────┐
           │   Ratchet State        │
           │   - Send Chain Key     │
           │   - Message Number     │
           │   - Epoch             │
           └────────┬───────────────┘
                    │
                    v
         derive_message_key(chain_key)
                    │
         ┌──────────┴──────────┐
         │                     │
         v                     v
    New Chain Key        Message Key
    (for next msg)       (32 bytes)
         │                     │
         │                     v
         │           ChaCha20-Poly1305
         │              Encryption
         │                     │
         └─────────────────────┘
```

### Ratchet Timeline

```
Time:  0s               60s              120s             180s
       │                │                │                │
       │  Handshake     │  Server        │  Server        │  Server
       │  Complete      │  Initiates     │  Initiates     │  Initiates
       │                │  ML-KEM        │  ML-KEM        │  ML-KEM
       │                │  Ratchet       │  Ratchet       │  Ratchet
       │                │                │                │
       v                v                v                v
    Epoch 0          Epoch 1          Epoch 2          Epoch 3
    ─────────────────────────────────────────────────────────>
                   Symmetric ratchet every packet
```

Note: The server always initiates every ML-KEM ratchet. The client responds by encapsulating to the server's public key and sending the ciphertext via CRYPTO stream at t=55s of each epoch.

## File Structure

```
quiche/src/
├── crypto/
│   ├── boringssl.rs          # ML-KEM-768 FFI bindings
│   ├── blake3_kdf.rs         # BLAKE3 key derivation
│   ├── ratchet.rs            # Double-ratchet implementation
│   └── mod.rs                # Module declarations
├── frame.rs                   # KEY_RATCHET frame definition
├── transport_params.rs        # PQDR-QUIC parameter
├── lib.rs                     # Connection integration
└── build.rs                   # C++ linking for BoringSSL
```

## Usage Example

### Programmatic API

```rust
use quiche;

// Server configuration
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
config.enable_pqdr_quic(true);  // Enable PQDR-QUIC
config.set_application_protos(&[b"h3"])?;
// ... standard configuration ...

// Client configuration
let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
config.enable_pqdr_quic(true);  // Enable PQDR-QUIC
config.set_application_protos(&[b"h3"])?;
// ... standard configuration ...

// Connection proceeds normally - PQDR-QUIC is transparent
// after negotiation during handshake
```

### Command-Line Usage

**Start PQDR-enabled server**:
```bash
./target/release/quiche-server \
    --listen 127.0.0.1:4433 \
    --cert apps/src/bin/cert.crt \
    --key apps/src/bin/cert.key \
    --root test-www
```

**Connect with PQDR-enabled client**:
```bash
./target/release/quiche-client \
    --no-verify \
    https://127.0.0.1:4433/test_20gb.bin > downloaded_file.bin
```

**Disable PQDR (use standard QUIC)**:
```bash
# Server
./target/release/quiche-server --disable-pqdr ...

# Client
./target/release/quiche-client --disable-pqdr ...
```

Both client and server must have PQDR enabled for the feature to activate. If either side disables it, the connection falls back to standard QUIC with TLS 1.3.

## Building

PQDR-QUIC requires the vendored BoringSSL (default feature):

```bash
# Clone the repository
git clone https://github.com/ale/pqdr-quic.git
cd pqdr-quic

# Build quiche library and client/server binaries (release mode for performance)
cargo build --release --bin quiche-server --bin quiche-client

# Binaries will be in target/release/
# - quiche-server: QUIC server with PQDR support
# - quiche-client: QUIC client with PQDR support
```

### Important: Cipher Suite Configuration

For fair performance comparison, this implementation modifies BoringSSL to prioritize **ChaCha20-Poly1305** over AES-GCM in TLS 1.3 cipher negotiation (see `quiche/deps/boringssl/ssl/handshake_client.cc:118-122`).

**Why this matters**:
- PQDR-QUIC uses ChaCha20-Poly1305 because it has **zero key schedule cost**, enabling efficient per-packet rekeying
- By default, BoringSSL prioritizes AES-GCM on systems with AES-NI hardware acceleration
- Comparing PQDR (ChaCha20) vs Vanilla (AES-GCM) would be unfair and misleading
- With both using ChaCha20-Poly1305, the measured 5-6% overhead accurately reflects the cost of per-packet rekeying and post-quantum features

To revert to default cipher preference (AES-GCM prioritized), modify `quiche/deps/boringssl/ssl/handshake_client.cc` and rebuild.

⚠️ **Note**: `tokio-quiche` uses the `boring` crate which doesn't have ML-KEM support. Use `quiche` directly or `quiche_apps` for PQDR-QUIC.

## Testing

### Unit Tests

Current test status:
- BLAKE3 KDF: 5/5 tests passing ✓
- Ratchet state: 8/8 tests passing ✓ (includes `test_epoch_transition_inflight_pn_sync` regression for Bug 4)
- ML-KEM serialization: 1 test ignored (needs CBS parsing)

Run tests:
```bash
cargo test -p quiche
```

### Performance Testing

A comprehensive performance test script is provided to compare vanilla QUIC vs PQDR-QUIC:

#### Setup Test Environment

1. **Create a test file** (20GB for realistic benchmarking):
```bash
dd if=/dev/urandom of=test-www/test_20gb.bin bs=1M count=20480
```

2. **Ensure you have certificates**:
```bash
# The default certs are in apps/src/bin/
ls apps/src/bin/cert.crt apps/src/bin/cert.key
```

#### Running Performance Tests

**Basic usage** (single run):
```bash
./performance_test.sh
```

**Multiple runs for statistical analysis** (recommended):
```bash
# 5 runs of each configuration (vanilla and PQDR)
./performance_test.sh --runs 5

# 10 runs for more robust statistics
./performance_test.sh --runs 10
```

**Available flags**:
- `--runs N`: Number of test runs per configuration (default: 1)
- `--help`: Show usage information

**Output**: Results are saved to `sanity_check.txt` with:
- Individual run results (download time, throughput, integrity check)
- Aggregate statistics (mean, median, standard deviation, min, max, CV%)
- Performance comparison (overhead percentage)

#### Test Results

Performance testing with **10 runs each** (20GB file transfer, loopback):

**Vanilla QUIC**:
- Mean throughput: **2351.75 Mbps** | Median: 2344.68 Mbps
- StdDev: 34.48 Mbps | CV: 1.0%
- Download time: 69.68s average (min: 67.89s, max: 71.39s)

**PQDR-QUIC (60s ratchet)**:
- Mean throughput: **2304.77 Mbps** | Median: 2329.25 Mbps
- StdDev: 46.23 Mbps | CV: 2.0%
- Download time: 71.11s average (min: 69.53s, max: 73.34s)

**Overhead: ~2.0%** (≈ 1.4 seconds for 20GB)

All 20 runs passed integrity check (BLAKE3 hash match).

## Performance Considerations

### Measured Overhead

Based on extensive testing with 20GB file transfers:

**Per-operation costs**:
- **BLAKE3 key derivation**: ~64ns per packet
- **EVP_AEAD_CTX init/cleanup**: ~186ns per packet (ChaCha20-Poly1305)
- **ML-KEM-768 encapsulation**: ~50μs per ratchet (every 60 seconds)
- **Total per-packet overhead**: ~250ns

**End-to-end performance**:
- Vanilla QUIC: ~2352 Mbps mean throughput (median 2345 Mbps)
- PQDR-QUIC: ~2305 Mbps mean throughput (median 2329 Mbps)
- **Overhead: ~2%** for bulk data transfer

**Memory usage**:
- Ratchet state: ~3KB per connection
- Skipped keys cache: Up to 512 keys for out-of-order packets (~16KB maximum)

### Packet Structure

QUIC uses 1200-byte UDP datagrams by default (minimum MTU size):

```
┌─────────────────────────────────────────────────────────┐
│                  UDP Datagram (1200 bytes)              │
├─────────────────────────────────────────────────────────┤
│ Short Header (1 byte)                                   │
│ DCID (8 bytes, typical)                                 │
│ Packet Number (2 bytes, typical)                        │
├─────────────────────────────────────────────────────────┤
│ Encrypted Payload (~1150 bytes)                         │
│   ├─ STREAM Frame Header (~12 bytes)                   │
│   └─ Application Data (~1138 bytes)                     │
├─────────────────────────────────────────────────────────┤
│ AEAD Tag (16 bytes, ChaCha20-Poly1305)                  │
└─────────────────────────────────────────────────────────┘

Effective data per packet: ~1161 bytes (96.7% efficiency)
20GB transfer ≈ 17.5 million packets ≈ 17.5 million key derivations
```

**PQDR vs Vanilla packet processing**:
- Vanilla: Reuses AEAD context for all packets (~50ns encryption overhead)
- PQDR: Fresh AEAD context + BLAKE3 derivation per packet (~250ns overhead)
- **5x slowdown per packet, but only ~2% end-to-end** (crypto is small fraction of total time)

### Why PQDR is Efficient

1. **ChaCha20-Poly1305 has zero key schedule**: Unlike AES, ChaCha20 doesn't need key expansion, making per-packet rekeying practical
2. **BLAKE3 is extremely fast**: Single-threaded performance of ~10GB/s means 32-byte derivation is only ~64ns
3. **Stack allocation**: EVP_AEAD_CTX allocated on stack (608 bytes) avoids heap allocation overhead
4. **QUIC packet coalescing**: During handshake, multiple QUIC packets can be coalesced. During data transfer (1-RTT), one packet per UDP datagram means overhead is predictable

## Security Properties

PQDR-QUIC provides multiple layers of security:

### 1. Post-Quantum Security
- **Achieved via**: ML-KEM-768 (NIST FIPS 203, security level 3)
- **Protects against**: Quantum computer attacks using Shor's algorithm
- **Key exchange every 60 seconds** introduces fresh post-quantum entropy
- Equivalent classical security: AES-192

### 2. Forward Secrecy
- **Achieved via**: BLAKE3 symmetric ratchet (per-packet key derivation)
- **Property**: Compromise of key K_n at time T cannot decrypt packets before n
- **Mechanism**: Each packet key is derived from a chain key via one-way KDF, then the chain key is replaced
- **Coverage**: Protects *all past communications*
- **Cost**: ~64ns per packet

**Example**: If an attacker compromises the system and extracts the chain key at packet 1,000,000:
- ✓ Can decrypt packet 1,000,000
- ✗ Cannot decrypt packets 1 through 999,999 (forward secrecy)
- ✓ Can decrypt future packets 1,000,001+ until next ML-KEM ratchet (post-compromise recovery needed)

### 3. Post-Compromise Recovery
- **Achieved via**: ML-KEM-768 asymmetric ratchet (every 60 seconds)
- **Property**: Full compromise at time T only allows decryption for ≤60 seconds
- **Mechanism**: New ML-KEM key exchange introduces fresh entropy not controlled by attacker
- **Coverage**: Protects *future communications after compromise*
- **Also called**: "Future secrecy" or "break-in recovery"
- **Cost**: ~50μs per ratchet

**Example**: Attacker fully compromises system at T=100s:
- ✓ Can decrypt messages from T=100s to T=160s (until next ratchet)
- ✗ Cannot decrypt messages after T=160s (post-compromise recovery via ML-KEM)
- ✗ Cannot decrypt messages before T=100s (forward secrecy via BLAKE3)

### 4. Per-Packet Security
- Each of the ~17.5 million packets in a 20GB transfer uses a unique encryption key
- Compromise of a single packet key reveals only that packet, not others
- Packet counter prevents replay attacks

### Double Ratchet Security Model

The combination of symmetric (BLAKE3) and asymmetric (ML-KEM) ratchets creates a **self-healing** security system:

```
Compromise → Forward Secrecy → Past Safe ✓
          ↓
   Post-Compromise Recovery → Future Safe (60s) ✓
```

This matches the security model of secure messaging apps like Signal, applied to transport-layer encryption.

## Future Work

### Completed ✓
- [x] Core double-ratchet implementation
- [x] ML-KEM-768 integration
- [x] BLAKE3 KDF integration
- [x] Packet encryption/decryption with per-packet rekeying
- [x] Performance optimization (achieved ~2% overhead)
- [x] Comprehensive performance testing framework (10-run statistical analysis)
- [x] ChaCha20-Poly1305 cipher standardization (fair comparison)
- [x] Bug 4 fix: epoch-transition `recv_chain_pn` sync for in-flight packets
- [x] Regression test suite (`test_epoch_transition_inflight_pn_sync`)

### In Progress / Future Enhancements

- [ ] Migration to tokio-quiche (requires boring crate ML-KEM support)
- [ ] Further optimization of EVP_AEAD_CTX initialization (investigate context pooling)
- [ ] Adaptive ratchet intervals based on connection characteristics
- [ ] Cross-implementation testing (interoperability with other PQDR implementations)
- [ ] Memory-constrained device testing (IoT, mobile)

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [Signal Double Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)
- [RFC 9000 - QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001 - QUIC TLS](https://www.rfc-editor.org/rfc/rfc9001.html)

## Quick Reference

| Parameter | Value | Description |
|-----------|-------|-------------|
| **ML-KEM Security Level** | NIST Level 3 (768) | Equivalent to AES-192 |
| **Ratchet Interval** | 60 seconds | ML-KEM key exchange frequency |
| **KDF Algorithm** | BLAKE3 | ~10GB/s single-threaded |
| **AEAD Cipher** | ChaCha20-Poly1305 | Zero key schedule cost |
| **Key Size** | 32 bytes (256 bits) | Per-packet encryption key |
| **Nonce** | 12 bytes (96 bits), always zero | Key rotates every packet so (key, nonce=0) is always a fresh pair |
| **AEAD Tag** | 16 bytes (128 bits) | Authentication tag |
| **UDP Datagram** | 1200 bytes | Minimum MTU size |
| **Effective Payload** | ~1161 bytes | 96.7% efficiency |
| **Overhead** | ~2% | End-to-end bulk transfer (10-run avg) |
| **Per-packet Cost** | ~250ns | BLAKE3 + AEAD context |
| **Per-ratchet Cost** | ~50μs | ML-KEM encapsulation |
| **Memory/Connection** | ~3KB | Ratchet state |
| **Skipped Keys Cache** | 512 keys max | ~16KB for OOO packets |

---

**Implementation**: Cloudflare quiche with PQDR extensions
**Status**: Functional with production-ready performance
**License**: BSD 2-Clause (same as quiche)
