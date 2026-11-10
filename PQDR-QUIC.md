# PQDR-QUIC Implementation Status

This document describes the PQDR-QUIC (Post-Quantum Double-Ratchet QUIC) implementation in quiche.

## Overview

PQDR-QUIC extends QUIC with post-quantum cryptography and advanced security properties through double-ratcheting, providing:

- **Post-quantum security**: ML-KEM-768 (Module-Lattice-Based KEM, NIST Level 3) for key exchange
- **Forward secrecy**: Each packet encrypted with a unique key derived via BLAKE3 KDF chain
- **Post-compromise recovery**: Automatic ML-KEM ratchets every 60 seconds restore security within two epochs of a compromise
- **Signal-style double ratchet**: Combines symmetric (BLAKE3 chain) and asymmetric (ML-KEM) ratchets
- **Low overhead**: 2–4% lower throughput in 20GB transfers, depending on the machine (see [Test Results](#test-results))

### Key Security Properties

**Forward Secrecy (via BLAKE3 Symmetric Ratchet)**
- Protects the *past*: Even if an attacker compromises key K_n, they cannot decrypt packets 1 through n-1
- Achieved through one-way BLAKE3 key derivation: each packet key is derived from a chain key that is immediately replaced
- Operates on every packet: one BLAKE3 compression per packet (88ns on a 4-core VM, ~64ns on the author's machine)

**Post-Compromise Recovery (via ML-KEM Asymmetric Ratchet)**
- Protects the *future*: Even if an attacker fully compromises the system at time T, they can only decrypt messages until the end of the following epoch: at most two epoch lengths (120 seconds by default), see [Post-Compromise Recovery](#3-post-compromise-recovery)
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
   - The per-packet chain step (`MessageKdf`) calls BLAKE3's compression function directly: its 8-byte input is a single block, so the 64 output bytes are one compression. This gives the same bytes as `blake3::Hasher` (checked against it and against fixed reference values) without the cost of setting up a general-purpose hasher. It uses `blake3::platform`, which is public but undocumented and exempt from semver: a `blake3` update that changes it would most likely fail to compile, and the reference-value tests catch any change in the output
   - All tests passing ✓

3. **Double-Ratchet State Machine** (`quiche/src/crypto/ratchet.rs`)
   - Complete ratchet state with symmetric and asymmetric ratchets
   - Timer-based epoch switches (every 60 seconds by default)
   - Server-always-initiates ratchet model: the server generates the ML-KEM key pair for the next epoch at the start of every epoch
   - Out-of-order packet handling with skipped keys cache
   - Receive keys are only committed after the packet authenticates (see [Epoch Switches and Robustness](#epoch-switches-and-robustness))
   - Locates the start of each epoch's chains (epoch 0 included) even if the first packets of the epoch are lost or reordered
   - Key material (chain keys, packet keys, KEM shared secrets and private keys) is wiped from memory when dropped

4. **KEM Material Transport**
   - Server ML-KEM pubkey: Reed-Solomon coded at rate 1/4 (`quiche/src/crypto/reed_solomon.rs`) into 76 chunks of 64 bytes, carried as a plaintext prefix by the server's first 76 packets of each epoch; any 19 chunks rebuild the key (see [Public Key Chunks](#public-key-chunks))
   - Client KEM ciphertext: sent as raw bytes via QUIC CRYPTO stream at t≈55s
   - `KEY_RATCHET` frame type 0x40 exists in `frame.rs` but is deprecated and ignored; reception is silently dropped for backwards compatibility

5. **Connection Integration** (`quiche/src/lib.rs`)
   - Ratchet state initialized after TLS handshake
   - Timer-based epoch activation in the send path
   - Packet encryption using ratchet-derived keys
   - Packet decryption with ratchet state
   - Packet protection (`crypto::PqdrAead` in `quiche/src/crypto/mod.rs`): ChaCha20-Poly1305 under the packet's key, with the QUIC header as associated data and a fixed nonce that is never sent (see [Nonce and Packet Number](#nonce-and-packet-number)), through one AEAD context per connection (see [Key Material Wiping](#key-material-wiping))

6. **Transport Parameter Negotiation** (`quiche/src/transport_params.rs`)
   - PQDR-QUIC support parameter (0xFF00)
   - Only enables when both peers support it
   - Proper negotiation and logging

7. **Configuration API** (`quiche/src/lib.rs`)
   - `Config::enable_pqdr_quic(bool)` method, disabled by default for compatibility
   - `Config::set_pqdr_ratchet_interval(Duration)`: epoch length (60 s by default)
   - `Config::enable_chacha20_preference(bool)`: make TLS prefer ChaCha20-Poly1305 (see [Cipher Suite Configuration](#cipher-suite-configuration))

## Architecture

### Packet Encryption Flow

```
┌─────────────────────────────────────────────────────────┐
│           Outgoing packet, packet number pn             │
└───────────────────────────┬─────────────────────────────┘
                            │
                            v
               ┌────────────────────────┐
               │   Ratchet State        │
               │   - Send chain key     │
               │   - Chain position     │
               │   - Epoch (key phase)  │
               └────────────┬───────────┘
                            │
                            v
          BLAKE3, keyed with the chain key, input pn
          (one compression, 64 bytes of output)
                            │
              ┌─────────────┴─────────────┐
              │                           │
              v                           v
        New chain key                Packet key
        (replaces the old one)       (32 bytes)
                                          │
                                          v
                                  ChaCha20-Poly1305
                                  nonce: always zero
                                  associated data: header
                                          │
                                          v
                                  packet key wiped
```

Packet numbers that quiche skips still advance the chain (their keys are discarded), so the chain moves in step with the packet numbers: the key for packet number `pn` comes from step `pn − start`, where `start` is the packet number the epoch's chain starts at.

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

Note: The server always initiates every ML-KEM ratchet: at the start of each epoch it generates the key pair for the next one and sends the public key in the epoch's first packets. The client responds by encapsulating to the server's public key and sending the ciphertext via CRYPTO stream at t=55s of each epoch. The next packet the server sends after t=60s switches both sides to the new epoch.

### Nonce and Packet Number

Every packet key protects exactly one packet, so the nonce does not have to change from packet to packet: it is the constant all-zero 12-byte value (`PQDR_NONCE` in `quiche/src/crypto/mod.rs`), neither sent nor derived. ChaCha20-Poly1305 only requires that a (key, nonce) pair is never used twice, and here every packet has a new key. The sender cannot reuse a key: `RatchetState::encrypt_key` refuses a packet number that the chain has already moved past. (Standard QUIC does not send its nonce either; it computes it from the packet number and a fixed IV.)

The packet number itself is still sent, as in standard QUIC, and hidden by QUIC's header protection. The receiver needs it to find the packet's position in the key chain when packets are lost or reordered, and QUIC needs it for acknowledgments and loss detection.

## File Structure

```
quiche/src/
├── crypto/
│   ├── boringssl.rs          # ML-KEM-768 FFI bindings
│   ├── blake3_kdf.rs         # BLAKE3 key derivation
│   ├── ratchet.rs            # Double-ratchet implementation
│   ├── reed_solomon.rs       # Erasure code for the public key chunks
│   ├── kdf_bench.rs          # Per-packet crypto microbenchmark (ignored test)
│   └── mod.rs                # Module declarations, PQDR packet AEAD
├── tls/
│   └── boringssl_shim.cc     # C wrapper for BoringSSL's cipher order override
├── frame.rs                   # KEY_RATCHET frame definition (deprecated)
├── transport_params.rs        # PQDR-QUIC parameter
├── lib.rs                     # Connection integration
├── pqdr_tests.rs              # End-to-end PQDR-QUIC tests
└── build.rs                   # BoringSSL build and C++ linking
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
    https://127.0.0.1:4433/index.html
```

The server streams files from disk as the connection takes them, so files of any size can be served with constant memory. It can also serve a named pipe (the response then has no `content-length` and ends when the pipe does), for example to stream generated data.

**Disable PQDR (use standard QUIC)**:
```bash
# Server
./target/release/quiche-server --disable-pqdr ...

# Client
./target/release/quiche-client --disable-pqdr ...
```

Both client and server must have PQDR enabled for the feature to activate. If either side disables it, the connection falls back to standard QUIC with TLS 1.3.

**Change the epoch length** (e.g. to exercise many epoch switches in a short transfer; use the same value on both sides):
```bash
./target/release/quiche-server --pqdr-ratchet-interval 2000 ...
./target/release/quiche-client --pqdr-ratchet-interval 2000 ...
```

Programmatically, use `Config::set_pqdr_ratchet_interval(Duration)`.

**Cipher selection**: both apps make TLS prefer ChaCha20-Poly1305 by default. Pass `--no-chacha20-preference` (on both sides) to let BoringSSL choose, i.e. AES-GCM on CPUs with AES instructions.

## Building

PQDR-QUIC requires the vendored BoringSSL (default feature), which is built from the `quiche/deps/boringssl` submodule.

**Prerequisites**: Rust 1.85 or later, a C/C++ compiler, CMake and git. The performance test script also needs `bc`. On Debian/Ubuntu: `apt install build-essential cmake git bc`; on Arch: `pacman -S base-devel cmake git bc`.

```bash
# Clone the repository, including the BoringSSL submodule
git clone --recurse-submodules https://github.com/AlessandroPerez/pqdr-quic.git
cd pqdr-quic

# (If you cloned without --recurse-submodules:)
git submodule update --init

# Build quiche library and client/server binaries (release mode for performance)
cargo build --release --package=quiche_apps

# Binaries will be in target/release/
# - quiche-server: QUIC server with PQDR support
# - quiche-client: QUIC client with PQDR support
```

### Cipher Suite Configuration

PQDR-QUIC always protects payloads with ChaCha20-Poly1305, because it has **zero key schedule cost**, which makes per-packet rekeying cheap. For a fair comparison, plain QUIC should use the same cipher.

Upstream BoringSSL prefers AES-GCM in TLS 1.3 on CPUs with AES instructions, and offers no regular API to change that order. `Config::enable_chacha20_preference(true)` makes it prefer ChaCha20-Poly1305 anyway, through BoringSSL's AES-hardware override (`SSL_CTX_set_aes_hw_override_for_testing`, which is C++-only and reached through the small wrapper in `quiche/src/tls/boringssl_shim.cc`). The apps enable it by default, so vanilla and PQDR runs both use ChaCha20-Poly1305 from a fresh clone, without modifying BoringSSL. (The published numbers were measured with an equivalent local change to BoringSSL's cipher order.)

⚠️ **Note**: `tokio-quiche` uses the `boring` crate which doesn't have ML-KEM support. Use `quiche` directly or `quiche_apps` for PQDR-QUIC.

## Testing

### Unit Tests

- `quiche/src/crypto/blake3_kdf.rs`: BLAKE3 KDF unit tests, including reference values for every derivation
- `quiche/src/crypto/reed_solomon.rs`: erasure code tests (decoding from any 19 of 76 chunks)
- `quiche/src/crypto/mod.rs`: `PqdrAead` against a context set up for each packet (identical output for 300 packet lengths, each opens what the other sealed, a wrong key is rejected)
- `quiche/src/crypto/boringssl.rs`: BoringSSL's ChaCha20-Poly1305 context holds nothing but its key, and the kept context holds a key only while a packet is sealed or opened
- `quiche/src/crypto/ratchet.rs`: ratchet state machine unit tests (key agreement, out-of-order delivery, epoch switches with lost or reordered packets, forged packets, public key chunk positions and decoding)
- `quiche/src/pqdr_tests.rs`: end-to-end tests over an in-memory client/server pipe, with epochs shortened via `Config::set_pqdr_ratchet_interval` (many epoch switches, ciphertext split over several packets, lost HANDSHAKE_DONE, tampered packets, lost and reordered packets at an epoch switch, the server's first ratchet-protected packets lost, three quarters of the public key chunks lost in every epoch, ChaCha20 negotiation)

Run tests:
```bash
cargo test -p quiche --lib -- crypto:: pqdr_tests
```

### Performance Testing

`performance_test.sh` compares vanilla QUIC and PQDR-QUIC with end-to-end transfers over loopback, using the release `quiche-server` and `quiche-client` (build them first, see [Building](#building)). Both configurations use ChaCha20-Poly1305.

No test data is stored, on disk or in memory, so a 20GB test needs neither 20GB of disk nor of RAM:

- **Timed runs** serve a sparse file, created instantly with `truncate`: it takes no disk space and reads back as zeros at memory speed. The server streams it as the connection takes it, and the client's output is only counted, so nothing else competes for CPU during the measurement.
- **Integrity check**: before the timed runs, one untimed transfer per configuration streams random data from `/dev/urandom` through a named pipe and compares hashes computed on both sides (`b3sum` if installed, otherwise `md5sum`). Hashing during the timed runs would itself slow them down noticeably on machines with few cores.
- **Alternating runs**: the timed runs alternate between vanilla and PQDR-QUIC, so that slow changes in machine speed during the test (thermal throttling, background load, a busy VM host) affect both configurations alike.

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
- `--runs N`: Number of timed runs per configuration (default: 1)
- `--size GB`: Transfer size in GiB (default: 20)
- `--no-verify`: Skip the integrity check
- `--port PORT`: UDP port for the server (default: 4433)
- `--help`: Show usage information

**Output**: Results are saved to `performance_results.txt` with:
- The integrity check results
- Individual run results (download time, throughput, bytes received)
- Aggregate statistics (mean, median, standard deviation, min, max, CV%)
- Performance comparison (overhead percentage)

Throughput is reported in Mbps computed as `GiB × 1024 × 8 / seconds`, as in the published results.

#### Test Results

**Current version**, on a 4-core QEMU VM (x86-64 with SSE4.1, no AVX), **5 alternating runs each** (20GB file transfer, loopback):

**Vanilla QUIC**:
- Mean throughput: **1573.68 Mbps** | Median: 1576.80 Mbps
- StdDev: 26.39 Mbps | CV: 1.7%
- Download time: 104.14s average (min: 101.23s, max: 106.03s)

**PQDR-QUIC (60s ratchet)**:
- Mean throughput: **1514.09 Mbps** | Median: 1512.12 Mbps
- StdDev: 14.69 Mbps | CV: 1.0%
- Download time: 108.21s average (min: 106.49s, max: 109.69s)

**Overhead: 3.8%** lower throughput, 3.9% longer downloads (≈ 4.1 seconds for 20GB). The five vanilla/PQDR pairs differed by 1.7% to 6.8%, so single runs say little on this machine.

Both integrity checks passed (20GB of random data each, md5sum).

**Earlier version**, which set up a new AEAD context for every packet, on the author's machine, **10 runs each** (20GB file transfer, loopback):

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

Absolute numbers, and the relative overhead, depend on the machine: the per-packet cost of PQDR-QUIC is roughly constant, so it is a larger fraction of the total on machines with slower cores. The VM reaches about two thirds of the throughput of the author's machine.

## Epoch Switches and Robustness

The receive side never changes ratchet state for a packet that has not authenticated:

- **Candidate keys, then commit**: for each incoming packet, the ratchet computes candidate keys without modifying itself; only the key that authenticates the packet is committed. Forged or corrupted packets cannot advance or desynchronize the chains, or trigger an epoch switch. The common case, the next packet in order on the current epoch's chain, takes a shortcut that follows the same rule: it derives the single possible key and skips the general search and skipped-key lookup.
- **Bounded work per packet**: a packet more than 65,536 packet numbers ahead of the receive chain is dropped without deriving any keys (`MAX_RECV_JUMP`).
- **Locating epoch chains**: each direction's chain for an epoch starts at the first packet number the sender protects with it (in epoch 0, its first ratchet-protected packet). If that packet is lost or reordered, the receiver tries the possible start packet numbers (at most 256, `MAX_ANCHOR_CANDIDATES`) and keeps the one that authenticates.
- **Previous epoch**: packets with the old key phase that arrive after a switch are decrypted with the previous epoch's keys, kept for 1/12 of the epoch length (5 s by default).
- **TLS keys only during the switch-over**: TLS-protected 1-RTT packets are accepted only until the peer's first ratchet-protected packet; after that they are rejected, so stolen TLS secrets cannot be used to inject packets. While they are accepted, the TLS key is tried first (one operation, where locating the peer's epoch-0 chain may take several), and each TLS-protected packet narrows down where that chain can start. The client also accepts ratchet-protected packets before HANDSHAKE_DONE arrives (in case it was lost).
- **Ciphertext transport**: the client's ciphertexts are reassembled from the CRYPTO stream regardless of how they were split into frames, and the stream is exempt from quiche's 64 KiB total CRYPTO offset limit (which it would otherwise exceed after ~60 epochs).

### Public Key Chunks

The server's 1184-byte ML-KEM public key for the next epoch is split into 19 data chunks of 64 bytes (zero-padded to 1216 bytes) and expanded with a systematic Reed-Solomon code over GF(2^8), at rate 1/4, into 76 chunks: chunks 0-18 are the key itself, chunks 19-75 parity.

- **Position, not marker**: the server's packet with packet number `start + i` carries chunk `i` as a 64-byte plaintext prefix, for `i < 76`, where `start` is the packet number the server's chain for the epoch starts at. The client knows `start` as soon as any packet of the epoch has authenticated (see above), so it tells which packets carry a chunk, and which one, from their packet number alone. Nothing is added to the wire.
- **Loss and reordering**: any 19 of the 76 chunks rebuild the key, in any order. Lost packets, reordered packets and packet numbers skipped by quiche (as a defense against optimistic ACK attacks) only cost the chunks they would have carried. Chunks in late packets from the previous epoch are stripped and ignored.

### Key Material Wiping

Chain keys, packet keys, cached skipped keys, KEM shared secrets, ML-KEM private keys, the TLS exporter secret and the key copy in the AEAD context are wiped from memory when dropped. Per-packet keys are wiped with a single volatile store each (`blake3_kdf::SecretKey`), which costs a few nanoseconds per packet; the rest uses the `zeroize` crate. BoringSSL's ChaCha20-Poly1305 context stores nothing but a copy of its key (the `chacha20_poly1305_ctx_holds_only_the_key` test checks this). So each connection sets up one context, and every packet's key is written into it, used and wiped again (`crypto::PqdrAead`): between packets the context holds no key, and no packet pays for setting up a context. Only the 32 key bytes are wiped; wiping the whole 608-byte context took longer than setting it up. A context that kept an old key would protect every packet with that key and the same nonce, so `PqdrAead` checks at run time, before keeping a context, that writing a key into it gives exactly the context that setting it up with that key would; if not, it sets up a context for every packet instead.

This is best effort: Rust moves values with plain memory copies, so short-lived copies can remain on the stack until overwritten, and the internal state of the BLAKE3 compression in the per-packet derivation is not wiped (the next packet's derivation overwrites it); the derivation's own copy of the chain key is.

### Known Limitations

- **Public key delivery needs traffic**: the client needs at least 19 of the server's first 76 packets of an epoch to rebuild the public key. If the server sends fewer packets than that in an epoch (an idle connection), the next asymmetric ratchet step is delayed until it has.
- **Chain start search is bounded**: if the first 256 packets of an epoch in one direction are all lost, the receiver cannot locate that epoch's chain.

## Performance Considerations

### Measured Overhead

**Per-operation costs**, current version, on a 4-core QEMU VM (SSE4.1, no AVX), measured with `kdf_bench` (each operation repeated in a tight loop):
- **BLAKE3 chain step**: 88ns per packet
- **Packet key written into the AEAD context and wiped after use**: ~3ns per packet (setting up and cleaning up a context for every packet instead: ~10ns)
- **ChaCha20-Poly1305 seal of a 1350-byte packet**: ~1.5μs, the same work as in vanilla QUIC

In a real transfer the caches are colder than in that loop. CPU profiles (`perf`) of the client during a transfer showed about 120ns per packet in the BLAKE3 chain step, and about 58ns per packet for setting up a context per packet, as earlier versions did.

**Per-operation costs**, earlier version, on the author's machine:
- **BLAKE3 key derivation**: ~64ns per packet
- **EVP_AEAD_CTX init/cleanup**: ~186ns per packet (ChaCha20-Poly1305); the context is now set up once per connection, and each packet only writes and wipes its 32-byte key
- **ML-KEM-768 encapsulation**: ~50μs per ratchet (every 60 seconds)
- **Total per-packet overhead**: ~250ns with the per-packet context setup

To measure the per-packet crypto on your own machine, including SHA-2 based alternatives to the BLAKE3 chain step (BoringSSL uses the CPU's SHA extensions when available):

```bash
cargo test --release -p quiche --lib -- --ignored --nocapture kdf_bench
```

**End-to-end performance** (see [Test Results](#test-results)):
- Current version, 4-core VM: 1574 Mbps vanilla, 1514 Mbps PQDR-QUIC, **3.8% overhead**
- Earlier version, author's machine: ~2352 Mbps vanilla, ~2305 Mbps PQDR-QUIC, **~2% overhead**
- CPU time on the VM (5 alternating 4GB transfers): PQDR-QUIC adds about 230ns per packet on the client (receiver), 3.8% of its ~6.0μs per packet, and about 160ns (3.7%) on the server (sender). The client is the bottleneck.

**Memory usage** per connection:
- Ratchet state: ~1.2KB, of which 616 bytes are the AEAD context
- Public key chunks: 76 × 64 bytes (~4.8KB) on the server, 76 slots of 65 bytes (~4.8KB) on the client
- Server: the ML-KEM-768 private key for the next epoch, 7.6KB (BoringSSL's expanded form), from the start of each epoch until the client's ciphertext arrives
- Skipped keys cache: Up to 512 keys for out-of-order packets (16KB of keys, about 45KB of memory when full)

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
- Vanilla: one AEAD key per direction (until a key update); the nonce is computed from the packet number
- PQDR: one BLAKE3 compression per packet to step the key chain, and the packet key written into the connection's AEAD context and wiped after use; the nonce is fixed
- Both encrypt and authenticate every byte with ChaCha20-Poly1305, which takes far longer than PQDR's per-packet key work (~1.5μs against ~90ns for a 1350-byte packet on the VM), so the end-to-end difference is a few percent

### Why PQDR is Efficient

1. **ChaCha20-Poly1305 has zero key schedule**: Unlike AES, ChaCha20 doesn't need key expansion, making per-packet rekeying practical
2. **One BLAKE3 compression per packet**: the 8-byte packet number fits in a single input block, and that one compression's 64 bytes of output are the next chain key and the packet key
3. **One AEAD context per connection**: each packet's key is written into a kept EVP_AEAD_CTX instead of setting up a new one (no allocation or setup per packet)
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
- **Cost**: one BLAKE3 compression per packet (88ns on a 4-core VM, ~64ns on the author's machine)

**Example**: If an attacker compromises the system and extracts the chain key at packet 1,000,000:
- ✓ Can decrypt packet 1,000,000
- ✗ Cannot decrypt packets 1 through 999,999 (forward secrecy)
- ✓ Can decrypt future packets 1,000,001+ until next ML-KEM ratchet (post-compromise recovery needed)

### 3. Post-Compromise Recovery
- **Achieved via**: ML-KEM-768 asymmetric ratchet (every 60 seconds)
- **Property**: Full compromise during epoch N allows decryption until the end of epoch N+1, i.e. for at most two epoch lengths (≤120 seconds by default)
- **Mechanism**: New ML-KEM key exchange introduces fresh entropy not controlled by attacker
- **Coverage**: Protects *future communications after compromise*
- **Also called**: "Future secrecy" or "break-in recovery"
- **Cost**: ~50μs per ratchet

Recovery takes two epochs because the key exchange for epoch N+1 happens during epoch N: the server generates its key pair at the start of epoch N, and the client encapsulates to it at t=55s. An attacker who compromises the server during epoch N obtains that private key (or the resulting shared secret) along with the epoch N keys. The key pair for epoch N+2 is only generated at the start of epoch N+1, after the compromise.

**Example**: Attacker fully compromises the system at T=100s (epoch 1, from 60s to 120s):
- ✓ Can decrypt messages from T=100s to T=120s (epoch 1)
- ✓ Can decrypt messages from T=120s to T=180s (epoch 2, negotiated with the key pair generated at 60s)
- ✗ Cannot decrypt messages after T=180s (epoch 3 uses a key pair generated after the compromise)
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
   Post-Compromise Recovery → Future Safe (within 2 epochs) ✓
```

This matches the security model of secure messaging apps like Signal, applied to transport-layer encryption.

## Future Work

### Completed ✓
- [x] Core double-ratchet implementation
- [x] ML-KEM-768 integration
- [x] BLAKE3 KDF integration
- [x] Packet encryption/decryption with per-packet rekeying
- [x] Performance optimization (~2% overhead on the author's machine)
- [x] Comprehensive performance testing framework (10-run statistical analysis)
- [x] ChaCha20-Poly1305 cipher standardization (fair comparison)
- [x] Bug 4 fix: epoch-transition `recv_chain_pn` sync for in-flight packets
- [x] Regression test suite (`test_epoch_transition_inflight_pn_sync`)
- [x] Robust epoch switches (authenticate before committing, locate chain starts by trial)
- [x] Reed-Solomon coded public key chunks, located by packet number
- [x] Key material wiping
- [x] Benchmark reproducible from a fresh clone (ChaCha20 preference in code, no stored test data)
- [x] No per-packet EVP_AEAD_CTX setup: one context per connection, re-keyed for each packet
- [x] Benchmark runs alternate between vanilla and PQDR-QUIC

### In Progress / Future Enhancements

- [ ] Migration to tokio-quiche (requires boring crate ML-KEM support)
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
| **Recovery Window** | ≤ 2 epochs (120 seconds) | After a full compromise |
| **Public Key Chunks** | 76 × 64 bytes per epoch | Rate-1/4 Reed-Solomon, any 19 suffice |
| **KDF Algorithm** | BLAKE3 | One compression per packet |
| **AEAD Cipher** | ChaCha20-Poly1305 | Zero key schedule cost |
| **Key Size** | 32 bytes (256 bits) | Per-packet encryption key |
| **Nonce** | 12 bytes (96 bits), always zero, never sent | Key rotates every packet so (key, nonce=0) is always a fresh pair |
| **AEAD Tag** | 16 bytes (128 bits) | Authentication tag |
| **UDP Datagram** | 1200 bytes | Minimum MTU size |
| **Effective Payload** | ~1161 bytes | 96.7% efficiency |
| **Overhead** | 2–4% | End-to-end bulk transfer: 3.8% on a 4-core VM (current version), ~2% on the author's machine (earlier version) |
| **Per-packet Cost** | ~90ns key work, ~230ns CPU in a transfer | 4-core VM: BLAKE3 chain step (88ns) and AEAD key write and wipe (~3ns) in a tight loop; about 230ns more client CPU per packet than vanilla in real transfers. Author's machine, earlier version: ~250ns with the AEAD context set up per packet |
| **Per-ratchet Cost** | ~50μs | ML-KEM encapsulation |
| **Memory/Connection** | ~6KB client, ~14KB server | Ratchet state, public key chunks and (server) the next epoch's ML-KEM private key |
| **Skipped Keys Cache** | 512 keys max | ~45KB when full, for out-of-order packets |

---

**Implementation**: Cloudflare quiche with PQDR extensions
**Status**: Functional with production-ready performance
**License**: BSD 2-Clause (same as quiche)
