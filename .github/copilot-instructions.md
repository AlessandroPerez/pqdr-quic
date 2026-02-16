# Quiche Development Guide

This is a Rust implementation of QUIC transport protocol and HTTP/3 used by Cloudflare and integrated into Android, curl, and other projects.

## Architecture Overview

### Workspace Structure
This is a Cargo workspace with 12 member crates organized by responsibility:
- **quiche/** - Core QUIC and HTTP/3 protocol implementation (low-level API)
- **tokio-quiche/** - Async wrapper bridging quiche with tokio's event loop  
- **apps/** - CLI tools (`quiche-client`, `quiche-server`) for testing (not production-ready)
- **h3i/** - Interactive HTTP/3 debugging/testing tool to bend RFC rules
- **buffer-pool/**, **datagram-socket/** - Performance-oriented I/O utilities
- **qlog/**, **qlog-dancer/** - QUIC event logging per IETF draft specs
- **netlog/**, **octets/** - Supporting protocol utilities
- **task-killswitch/** - Graceful async task cancellation
- **fuzz/** - Fuzzing harnesses (excluded from workspace)

### Key Design Principles
- **Low-level control**: quiche provides packet processing APIs; applications own I/O and event loops
- **Zero config defaults**: Flow control and stream limits default to 0 - applications MUST configure via `set_initial_max_streams_*()` and `set_initial_max_data()` methods
- **BoringSSL dependency**: Uses vendored BoringSSL by default (feature: `boringssl-vendored`), or `boring` crate (feature: `boringssl-boring-crate`)
- **Connection lifecycle**: Apps use `quiche::connect()` for clients, `quiche::accept()` for servers, then drive with `recv()`/`send()` methods

## Development Workflows

### Building & Testing
```bash
# Build all workspace members
cargo build --workspace

# Build client/server apps specifically
cargo build --package=quiche_apps
cargo run --bin quiche-client -- https://cloudflare-quic.com/
cargo run --bin quiche-server -- --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key

# Run tests with specific TLS backend
cargo test --verbose --all-targets --features=boringssl-boring-crate
cargo test --verbose --doc --features=boringssl-boring-crate

# Build with alternative congestion control (gcongestion feature)
cargo build --features=gcongestion
```

### Docker Images
- `make docker-base` - Builds base quiche image
- `make docker-qns` - Builds QNS interop testing image
- `make docker-fuzz` - Builds fuzzing image with nightly toolchain

### Fuzzing
```bash
cargo +nightly fuzz build --release --debug-assertions packet_recv_client
# See fuzz/ directory for corpus and harnesses
```

## Code Conventions

### Error Handling Pattern
Use `quiche::Result<T>` which wraps `Result<T, quiche::Error>`. The `Error::Done` variant signals "no more work" rather than failure:
```rust
match conn.recv(&mut buf[..read], recv_info) {
    Ok(v) => v,
    Err(quiche::Error::Done) => break, // Not an error - done processing
    Err(e) => // Handle actual error
}
```

### Logging
Uses `log` crate macros (`trace!`, `debug!`, `warn!`, `error!`). Enable with `RUST_LOG=debug` environment variable.

### Code Style
- **rustfmt**: Max width 82 chars, vertical imports, wide type punctuation (enforced via [rustfmt.toml](../rustfmt.toml))
- **clippy**: Cognitive complexity threshold of 100 (see [clippy.toml](../clippy.toml))
- **Tests**: Located in `#[cfg(test)] mod tests` blocks within source files, not separate test directories

### Stream & Connection State
- Streams can be in invalid states - always check with connection methods before operations
- Use `conn.readable()` iterator to discover streams with data, then `stream_recv()` to read
- `stream_send()` with `fin=true` signals stream end per QUIC spec

## Integration Patterns

### Async with Tokio
Use `tokio-quiche` for production async applications. It manages:
- Connection to tokio event loop via `H3Driver` or custom `ApplicationOverQuic` trait
- Buffer pooling with `BufFactory` trait for zero-copy operations
- HTTP/3 via `ServerH3Driver`/`ClientH3Driver` with `ServerH3Controller`/`ClientH3Controller`

Example server pattern:
```rust
let (driver, controller) = ServerH3Driver::new(Http3Settings::default());
conn?.start(driver);
tokio::spawn(handle_connection(controller));
```

### HTTP/3 Layer
The `quiche::h3` module provides high-level HTTP/3 over QUIC transport:
- `send_request()`/`send_response()` for headers
- `send_body()`/`recv_body()` for streaming data
- Requires properly configured QUIC `Config` with ALPN set to `h3`

### C/FFI Boundary
Enable `ffi` feature to expose C API in `include/quiche.h`. Produces `libquiche.a` static library. See [quiche/examples/](../quiche/examples/) for C usage.

## Common Pitfalls

1. **Forgetting to configure flow control**: Set `initial_max_*` limits or connections will stall
2. **Not handling `Error::Done`**: This is normal return value, not an error
3. **Ignoring pacing hints**: Use `SendInfo.at` field for packet pacing to avoid bursts
4. **Using apps/ binaries in production**: They're examples only - see disclaimers in README

## Key Files
- [quiche/src/lib.rs](../quiche/src/lib.rs) - Main QUIC connection API
- [quiche/src/h3/mod.rs](../quiche/src/h3/mod.rs) - HTTP/3 implementation
- [tokio-quiche/src/](../tokio-quiche/src/) - Async tokio integration
- [apps/src/bin/](../apps/src/bin/) - Reference client/server implementations
