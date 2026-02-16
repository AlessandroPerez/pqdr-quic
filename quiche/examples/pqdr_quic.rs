// Example demonstrating PQDR-QUIC (Post-Quantum Double-Ratchet QUIC)
//
// This example shows how to enable PQDR-QUIC on both client and server.
// PQDR-QUIC provides post-quantum security using ML-KEM-768 and forward
// secrecy through double-ratcheting.

use quiche;

fn main() {
    // Configure server with PQDR-QUIC enabled
    let mut server_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // Enable PQDR-QUIC extension
    server_config.enable_pqdr_quic(true);

    // Standard QUIC configuration
    server_config.set_application_protos(&[b"h3"]).unwrap();
    server_config.set_max_idle_timeout(5000);
    server_config.set_max_recv_udp_payload_size(1350);
    server_config.set_max_send_udp_payload_size(1350);
    server_config.set_initial_max_data(10_000_000);
    server_config.set_initial_max_stream_data_bidi_local(1_000_000);
    server_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    server_config.set_initial_max_streams_bidi(100);
    server_config.set_initial_max_streams_uni(100);
    server_config.set_disable_active_migration(true);

    println!("Server configured with PQDR-QUIC enabled");
    println!();
    println!("PQDR-QUIC Features:");
    println!("  - ML-KEM-768 for post-quantum key exchange");
    println!("  - Double-ratcheting for forward/backward secrecy");
    println!("  - ChaCha20-Poly1305 AEAD encryption");
    println!("  - BLAKE3-based key derivation");
    println!("  - Automatic ratchet rotation every 2 minutes");
    println!("  - Per-packet key derivation from ratchet chain");
    println!();

    // Similarly configure client
    let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    client_config.enable_pqdr_quic(true);
    client_config.set_application_protos(&[b"h3"]).unwrap();
    // ... (same settings as server)

    println!("Client configured with PQDR-QUIC enabled");
    println!();
    println!("During handshake:");
    println!("  1. Standard TLS 1.3 handshake completes");
    println!("  2. PQDR-QUIC transport parameter is negotiated");
    println!("  3. If both peers support it, PQDR-QUIC is activated");
    println!("  4. Ratchet state is initialized from handshake secret");
    println!("  5. Application packets use ratchet-derived keys");
    println!();
    println!("Ratchet behavior:");
    println!("  - Symmetric ratchet: each packet gets a new encryption key");
    println!("  - Asymmetric ratchet: ML-KEM-768 exchange every 2 minutes");
    println!("  - Client and server alternate initiating ratchets");
    println!("  - Provides forward secrecy and post-compromise security");
}
