// Copyright (C) 2026, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! End-to-end PQDR-QUIC tests over an in-memory client/server pipe.
//!
//! Epochs are shortened with `Config::set_pqdr_ratchet_interval` so several
//! asymmetric ratchet steps happen within a test. The ratchet uses wall-clock
//! time, so these tests sleep briefly between rounds.

use super::*;

use std::collections::HashMap;

use crate::test_utils;
use crate::test_utils::Pipe;

/// Bytes each side writes to stream 0 per round.
const ROUND_DATA: usize = 1000;

fn pqdr_config(interval: Duration) -> Config {
    let mut config = Config::new(PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config.set_application_protos(&[b"proto1"]).unwrap();
    config.set_initial_max_data(1 << 30);
    config.set_initial_max_stream_data_bidi_local(1 << 30);
    config.set_initial_max_stream_data_bidi_remote(1 << 30);
    config.set_initial_max_streams_bidi(10);
    config.set_max_idle_timeout(180_000);
    config.verify_peer(false);
    config.enable_pqdr_quic(true);
    config.set_pqdr_ratchet_interval(interval);
    config
}

fn pqdr_pipe(interval: Duration) -> Pipe {
    let mut config = pqdr_config(interval);
    let mut pipe = Pipe::with_config(&mut config).unwrap();
    assert_eq!(pipe.handshake(), Ok(()));
    pipe
}

fn epoch(conn: &Connection) -> u32 {
    conn.ratchet_state.as_ref().unwrap().epoch()
}

/// Bytes written to and read from stream 0 on each side.
#[derive(Default)]
struct Counts {
    client_tx: usize,
    client_rx: usize,
    server_tx: usize,
    server_rx: usize,
}

fn drain(conn: &mut Connection) -> usize {
    let mut buf = [0; 65535];
    let mut total = 0;

    while let Ok((read, _)) = conn.stream_recv(0, &mut buf) {
        total += read;
    }

    total
}

fn deliver(conn: &mut Connection, pkts: Vec<(Vec<u8>, SendInfo)>) {
    test_utils::process_flight(conn, pkts).unwrap();
}

/// Like `Pipe::advance()`, but limits the size of client packets.
fn advance(pipe: &mut Pipe, client_mtu: usize) {
    loop {
        let mut idle = true;

        match test_utils::emit_flight_with_max_buffer(
            &mut pipe.client,
            client_mtu,
            None,
            None,
        ) {
            Ok(flight) => {
                idle = false;
                deliver(&mut pipe.server, flight);
            },

            Err(Error::Done) => (),

            Err(e) => panic!("client send failed: {e:?}"),
        }

        match test_utils::emit_flight(&mut pipe.server) {
            Ok(flight) => {
                idle = false;
                deliver(&mut pipe.client, flight);
            },

            Err(Error::Done) => (),

            Err(e) => panic!("server send failed: {e:?}"),
        }

        if idle {
            return;
        }
    }
}

/// Each side writes `ROUND_DATA` bytes on stream 0, everything is
/// delivered, and each side reads what it received.
fn round(pipe: &mut Pipe, counts: &mut Counts, client_mtu: usize) {
    let data = [0x5a; ROUND_DATA];

    counts.client_tx += pipe.client.stream_send(0, &data, false).unwrap();
    advance(pipe, client_mtu);
    counts.server_rx += drain(&mut pipe.server);

    counts.server_tx += pipe.server.stream_send(0, &data, false).unwrap();
    advance(pipe, client_mtu);
    counts.client_rx += drain(&mut pipe.client);
}

/// Runs rounds until the server reaches `target` epoch, then a few more so
/// the client catches up.
fn run_until_epoch(
    pipe: &mut Pipe, counts: &mut Counts, target: u32, client_mtu: usize,
) {
    let deadline = Instant::now() + Duration::from_secs(60);

    while epoch(&pipe.server) < target {
        assert!(
            Instant::now() < deadline,
            "stuck at server epoch {} (client epoch {})",
            epoch(&pipe.server),
            epoch(&pipe.client)
        );

        round(pipe, counts, client_mtu);
        std::thread::sleep(Duration::from_millis(1));
    }

    for _ in 0..3 {
        round(pipe, counts, client_mtu);
    }
}

fn assert_healthy(pipe: &Pipe, counts: &Counts) {
    assert!(pipe.client.pqdr_quic_enabled && pipe.server.pqdr_quic_enabled);
    assert_eq!(pipe.client.local_error(), None);
    assert_eq!(pipe.server.local_error(), None);
    assert_eq!(pipe.client.peer_error(), None);
    assert_eq!(pipe.server.peer_error(), None);
    assert_eq!(counts.server_rx, counts.client_tx);
    assert_eq!(counts.client_rx, counts.server_tx);
}

/// Runs rounds until the server has the client's ciphertext and is about
/// to switch epochs, then waits for the switch time to pass. The server's
/// next 1-RTT packet switches epochs.
fn wait_for_imminent_switch(pipe: &mut Pipe, counts: &mut Counts) {
    let deadline = Instant::now() + Duration::from_secs(60);

    while pipe.server.pqdr_key_activation_time.is_none() {
        assert!(Instant::now() < deadline, "server never got a ciphertext");

        round(pipe, counts, 65535);
        std::thread::sleep(Duration::from_millis(1));
    }

    let switch_at = pipe.server.pqdr_key_activation_time.unwrap();
    std::thread::sleep(switch_at.saturating_duration_since(Instant::now()));
}

#[test]
fn pqdr_epochs_advance() {
    let mut pipe = pqdr_pipe(Duration::from_millis(150));
    let mut counts = Counts::default();

    run_until_epoch(&mut pipe, &mut counts, 3, 65535);

    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_survives_crypto_stream_offset_limit() {
    // The client sends one 1088-byte ciphertext per epoch on its 1-RTT
    // CRYPTO stream, which crosses quiche's 64 KiB CRYPTO stream offset
    // limit after ~60 epochs (about an hour with 60-second epochs).
    let mut pipe = pqdr_pipe(Duration::from_millis(60));
    let mut counts = Counts::default();

    let epochs_to_limit = (MAX_CRYPTO_STREAM_OFFSET as usize)
        .div_ceil(crypto::ratchet::MLKEM768_CIPHERTEXT_SIZE)
        as u32;

    run_until_epoch(&mut pipe, &mut counts, epochs_to_limit + 2, 65535);

    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_ciphertext_split_across_packets() {
    // With small client packets, the 1088-byte ciphertext is split over
    // several CRYPTO frames.
    let mut pipe = pqdr_pipe(Duration::from_millis(150));
    let mut counts = Counts::default();

    run_until_epoch(&mut pipe, &mut counts, 2, 600);

    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_handshake_done_lost() {
    // The server switches to ratchet keys right after sending
    // HANDSHAKE_DONE. If that packet is lost, the client must still accept
    // the ratchet-protected packets that follow (including the one that
    // retransmits HANDSHAKE_DONE).
    let mut config = pqdr_config(Duration::from_secs(60));
    let mut pipe = Pipe::with_config(&mut config).unwrap();

    loop {
        let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
        deliver(&mut pipe.server, flight);

        if pipe.server.is_established() {
            break;
        }

        let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
        deliver(&mut pipe.client, flight);
    }

    let lost = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert!(pipe.server.handshake_done_sent);
    drop(lost);

    assert!(!pipe.client.handshake_confirmed);

    pipe.client.stream_send(0, b"ping", true).unwrap();
    advance(&mut pipe, 65535);

    let mut buf = [0; 16];
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Ok((4, true)));

    pipe.server.stream_send(0, b"pong", true).unwrap();
    advance(&mut pipe, 65535);

    assert_eq!(pipe.client.stream_recv(0, &mut buf), Ok((4, true)));
    assert_eq!(&buf[..4], b"pong");
    assert!(pipe.client.pqdr_ratchet_ready);
}

#[test]
fn pqdr_tampered_packets_rejected() {
    // Corrupted copies of a packet must be rejected cheaply and must not
    // stop the genuine packet from being accepted afterwards.
    let mut pipe = pqdr_pipe(Duration::from_secs(60));
    let mut counts = Counts::default();

    // Get well into ratchet-protected traffic. By now the client also has
    // the server's next public key, so it is waiting for an epoch switch.
    for _ in 0..30 {
        round(&mut pipe, &mut counts, 65535);
    }

    assert!(pipe.client.pqdr_peer_first_pn.is_some());
    assert!(pipe.client.ratchet_state.as_ref().unwrap().has_precomputed_keys());

    pipe.server.stream_send(0, b"genuine", false).unwrap();
    let flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert_eq!(flight.len(), 1);

    let (pkt, info) = &flight[0];

    // Short header: first byte, then the client's connection ID, then the
    // packet number (all but the connection ID under header protection).
    let pn_off = 1 + pipe.client.source_id().len();

    let tampering = [
        (0, 0x04),                // key phase bit
        (0, 0x03),                // packet number length
        (pn_off, 0x80),           // packet number
        (pkt.len() - 1, 0x01),    // AEAD tag
        (pkt.len() / 2, 0x10),    // ciphertext
    ];

    for (off, mask) in tampering {
        let mut bad = pkt.clone();
        bad[off] ^= mask;

        let recv_info = RecvInfo {
            to: info.to,
            from: info.from,
        };

        let start = Instant::now();
        assert!(pipe.client.recv(&mut bad, recv_info).is_ok());
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "tampered packet (offset {off}, mask {mask:#x}) took {:?}",
            start.elapsed()
        );
    }

    assert_eq!(epoch(&pipe.client), 0);

    let recv_count = pipe.client.recv_count;
    deliver(&mut pipe.client, flight);
    assert_eq!(pipe.client.recv_count, recv_count + 1);

    let mut buf = [0; 16];
    assert_eq!(pipe.client.stream_recv(0, &mut buf), Ok((7, false)));
    assert_eq!(&buf[..7], b"genuine");

    round(&mut pipe, &mut counts, 65535);
    counts.client_rx += 7;
    counts.server_tx += 7;
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_tls_keys_rejected_after_switch() {
    // Once the peer uses ratchet keys, a packet protected with the TLS keys
    // (as an attacker who stole the TLS secrets could produce) is rejected.
    let mut pipe = pqdr_pipe(Duration::from_secs(60));
    let mut counts = Counts::default();

    for _ in 0..5 {
        round(&mut pipe, &mut counts, 65535);
    }

    assert!(pipe.server.pqdr_peer_first_pn.is_some());

    // Build a TLS-protected packet from the client, as quiche would without
    // PQDR.
    pipe.client.pqdr_quic_enabled = false;
    pipe.client.stream_send(0, b"forged", false).unwrap();
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    pipe.client.pqdr_quic_enabled = true;

    let recv_count = pipe.server.recv_count;
    deliver(&mut pipe.server, flight);
    assert_eq!(pipe.server.recv_count, recv_count);

    let mut buf = [0; 16];
    assert_eq!(pipe.server.stream_recv(0, &mut buf), Err(Error::Done));
}

#[test]
fn pqdr_client_packet_lost_at_epoch_switch() {
    // The client's last packet before it sees the server's epoch switch is
    // lost, so the server can't tell where the client's new-epoch chain
    // starts from the packets it received.
    let mut pipe = pqdr_pipe(Duration::from_millis(300));
    let mut counts = Counts::default();

    wait_for_imminent_switch(&mut pipe, &mut counts);

    pipe.server.stream_send(0, &[1; 100], false).unwrap();
    counts.server_tx += 100;
    let switch_flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert_eq!(epoch(&pipe.server), 1);

    pipe.client.stream_send(0, &[2; 100], false).unwrap();
    let lost = test_utils::emit_flight(&mut pipe.client).unwrap();
    drop(lost);

    deliver(&mut pipe.client, switch_flight);
    assert_eq!(epoch(&pipe.client), 1);
    counts.client_rx += drain(&mut pipe.client);

    // The client's first new-epoch packets. (The stream data in them can't
    // be read until the lost data is retransmitted, so count packets.)
    pipe.client.stream_send(0, &[2; 100], false).unwrap();
    let flight = test_utils::emit_flight(&mut pipe.client).unwrap();
    let sent = flight.len();

    let recv_count = pipe.server.recv_count;
    deliver(&mut pipe.server, flight);
    assert_eq!(pipe.server.recv_count, recv_count + sent);

    // Later epochs still work in both directions, and the lost data is
    // retransmitted.
    run_until_epoch(&mut pipe, &mut counts, 3, 65535);
    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));

    counts.client_tx += 200;
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_packets_reordered_across_epoch_switch() {
    // The server's first new-epoch packets arrive in reverse order, and an
    // old-epoch packet arrives after all of them. Every packet must still
    // decrypt.
    let mut pipe = pqdr_pipe(Duration::from_millis(300));
    let mut counts = Counts::default();

    wait_for_imminent_switch(&mut pipe, &mut counts);

    // Sent just before the switch: an old-epoch packet, delivered late.
    // (The switch time has passed, but the switch happens on the next
    // send, which is this one; so send it before the timer check instead.)
    let switch_at = pipe.server.pqdr_key_activation_time.take();
    pipe.server.stream_send(0, &[3; 100], false).unwrap();
    counts.server_tx += 100;
    let late = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert_eq!(epoch(&pipe.server), 0);
    pipe.server.pqdr_key_activation_time = switch_at;

    pipe.server.stream_send(0, &[4; 3000], false).unwrap();
    counts.server_tx += 3000;
    let mut switch_flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert_eq!(epoch(&pipe.server), 1);
    assert!(switch_flight.len() >= 3);

    switch_flight.reverse();

    let delivered = switch_flight.len() + late.len();
    let recv_count = pipe.client.recv_count;

    deliver(&mut pipe.client, switch_flight);
    assert_eq!(epoch(&pipe.client), 1);
    deliver(&mut pipe.client, late);

    assert_eq!(pipe.client.recv_count, recv_count + delivered);

    counts.client_rx += drain(&mut pipe.client);

    run_until_epoch(&mut pipe, &mut counts, 3, 65535);
    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_server_switch_packet_lost() {
    // The server's first new-epoch packet is lost. The client finds the new
    // chain's start from the next packet, and from it which public key
    // chunk each packet carries.
    let mut pipe = pqdr_pipe(Duration::from_millis(300));
    let mut counts = Counts::default();

    wait_for_imminent_switch(&mut pipe, &mut counts);

    pipe.server.stream_send(0, &[5; 3000], false).unwrap();
    counts.server_tx += 3000;
    let mut switch_flight = test_utils::emit_flight(&mut pipe.server).unwrap();
    assert_eq!(epoch(&pipe.server), 1);
    assert!(switch_flight.len() >= 2);

    switch_flight.remove(0);
    deliver(&mut pipe.client, switch_flight);
    assert_eq!(epoch(&pipe.client), 1);
    counts.client_rx += drain(&mut pipe.client);

    run_until_epoch(&mut pipe, &mut counts, 3, 65535);
    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

/// Like `advance()`, but drops the server packets for which `lose` returns
/// true. `lose` is given the server's epoch and the index of the public key
/// chunk the packet carries, if any.
fn advance_lossy(
    pipe: &mut Pipe, lose: &mut impl FnMut(u32, Option<usize>) -> bool,
) {
    loop {
        let mut idle = true;

        match test_utils::emit_flight(&mut pipe.client) {
            Ok(flight) => {
                idle = false;
                deliver(&mut pipe.server, flight);
            },

            Err(Error::Done) => (),

            Err(e) => panic!("client send failed: {e:?}"),
        }

        let mut flight = Vec::new();

        loop {
            let mut out = vec![0; 65535];

            match pipe.server.send(&mut out) {
                Ok((len, info)) => {
                    idle = false;
                    out.truncate(len);

                    let ratchet = pipe.server.ratchet_state.as_ref().unwrap();

                    if !lose(ratchet.epoch(), ratchet.last_sent_chunk_index()) {
                        flight.push((out, info));
                    }
                },

                Err(Error::Done) => break,

                Err(e) => panic!("server send failed: {e:?}"),
            }
        }

        if !flight.is_empty() {
            deliver(&mut pipe.client, flight);
        }

        for conn in [&mut pipe.client, &mut pipe.server] {
            if conn.timeout().is_some_and(|t| t.is_zero()) {
                conn.on_timeout();
                idle = false;
            }
        }

        if idle {
            return;
        }
    }
}

/// Like `round()`, with `advance_lossy()`. After heavy loss, the congestion
/// window may leave no room for new data in a round.
fn round_lossy(
    pipe: &mut Pipe, counts: &mut Counts,
    lose: &mut impl FnMut(u32, Option<usize>) -> bool,
) {
    let data = [0x5a; ROUND_DATA];

    let send = |conn: &mut Connection| match conn.stream_send(0, &data, false) {
        Ok(written) => written,

        Err(Error::Done) => 0,

        Err(e) => panic!("stream_send failed: {e:?}"),
    };

    counts.client_tx += send(&mut pipe.client);
    advance_lossy(pipe, lose);
    counts.server_rx += drain(&mut pipe.server);

    counts.server_tx += send(&mut pipe.server);
    advance_lossy(pipe, lose);
    counts.client_rx += drain(&mut pipe.client);
}

#[test]
fn pqdr_public_key_survives_chunk_loss() {
    // In every epoch, about three of every four of the server's packets
    // carrying public key chunks are lost, leaving exactly the minimum
    // number of chunks, mostly parity ones. The client must still rebuild
    // every public key.
    let mut pipe = pqdr_pipe(Duration::from_millis(200));
    let mut counts = Counts::default();

    let needed = crypto::ratchet::PUBKEY_CHUNK_COUNT;
    let coded = crypto::ratchet::PUBKEY_CODED_CHUNK_COUNT;

    let mut kept = HashMap::<u32, usize>::new();
    let mut lost = HashMap::<u32, usize>::new();

    // Keep every fourth chunk. The server occasionally skips a pn (see
    // `should_skip_pn()`), and with it a chunk, so near the end of the window
    // keep whatever it takes to still deliver exactly `needed` chunks.
    let mut lose = |epoch: u32, chunk: Option<usize>| {
        let Some(index) = chunk else {
            return false;
        };

        let kept = kept.entry(epoch).or_default();
        let left = coded - index; // including this one

        let keep =
            *kept < needed && (index % 4 == 3 || left <= needed - *kept + 8);

        if keep {
            *kept += 1;
        } else {
            *lost.entry(epoch).or_default() += 1;
        }

        !keep
    };

    let deadline = Instant::now() + Duration::from_secs(60);

    while epoch(&pipe.server) < 3 {
        assert!(
            Instant::now() < deadline,
            "stuck at server epoch {} (client epoch {})",
            epoch(&pipe.server),
            epoch(&pipe.client)
        );

        round_lossy(&mut pipe, &mut counts, &mut lose);
        std::thread::sleep(Duration::from_millis(1));
    }

    // Each completed epoch delivered only the minimum number of chunks.
    for e in 0..3 {
        assert_eq!(kept.get(&e), Some(&needed), "epoch {e}");
        assert!(lost[&e] >= coded / 2, "epoch {e}: {lost:?}");
    }

    // Without loss, all data gets through once the congestion window has
    // recovered.
    let deadline = Instant::now() + Duration::from_secs(10);

    while counts.client_rx != counts.server_tx ||
        counts.server_rx != counts.client_tx
    {
        assert!(Instant::now() < deadline, "data still missing");

        round_lossy(&mut pipe, &mut counts, &mut |_, _| false);
        std::thread::sleep(Duration::from_millis(1));
    }

    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn pqdr_first_ratchet_packets_lost() {
    // The server's first ratchet-protected packets are lost, so the client
    // has to find where the server's epoch-0 chain starts (and so which
    // packets carry public key chunks) from later ones.
    let mut pipe = pqdr_pipe(Duration::from_millis(200));
    let mut counts = Counts::default();

    let mut lost = 0;

    let mut lose = |epoch: u32, chunk: Option<usize>| {
        let lose = epoch == 0 && chunk.is_some_and(|index| index < 3);

        if lose {
            lost += 1;
        }

        lose
    };

    for _ in 0..5 {
        round_lossy(&mut pipe, &mut counts, &mut lose);
    }

    assert_eq!(lost, 3);

    run_until_epoch(&mut pipe, &mut counts, 2, 65535);
    assert_eq!(epoch(&pipe.client), epoch(&pipe.server));
    assert_healthy(&pipe, &counts);
}

#[test]
fn chacha20_preference() {
    // With the preference on both endpoints, ChaCha20-Poly1305 is negotiated
    // even on CPUs with AES instructions (so plain QUIC uses the same cipher
    // as PQDR-QUIC payloads).
    for pqdr in [false, true] {
        let mut config = pqdr_config(Duration::from_secs(60));
        config.enable_pqdr_quic(pqdr);
        config.enable_chacha20_preference(true);

        let mut pipe = Pipe::with_config(&mut config).unwrap();
        assert_eq!(pipe.handshake(), Ok(()));

        assert_eq!(
            pipe.client.handshake.cipher(),
            Some(crypto::Algorithm::ChaCha20_Poly1305)
        );
        assert_eq!(
            pipe.server.handshake.cipher(),
            Some(crypto::Algorithm::ChaCha20_Poly1305)
        );
    }
}
