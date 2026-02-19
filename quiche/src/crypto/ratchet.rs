// Copyright (C) 2024, Cloudflare, Inc.
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
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY TORTIOUS ACTION, ARISING OUT OF OR
// IN CONNECTION WITH THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

//! Double-ratchet implementation for PQDR-QUIC
//!
//! Key design:
//! - Epoch 0: chain keys derived from TLS handshake secret
//! - Per-packet key: `H(chain_key_{pn-1}, pn)` → (new_chain_key, enc_key)
//! - Epoch N≥1: chain keys derived from `KDF(kem_shared_secret, starting_pn)`
//! - Server sends ML-KEM-768 pubkey in first 19 packets of every epoch
//! - Client sends encapsulated ciphertext via CRYPTO frame at t=55s
//! - Epoch activates at t=60s; old epoch keys retained 5 seconds for reordering
//!
//! Chain advancement:
//!   send side: advance chain from `send_chain_pn` to target pn, returning enc_key
//!              (QUIC never retransmits the same pn, so no caching is needed)
//!   recv side: advance chain storing skipped keys for out-of-order packets

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::crypto::blake3_kdf::{self, BLAKE3_OUT_LEN};
use crate::crypto::boringssl::{
    MLKEM768_private_key, MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES,
};
use crate::Error;
use crate::Result;

/// Ratchet epoch number
pub type RatchetEpoch = u32;

/// Type of KEM chunk being transmitted
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkType {
    PublicKey,
    Ciphertext,
}

/// Maximum number of skipped receive keys to cache (out-of-order delivery)
const MAX_SKIP: usize = 512;

/// KEM chunk size in bytes (embedded in packet plaintext prefix)
pub const KEM_CHUNK_SIZE: usize = 64;

/// ML-KEM-768 public key size (1184 bytes)
pub const MLKEM768_PUBLIC_KEY_SIZE: usize = MLKEM768_PUBLIC_KEY_BYTES;

/// ML-KEM-768 ciphertext size (1088 bytes)
pub const MLKEM768_CIPHERTEXT_SIZE: usize = MLKEM768_CIPHERTEXT_BYTES;

/// Number of 64-byte chunks needed for the ML-KEM-768 public key (1184 / 64 = 19 chunks)
pub const PUBKEY_CHUNK_COUNT: usize =
    (MLKEM768_PUBLIC_KEY_BYTES + KEM_CHUNK_SIZE - 1) / KEM_CHUNK_SIZE;

/// Number of 64-byte chunks needed for ML-KEM-768 ciphertext (1088 bytes, sent via CRYPTO frame)
pub const CIPHERTEXT_CHUNK_COUNT: usize =
    (MLKEM768_CIPHERTEXT_BYTES + KEM_CHUNK_SIZE - 1) / KEM_CHUNK_SIZE;

/// Epoch length: 60 seconds
pub const RATCHET_INTERVAL_MS: u64 = 60 * 1000;

/// Client sends KEM ciphertext 5 seconds before epoch boundary
pub const CLIENT_RESPONSE_TIME_MS: u64 = 55 * 1000;

/// Old epoch state kept this long after epoch transition for reordered packets
const OLD_EPOCH_RETENTION_MS: u64 = 5 * 1000;

// ---------------------------------------------------------------------------
// Retained previous-epoch receive state (5-second TTL)
// ---------------------------------------------------------------------------

struct PrevEpochRecv {
    epoch: RatchetEpoch,
    /// Chain key for the previous epoch (used to derive any not-yet-skipped keys)
    chain_key: [u8; BLAKE3_OUT_LEN],
    /// Next pn the chain would advance to
    chain_pn: u64,
    /// Already-skipped keys from the previous epoch
    skipped: HashMap<u64, [u8; BLAKE3_OUT_LEN]>,
    expires: Instant,
}

// ---------------------------------------------------------------------------
// Pre-computed epoch state (activated at t=60s)
// ---------------------------------------------------------------------------

struct PrecomputedEpoch {
    epoch: RatchetEpoch,
    /// Raw KEM shared secret — chain keys are derived at activation time,
    /// because we don't know `starting_pn` until the first packet is sent/received.
    shared_secret: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Pending asymmetric ratchet exchange state
// ---------------------------------------------------------------------------

enum PendingRatchet {
    /// We initiated (server): waiting for client's ciphertext
    WaitingForCiphertext {
        our_private_key: MLKEM768_private_key,
        epoch: RatchetEpoch,
    },
    /// They initiated (client): we've encapsulated and stored ciphertext for sending
    WaitingToActivate {
        epoch: RatchetEpoch,
    },
}

// ---------------------------------------------------------------------------
// Main ratchet state
// ---------------------------------------------------------------------------

pub struct RatchetState {
    /// True if we are the server (server always initiates ratchets)
    is_server: bool,

    /// Current ratchet epoch
    epoch: RatchetEpoch,

    // --- Send chain ---
    /// Current send chain key (carry-forward; only the latest is kept)
    send_chain_key: [u8; BLAKE3_OUT_LEN],
    /// Next pn the send chain is ready to advance to
    send_chain_pn: u64,

    // --- Receive chain ---
    /// Current receive chain key
    recv_chain_key: [u8; BLAKE3_OUT_LEN],
    /// Next pn the receive chain is ready to advance to
    recv_chain_pn: u64,
    /// Skipped receive keys: (epoch, pn) → enc_key
    skipped_recv_keys: HashMap<(RatchetEpoch, u64), [u8; BLAKE3_OUT_LEN]>,
    /// Insertion-order queue for LRU eviction of `skipped_recv_keys`
    skipped_recv_queue: VecDeque<(RatchetEpoch, u64)>,

    // --- Previous epoch retention ---
    /// Retain previous epoch receive state for 5 seconds after transition
    prev_epoch_recv: Option<PrevEpochRecv>,

    // --- KEM state ---
    pending_ratchet: Option<PendingRatchet>,

    /// Incoming pubkey chunks being assembled (packet_number → 64-byte chunk)
    incoming_pubkey_chunks: HashMap<u64, Vec<u8>>,

    /// Outgoing KEM chunks queued for embedding in packet plaintext
    outgoing_chunks: Option<Vec<Vec<u8>>>,
    next_chunk_to_send: usize,

    /// Client: ciphertext ready to send via CRYPTO frame at t=55s
    pending_ciphertext_response: Option<(RatchetEpoch, Vec<u8>)>,
    ciphertext_send_time: Option<Instant>,

    /// Pre-computed next epoch (activated at t=60s)
    precomputed_next_epoch: Option<PrecomputedEpoch>,

    // --- Timing ---
    /// When to fire next ratchet initiation (server: immediately at start of each epoch)
    next_ratchet_time: Option<Instant>,
    /// True if server, false if client (determines who calls initiate_ratchet)
    we_initiate_next: bool,

    // --- Epoch packet counters (reset at epoch boundaries) ---
    /// Received packets in current epoch — used to detect first PUBKEY_CHUNK_COUNT packets
    recv_epoch_packet_count: u64,
    /// Sent packets in current epoch
    send_epoch_packet_count: u64,
}

// ---------------------------------------------------------------------------
// Debug helper
// ---------------------------------------------------------------------------

fn hex_short(key: &[u8; BLAKE3_OUT_LEN]) -> String {
    key[..8].iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl RatchetState {
    /// Initialize ratchet from TLS handshake shared secret.
    ///
    /// `is_client` determines chain orientation:
    /// - Client send chain == Server recv chain
    /// - Server send chain == Client recv chain
    pub fn from_handshake_secret(handshake_secret: &[u8], is_client: bool) -> Self {
        let root_key = blake3_kdf::init_root_key_from_handshake(handshake_secret);

        // derive_initial_chain_keys returns (chain_A, chain_B)
        // Client uses chain_A as send, chain_B as recv
        // Server swaps so server-send == client-recv
        let (send_chain_key, recv_chain_key) = if is_client {
            let (a, b) = blake3_kdf::derive_initial_chain_keys(&root_key);
            (a, b)
        } else {
            let (a, b) = blake3_kdf::derive_initial_chain_keys(&root_key);
            (b, a) // server swaps
        };

        let is_server = !is_client;

        // Server: initiate ratchet immediately (sends pubkey in first 19 packets of epoch 0)
        // Client: set timer for epoch boundary so ciphertext_send_time can be calculated
        let next_ratchet_time = if is_server {
            Some(Instant::now()) // Server fires immediately
        } else {
            Some(Instant::now() + Duration::from_millis(RATCHET_INTERVAL_MS)) // used for timing only
        };

        let state = RatchetState {
            is_server,
            epoch: 0,
            send_chain_key,
            send_chain_pn: 0,
            recv_chain_key,
            recv_chain_pn: 0,
            skipped_recv_keys: HashMap::new(),
            skipped_recv_queue: VecDeque::new(),
            prev_epoch_recv: None,
            pending_ratchet: None,
            incoming_pubkey_chunks: HashMap::new(),
            outgoing_chunks: None,
            next_chunk_to_send: 0,
            pending_ciphertext_response: None,
            ciphertext_send_time: None,
            precomputed_next_epoch: None,
            next_ratchet_time,
            we_initiate_next: is_server, // server always initiates
            recv_epoch_packet_count: 0,
            send_epoch_packet_count: 0,
        };

        eprintln!(
            "[PQDR] Epoch 0 initialized ({}): starting_pn=0 send_chain={} recv_chain={}",
            if is_client { "client" } else { "server" },
            hex_short(&state.send_chain_key),
            hex_short(&state.recv_chain_key),
        );

        state
    }

    // -----------------------------------------------------------------------
    // Ratchet initiation / response
    // -----------------------------------------------------------------------

    /// True if it's time for the server to initiate a new asymmetric ratchet step.
    pub fn should_initiate_ratchet(&self) -> bool {
        if !self.we_initiate_next {
            return false;
        }
        if self.pending_ratchet.is_some() {
            return false;
        }
        match self.next_ratchet_time {
            Some(t) => Instant::now() >= t,
            None => false,
        }
    }

    /// Server: generate ML-KEM keypair, queue pubkey chunks for first 19 packets.
    pub fn initiate_ratchet(&mut self) -> Result<RatchetEpoch> {
        if !self.we_initiate_next || self.pending_ratchet.is_some() {
            return Err(Error::InvalidState);
        }

        let next_epoch = self.epoch + 1;
        let (private_key, public_key_bytes) = MLKEM768_private_key::generate();

        self.prepare_outgoing_chunks(&public_key_bytes);

        self.pending_ratchet = Some(PendingRatchet::WaitingForCiphertext {
            our_private_key: private_key,
            epoch: next_epoch,
        });

        Ok(next_epoch)
    }

    /// Client: assemble server pubkey, encapsulate, schedule ciphertext send at t=55s.
    pub fn respond_to_ratchet(
        &mut self,
        epoch: RatchetEpoch,
        their_pubkey_bytes: &[u8],
    ) -> Result<RatchetEpoch> {
        if self.we_initiate_next {
            return Err(Error::InvalidState);
        }
        if epoch != self.epoch + 1 {
            return Err(Error::InvalidState);
        }

        // Encapsulate to server's pubkey → (shared_secret, ciphertext)
        let (shared_secret, ciphertext) =
            MLKEM768_private_key::encapsulate_to_bytes(their_pubkey_bytes)?;

        // Pre-compute the next epoch keys now using the shared secret.
        // Chain keys are derived at activation time (we don't know starting_pn yet).
        self.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch,
            shared_secret: shared_secret.to_vec(),
        });

        self.pending_ratchet = Some(PendingRatchet::WaitingToActivate { epoch });

        // Schedule ciphertext send at t=55s (5s before epoch boundary)
        self.pending_ciphertext_response = Some((epoch, ciphertext));
        if let Some(next_ratchet) = self.next_ratchet_time {
            self.ciphertext_send_time = Some(
                next_ratchet - Duration::from_millis(
                    RATCHET_INTERVAL_MS - CLIENT_RESPONSE_TIME_MS
                ),
            );
        } else {
            // Fallback: send 5s from now
            self.ciphertext_send_time =
                Some(Instant::now() + Duration::from_millis(CLIENT_RESPONSE_TIME_MS));
        }

        Ok(epoch)
    }

    /// Server: receive client ciphertext, decapsulate, store shared secret.
    /// Chain keys derived at activation time (t=60s) once starting_pn is known.
    pub fn store_and_precompute_from_ciphertext(
        &mut self,
        epoch: RatchetEpoch,
        ciphertext: &[u8],
    ) -> Result<()> {
        let private_key = match self.pending_ratchet.as_ref() {
            Some(PendingRatchet::WaitingForCiphertext {
                our_private_key,
                epoch: expected_epoch,
            }) if epoch == *expected_epoch => {
                // Decapsulate: get shared secret
                our_private_key.decapsulate(ciphertext)?
            },
            _ => return Err(Error::InvalidState),
        };

        self.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch,
            shared_secret: private_key.to_vec(),
        });

        Ok(())
    }

    /// Activate precomputed epoch keys.
    ///
    /// `starting_pn`: the first QUIC packet number of the new epoch.
    /// Both send and receive chains start from this pn.
    pub fn activate_precomputed_epoch(&mut self, starting_pn: u64) -> Result<()> {
        let pre = self.precomputed_next_epoch.take()
            .ok_or(Error::InvalidState)?;

        // Derive chain keys, binding them to the starting_pn of this epoch
        let (chain_a, chain_b) =
            blake3_kdf::derive_epoch_chain_keys(&pre.shared_secret, starting_pn);

        // Server swaps so server-send == client-recv (same orientation as epoch 0)
        let (new_send_chain, new_recv_chain) = if self.is_server {
            (chain_b, chain_a)
        } else {
            (chain_a, chain_b)
        };

        // Save current recv state for 5-second retention (handle reordered old packets)
        self.prev_epoch_recv = Some(PrevEpochRecv {
            epoch: self.epoch,
            chain_key: self.recv_chain_key,
            chain_pn: self.recv_chain_pn,
            skipped: self.skipped_recv_keys
                .iter()
                .filter(|((e, _), _)| *e == self.epoch)
                .map(|((_, pn), k)| (*pn, *k))
                .collect(),
            expires: Instant::now() + Duration::from_millis(OLD_EPOCH_RETENTION_MS),
        });

        // Clear skipped keys for old epoch (prev_epoch_recv has its own copy above)
        self.skipped_recv_keys.retain(|(e, _), _| *e > self.epoch);
        self.skipped_recv_queue.retain(|(e, _)| *e > self.epoch);

        // Switch to new epoch.
        // CRITICAL: pn spaces are independent per direction.
        //   - Server→client direction: server's tx pns start at `starting_pn` (the KEY_UPDATE pn).
        //     Both sides know this value (client learns it from the first KEY_UPDATE packet).
        //   - Client→server direction: client's tx pns are in a separate, much-smaller pn space.
        //     We do NOT know the client's next tx pn at activation time, so we must NOT reset
        //     the perpendicular chain cursor. Each side keeps its own cursor from epoch N-1.
        //
        //   Server:  send_chain_pn = starting_pn  (server→client: fresh at KEY_UPDATE pn)
        //            recv_chain_pn = UNCHANGED      (client→server: continues from epoch N-1)
        //   Client:  recv_chain_pn = starting_pn  (server→client: fresh at KEY_UPDATE pn)
        //            send_chain_pn = UNCHANGED      (client→server: continues from epoch N-1)
        self.epoch = pre.epoch;
        self.send_chain_key = new_send_chain;
        self.recv_chain_key = new_recv_chain;

        if self.is_server {
            self.send_chain_pn = starting_pn; // server→client: anchored to KEY_UPDATE pn
            // recv_chain_pn intentionally unchanged: client→server pn space continues
        } else {
            self.recv_chain_pn = starting_pn; // server→client: anchored to KEY_UPDATE pn
            // send_chain_pn intentionally unchanged: client→server pn space continues
        }

        // Reset epoch packet counters
        self.send_epoch_packet_count = 0;
        self.recv_epoch_packet_count = 0;

        // Clear pending ratchet state and any partially-assembled pubkey chunks
        // from the previous epoch to avoid stale data interfering with the next assembly.
        self.pending_ratchet = None;
        self.incoming_pubkey_chunks.clear();

        // Update epoch boundary reference for next ratchet
        if self.is_server {
            // Server: immediately queue next ratchet initiation
            self.next_ratchet_time = Some(Instant::now());
        } else {
            // Client: next ciphertext_send_time is computed relative to this reference.
            // Reset to now + RATCHET_INTERVAL_MS so respond_to_ratchet schedules
            // correctly for the next epoch (t+55s, not a stale past value).
            self.next_ratchet_time =
                Some(Instant::now() + Duration::from_millis(RATCHET_INTERVAL_MS));
        }
        self.we_initiate_next = self.is_server;

        eprintln!(
            "[PQDR] Epoch {} activated: send_chain_pn={} recv_chain_pn={} send_chain={} recv_chain={}",
            self.epoch,
            self.send_chain_pn,
            self.recv_chain_pn,
            hex_short(&self.send_chain_key),
            hex_short(&self.recv_chain_key),
        );

        Ok(())
    }

    /// Client: activate precomputed epoch on KEY_UPDATE.
    /// `starting_pn` is the pn of the KEY_UPDATE packet (first pn of new epoch).
    pub fn complete_client_ratchet_on_key_update(&mut self, starting_pn: u64) -> Result<()> {
        // pending_ratchet must be WaitingToActivate
        match self.pending_ratchet.as_ref() {
            Some(PendingRatchet::WaitingToActivate { .. }) => {},
            _ => return Err(Error::InvalidState),
        }
        self.activate_precomputed_epoch(starting_pn)?;
        Ok(())
    }

    pub fn has_precomputed_keys(&self) -> bool {
        self.precomputed_next_epoch.is_some()
    }

    // -----------------------------------------------------------------------
    // Ciphertext scheduling (client-side)
    // -----------------------------------------------------------------------

    pub fn should_send_ciphertext(&self) -> bool {
        match self.ciphertext_send_time {
            Some(t) => Instant::now() >= t,
            None => false,
        }
    }

    pub fn take_pending_ciphertext(&mut self) -> Option<(RatchetEpoch, Vec<u8>)> {
        self.ciphertext_send_time = None;
        self.pending_ciphertext_response.take()
    }

    // -----------------------------------------------------------------------
    // Encrypt / Decrypt  (pn-indexed chain)
    // -----------------------------------------------------------------------

    /// Derive encryption key for outgoing packet `pn`.
    ///
    /// Advances the send chain from `send_chain_pn` to `pn`, discarding
    /// keys for any skipped pns (QUIC never retransmits the same pn, so
    /// there is no need to cache intermediate enc keys).
    /// Returns the enc key for `pn`.
    pub fn encrypt_key(&mut self, pn: u64) -> Result<[u8; BLAKE3_OUT_LEN]> {
        if pn < self.send_chain_pn {
            // pn went backwards — should never happen in QUIC
            return Err(Error::CryptoFail);
        }

        // Advance chain through any skipped pns (discard their keys)
        while self.send_chain_pn < pn {
            let (new_chain, _) =
                blake3_kdf::derive_message_key(&self.send_chain_key, self.send_chain_pn);
            self.send_chain_key = new_chain;
            self.send_chain_pn += 1;
        }

        // Derive key for target pn
        let (new_chain, enc_key) =
            blake3_kdf::derive_message_key(&self.send_chain_key, pn);
        self.send_chain_key = new_chain;
        self.send_chain_pn = pn + 1;

        Ok(enc_key)
    }

    /// No-op: QUIC never retransmits the same pn, so there are no cached send keys to free.
    #[inline]
    pub fn on_packet_acked(&mut self, _pn: u64) {}

    /// Derive decryption key for incoming packet `(epoch, pn)`.
    ///
    /// Handles:
    /// - Current epoch in-order or out-of-order (skipped keys cache)
    /// - Previous epoch within 5-second retention window
    pub fn decrypt_key(
        &mut self,
        epoch: RatchetEpoch,
        pn: u64,
    ) -> Result<[u8; BLAKE3_OUT_LEN]> {
        // 1. Check skipped keys for current epoch
        if let Some(key) = self.skipped_recv_keys.remove(&(epoch, pn)) {
            return Ok(key);
        }

        if epoch == self.epoch {
            // Current epoch: advance the chain
            return self.advance_recv_chain(epoch, pn);
        }

        if epoch < self.epoch {
            // Previous epoch: check 5-second retention
            return self.decrypt_prev_epoch(epoch, pn);
        }

        // Future epoch — not yet reached
        Err(Error::CryptoFail)
    }

    /// Advance current recv chain to `pn`, storing intermediate skipped keys.
    fn advance_recv_chain(
        &mut self,
        epoch: RatchetEpoch,
        pn: u64,
    ) -> Result<[u8; BLAKE3_OUT_LEN]> {
        // Sync recv chain start with the prev-epoch chain's final position.
        //
        // After a ratchet epoch transition, the "perpendicular" chain (the one
        // whose direction spans epoch boundaries, e.g. client→server) starts at
        // a fresh root key but `recv_chain_pn` is left at the old epoch's value
        // (say N).  In-flight old-epoch packets are processed first via
        // `prev_epoch_recv`, which advances `prev_epoch_recv.chain_pn` to N+k
        // (where k = number of in-flight packets).  The NEW epoch's chain must
        // then start at N+k, not N — otherwise the first ratchet step is
        //
        //   server: H(H(…H(root, N), …, N+k-1), N+k)   [wrong — skips N..N+k-1]
        //   client: H(root, N+k)                        [correct — starts fresh]
        //
        // Syncing `recv_chain_pn` to `prev_epoch_recv.chain_pn` before advancing
        // aligns the two sides so both compute H(root, N+k) for the first new-epoch
        // packet.  This is safe because:
        //   • the old-epoch packets (pns N..N+k-1) were already handled by
        //     `prev_epoch_recv`, so they will never reach `advance_recv_chain`;
        //   • once synced the check below is idempotent on subsequent calls.
        if let Some(ref prev) = self.prev_epoch_recv {
            if prev.chain_pn > self.recv_chain_pn {
                self.recv_chain_pn = prev.chain_pn;
            }
        }

        if pn < self.recv_chain_pn {
            // Already advanced past this pn — should have been in skipped keys
            return Err(Error::CryptoFail);
        }

        // Advance, storing keys for skipped pns
        while self.recv_chain_pn < pn {
            if self.skipped_recv_keys.len() >= MAX_SKIP {
                if let Some(oldest) = self.skipped_recv_queue.pop_front() {
                    self.skipped_recv_keys.remove(&oldest);
                }
            }
            let cur_pn = self.recv_chain_pn;
            let (new_chain, skipped_key) =
                blake3_kdf::derive_message_key(&self.recv_chain_key, cur_pn);
            let key_id = (epoch, cur_pn);
            self.skipped_recv_keys.insert(key_id, skipped_key);
            self.skipped_recv_queue.push_back(key_id);
            self.recv_chain_key = new_chain;
            self.recv_chain_pn = cur_pn + 1;
        }

        // Derive key for target pn
        let (new_chain, enc_key) =
            blake3_kdf::derive_message_key(&self.recv_chain_key, pn);
        self.recv_chain_key = new_chain;
        self.recv_chain_pn = pn + 1;

        Ok(enc_key)
    }

    /// Try to decrypt a packet from the previous epoch (within 5s retention window).
    fn decrypt_prev_epoch(
        &mut self,
        epoch: RatchetEpoch,
        pn: u64,
    ) -> Result<[u8; BLAKE3_OUT_LEN]> {
        let prev = match self.prev_epoch_recv.as_mut() {
            Some(p) if p.epoch == epoch => p,
            _ => return Err(Error::CryptoFail),
        };

        // Expired — remove and fail
        if Instant::now() >= prev.expires {
            self.prev_epoch_recv = None;
            return Err(Error::CryptoFail);
        }

        // Check cached skipped keys
        if let Some(key) = prev.skipped.remove(&pn) {
            return Ok(key);
        }

        if pn < prev.chain_pn {
            return Err(Error::CryptoFail);
        }

        // Advance previous epoch chain
        while prev.chain_pn < pn {
            let cur_pn = prev.chain_pn;
            let (new_chain, skipped_key) =
                blake3_kdf::derive_message_key(&prev.chain_key, cur_pn);
            prev.skipped.insert(cur_pn, skipped_key);
            prev.chain_key = new_chain;
            prev.chain_pn = cur_pn + 1;
        }

        let (new_chain, enc_key) =
            blake3_kdf::derive_message_key(&prev.chain_key, pn);
        prev.chain_key = new_chain;
        prev.chain_pn = pn + 1;

        Ok(enc_key)
    }

    /// Evict expired old-epoch state (call periodically).
    pub fn cleanup_old_epoch(&mut self) {
        if let Some(ref p) = self.prev_epoch_recv {
            if Instant::now() >= p.expires {
                self.prev_epoch_recv = None;
            }
        }
    }

    // -----------------------------------------------------------------------
    // KEM chunk management
    // -----------------------------------------------------------------------

    fn prepare_outgoing_chunks(&mut self, kem_data: &[u8]) {
        let padded_len =
            ((kem_data.len() + KEM_CHUNK_SIZE - 1) / KEM_CHUNK_SIZE) * KEM_CHUNK_SIZE;
        let mut padded = vec![0u8; padded_len];
        padded[..kem_data.len()].copy_from_slice(kem_data);

        let chunks: Vec<Vec<u8>> = padded
            .chunks(KEM_CHUNK_SIZE)
            .map(|c| c.to_vec())
            .collect();

        self.outgoing_chunks = Some(chunks);
        self.next_chunk_to_send = 0;
    }

    /// Get next outgoing KEM chunk to embed in the packet.
    /// Returns None when all chunks have been sent.
    pub fn get_next_outgoing_chunk(&mut self) -> Option<Vec<u8>> {
        let chunks = self.outgoing_chunks.as_ref()?;
        if self.next_chunk_to_send >= chunks.len() {
            self.outgoing_chunks = None;
            return None;
        }
        let chunk = chunks[self.next_chunk_to_send].clone();
        self.next_chunk_to_send += 1;
        if self.next_chunk_to_send >= self.outgoing_chunks.as_ref().map_or(0, |c| c.len()) {
            self.outgoing_chunks = None;
            self.next_chunk_to_send = 0;
        }
        Some(chunk)
    }

    /// Store an incoming pubkey chunk (indexed by packet number).
    /// Returns assembled pubkey bytes once all PUBKEY_CHUNK_COUNT chunks are gathered.
    pub fn receive_pubkey_chunk(
        &mut self,
        packet_number: u64,
        chunk: Vec<u8>,
    ) -> Option<Vec<u8>> {
        self.incoming_pubkey_chunks.insert(packet_number, chunk);

        if self.incoming_pubkey_chunks.len() < PUBKEY_CHUNK_COUNT {
            return None;
        }

        // Assemble in packet-number order
        let mut pkt_nums: Vec<u64> =
            self.incoming_pubkey_chunks.keys().copied().collect();
        pkt_nums.sort_unstable();

        let mut assembled = Vec::with_capacity(MLKEM768_PUBLIC_KEY_BYTES);
        for pn in pkt_nums.iter().take(PUBKEY_CHUNK_COUNT) {
            if let Some(c) = self.incoming_pubkey_chunks.get(pn) {
                assembled.extend_from_slice(c);
            }
        }
        self.incoming_pubkey_chunks.clear();

        if assembled.len() >= MLKEM768_PUBLIC_KEY_BYTES {
            assembled.truncate(MLKEM768_PUBLIC_KEY_BYTES);
            Some(assembled)
        } else {
            None
        }
    }

    /// Whether there are outgoing chunks still to send.
    pub fn has_outgoing_chunks(&self) -> bool {
        self.outgoing_chunks
            .as_ref()
            .map_or(false, |c| self.next_chunk_to_send < c.len())
    }

    /// What type of chunk to expect in incoming packets, based on epoch state.
    ///
    /// The server embeds pubkey chunks in the first `PUBKEY_CHUNK_COUNT` packets
    /// of every epoch (recv counter resets at each epoch boundary).
    /// No `ratchet_started` guard — chunks may arrive before KEY_UPDATE.
    pub fn expected_chunk_type(&self) -> Option<ChunkType> {
        // Only the non-initiating side (client) receives chunked pubkeys
        if !self.we_initiate_next && self.pending_ratchet.is_none() {
            // Counter is incremented BEFORE this check in lib.rs, so use <=
            if self.recv_epoch_packet_count <= PUBKEY_CHUNK_COUNT as u64 {
                return Some(ChunkType::PublicKey);
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Epoch packet counters
    // -----------------------------------------------------------------------

    pub fn increment_recv_packet_count(&mut self) {
        self.recv_epoch_packet_count += 1;
    }

    pub fn reset_recv_packet_count(&mut self) {
        self.recv_epoch_packet_count = 0;
    }

    pub fn increment_send_packet_count(&mut self) {
        self.send_epoch_packet_count += 1;
    }

    pub fn reset_send_packet_count(&mut self) {
        self.send_epoch_packet_count = 0;
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn epoch(&self) -> RatchetEpoch {
        self.epoch
    }

    pub fn has_pending_ratchet(&self) -> bool {
        self.pending_ratchet.is_some()
    }

    pub fn send_epoch_packet_count(&self) -> u64 {
        self.send_epoch_packet_count
    }
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_init() {
        let secret = b"test-handshake-secret";

        let client = RatchetState::from_handshake_secret(secret, true);
        let server = RatchetState::from_handshake_secret(secret, false);

        assert_eq!(client.epoch(), 0);
        assert_eq!(server.epoch(), 0);
        assert_eq!(client.send_chain_pn, 0);
        assert_eq!(server.send_chain_pn, 0);

        // Server initiates, client does not
        assert!(server.we_initiate_next);
        assert!(!client.we_initiate_next);
    }

    #[test]
    fn test_send_recv_key_match_epoch0() {
        let secret = b"test-handshake-secret-abc";
        let mut client = RatchetState::from_handshake_secret(secret, true);
        let mut server = RatchetState::from_handshake_secret(secret, false);

        // Server sends pn=0,1,2; client receives same pn values
        for pn in 0u64..5 {
            let enc_key = server.encrypt_key(pn).unwrap();
            let dec_key = client.decrypt_key(0, pn).unwrap();
            assert_eq!(enc_key, dec_key, "Key mismatch at pn={}", pn);
        }

        // Client sends pn=0,1,2; server receives
        for pn in 0u64..5 {
            let enc_key = client.encrypt_key(pn).unwrap();
            let dec_key = server.decrypt_key(0, pn).unwrap();
            assert_eq!(enc_key, dec_key, "Key mismatch at pn={}", pn);
        }
    }

    #[test]
    fn test_encrypt_key_retransmit() {
        let secret = b"test-handshake-secret-abc";
        let mut sender = RatchetState::from_handshake_secret(secret, true);

        // Send pn 0,1,2 — chain advances on each call, no caching
        let k0 = sender.encrypt_key(0).unwrap();
        let k1 = sender.encrypt_key(1).unwrap();
        let _k2 = sender.encrypt_key(2).unwrap();

        // All three keys must be distinct
        assert_ne!(k0, k1);

        // QUIC never retransmits the same pn: attempting to re-encrypt an already-used pn
        // should fail because the chain has already advanced past it.
        assert!(sender.encrypt_key(0).is_err(), "Re-encrypting old pn should fail");
        assert!(sender.encrypt_key(1).is_err(), "Re-encrypting old pn should fail");

        // on_packet_acked is a no-op (no cached keys to free); subsequent sends still work.
        sender.on_packet_acked(0);
        sender.on_packet_acked(1);
        let k3 = sender.encrypt_key(3).unwrap();
        assert_ne!(k0, k3);
    }

    #[test]
    fn test_decrypt_out_of_order() {
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        // Pre-compute send keys
        let k0 = sender.encrypt_key(0).unwrap();
        let k1 = sender.encrypt_key(1).unwrap();
        let k2 = sender.encrypt_key(2).unwrap();

        // Receive out-of-order: 2 first, then 0, then 1
        let dk2 = recver.decrypt_key(0, 2).unwrap();
        let dk0 = recver.decrypt_key(0, 0).unwrap();
        let dk1 = recver.decrypt_key(0, 1).unwrap();

        assert_eq!(k0, dk0);
        assert_eq!(k1, dk1);
        assert_eq!(k2, dk2);
    }

    #[test]
    fn test_expected_chunk_type() {
        let secret = b"test-handshake-secret";
        let mut client = RatchetState::from_handshake_secret(secret, true);

        // Client (non-initiator) should expect pubkey in first PUBKEY_CHUNK_COUNT packets
        // recv_epoch_packet_count starts at 0; lib.rs increments BEFORE calling expected_chunk_type
        // So at count=1 (first packet incremented to 1) → count <= 19 → Some
        for i in 1..=PUBKEY_CHUNK_COUNT {
            client.recv_epoch_packet_count = i as u64;
            assert_eq!(
                client.expected_chunk_type(),
                Some(ChunkType::PublicKey),
                "Expected chunk at count={}",
                i
            );
        }
        // count = PUBKEY_CHUNK_COUNT + 1 → None
        client.recv_epoch_packet_count = (PUBKEY_CHUNK_COUNT + 1) as u64;
        assert_eq!(client.expected_chunk_type(), None);

        // Server (initiator) never expects incoming pubkey chunks
        let server = RatchetState::from_handshake_secret(secret, false);
        assert_eq!(server.expected_chunk_type(), None);
    }

    #[test]
    fn test_ratchet_timer() {
        let secret = b"test-handshake-secret";
        let server = RatchetState::from_handshake_secret(secret, false);

        // Server timer fires immediately
        assert!(server.should_initiate_ratchet());

        // Client never initiates
        let client = RatchetState::from_handshake_secret(secret, true);
        assert!(!client.should_initiate_ratchet());
    }

    #[test]
    fn test_epoch_transition_asymmetric_pn() {
        // Regression test for the bug where activate_precomputed_epoch reset BOTH
        // send_chain_pn and recv_chain_pn to starting_pn (server's tx pn), even though
        // the perpendicular direction (client→server) is in a completely separate,
        // much-smaller pn space.
        //
        // Scenario: simulate a heavy download where the server has sent 100 packets
        // (pns 0..99) but the client has only sent 10 ACK packets (pns 0..9).
        // At the epoch boundary, starting_pn = 100 (server's next tx pn).
        // The client→server chain must continue from pn=10, not restart at 100.

        let handshake_secret = b"test-epoch-transition-secret";
        let mut server = RatchetState::from_handshake_secret(handshake_secret, false);
        let mut client = RatchetState::from_handshake_secret(handshake_secret, true);

        // Advance epoch-0 chains to simulate asymmetric traffic:
        //   - server sent 100 packets (pns 0..99), client received them
        //   - client sent 10 packets (pns 0..9), server received them
        for pn in 0..100u64 {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(0, pn).unwrap();
            assert_eq!(sk, ck, "epoch-0 server→client key mismatch at pn={}", pn);
        }
        for pn in 0..10u64 {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(0, pn).unwrap();
            assert_eq!(ck, sk, "epoch-0 client→server key mismatch at pn={}", pn);
        }

        // Inject a synthetic epoch-1 shared secret on both sides (bypasses KEM for test speed)
        let shared_secret = b"synthetic-kem-shared-secret-32bb";
        let epoch1 = 1u32;
        server.pending_ratchet = Some(PendingRatchet::WaitingForCiphertext {
            our_private_key: {
                // Generate a throwaway keypair just to satisfy the type system
                let (priv_key, _) = crate::crypto::boringssl::MLKEM768_private_key::generate();
                priv_key
            },
            epoch: epoch1,
        });
        server.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: epoch1,
            shared_secret: shared_secret.to_vec(),
        });
        client.pending_ratchet = Some(PendingRatchet::WaitingToActivate { epoch: epoch1 });
        client.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: epoch1,
            shared_secret: shared_secret.to_vec(),
        });

        // Epoch-1 activation: starting_pn = 100 (server's next tx pn after 100 sent packets).
        // With the BUG: both sides would set recv_chain_pn = 100, causing client→server to fail
        //   because client's send_chain_pn is still at 10.
        // With the FIX: only the server→client direction resets to 100; client→server continues.
        let starting_pn = 100u64;
        server.activate_precomputed_epoch(starting_pn).unwrap();
        client.complete_client_ratchet_on_key_update(starting_pn).unwrap();

        // Verify direction 1: server→client (server sends at pns 100, 101, 102)
        for pn in [100u64, 101, 102] {
            let enc = server.encrypt_key(pn).unwrap();
            let dec = client.decrypt_key(epoch1, pn).unwrap();
            assert_eq!(enc, dec, "epoch-1 server→client key mismatch at pn={}", pn);
        }

        // Verify direction 2: client→server (client sends at pns 10, 11, 12)
        // This would FAIL with the old code because client.send_chain_pn would be 100
        // but the actual pn is 10, triggering "pn went backwards" error.
        for pn in [10u64, 11, 12] {
            let enc = client.encrypt_key(pn).unwrap();
            let dec = server.decrypt_key(epoch1, pn).unwrap();
            assert_eq!(enc, dec, "epoch-1 client→server key mismatch at pn={}", pn);
        }
    }

    #[test]
    fn test_epoch_transition_inflight_pn_sync() {
        // Regression test for Bug 4: in-flight epoch-0 client packet causes epoch-1
        // recv_chain_pn misalignment on the server side.
        //
        // Scenario:
        //   - Server sends epoch-0 packets pn=0..99 (client receives all).
        //   - Client sends epoch-0 packets pn=0..3 (server receives all 4).
        //   - Client sends epoch-0 packet pn=4 — in-flight (server has NOT received it yet).
        //     At this point: client.send_chain_pn=5, server.recv_chain_pn=4.
        //   - Epoch-1 activates. Server recv_chain_pn stays at 4; client send_chain_pn stays at 5.
        //   - Server processes the in-flight epoch-0 pn=4 via decrypt_prev_epoch →
        //     prev_epoch_recv.chain_pn advances to 5.
        //   - Client encrypts first epoch-1 packet at pn=5.
        //
        // WITHOUT FIX: server.advance_recv_chain(1, 5) starts at recv_chain_pn=4, advances
        //   through pos-4, producing H(H(epoch1_root, 4), 5) ≠ client's H(epoch1_root, 5).
        //
        // WITH FIX: server syncs recv_chain_pn = max(4, prev_epoch_recv.chain_pn=5) = 5,
        //   so H(epoch1_root, 5) == H(epoch1_root, 5) ✓
        let handshake_secret = b"test-inflight-b4-regression-key!";
        let mut server = RatchetState::from_handshake_secret(handshake_secret, false);
        let mut client = RatchetState::from_handshake_secret(handshake_secret, true);

        // Epoch-0: server sends 100 packets (download direction), client receives all.
        for pn in 0..100u64 {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(0, pn).unwrap();
            assert_eq!(sk, ck, "epoch-0 s→c key mismatch at pn={}", pn);
        }

        // Epoch-0: client sends 4 ACK packets (pn=0..3), server receives all.
        for pn in 0..4u64 {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(0, pn).unwrap();
            assert_eq!(ck, sk, "epoch-0 c→s key mismatch at pn={}", pn);
        }

        // Client sends epoch-0 packet pn=4 — in-flight, server will NOT receive it until
        // after epoch-1 activates. client.send_chain_pn is now 5; server.recv_chain_pn is 4.
        let inflight_key_client = client.encrypt_key(4).unwrap();

        // Inject synthetic epoch-1 shared secret, bypassing KEM for test speed.
        let shared_secret = b"synthetic-kem-secret-bug4-test!!";
        let epoch1: RatchetEpoch = 1;
        server.pending_ratchet = Some(PendingRatchet::WaitingForCiphertext {
            our_private_key: {
                let (priv_key, _) =
                    crate::crypto::boringssl::MLKEM768_private_key::generate();
                priv_key
            },
            epoch: epoch1,
        });
        server.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: epoch1,
            shared_secret: shared_secret.to_vec(),
        });
        client.pending_ratchet =
            Some(PendingRatchet::WaitingToActivate { epoch: epoch1 });
        client.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: epoch1,
            shared_secret: shared_secret.to_vec(),
        });

        // Activate epoch-1. starting_pn = 100 (server's next tx pn in epoch-1).
        // Server recv_chain_pn remains 4 (unchanged); client send_chain_pn remains 5 (unchanged).
        let starting_pn = 100u64;
        server.activate_precomputed_epoch(starting_pn).unwrap();
        client.complete_client_ratchet_on_key_update(starting_pn).unwrap();

        // Server now receives the in-flight epoch-0 packet (pn=4).
        // decrypt_key routes to decrypt_prev_epoch which advances prev_epoch_recv.chain_pn → 5.
        let inflight_key_server = server.decrypt_key(0, 4).unwrap();
        assert_eq!(
            inflight_key_client, inflight_key_server,
            "In-flight epoch-0 c→s key mismatch at pn=4"
        );

        // Client sends first epoch-1 packet at pn=5 (send_chain_pn was 5 after sending pn=4).
        // Server must sync recv_chain_pn from prev_epoch_recv.chain_pn=5 before advancing.
        // This is the core Bug-4 regression check.
        let epoch1_key_client = client.encrypt_key(5).unwrap();
        let epoch1_key_server = server.decrypt_key(epoch1, 5).unwrap();
        assert_eq!(
            epoch1_key_client, epoch1_key_server,
            "Epoch-1 first c→s packet key mismatch at pn=5 (Bug 4 regression)"
        );

        // Subsequent epoch-1 client→server packets must also match.
        for pn in [6u64, 7, 10, 50] {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(epoch1, pn).unwrap();
            assert_eq!(ck, sk, "epoch-1 c→s key mismatch at pn={}", pn);
        }

        // Server→client direction in epoch-1 must also work correctly.
        for pn in [100u64, 101, 102] {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(epoch1, pn).unwrap();
            assert_eq!(sk, ck, "epoch-1 s→c key mismatch at pn={}", pn);
        }
    }

}
