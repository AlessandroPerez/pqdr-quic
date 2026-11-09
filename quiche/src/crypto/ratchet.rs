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
//! - Epoch 0: chain keys derived from the TLS exporter secret
//! - Per-packet key: `H(chain_key_{pn-1}, pn)` → (new_chain_key, enc_key)
//! - Epoch N≥1: chain keys derived from `KDF(kem_shared_secret, starting_pn)`
//! - At the start of every epoch the server generates an ML-KEM-768 key pair
//!   for the next one, and sends the public key in the epoch's first packets
//!   (see "Public key chunks" below)
//! - The client sends the encapsulated ciphertext via CRYPTO frame shortly
//!   before the epoch boundary (t=55s of 60s)
//! - The next 1-RTT packet after the boundary switches epochs; the old
//!   epoch's receive keys are kept for a while for reordered packets
//!
//! Chain advancement:
//!   send side: advance chain from `send_chain_pn` to target pn, returning
//!              enc_key (QUIC never retransmits the same pn, so no caching is
//!              needed)
//!   recv side: candidate keys are computed without touching the ratchet
//!              (`recv_key_candidate`); the ratchet only advances once the
//!              packet authenticates (`commit_recv_key`). Forged or corrupted
//!              packets therefore cannot move the chains.
//!
//! Epoch anchors:
//!   Each direction's chain for an epoch, epoch 0 included, starts at the
//!   first pn the sender protects with it. The receiver cannot observe that
//!   pn directly if the packet carrying it is lost or reordered, so it tries
//!   the possible start pns (bounded by `MAX_ANCHOR_CANDIDATES`) and keeps
//!   the one whose key authenticates the packet.
//!
//! Public key chunks:
//!   The public key is split into `PUBKEY_CHUNK_COUNT` chunks of
//!   `KEM_CHUNK_SIZE` bytes and expanded with a rate-1/4 Reed-Solomon code
//!   into `PUBKEY_CODED_CHUNK_COUNT` chunks. The server's packet `start + i`
//!   of an epoch (where `start` is the epoch's anchor) carries coded chunk
//!   `i`, for `i < PUBKEY_CODED_CHUNK_COUNT`, as a prefix of its plaintext.
//!   The client knows `start` once any packet of the epoch has authenticated,
//!   so it tells which packets carry a chunk, and which one, from their pn
//!   alone. Any `PUBKEY_CHUNK_COUNT` of the coded chunks rebuild the key, so
//!   up to three quarters of those packets can be lost, in any order.
//!
//! Key material (chain keys, packet keys, KEM shared secrets and private
//! keys) is wiped from memory when dropped. This is best effort: Rust moves
//! values with plain copies, so a short-lived copy can remain on the stack
//! until it is overwritten.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::time::Duration;
use std::time::Instant;

use zeroize::Zeroizing;

use crate::crypto::blake3_kdf;
use crate::crypto::blake3_kdf::MessageKdf;
use crate::crypto::blake3_kdf::SecretKey;
use crate::crypto::blake3_kdf::BLAKE3_OUT_LEN;
use crate::crypto::boringssl::MLKEM768_private_key;
use crate::crypto::boringssl::MLKEM768_CIPHERTEXT_BYTES;
use crate::crypto::boringssl::MLKEM768_PUBLIC_KEY_BYTES;
use crate::crypto::boringssl::MLKEM_SHARED_SECRET_BYTES;
use crate::crypto::reed_solomon;
use crate::crypto::PqdrAead;
use crate::Error;
use crate::Result;

/// Ratchet epoch number
pub type RatchetEpoch = u32;

/// Maximum number of skipped receive keys to cache (out-of-order delivery)
const MAX_SKIP: usize = 512;

/// Largest forward jump, in packet numbers, the receive chain will derive
/// through for a single packet.
///
/// Every pn skipped costs one BLAKE3 call, and the pn of an incoming packet
/// is read before the packet is authenticated, so this bounds the work a
/// forged packet can cause. Legitimate gaps are bounded by the sender's
/// in-flight window, which stays well below this.
pub const MAX_RECV_JUMP: u64 = 1 << 16;

/// Maximum number of start pns tried when locating where the peer started
/// an epoch's chain (see the module docs).
pub const MAX_ANCHOR_CANDIDATES: u64 = 256;

/// Size of one public key chunk, carried as a prefix of a packet's
/// plaintext.
pub const KEM_CHUNK_SIZE: usize = 64;

/// ML-KEM-768 ciphertext size (1088 bytes)
pub const MLKEM768_CIPHERTEXT_SIZE: usize = MLKEM768_CIPHERTEXT_BYTES;

/// Number of chunks the ML-KEM-768 public key is split into (1184 bytes,
/// zero-padded to 19 chunks). Any this many coded chunks rebuild the key.
pub const PUBKEY_CHUNK_COUNT: usize =
    MLKEM768_PUBLIC_KEY_BYTES.div_ceil(KEM_CHUNK_SIZE);

/// Number of coded public key chunks the server sends per epoch, one in
/// each of its first packets of the epoch. Rate 1/4: the key survives the
/// loss of up to three quarters of them.
pub const PUBKEY_CODED_CHUNK_COUNT: usize = 4 * PUBKEY_CHUNK_COUNT;

/// Default epoch length: 60 seconds
pub const RATCHET_INTERVAL_MS: u64 = 60 * 1000;

/// The client's ciphertext lead time and the previous-epoch retention time
/// are both this fraction of the epoch length (5 s of 60 s by default).
const EPOCH_FRACTION_DIVISOR: u32 = 12;

/// Upper bound on buffered, not yet complete, KEM ciphertext bytes.
const MAX_BUFFERED_CIPHERTEXT: usize = 2 * MLKEM768_CIPHERTEXT_BYTES;

/// One public key chunk.
type KemChunk = [u8; KEM_CHUNK_SIZE];

/// A KEM shared secret, wiped when dropped.
type SharedSecret = Zeroizing<[u8; MLKEM_SHARED_SECRET_BYTES]>;

// ---------------------------------------------------------------------------
// Receive chains
// ---------------------------------------------------------------------------

/// Receive-direction hash chain for one epoch.
#[derive(Clone)]
struct RecvChain {
    /// Anchored: chain key that derives the key for `next_pn`.
    /// Unanchored: the epoch's root chain key.
    key: SecretKey,

    /// Anchored: next pn the chain will derive.
    /// Unanchored: lowest pn the peer can have started this chain at.
    next_pn: u64,

    /// Anchored: the pn at which the peer started this chain.
    start: u64,

    /// False until the first authenticated packet of the epoch fixes the pn
    /// at which the peer started the chain.
    anchored: bool,
}

impl RecvChain {
    /// A chain whose start is not known yet, but is at least `lower`.
    fn unanchored(root: SecretKey, lower: u64) -> Self {
        RecvChain {
            key: root,
            next_pn: lower,
            start: 0,
            anchored: false,
        }
    }
}

/// Result of walking a chain forward to a target pn.
struct Walk {
    enc_key: SecretKey,

    /// Chain key after the target pn (derives the key for target + 1).
    chain_key: SecretKey,

    /// Keys for the skipped pns before the target, at most `MAX_SKIP` of the
    /// most recent ones.
    skipped: Vec<(u64, SecretKey)>,
}

/// Walks a chain positioned at `from` (i.e. `key` derives the key for `from`)
/// up to and including `pn`. Does not modify any state.
fn walk_chain(
    kdf: MessageKdf, key: &[u8; BLAKE3_OUT_LEN], from: u64, pn: u64,
) -> Option<Walk> {
    if pn < from || pn - from > MAX_RECV_JUMP {
        return None;
    }

    let keep_from = pn.saturating_sub(MAX_SKIP as u64).max(from);

    let mut chain: Option<SecretKey> = None;
    let mut skipped = Vec::new();

    for cur in from..pn {
        let (next, skipped_key) =
            kdf.derive(chain.as_deref().unwrap_or(key), cur);

        if cur >= keep_from {
            skipped.push((cur, skipped_key));
        }

        chain = Some(next);
    }

    let (chain_key, enc_key) = kdf.derive(chain.as_deref().unwrap_or(key), pn);

    Some(Walk {
        enc_key,
        chain_key,
        skipped,
    })
}

/// Returns the `attempt`-th start pn to try for a chain known to start
/// somewhere in `[lower, pn]`.
///
/// The common case is that `pn` itself is the first packet of the epoch, so
/// it is tried first. Candidates then alternate between the two ends of the
/// range: near `pn` (the epoch's first packets were reordered behind this
/// one) and near `lower` (they were lost). If the range is too large to try
/// exhaustively, only candidates near `pn` are tried.
fn anchor_candidate(lower: u64, pn: u64, attempt: u64) -> Option<u64> {
    if pn < lower || attempt >= MAX_ANCHOR_CANDIDATES {
        return None;
    }

    let span = pn - lower + 1;

    if attempt >= span {
        return None;
    }

    if span <= MAX_ANCHOR_CANDIDATES {
        let half = attempt / 2;

        Some(if attempt % 2 == 0 { pn - half } else { lower + half })
    } else {
        Some(pn - attempt)
    }
}

/// Removes `id` from `map`, wiping its key first: removal moves the value
/// out of the map's storage and would leave a copy behind.
fn remove_secret<K: Eq + Hash>(map: &mut HashMap<K, SecretKey>, id: &K) {
    if let Some(key) = map.get_mut(id) {
        blake3_kdf::wipe(&mut **key);
    }

    map.remove(id);
}

/// Returns the index of the public key chunk carried by packet `pn` of a
/// chain started at `start`, if it carries one.
fn chunk_index(start: u64, pn: u64) -> Option<usize> {
    let index = usize::try_from(pn.checked_sub(start)?).ok()?;

    (index < PUBKEY_CODED_CHUNK_COUNT).then_some(index)
}

/// Splits a public key into chunks and Reed-Solomon codes them.
fn encode_pubkey(pubkey: &[u8]) -> Vec<KemChunk> {
    let mut data = vec![[0u8; KEM_CHUNK_SIZE]; PUBKEY_CHUNK_COUNT];

    for (chunk, bytes) in data.iter_mut().zip(pubkey.chunks(KEM_CHUNK_SIZE)) {
        chunk[..bytes.len()].copy_from_slice(bytes);
    }

    reed_solomon::encode(&data, PUBKEY_CODED_CHUNK_COUNT)
}

/// Rebuilds a public key from any `PUBKEY_CHUNK_COUNT` coded chunks.
fn decode_pubkey(chunks: &[Option<KemChunk>]) -> Option<Vec<u8>> {
    let data = reed_solomon::decode(chunks, PUBKEY_CHUNK_COUNT)?;

    let mut pubkey = data.concat();
    pubkey.truncate(MLKEM768_PUBLIC_KEY_BYTES);

    Some(pubkey)
}

// ---------------------------------------------------------------------------
// Receive key candidates
// ---------------------------------------------------------------------------

/// Which epoch an incoming packet belongs to, as indicated by its key phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvEpoch {
    /// Same key phase as our current epoch.
    Current,

    /// Old key phase: sent before the most recent epoch switch.
    Previous,

    /// New key phase: the server switched to the next epoch (client only).
    Next,
}

/// A candidate decryption key for an incoming packet, together with the
/// ratchet update to apply if the packet authenticates under it.
pub struct RecvKey {
    key: SecretKey,
    commit: RecvCommit,
}

impl RecvKey {
    pub fn key(&self) -> &[u8; BLAKE3_OUT_LEN] {
        &self.key
    }
}

/// The key for the next packet on the current epoch's chain, from
/// `RatchetState::recv_key_in_order`.
pub struct InOrderRecvKey {
    pn: u64,
    key: SecretKey,

    /// Chain key that derives the key for `pn + 1`.
    chain_key: SecretKey,
}

impl InOrderRecvKey {
    pub fn key(&self) -> &[u8; BLAKE3_OUT_LEN] {
        &self.key
    }
}

enum RecvCommit {
    /// Key came from the current epoch's skipped-key cache.
    CurrentCached { pn: u64 },

    /// Key came from the previous epoch's skipped-key cache.
    PreviousCached { pn: u64 },

    /// Advance the current epoch's chain past `pn`. `anchor` is the start
    /// pn this candidate assumed, if the chain's start was not known yet.
    Current {
        pn: u64,
        anchor: Option<u64>,
        chain_key: SecretKey,
        skipped: Vec<(u64, SecretKey)>,
    },

    /// Advance the previous epoch's chain past `pn`.
    Previous {
        pn: u64,
        anchor: Option<u64>,
        chain_key: SecretKey,
        skipped: Vec<(u64, SecretKey)>,
    },

    /// Client: activate the precomputed epoch, which the server started at
    /// `starting_pn`, then advance its receive chain past `pn`.
    Activate {
        starting_pn: u64,
        pn: u64,
        chain_key: SecretKey,
        skipped: Vec<(u64, SecretKey)>,
    },
}

// ---------------------------------------------------------------------------
// Retained previous-epoch receive state
// ---------------------------------------------------------------------------

struct PrevEpochRecv {
    epoch: RatchetEpoch,

    chain: RecvChain,

    /// Already-skipped keys from the previous epoch
    skipped: HashMap<u64, SecretKey>,

    expires: Instant,
}

// ---------------------------------------------------------------------------
// Pre-computed epoch state (activated at t=60s)
// ---------------------------------------------------------------------------

struct PrecomputedEpoch {
    epoch: RatchetEpoch,
    /// Raw KEM shared secret — chain keys are derived at activation time,
    /// because we don't know `starting_pn` until the first packet is
    /// sent/received.
    shared_secret: SharedSecret,
}

// ---------------------------------------------------------------------------
// Pending asymmetric ratchet exchange state
// ---------------------------------------------------------------------------

enum PendingRatchet {
    /// We initiated (server): waiting for client's ciphertext
    WaitingForCiphertext {
        our_private_key: Box<MLKEM768_private_key>,
        epoch: RatchetEpoch,
    },
    /// They initiated (client): we've encapsulated and stored ciphertext for
    /// sending
    WaitingToActivate,
}

// ---------------------------------------------------------------------------
// Main ratchet state
// ---------------------------------------------------------------------------

pub struct RatchetState {
    /// True if we are the server (server always initiates ratchets)
    is_server: bool,

    /// Per-packet key derivation.
    kdf: MessageKdf,

    /// Per-packet encryption and decryption.
    aead: PqdrAead,

    /// Current ratchet epoch
    epoch: RatchetEpoch,

    // --- Timing ---
    /// Epoch length.
    interval: Duration,

    /// How long before the epoch boundary the client sends its ciphertext.
    client_lead: Duration,

    /// How long previous-epoch receive state is kept after a switch.
    retention: Duration,

    // --- Send chain ---
    /// Current send chain key (carry-forward; only the latest is kept)
    send_chain_key: SecretKey,
    /// Next pn the send chain is ready to advance to
    send_chain_pn: u64,
    /// First pn sent with this epoch's keys, once known. Until then, the
    /// next packet sent starts the chain.
    send_epoch_start: Option<u64>,

    // --- Receive chain ---
    recv_chain: RecvChain,
    /// Skipped receive keys of the current epoch: pn → enc_key
    skipped_recv_keys: HashMap<u64, SecretKey>,
    /// Insertion-order queue for eviction of `skipped_recv_keys`
    skipped_recv_queue: VecDeque<u64>,

    // --- Previous epoch retention ---
    prev_epoch_recv: Option<PrevEpochRecv>,

    // --- KEM state ---
    pending_ratchet: Option<PendingRatchet>,

    /// Server: coded chunks of our next public key, sent at the start of
    /// the current epoch.
    outgoing_pubkey_chunks: Vec<KemChunk>,

    /// Client: coded chunks of the server's next public key received so
    /// far, by chunk index.
    incoming_pubkey_chunks: Vec<Option<KemChunk>>,

    /// Client: ciphertext ready to send via CRYPTO frame at t=55s
    pending_ciphertext_response: Option<(RatchetEpoch, Vec<u8>)>,
    ciphertext_send_time: Option<Instant>,

    /// Server: ciphertext bytes received so far (CRYPTO frames may split a
    /// ciphertext arbitrarily).
    incoming_ciphertext: Vec<u8>,

    /// Pre-computed next epoch (activated at t=60s)
    precomputed_next_epoch: Option<PrecomputedEpoch>,

    /// Client: when the server is expected to switch to the next epoch, from
    /// which the ciphertext send time is derived.
    next_ratchet_time: Option<Instant>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl RatchetState {
    /// Initialize ratchet from TLS handshake shared secret, with the default
    /// 60-second epoch length.
    ///
    /// `is_client` determines chain orientation:
    /// - Client send chain == Server recv chain
    /// - Server send chain == Client recv chain
    #[cfg(test)]
    pub fn from_handshake_secret(
        handshake_secret: &[u8], is_client: bool,
    ) -> Self {
        Self::from_handshake_secret_with_interval(
            handshake_secret,
            is_client,
            Duration::from_millis(RATCHET_INTERVAL_MS),
        )
    }

    /// Like `from_handshake_secret`, with a custom epoch length.
    pub fn from_handshake_secret_with_interval(
        handshake_secret: &[u8], is_client: bool, interval: Duration,
    ) -> Self {
        let root_key = blake3_kdf::init_root_key_from_handshake(handshake_secret);

        // derive_initial_chain_keys returns (chain_A, chain_B)
        // Client uses chain_A as send, chain_B as recv
        // Server swaps so server-send == client-recv
        let (chain_a, chain_b) = blake3_kdf::derive_initial_chain_keys(&root_key);

        let (send_chain_key, recv_chain_key) = if is_client {
            (chain_a, chain_b)
        } else {
            (chain_b, chain_a)
        };

        let is_server = !is_client;

        let mut state = RatchetState {
            is_server,
            kdf: MessageKdf::new(),
            aead: PqdrAead::new(),
            epoch: 0,
            interval,
            client_lead: interval / EPOCH_FRACTION_DIVISOR,
            retention: interval / EPOCH_FRACTION_DIVISOR,
            send_chain_key,
            send_chain_pn: 0,
            send_epoch_start: None,
            // The peer starts its epoch-0 chain at its first
            // ratchet-protected packet.
            recv_chain: RecvChain::unanchored(recv_chain_key, 0),
            skipped_recv_keys: HashMap::with_capacity(MAX_SKIP),
            skipped_recv_queue: VecDeque::new(),
            prev_epoch_recv: None,
            pending_ratchet: None,
            outgoing_pubkey_chunks: Vec::new(),
            incoming_pubkey_chunks: vec![None; PUBKEY_CODED_CHUNK_COUNT],
            pending_ciphertext_response: None,
            ciphertext_send_time: None,
            incoming_ciphertext: Vec::new(),
            precomputed_next_epoch: None,
            next_ratchet_time: is_client.then(|| Instant::now() + interval),
        };

        // The server's first packets of epoch 0 carry its first public key.
        if is_server {
            state.initiate_ratchet();
        }

        debug!(
            "PQDR epoch 0 initialized ({})",
            if is_client { "client" } else { "server" },
        );

        state
    }

    /// How long before the epoch boundary the client sends its ciphertext;
    /// the server activates the new epoch this long after receiving it.
    pub fn client_lead(&self) -> Duration {
        self.client_lead
    }

    // -----------------------------------------------------------------------
    // Ratchet initiation / response
    // -----------------------------------------------------------------------

    /// Server: generate the ML-KEM key pair for the next epoch, and code its
    /// public key into the chunks sent at the start of the current one.
    fn initiate_ratchet(&mut self) {
        debug_assert!(self.is_server);

        let next_epoch = self.epoch + 1;
        let (private_key, public_key_bytes) = MLKEM768_private_key::generate();

        self.outgoing_pubkey_chunks = encode_pubkey(&public_key_bytes);

        self.pending_ratchet = Some(PendingRatchet::WaitingForCiphertext {
            our_private_key: private_key,
            epoch: next_epoch,
        });
    }

    /// Client: encapsulate to the server's public key, and schedule the
    /// ciphertext to be sent shortly before the epoch boundary (t=55s).
    pub fn respond_to_ratchet(
        &mut self, epoch: RatchetEpoch, their_pubkey_bytes: &[u8],
    ) -> Result<RatchetEpoch> {
        if self.is_server {
            return Err(Error::InvalidState);
        }
        if epoch != self.epoch + 1 {
            return Err(Error::InvalidState);
        }

        // Encapsulate to server's pubkey → (shared_secret, ciphertext)
        let (shared_secret, ciphertext) =
            MLKEM768_private_key::encapsulate_to_bytes(their_pubkey_bytes)?;

        // Chain keys are derived at activation time (we don't know
        // starting_pn yet).
        self.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch,
            shared_secret,
        });

        self.pending_ratchet = Some(PendingRatchet::WaitingToActivate);

        // Schedule ciphertext send shortly before the epoch boundary.
        self.pending_ciphertext_response = Some((epoch, ciphertext));
        self.ciphertext_send_time = Some(match self.next_ratchet_time {
            Some(next_ratchet) => next_ratchet - self.client_lead,

            None => Instant::now() + self.interval - self.client_lead,
        });

        Ok(epoch)
    }

    /// Server: receive client ciphertext, decapsulate, store shared secret.
    /// Chain keys derived at activation time (t=60s) once starting_pn is
    /// known.
    pub fn store_and_precompute_from_ciphertext(
        &mut self, epoch: RatchetEpoch, ciphertext: &[u8],
    ) -> Result<()> {
        let shared_secret = match self.pending_ratchet.as_ref() {
            Some(PendingRatchet::WaitingForCiphertext {
                our_private_key,
                epoch: expected_epoch,
            }) if epoch == *expected_epoch => our_private_key.decapsulate(ciphertext)?,

            _ => return Err(Error::InvalidState),
        };

        self.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch,
            shared_secret,
        });

        Ok(())
    }

    /// Server: process bytes read from the client's application-level CRYPTO
    /// stream, which carries only ML-KEM ciphertexts.
    ///
    /// Ciphertexts have a fixed size, so the stream is split into
    /// consecutive ciphertexts regardless of how CRYPTO frames fragmented
    /// it. Returns true once a complete ciphertext has been decapsulated.
    pub fn receive_ciphertext_bytes(&mut self, data: &[u8]) -> Result<bool> {
        if !self.is_server {
            return Err(Error::InvalidState);
        }

        self.incoming_ciphertext.extend_from_slice(data);

        if self.incoming_ciphertext.len() > MAX_BUFFERED_CIPHERTEXT {
            return Err(Error::CryptoBufferExceeded);
        }

        if self.incoming_ciphertext.len() < MLKEM768_CIPHERTEXT_SIZE {
            return Ok(false);
        }

        let ciphertext: Vec<u8> = self
            .incoming_ciphertext
            .drain(..MLKEM768_CIPHERTEXT_SIZE)
            .collect();

        self.store_and_precompute_from_ciphertext(self.epoch + 1, &ciphertext)?;

        Ok(true)
    }

    /// Activate precomputed epoch keys.
    ///
    /// `starting_pn`: the first server→client packet number of the new
    /// epoch. On the server, this is the packet about to be sent; it also
    /// generates the key pair for the following epoch, whose public key that
    /// packet starts carrying.
    pub fn activate_precomputed_epoch(&mut self, starting_pn: u64) -> Result<()> {
        let pre = self
            .precomputed_next_epoch
            .take()
            .ok_or(Error::InvalidState)?;

        // Derive chain keys, binding them to the starting_pn of this epoch
        let (chain_a, chain_b) =
            blake3_kdf::derive_epoch_chain_keys(&pre.shared_secret[..], starting_pn);

        // Server swaps so server-send == client-recv (same orientation as
        // epoch 0)
        let (new_send_chain, new_recv_chain) = if self.is_server {
            (chain_b, chain_a)
        } else {
            (chain_a, chain_b)
        };

        // pn spaces are independent per direction:
        //
        // - Server→client: the server picks `starting_pn` (the pn of its
        //   first new-epoch packet), and the client learns it from that
        //   packet. That chain starts at `starting_pn`.
        //
        // - Client→server: the client starts its new-epoch chain at the first
        //   packet it sends after seeing the server's switch. The server
        //   can't know that pn in advance, so its receive chain stays
        //   unanchored until the first new-epoch client packet
        //   authenticates. The previous cursor is a lower bound for where the
        //   client starts.
        let recv_chain = if self.is_server {
            RecvChain::unanchored(new_recv_chain, self.recv_chain.next_pn)
        } else {
            RecvChain {
                key: new_recv_chain,
                next_pn: starting_pn,
                start: starting_pn,
                anchored: true,
            }
        };

        // Keep the outgoing epoch's receive state for a short while, so
        // packets the peer sent before the switch can still be decrypted.
        let old_chain = std::mem::replace(&mut self.recv_chain, recv_chain);

        self.prev_epoch_recv = Some(PrevEpochRecv {
            epoch: self.epoch,
            chain: old_chain,
            skipped: std::mem::take(&mut self.skipped_recv_keys),
            expires: Instant::now() + self.retention,
        });

        self.skipped_recv_keys.reserve(MAX_SKIP);
        self.skipped_recv_queue.clear();

        self.epoch = pre.epoch;
        self.send_chain_key = new_send_chain;

        if self.is_server {
            self.send_chain_pn = starting_pn;
            self.send_epoch_start = Some(starting_pn);
        } else {
            self.send_epoch_start = None;
        }

        self.pending_ratchet = None;
        self.incoming_pubkey_chunks.fill(None);

        if self.is_server {
            self.initiate_ratchet();
        } else {
            // The next ciphertext send time is computed relative to this.
            self.next_ratchet_time = Some(Instant::now() + self.interval);
        }

        debug!(
            "PQDR epoch {} activated: starting_pn={}",
            self.epoch, starting_pn,
        );

        Ok(())
    }

    /// Client: activate the precomputed epoch, given the pn of the server's
    /// first new-epoch packet.
    pub fn complete_client_ratchet_on_key_update(
        &mut self, starting_pn: u64,
    ) -> Result<()> {
        // pending_ratchet must be WaitingToActivate
        match self.pending_ratchet.as_ref() {
            Some(PendingRatchet::WaitingToActivate) => {},
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
    // Encrypt (pn-indexed chain)
    // -----------------------------------------------------------------------

    /// The AEAD that packet payloads are protected with, under the keys
    /// from this ratchet.
    #[inline]
    pub fn aead(&mut self) -> &mut PqdrAead {
        &mut self.aead
    }

    /// Derive encryption key for outgoing packet `pn`.
    ///
    /// Advances the send chain from `send_chain_pn` to `pn`, discarding
    /// keys for any skipped pns (QUIC never retransmits the same pn, so
    /// there is no need to cache intermediate enc keys). The first packet
    /// sent with an epoch's keys starts that epoch's chain.
    /// Returns the enc key for `pn`.
    pub fn encrypt_key(&mut self, pn: u64) -> Result<SecretKey> {
        if pn < self.send_chain_pn {
            // pn went backwards — should never happen in QUIC
            return Err(Error::CryptoFail);
        }

        if self.send_epoch_start.is_none() {
            self.send_epoch_start = Some(pn);
            self.send_chain_pn = pn;
        }

        // Advance chain through any skipped pns (discard their keys)
        while self.send_chain_pn < pn {
            let (new_chain, _) =
                self.kdf.derive(&self.send_chain_key, self.send_chain_pn);
            self.send_chain_key = new_chain;
            self.send_chain_pn += 1;
        }

        // Derive key for target pn
        let (new_chain, enc_key) = self.kdf.derive(&self.send_chain_key, pn);
        self.send_chain_key = new_chain;
        self.send_chain_pn = pn + 1;

        Ok(enc_key)
    }

    // -----------------------------------------------------------------------
    // Decrypt (pn-indexed chain)
    // -----------------------------------------------------------------------

    /// Returns the `attempt`-th candidate key for incoming packet `pn`, or
    /// `None` once there are no more candidates.
    ///
    /// Does not modify the ratchet: call `commit_recv_key` with the
    /// candidate that authenticates the packet. Usually there is a single
    /// candidate; there can be more while the start of an epoch's chain is
    /// still unknown (see `recv_may_need_trial`).
    pub fn recv_key_candidate(
        &self, which: RecvEpoch, pn: u64, attempt: u64,
    ) -> Option<RecvKey> {
        match which {
            RecvEpoch::Current => {
                if let Some(k) = self.skipped_recv_keys.get(&pn) {
                    return (attempt == 0).then(|| RecvKey {
                        key: k.clone(),
                        commit: RecvCommit::CurrentCached { pn },
                    });
                }

                let chain = &self.recv_chain;

                let anchor = if chain.anchored {
                    if attempt > 0 {
                        return None;
                    }

                    None
                } else {
                    // Packets of the previous epoch that arrived after the
                    // switch raise the lowest pn the new chain can start at.
                    let lower = match &self.prev_epoch_recv {
                        Some(prev) if prev.chain.anchored =>
                            chain.next_pn.max(prev.chain.next_pn),

                        _ => chain.next_pn,
                    };

                    Some(anchor_candidate(lower, pn, attempt)?)
                };

                let walk = walk_chain(
                    self.kdf,
                    &chain.key,
                    anchor.unwrap_or(chain.next_pn),
                    pn,
                )?;

                Some(RecvKey {
                    key: walk.enc_key,
                    commit: RecvCommit::Current {
                        pn,
                        anchor,
                        chain_key: walk.chain_key,
                        skipped: walk.skipped,
                    },
                })
            },

            RecvEpoch::Previous => {
                let prev = self.prev_epoch_recv.as_ref()?;

                if prev.epoch + 1 != self.epoch || Instant::now() >= prev.expires {
                    return None;
                }

                if let Some(k) = prev.skipped.get(&pn) {
                    return (attempt == 0).then(|| RecvKey {
                        key: k.clone(),
                        commit: RecvCommit::PreviousCached { pn },
                    });
                }

                let anchor = if prev.chain.anchored {
                    if attempt > 0 {
                        return None;
                    }

                    None
                } else {
                    Some(anchor_candidate(prev.chain.next_pn, pn, attempt)?)
                };

                let walk = walk_chain(
                    self.kdf,
                    &prev.chain.key,
                    anchor.unwrap_or(prev.chain.next_pn),
                    pn,
                )?;

                Some(RecvKey {
                    key: walk.enc_key,
                    commit: RecvCommit::Previous {
                        pn,
                        anchor,
                        chain_key: walk.chain_key,
                        skipped: walk.skipped,
                    },
                })
            },

            RecvEpoch::Next => {
                if self.is_server {
                    return None;
                }

                if !matches!(
                    self.pending_ratchet,
                    Some(PendingRatchet::WaitingToActivate)
                ) {
                    return None;
                }

                let pre = self.precomputed_next_epoch.as_ref()?;

                // The server's first new-epoch pn comes after every pn it
                // used in the current epoch.
                let anchor =
                    anchor_candidate(self.recv_chain.next_pn, pn, attempt)?;

                // Client orientation: (send, recv) = (chain_a, chain_b).
                let (_, recv_root) = blake3_kdf::derive_epoch_chain_keys(
                    &pre.shared_secret[..],
                    anchor,
                );

                let walk = walk_chain(self.kdf, &recv_root, anchor, pn)?;

                Some(RecvKey {
                    key: walk.enc_key,
                    commit: RecvCommit::Activate {
                        starting_pn: anchor,
                        pn,
                        chain_key: walk.chain_key,
                        skipped: walk.skipped,
                    },
                })
            },
        }
    }

    /// Fast path for the common case: the key for `pn` if it is the next
    /// packet on the current epoch's chain and the chain's start is known.
    ///
    /// Gives the same key as `recv_key_candidate(RecvEpoch::Current, pn, 0)`
    /// without its bookkeeping. Does not modify the ratchet: call
    /// `commit_in_order` once the packet authenticates.
    pub fn recv_key_in_order(&self, pn: u64) -> Option<InOrderRecvKey> {
        let chain = &self.recv_chain;

        if !chain.anchored || pn != chain.next_pn {
            return None;
        }

        let (chain_key, key) = self.kdf.derive(&chain.key, pn);

        Some(InOrderRecvKey { pn, key, chain_key })
    }

    /// Advances the current epoch's chain past the packet that a key from
    /// `recv_key_in_order` authenticated.
    pub fn commit_in_order(&mut self, recv_key: InOrderRecvKey) {
        debug_assert!(self.recv_chain.anchored);
        debug_assert_eq!(self.recv_chain.next_pn, recv_key.pn);

        // Cloned rather than moved out of `recv_key`, which wipes its copies
        // when dropped. The replaced chain key is wiped too.
        self.recv_chain.key = recv_key.chain_key.clone();
        self.recv_chain.next_pn = recv_key.pn + 1;
    }

    /// Whether more than one candidate key may need to be tried for a packet
    /// of epoch `which`.
    pub fn recv_may_need_trial(&self, which: RecvEpoch) -> bool {
        match which {
            RecvEpoch::Current => !self.recv_chain.anchored,

            RecvEpoch::Previous => self
                .prev_epoch_recv
                .as_ref()
                .is_some_and(|prev| !prev.chain.anchored),

            RecvEpoch::Next => true,
        }
    }

    /// Records that the peer's packet `pn` was protected with the TLS keys.
    ///
    /// The peer switches to ratchet keys once and for all, so its epoch-0
    /// chain starts after `pn`. This narrows down the start pns to try.
    pub fn note_tls_protected_pn(&mut self, pn: u64) {
        if self.epoch == 0 && !self.recv_chain.anchored {
            self.recv_chain.next_pn = self.recv_chain.next_pn.max(pn + 1);
        }
    }

    /// The pn at which the peer started its chain for the current epoch, if
    /// known.
    pub fn peer_chain_start(&self) -> Option<u64> {
        self.recv_chain
            .anchored
            .then_some(self.recv_chain.start)
    }

    /// Applies the ratchet update for a candidate key that authenticated a
    /// packet.
    pub fn commit_recv_key(&mut self, candidate: RecvKey) -> Result<()> {
        // Keys are cloned rather than moved out of `candidate`, which wipes
        // its copies when dropped.
        match &candidate.commit {
            RecvCommit::CurrentCached { pn } => {
                remove_secret(&mut self.skipped_recv_keys, pn);
            },

            RecvCommit::PreviousCached { pn } => {
                if let Some(prev) = self.prev_epoch_recv.as_mut() {
                    remove_secret(&mut prev.skipped, pn);
                }
            },

            RecvCommit::Current {
                pn,
                anchor,
                chain_key,
                skipped,
            } => self.advance_recv_chain(*pn, *anchor, chain_key, skipped),

            RecvCommit::Previous {
                pn,
                anchor,
                chain_key,
                skipped,
            } => {
                let prev =
                    self.prev_epoch_recv.as_mut().ok_or(Error::InvalidState)?;

                for (skipped_pn, key) in skipped {
                    if prev.skipped.len() >= MAX_SKIP {
                        break;
                    }

                    prev.skipped.insert(*skipped_pn, key.clone());
                }

                prev.chain = RecvChain {
                    key: chain_key.clone(),
                    next_pn: pn + 1,
                    start: anchor.unwrap_or(prev.chain.start),
                    anchored: true,
                };
            },

            RecvCommit::Activate {
                starting_pn,
                pn,
                chain_key,
                skipped,
            } => {
                self.complete_client_ratchet_on_key_update(*starting_pn)?;

                self.advance_recv_chain(*pn, None, chain_key, skipped);
            },
        }

        Ok(())
    }

    fn advance_recv_chain(
        &mut self, pn: u64, anchor: Option<u64>, chain_key: &SecretKey,
        skipped: &[(u64, SecretKey)],
    ) {
        for (skipped_pn, key) in skipped {
            self.insert_skipped_key(*skipped_pn, key.clone());
        }

        self.recv_chain = RecvChain {
            key: chain_key.clone(),
            next_pn: pn + 1,
            start: anchor.unwrap_or(self.recv_chain.start),
            anchored: true,
        };
    }

    fn insert_skipped_key(&mut self, pn: u64, key: SecretKey) {
        while self.skipped_recv_keys.len() >= MAX_SKIP {
            match self.skipped_recv_queue.pop_front() {
                Some(oldest) => {
                    remove_secret(&mut self.skipped_recv_keys, &oldest);
                },

                None => break,
            }
        }

        self.skipped_recv_keys.insert(pn, key);
        self.skipped_recv_queue.push_back(pn);

        // Keys that were used leave stale entries in the queue; prune them
        // so the queue can't grow without bound.
        if self.skipped_recv_queue.len() > 2 * MAX_SKIP {
            let keys = &self.skipped_recv_keys;
            self.skipped_recv_queue.retain(|pn| keys.contains_key(pn));
        }
    }

    /// Derive and consume the decryption key for `(epoch, pn)`, assuming the
    /// packet authenticates. Test helper: the connection uses
    /// `recv_key_candidate` and `commit_recv_key`.
    #[cfg(test)]
    pub fn decrypt_key(
        &mut self, epoch: RatchetEpoch, pn: u64,
    ) -> Result<SecretKey> {
        let which = if epoch == self.epoch {
            RecvEpoch::Current
        } else if epoch + 1 == self.epoch {
            RecvEpoch::Previous
        } else {
            return Err(Error::CryptoFail);
        };

        let candidate = self
            .recv_key_candidate(which, pn, 0)
            .ok_or(Error::CryptoFail)?;

        let key = candidate.key.clone();

        self.commit_recv_key(candidate)?;

        Ok(key)
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
    // Public key chunks
    // -----------------------------------------------------------------------

    /// Server: the public key chunk to embed in our ratchet-protected packet
    /// `pn`, if it carries one (see the module docs).
    pub fn outgoing_chunk(&self, pn: u64) -> Option<&KemChunk> {
        // Until the first packet of epoch 0 is sent, `pn` would start it.
        let start = self.send_epoch_start.unwrap_or(pn);

        self.outgoing_pubkey_chunks.get(chunk_index(start, pn)?)
    }

    /// Client: the index of the public key chunk carried by the server's
    /// packet `pn`, if it carries one. `which` is the epoch the packet was
    /// decrypted as, after its key has been committed.
    pub fn incoming_chunk_index(&self, which: RecvEpoch, pn: u64) -> Option<usize> {
        if self.is_server {
            return None;
        }

        let chain = match which {
            RecvEpoch::Previous => &self.prev_epoch_recv.as_ref()?.chain,

            // A packet that started the next epoch has made it the current
            // one.
            RecvEpoch::Current | RecvEpoch::Next => &self.recv_chain,
        };

        if !chain.anchored {
            return None;
        }

        chunk_index(chain.start, pn)
    }

    /// Client: stores public key chunk `index` of the current epoch.
    ///
    /// Once enough chunks have arrived to rebuild the server's next public
    /// key, encapsulates to it (see `respond_to_ratchet`) and returns the
    /// epoch the resulting keys are for.
    pub fn receive_pubkey_chunk(
        &mut self, index: usize, chunk: &[u8],
    ) -> Result<Option<RatchetEpoch>> {
        // Only the current epoch's key matters, and once it is rebuilt the
        // remaining chunks carry nothing new.
        if self.is_server || self.pending_ratchet.is_some() {
            return Ok(None);
        }

        let slot = self
            .incoming_pubkey_chunks
            .get_mut(index)
            .ok_or(Error::InvalidPacket)?;

        if slot.is_none() {
            *slot = Some(chunk.try_into().map_err(|_| Error::InvalidPacket)?);
        }

        let received = self
            .incoming_pubkey_chunks
            .iter()
            .filter(|c| c.is_some())
            .count();

        if received < PUBKEY_CHUNK_COUNT {
            return Ok(None);
        }

        let pubkey = decode_pubkey(&self.incoming_pubkey_chunks)
            .ok_or(Error::CryptoFail)?;

        self.incoming_pubkey_chunks.fill(None);

        let epoch = self.respond_to_ratchet(self.epoch + 1, &pubkey)?;

        Ok(Some(epoch))
    }

    /// The index of the public key chunk our last packet carried, if any.
    #[cfg(test)]
    pub fn last_sent_chunk_index(&self) -> Option<usize> {
        if self.outgoing_pubkey_chunks.is_empty() {
            return None;
        }

        chunk_index(self.send_epoch_start?, self.send_chain_pn.checked_sub(1)?)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn epoch(&self) -> RatchetEpoch {
        self.epoch
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Gives both sides the same synthetic epoch-1 shared secret, as if the
    /// KEM exchange had completed (bypasses ML-KEM for test speed).
    fn inject_epoch1(
        server: &mut RatchetState, client: &mut RatchetState, secret: &[u8],
    ) {
        let shared_secret = || Zeroizing::new(*blake3::hash(secret).as_bytes());

        server.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: 1,
            shared_secret: shared_secret(),
        });

        client.pending_ratchet = Some(PendingRatchet::WaitingToActivate);
        client.precomputed_next_epoch = Some(PrecomputedEpoch {
            epoch: 1,
            shared_secret: shared_secret(),
        });
    }

    /// Simulates receiving a packet: tries candidates until one matches the
    /// sender's key (standing in for AEAD verification) and commits it.
    /// Returns the number of candidates tried, or None if none matched.
    fn recv_with_trial(
        r: &mut RatchetState, which: RecvEpoch, pn: u64,
        sender_key: &[u8; BLAKE3_OUT_LEN],
    ) -> Option<u64> {
        let mut attempt = 0;

        while let Some(candidate) = r.recv_key_candidate(which, pn, attempt) {
            if candidate.key() == sender_key {
                r.commit_recv_key(candidate).unwrap();
                return Some(attempt + 1);
            }

            attempt += 1;
        }

        None
    }

    /// The server's current public key, rebuilt from its first data chunks.
    fn server_pubkey(server: &RatchetState) -> Vec<u8> {
        let mut pubkey = server.outgoing_pubkey_chunks[..PUBKEY_CHUNK_COUNT]
            .concat();
        pubkey.truncate(MLKEM768_PUBLIC_KEY_BYTES);
        pubkey
    }

    #[test]
    fn test_ratchet_init() {
        let secret = b"test-handshake-secret";

        let client = RatchetState::from_handshake_secret(secret, true);
        let server = RatchetState::from_handshake_secret(secret, false);

        assert_eq!(client.epoch(), 0);
        assert_eq!(server.epoch(), 0);

        // Both chains start at the first ratchet-protected packet.
        assert_eq!(client.send_epoch_start, None);
        assert_eq!(server.send_epoch_start, None);
        assert!(!client.recv_chain.anchored);
        assert!(!server.recv_chain.anchored);

        // The server has its first key pair ready; the client never
        // initiates.
        assert_eq!(server.outgoing_pubkey_chunks.len(), PUBKEY_CODED_CHUNK_COUNT);
        assert!(matches!(
            server.pending_ratchet,
            Some(PendingRatchet::WaitingForCiphertext { epoch: 1, .. })
        ));
        assert!(client.outgoing_pubkey_chunks.is_empty());
        assert!(client.pending_ratchet.is_none());
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
            assert_eq!(enc_key, dec_key, "Key mismatch at pn={pn}");
        }

        // Client sends pn=0,1,2; server receives
        for pn in 0u64..5 {
            let enc_key = client.encrypt_key(pn).unwrap();
            let dec_key = server.decrypt_key(0, pn).unwrap();
            assert_eq!(enc_key, dec_key, "Key mismatch at pn={pn}");
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

        // QUIC never retransmits the same pn: attempting to re-encrypt an
        // already-used pn should fail because the chain has already advanced
        // past it.
        assert!(sender.encrypt_key(0).is_err());
        assert!(sender.encrypt_key(1).is_err());

        let k3 = sender.encrypt_key(3).unwrap();
        assert_ne!(k0, k3);
    }

    #[test]
    fn test_decrypt_out_of_order() {
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        let keys: Vec<_> = (0..4).map(|pn| sender.encrypt_key(pn).unwrap()).collect();

        // Receive out of order: 0 (which starts the chain), 3, 1, 2.
        for pn in [0, 3, 1, 2] {
            assert_eq!(recver.decrypt_key(0, pn).unwrap(), keys[pn as usize]);
        }
    }

    #[test]
    fn test_epoch0_chain_starts_at_first_ratchet_packet() {
        // The server's pns 0..5 were protected with the TLS keys, so its
        // epoch-0 chain starts at pn 5. Pns 5 and 6 are lost; the client
        // finds the start from pn 7, and can still decrypt 5 and 6 if they
        // arrive later.
        let secret = b"test-epoch0-anchor-secret";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        let keys: Vec<_> =
            (5..10).map(|pn| server.encrypt_key(pn).unwrap()).collect();
        assert_eq!(server.send_epoch_start, Some(5));

        client.note_tls_protected_pn(3);

        assert!(recv_with_trial(&mut client, RecvEpoch::Current, 7, &keys[2])
            .is_some());
        assert_eq!(client.peer_chain_start(), Some(5));

        for pn in [5, 6, 8, 9] {
            assert_eq!(
                recv_with_trial(&mut client, RecvEpoch::Current, pn, &keys[pn as usize - 5]),
                Some(1),
            );
        }

        // TLS-protected pns only narrow down the search while the start is
        // unknown.
        client.note_tls_protected_pn(100);
        assert_eq!(client.recv_chain.next_pn, 10);
    }

    #[test]
    fn test_candidate_does_not_modify_state() {
        // A forged packet can claim any pn. Looking up its key must not
        // move the chain, or a single forged packet would desynchronise the
        // receiver.
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        let forged = recver
            .recv_key_candidate(RecvEpoch::Current, 5000, 0)
            .unwrap();
        drop(forged); // never authenticates, so never committed

        for pn in 0..10 {
            let k = sender.encrypt_key(pn).unwrap();
            assert_eq!(recver.decrypt_key(0, pn).unwrap(), k);
        }
    }

    #[test]
    fn test_in_order_fast_path() {
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        let keys: Vec<_> =
            (0..8).map(|pn| sender.encrypt_key(pn).unwrap()).collect();

        // Until the first packet fixes the chain's start, the start pn has
        // to be searched for.
        assert!(recver.recv_key_in_order(0).is_none());
        assert_eq!(recver.decrypt_key(0, 0).unwrap(), keys[0]);

        // Only the next pn takes the fast path, which gives the same key as
        // the general one and changes nothing until committed.
        assert!(recver.recv_key_in_order(2).is_none());

        let fast = recver.recv_key_in_order(1).unwrap();
        let general =
            recver.recv_key_candidate(RecvEpoch::Current, 1, 0).unwrap();
        assert_eq!(fast.key(), general.key());
        assert_eq!(fast.key(), &*keys[1]);

        drop(fast); // a forged packet: never committed
        let fast = recver.recv_key_in_order(1).unwrap();
        recver.commit_in_order(fast);

        // Skip pn 3: the general path keeps its key for later.
        assert_eq!(recver.recv_key_in_order(2).unwrap().key(), &*keys[2]);
        recver.commit_in_order(recver.recv_key_in_order(2).unwrap());
        assert_eq!(recver.decrypt_key(0, 4).unwrap(), keys[4]);

        assert_eq!(recver.recv_key_in_order(5).unwrap().key(), &*keys[5]);
        assert_eq!(recver.decrypt_key(0, 3).unwrap(), keys[3]);
        assert!(recver.recv_key_in_order(3).is_none());

        for pn in 5..8 {
            let fast = recver.recv_key_in_order(pn).unwrap();
            assert_eq!(fast.key(), &*keys[pn as usize]);
            recver.commit_in_order(fast);
        }
    }

    #[test]
    fn test_recv_jump_limit() {
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        let k0 = sender.encrypt_key(0).unwrap();
        assert_eq!(recver.decrypt_key(0, 0).unwrap(), k0);

        // The chain is now positioned at pn 1.
        assert!(recver
            .recv_key_candidate(RecvEpoch::Current, 1 + MAX_RECV_JUMP, 0)
            .is_some());
        assert!(recver
            .recv_key_candidate(RecvEpoch::Current, 2 + MAX_RECV_JUMP, 0)
            .is_none());
    }

    #[test]
    fn test_skipped_queue_bounded() {
        let secret = b"test-handshake-secret";
        let mut sender = RatchetState::from_handshake_secret(secret, true);
        let mut recver = RatchetState::from_handshake_secret(secret, false);

        let k0 = sender.encrypt_key(0).unwrap();
        assert_eq!(recver.decrypt_key(0, 0).unwrap(), k0);

        // Every packet arrives after its successor, so every key is skipped
        // once and then consumed.
        for pair in 0..5000u64 {
            let a = 2 * pair + 1;
            let b = a + 1;
            let ka = sender.encrypt_key(a).unwrap();
            let kb = sender.encrypt_key(b).unwrap();

            assert_eq!(recver.decrypt_key(0, b).unwrap(), kb);
            assert_eq!(recver.decrypt_key(0, a).unwrap(), ka);
        }

        assert!(recver.skipped_recv_keys.is_empty());
        assert!(recver.skipped_recv_queue.len() <= 2 * MAX_SKIP + 1);
    }

    #[test]
    fn test_pubkey_chunk_positions() {
        let secret = b"test-chunk-position-secret";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        // Before its first ratchet-protected packet, whichever pn the server
        // sends next starts the epoch and carries chunk 0.
        assert_eq!(server.outgoing_chunk(1234), Some(&server.outgoing_pubkey_chunks[0]));

        let k10 = server.encrypt_key(10).unwrap();
        let last = 10 + PUBKEY_CODED_CHUNK_COUNT as u64 - 1;

        assert_eq!(server.outgoing_chunk(9), None);
        assert_eq!(server.outgoing_chunk(10), Some(&server.outgoing_pubkey_chunks[0]));
        assert_eq!(
            server.outgoing_chunk(last),
            Some(&server.outgoing_pubkey_chunks[PUBKEY_CODED_CHUNK_COUNT - 1])
        );
        assert_eq!(server.outgoing_chunk(last + 1), None);

        // The client needs to know where the chain starts first.
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, 10), None);
        assert!(recv_with_trial(&mut client, RecvEpoch::Current, 10, &k10).is_some());

        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, 9), None);
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, 10), Some(0));
        assert_eq!(
            client.incoming_chunk_index(RecvEpoch::Current, last),
            Some(PUBKEY_CODED_CHUNK_COUNT - 1)
        );
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, last + 1), None);

        // The client sends no chunks, and the server expects none.
        assert_eq!(client.outgoing_chunk(0), None);
        assert_eq!(server.incoming_chunk_index(RecvEpoch::Current, 10), None);
    }

    #[test]
    fn test_pubkey_rebuilt_from_any_quarter_of_chunks() {
        let secret = b"test-pubkey-quarter-secret";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        // Only every fourth chunk arrives, in reverse order.
        let received: Vec<usize> =
            (0..PUBKEY_CODED_CHUNK_COUNT).rev().filter(|i| i % 4 == 3).collect();
        assert_eq!(received.len(), PUBKEY_CHUNK_COUNT);

        for (n, &index) in received.iter().enumerate() {
            let chunk = server.outgoing_pubkey_chunks[index];
            let done = client.receive_pubkey_chunk(index, &chunk).unwrap();

            assert_eq!(done, (n + 1 == PUBKEY_CHUNK_COUNT).then_some(1));
        }

        // The client encapsulated to the right key: both sides agree on the
        // epoch-1 keys.
        let (_, ciphertext) = client.take_pending_ciphertext().unwrap();
        assert!(server.receive_ciphertext_bytes(&ciphertext).unwrap());

        server.activate_precomputed_epoch(50).unwrap();
        client.complete_client_ratchet_on_key_update(50).unwrap();

        let sk = server.encrypt_key(50).unwrap();
        assert_eq!(client.decrypt_key(1, 50).unwrap(), sk);

        // Further chunks of the same key are ignored.
        let chunk = server.outgoing_pubkey_chunks[0];
        assert_eq!(client.receive_pubkey_chunk(0, &chunk), Ok(None));
    }

    #[test]
    fn test_new_key_pair_every_epoch() {
        let secret = b"test-new-key-pair-every-epoch!";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        let epoch0_pubkey = server_pubkey(&server);

        client.respond_to_ratchet(1, &epoch0_pubkey).unwrap();
        let (_, ciphertext) = client.take_pending_ciphertext().unwrap();
        server.receive_ciphertext_bytes(&ciphertext).unwrap();

        server.activate_precomputed_epoch(20).unwrap();

        assert_ne!(server_pubkey(&server), epoch0_pubkey);
        assert_eq!(server.send_epoch_start, Some(20));
        assert!(matches!(
            server.pending_ratchet,
            Some(PendingRatchet::WaitingForCiphertext { epoch: 2, .. })
        ));
        assert_eq!(server.outgoing_chunk(20), Some(&server.outgoing_pubkey_chunks[0]));
    }

    #[test]
    fn test_previous_epoch_chunk_positions() {
        // A late epoch-0 packet still carries an epoch-0 chunk, which must be
        // located relative to the epoch-0 chain, not the new one.
        let secret = b"test-previous-chunk-positions!";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        let keys: Vec<_> =
            (0..100).map(|pn| server.encrypt_key(pn).unwrap()).collect();

        for pn in 0..99u64 {
            assert!(recv_with_trial(&mut client, RecvEpoch::Current, pn, &keys[pn as usize])
                .is_some());
        }

        inject_epoch1(&mut server, &mut client, b"previous-chunk-positions-secret");
        server.activate_precomputed_epoch(100).unwrap();
        let k100 = server.encrypt_key(100).unwrap();

        assert!(recv_with_trial(&mut client, RecvEpoch::Next, 100, &k100).is_some());
        assert_eq!(client.epoch(), 1);

        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, 100), Some(0));
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Previous, 5), Some(5));
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Previous, 99), None);

        assert!(recv_with_trial(&mut client, RecvEpoch::Previous, 99, &keys[99])
            .is_some());
    }

    #[test]
    fn test_epoch_transition_asymmetric_pn() {
        // The two directions use separate pn spaces: after the server has
        // sent 100 packets and the client 10, the server→client chain
        // restarts at the switch pn (100) while the client→server chain
        // continues from the client's own cursor (10).
        let handshake_secret = b"test-epoch-transition-secret";
        let mut server =
            RatchetState::from_handshake_secret(handshake_secret, false);
        let mut client = RatchetState::from_handshake_secret(handshake_secret, true);

        for pn in 0..100u64 {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(0, pn).unwrap();
            assert_eq!(sk, ck, "epoch-0 server→client key mismatch at pn={pn}");
        }
        for pn in 0..10u64 {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(0, pn).unwrap();
            assert_eq!(ck, sk, "epoch-0 client→server key mismatch at pn={pn}");
        }

        inject_epoch1(&mut server, &mut client, b"synthetic-kem-shared-secret-32bb");

        let starting_pn = 100u64;
        server.activate_precomputed_epoch(starting_pn).unwrap();
        client
            .complete_client_ratchet_on_key_update(starting_pn)
            .unwrap();

        for pn in [100u64, 101, 102] {
            let enc = server.encrypt_key(pn).unwrap();
            let dec = client.decrypt_key(1, pn).unwrap();
            assert_eq!(enc, dec, "epoch-1 server→client key mismatch at pn={pn}");
        }

        for pn in [10u64, 11, 12] {
            let enc = client.encrypt_key(pn).unwrap();
            let dec = server.decrypt_key(1, pn).unwrap();
            assert_eq!(enc, dec, "epoch-1 client→server key mismatch at pn={pn}");
        }
    }

    #[test]
    fn test_epoch_transition_inflight_pn_sync() {
        // An epoch-0 client packet still in flight at the switch arrives
        // after the server has activated epoch 1. It must decrypt with the
        // retained epoch-0 chain, and the client's epoch-1 chain (which
        // starts after it) must still line up.
        let handshake_secret = b"test-inflight-b4-regression-key!";
        let mut server =
            RatchetState::from_handshake_secret(handshake_secret, false);
        let mut client = RatchetState::from_handshake_secret(handshake_secret, true);

        for pn in 0..100u64 {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(0, pn).unwrap();
            assert_eq!(sk, ck, "epoch-0 s→c key mismatch at pn={pn}");
        }

        for pn in 0..4u64 {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(0, pn).unwrap();
            assert_eq!(ck, sk, "epoch-0 c→s key mismatch at pn={pn}");
        }

        // In flight across the switch.
        let inflight_key_client = client.encrypt_key(4).unwrap();

        inject_epoch1(&mut server, &mut client, b"synthetic-kem-secret-bug4-test!!");

        let starting_pn = 100u64;
        server.activate_precomputed_epoch(starting_pn).unwrap();
        client
            .complete_client_ratchet_on_key_update(starting_pn)
            .unwrap();

        let inflight_key_server = server.decrypt_key(0, 4).unwrap();
        assert_eq!(inflight_key_client, inflight_key_server);

        let epoch1_key_client = client.encrypt_key(5).unwrap();
        let epoch1_key_server = server.decrypt_key(1, 5).unwrap();
        assert_eq!(epoch1_key_client, epoch1_key_server);

        for pn in [6u64, 7, 10, 50] {
            let ck = client.encrypt_key(pn).unwrap();
            let sk = server.decrypt_key(1, pn).unwrap();
            assert_eq!(ck, sk, "epoch-1 c→s key mismatch at pn={pn}");
        }

        for pn in [100u64, 101, 102] {
            let sk = server.encrypt_key(pn).unwrap();
            let ck = client.decrypt_key(1, pn).unwrap();
            assert_eq!(sk, ck, "epoch-1 s→c key mismatch at pn={pn}");
        }
    }

    #[test]
    fn test_epoch_transition_lost_client_packets() {
        // The client's last epoch-0 packet and its first epoch-1 packet are
        // both lost. The server only knows the client started epoch 1
        // somewhere after pn 3, and must still find the right start.
        let secret = b"test-lost-client-packets-secret";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        for pn in 0..4u64 {
            let ck = client.encrypt_key(pn).unwrap();
            assert_eq!(server.decrypt_key(0, pn).unwrap(), ck);
        }

        let _lost_epoch0 = client.encrypt_key(4).unwrap();

        inject_epoch1(&mut server, &mut client, b"synthetic-kem-secret-lost-pkts!!");
        server.activate_precomputed_epoch(100).unwrap();
        client.complete_client_ratchet_on_key_update(100).unwrap();

        // The client's epoch-1 chain starts at pn 5; pn 5 is lost.
        let _lost_epoch1 = client.encrypt_key(5).unwrap();
        let k6 = client.encrypt_key(6).unwrap();
        assert!(recv_with_trial(&mut server, RecvEpoch::Current, 6, &k6).is_some());

        // Anchored now: later packets need a single candidate.
        for pn in 7..20u64 {
            let ck = client.encrypt_key(pn).unwrap();
            assert_eq!(
                recv_with_trial(&mut server, RecvEpoch::Current, pn, &ck),
                Some(1)
            );
        }
    }

    #[test]
    fn test_epoch_transition_lost_server_switch_packet() {
        // The server's first epoch-1 packet (which tells the client where
        // the epoch-1 chain starts) is lost. The client must locate the
        // start from the next packet and derive the same epoch-1 keys.
        let secret = b"test-lost-switch-packet-secret!!";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        for pn in 0..100u64 {
            let sk = server.encrypt_key(pn).unwrap();
            assert_eq!(client.decrypt_key(0, pn).unwrap(), sk);
        }

        inject_epoch1(&mut server, &mut client, b"synthetic-kem-secret-lost-switch");
        server.activate_precomputed_epoch(100).unwrap();

        let _lost = server.encrypt_key(100).unwrap();
        let k101 = server.encrypt_key(101).unwrap();

        assert!(recv_with_trial(&mut client, RecvEpoch::Next, 101, &k101).is_some());
        assert_eq!(client.epoch(), 1);

        // The chunk positions follow the server's actual start.
        assert_eq!(client.incoming_chunk_index(RecvEpoch::Current, 101), Some(1));

        // Both directions agree on epoch-1 keys afterwards.
        for pn in 102..110u64 {
            let sk = server.encrypt_key(pn).unwrap();
            assert_eq!(client.decrypt_key(1, pn).unwrap(), sk);
        }

        for pn in 0..10u64 {
            let ck = client.encrypt_key(pn).unwrap();
            assert!(recv_with_trial(&mut server, RecvEpoch::Current, pn, &ck)
                .is_some());
        }
    }

    #[test]
    fn test_next_epoch_candidates_do_not_activate() {
        let secret = b"test-next-epoch-no-activate-key!";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        inject_epoch1(&mut server, &mut client, b"synthetic-kem-secret-no-activate");

        // A forged packet with the new key phase: candidates are computed
        // but nothing is committed.
        let mut attempt = 0;
        while client
            .recv_key_candidate(RecvEpoch::Next, 3, attempt)
            .is_some()
        {
            attempt += 1;
        }

        assert_eq!(attempt, 4); // start pns 0..=3
        assert_eq!(client.epoch(), 0);
        assert!(client.has_precomputed_keys());
    }

    #[test]
    fn test_anchor_candidate_order() {
        let order: Vec<u64> =
            (0..10).map_while(|a| anchor_candidate(10, 13, a)).collect();
        assert_eq!(order, vec![13, 10, 12, 11]);

        assert_eq!(anchor_candidate(5, 4, 0), None);

        // Too large to search exhaustively: only candidates near pn.
        let far = 10 * MAX_ANCHOR_CANDIDATES;
        assert_eq!(anchor_candidate(0, far, 0), Some(far));
        assert_eq!(anchor_candidate(0, far, 1), Some(far - 1));
        assert_eq!(anchor_candidate(0, far, MAX_ANCHOR_CANDIDATES), None);
    }

    #[test]
    fn test_ciphertext_split_across_frames() {
        let secret = b"test-ciphertext-split-secret!!!!";
        let mut server = RatchetState::from_handshake_secret(secret, false);
        let mut client = RatchetState::from_handshake_secret(secret, true);

        client.respond_to_ratchet(1, &server_pubkey(&server)).unwrap();
        let (_, ciphertext) = client.take_pending_ciphertext().unwrap();

        assert!(!server.receive_ciphertext_bytes(&ciphertext[..500]).unwrap());
        assert!(!server.receive_ciphertext_bytes(&ciphertext[500..1000]).unwrap());
        assert!(server.receive_ciphertext_bytes(&ciphertext[1000..]).unwrap());
        assert!(server.has_precomputed_keys());

        server.activate_precomputed_epoch(7).unwrap();
        client.complete_client_ratchet_on_key_update(7).unwrap();

        let sk = server.encrypt_key(7).unwrap();
        assert_eq!(client.decrypt_key(1, 7).unwrap(), sk);
    }
}
