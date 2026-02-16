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
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! Double-ratchet implementation for PQDR-QUIC
//!
//! Implements a modified Signal Protocol double-ratchet:
//! - Symmetric ratchet: advances on every message via KDF chain
//! - Asymmetric ratchet: triggered every 60 seconds, alternating client/server
//! - Uses ML-KEM-768 for post-quantum key exchange
//! - Uses BLAKE3 for all key derivation

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use crate::crypto::blake3_kdf::{self, BLAKE3_OUT_LEN};
use crate::crypto::boringssl::{
    MLKEM768_private_key, MLKEM768_CIPHERTEXT_BYTES,
    MLKEM768_PUBLIC_KEY_BYTES, MLKEM_SHARED_SECRET_BYTES,
};
use crate::Error;
use crate::Result;

/// Ratchet epoch number
pub type RatchetEpoch = u32;

/// Message number within a chain
pub type MessageNumber = u64;

/// Maximum number of skipped message keys to store
const MAX_SKIP: usize = 512;

/// Ratchet interval: 60 seconds
pub const RATCHET_INTERVAL_MS: u64 = 60 * 1000;

/// State of the double-ratchet
pub struct RatchetState {
    /// Root key - never used directly, only for deriving new keys
    root_key: [u8; BLAKE3_OUT_LEN],

    /// Current ratchet epoch (increments on each DH ratchet step)
    epoch: RatchetEpoch,

    /// Sending chain key
    send_chain_key: [u8; BLAKE3_OUT_LEN],

    /// Number of messages sent in current sending chain
    send_msg_number: MessageNumber,

    /// Receiving chain key
    recv_chain_key: [u8; BLAKE3_OUT_LEN],

    /// Number of messages received in current receiving chain
    recv_msg_number: MessageNumber,

    /// Our current ML-KEM keypair (for receiving next ratchet)
    our_kem_keypair: Option<(Vec<u8>, MLKEM768_private_key)>,

    /// Their most recent ML-KEM public key bytes (for sending next ratchet)
    their_kem_pubkey_bytes: Option<Vec<u8>>,

    /// Skipped message keys for out-of-order delivery
    /// Map: (epoch, msg_number) -> message_key
    /// O(1) retrieval using HashMap
    skipped_keys: HashMap<(RatchetEpoch, MessageNumber), [u8; BLAKE3_OUT_LEN]>,

    /// Insertion order queue for LRU eviction
    /// Tracks (epoch, msg_number) in insertion order for O(1) oldest-key removal
    skipped_keys_queue: VecDeque<(RatchetEpoch, MessageNumber)>,

    /// Timer for next asymmetric ratchet
    next_ratchet_time: Option<Instant>,

    /// Are we the initiator for the next ratchet?
    we_initiate_next: bool,

    /// Pending ratchet state
    pending_ratchet: Option<PendingRatchet>,
}

/// Pending asymmetric ratchet exchange
enum PendingRatchet {
    /// We initiated: waiting for their ciphertext
    WaitingForCiphertext {
        our_private_key: MLKEM768_private_key,
        our_public_key_bytes: Vec<u8>,
        epoch: RatchetEpoch,
    },

    /// They initiated: we have their pubkey bytes, need to respond with ciphertext
    WaitingToRespond {
        their_public_key_bytes: Vec<u8>,
        epoch: RatchetEpoch,
    },
}

impl RatchetState {
    /// Initialize ratchet state from TLS handshake shared secret
    ///
    /// The `is_client` parameter determines who initiates the first ratchet.
    /// Clients initiate at t=2min, servers at t=4min, etc.
    pub fn from_handshake_secret(
        handshake_secret: &[u8],
        is_client: bool,
    ) -> Self {
        // Derive initial root key from handshake
        let root_key = blake3_kdf::init_root_key_from_handshake(handshake_secret);

        // Derive initial chain keys from root key
        let (send_chain_key, recv_chain_key) = if is_client {
            // Client sends first, so client's send = server's receive
            let (chain_send, chain_recv) = blake3_kdf::derive_initial_chain_keys(&root_key);
            (chain_send, chain_recv)
        } else {
            // Server receives first, so swap the keys
            let (chain_send, chain_recv) = blake3_kdf::derive_initial_chain_keys(&root_key);
            (chain_recv, chain_send)
        };

        RatchetState {
            root_key,
            epoch: 0,
            send_chain_key,
            send_msg_number: 0,
            recv_chain_key,
            recv_msg_number: 0,
            our_kem_keypair: None,
            their_kem_pubkey_bytes: None,
            skipped_keys: HashMap::new(),
            skipped_keys_queue: VecDeque::new(),
            next_ratchet_time: Some(Instant::now() + std::time::Duration::from_millis(
                RATCHET_INTERVAL_MS
            )),
            we_initiate_next: is_client, // Client initiates first
            pending_ratchet: None,
        }
    }

    /// Check if it's time to initiate an asymmetric ratchet
    pub fn should_initiate_ratchet(&self) -> bool {
        if !self.we_initiate_next {
            return false;
        }

        if self.pending_ratchet.is_some() {
            return false; // Already have a pending ratchet
        }

        match self.next_ratchet_time {
            Some(time) => Instant::now() >= time,
            None => false,
        }
    }

    /// Initiate an asymmetric ratchet step
    ///
    /// Generates a new ML-KEM keypair and returns the public key to send.
    /// Returns: (epoch, public_key_bytes)
    pub fn initiate_ratchet(&mut self) -> Result<(RatchetEpoch, Vec<u8>)> {
        if !self.we_initiate_next {
            return Err(Error::InvalidState);
        }

        let next_epoch = self.epoch + 1;

        // Generate new ML-KEM keypair
        let (private_key, public_key_bytes) = MLKEM768_private_key::generate();

        let pending = PendingRatchet::WaitingForCiphertext {
            our_private_key: private_key,
            our_public_key_bytes: public_key_bytes.clone(),
            epoch: next_epoch,
        };

        self.pending_ratchet = Some(pending);

        Ok((next_epoch, public_key_bytes))
    }

    /// Process received ML-KEM public key (they initiated ratchet)
    ///
    /// Stores their public key and returns ciphertext to send back.
    /// Returns: (epoch, ciphertext_bytes)
    pub fn respond_to_ratchet(
        &mut self,
        epoch: RatchetEpoch,
        their_pubkey_bytes: &[u8],
    ) -> Result<(RatchetEpoch, Vec<u8>)> {
        if self.we_initiate_next {
            return Err(Error::InvalidState); // We should initiate, not them
        }

        if epoch != self.epoch + 1 {
            return Err(Error::InvalidState); // Wrong epoch
        }

        // Encapsulate to their public key bytes
        let (shared_secret, ciphertext) = MLKEM768_private_key::encapsulate_to_bytes(their_pubkey_bytes)?;

        // Derive new keys from shared secret
        self.complete_ratchet_step(epoch, &shared_secret)?;

        Ok((epoch, ciphertext))
    }

    /// Process received ML-KEM ciphertext (completing our initiated ratchet)
    pub fn complete_ratchet(
        &mut self,
        epoch: RatchetEpoch,
        ciphertext: &[u8],
    ) -> Result<()> {
        let pending = self.pending_ratchet.take()
            .ok_or(Error::InvalidState)?;

        match pending {
            PendingRatchet::WaitingForCiphertext {
                our_private_key,
                epoch: expected_epoch,
                ..
            } => {
                if epoch != expected_epoch {
                    return Err(Error::InvalidState);
                }

                // Dec encapsulate to get shared secret
                let shared_secret = our_private_key.decapsulate(ciphertext)?;

                // Derive new keys
                self.complete_ratchet_step(epoch, &shared_secret)?;

                Ok(())
            },
            _ => Err(Error::InvalidState),
        }
    }

    /// Complete the ratchet step with the shared secret
    fn complete_ratchet_step(
        &mut self,
        new_epoch: RatchetEpoch,
        shared_secret: &[u8],
    ) -> Result<()> {
        // Derive new root key and chain keys from shared secret
        let (new_root_key, new_send_chain) = blake3_kdf::derive_ratchet_keys(
            &self.root_key,
            shared_secret,
        );

        let (_, new_recv_chain) = blake3_kdf::derive_ratchet_keys(
            &new_root_key,
            shared_secret,
        );

        // Update state
        self.root_key = new_root_key;
        self.epoch = new_epoch;
        self.send_chain_key = new_send_chain;
        self.send_msg_number = 0;
        self.recv_chain_key = new_recv_chain;
        self.recv_msg_number = 0;

        // Clean up skipped keys from old epochs - they'll never be used
        self.skipped_keys.retain(|&(epoch, _), _| epoch >= new_epoch);
        self.skipped_keys_queue.retain(|&(epoch, _)| epoch >= new_epoch);

        // Toggle who initiates next
        self.we_initiate_next = !self.we_initiate_next;

        // Schedule next ratchet for 60 seconds from now
        self.next_ratchet_time = Some(
            Instant::now() + std::time::Duration::from_millis(RATCHET_INTERVAL_MS)
        );

        // Clear pending state
        self.pending_ratchet = None;

        Ok(())
    }

    /// Derive encryption key for the next outgoing message
    ///
    /// Advances the sending chain and returns the message key.
    pub fn encrypt_key(&mut self) -> [u8; BLAKE3_OUT_LEN] {
        let (new_chain_key, message_key) = blake3_kdf::derive_message_key(&self.send_chain_key);

        self.send_chain_key = new_chain_key;
        let msg_num = self.send_msg_number;
        self.send_msg_number += 1;

        message_key
    }

    /// Derive encryption key for a specific message number
    ///
    /// Used when packet_number = message_number mapping.
    /// Advances the sending chain to match the message number.
    pub fn encrypt_key_for_msg(&mut self, msg_number: MessageNumber) -> Result<[u8; BLAKE3_OUT_LEN]> {
        // Can't go backwards
        if msg_number < self.send_msg_number {
            return Err(Error::CryptoFail);
        }

        // Advance chain to the target message number (skipping any gaps)
        while self.send_msg_number < msg_number {
            let (new_chain_key, _skipped_key) = blake3_kdf::derive_message_key(&self.send_chain_key);
            self.send_chain_key = new_chain_key;
            self.send_msg_number += 1;
            // Note: We discard skipped keys on send side - they're never used
        }

        // Now derive the key for the target message number
        let (new_chain_key, message_key) = blake3_kdf::derive_message_key(&self.send_chain_key);

        self.send_chain_key = new_chain_key;
        self.send_msg_number = msg_number + 1;

        Ok(message_key)
    }

    /// Derive decryption key for an incoming message
    ///
    /// Handles out-of-order delivery by storing skipped keys.
    pub fn decrypt_key(
        &mut self,
        epoch: RatchetEpoch,
        msg_number: MessageNumber,
    ) -> Result<[u8; BLAKE3_OUT_LEN]> {
        // Check if we have a skipped key for this message
        if let Some(key) = self.skipped_keys.remove(&(epoch, msg_number)) {
            return Ok(key);
        }

        // Epoch must match current or be old (for reordered packets)
        if epoch > self.epoch {
            return Err(Error::CryptoFail); // Future epoch not yet reached
        }

        if epoch < self.epoch {
            // Old epoch - we should have the skipped key
            return Err(Error::CryptoFail);
        }

        // Current epoch - need to advance chain
        if msg_number < self.recv_msg_number {
            // Old message number - should have skipped key
            return Err(Error::CryptoFail);
        }

        // Skip ahead and store intermediate keys
        while self.recv_msg_number < msg_number {
            if self.skipped_keys.len() >= MAX_SKIP {
                // Cache full - evict oldest key (proper LRU)
                if let Some(oldest_key) = self.skipped_keys_queue.pop_front() {
                    self.skipped_keys.remove(&oldest_key);
                }
            }

            let (new_chain_key, skipped_msg_key) = blake3_kdf::derive_message_key(&self.recv_chain_key);

            let key_id = (epoch, self.recv_msg_number);
            self.skipped_keys.insert(key_id, skipped_msg_key);
            self.skipped_keys_queue.push_back(key_id);  // Track insertion order

            self.recv_chain_key = new_chain_key;
            self.recv_msg_number += 1;
        }

        // Now derive the key for the current message
        let (new_chain_key, message_key) = blake3_kdf::derive_message_key(&self.recv_chain_key);

        self.recv_chain_key = new_chain_key;
        self.recv_msg_number += 1;

        Ok(message_key)
    }

    /// Get current ratchet epoch
    pub fn epoch(&self) -> RatchetEpoch {
        self.epoch
    }

    /// Get current send message number
    pub fn send_msg_number(&self) -> MessageNumber {
        self.send_msg_number
    }

    /// Get current receive message number
    pub fn recv_msg_number(&self) -> MessageNumber {
        self.recv_msg_number
    }

    /// Check if we have a pending ratchet
    pub fn has_pending_ratchet(&self) -> bool {
        self.pending_ratchet.is_some()
    }
}

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
        assert_eq!(client.send_msg_number(), 0);
        assert_eq!(server.send_msg_number(), 0);

        // Client should initiate first ratchet
        assert!(client.we_initiate_next);
        assert!(!server.we_initiate_next);
    }

    #[test]
    fn test_symmetric_ratchet() {
        let secret = b"test-handshake-secret";
        let mut state = RatchetState::from_handshake_secret(secret, true);

        // Derive several message keys
        let key1 = state.encrypt_key();
        let key2 = state.encrypt_key();
        let key3 = state.encrypt_key();

        // All keys should be different
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);

        // Message numbers should advance
        assert_eq!(state.send_msg_number(), 3);
    }

    #[test]
    fn test_decrypt_in_order() {
        let secret = b"test-handshake-secret";
        let mut state = RatchetState::from_handshake_secret(secret, false);

        // Decrypt messages in order
        let key1 = state.decrypt_key(0, 0).unwrap();
        let key2 = state.decrypt_key(0, 1).unwrap();
        let key3 = state.decrypt_key(0, 2).unwrap();

        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_eq!(state.recv_msg_number(), 3);
    }

    #[test]
    fn test_decrypt_out_of_order() {
        let secret = b"test-handshake-secret";
        let mut state = RatchetState::from_handshake_secret(secret, false);

        // Receive message 2 first (should skip 0 and 1)
        let key2 = state.decrypt_key(0, 2).unwrap();
        assert_eq!(state.recv_msg_number(), 3);
        assert_eq!(state.skipped_keys.len(), 2); // Keys for msg 0 and 1

        // Now receive message 0 (should use skipped key)
        let key0 = state.decrypt_key(0, 0).unwrap();
        assert_eq!(state.skipped_keys.len(), 1); // Only msg 1 left

        // Receive message 1
        let key1 = state.decrypt_key(0, 1).unwrap();
        assert_eq!(state.skipped_keys.len(), 0); // All skipped keys used

        // All keys should be different
        assert_ne!(key0, key1);
        assert_ne!(key1, key2);
        assert_ne!(key0, key2);
    }

    // TODO: Re-enable this test once CBS-based ML-KEM parsing is implemented
    // The issue is that BoringSSL's ML-KEM internal representation cannot be
    // constructed from raw encoded bytes without using CBS parsing functions.
    // We'll implement proper serialization when integrating with QUIC frames.
    #[test]
    #[ignore]
    fn test_full_ratchet_exchange() {
        let secret = b"test-handshake-secret";

        let mut client = RatchetState::from_handshake_secret(secret, true);
        let mut server = RatchetState::from_handshake_secret(secret, false);

        // Simulate time passing (though we can't actually test the timer)
        // In real code, should_initiate_ratchet() would check the timer

        // Client initiates ratchet
        client.next_ratchet_time = Some(Instant::now() - std::time::Duration::from_secs(1));
        assert!(client.should_initiate_ratchet());

        let (epoch1, pubkey) = client.initiate_ratchet().unwrap();
        assert_eq!(epoch1, 1);
        assert_eq!(pubkey.len(), MLKEM768_PUBLIC_KEY_BYTES);

        // Server responds with ciphertext
        let (epoch2, ciphertext) = server.respond_to_ratchet(epoch1, &pubkey).unwrap();
        assert_eq!(epoch2, 1);
        assert_eq!(ciphertext.len(), MLKEM768_CIPHERTEXT_BYTES);

        // After responding, server completes the ratchet
        assert_eq!(server.epoch(), 1);
        assert!(!server.we_initiate_next); // Still false, client goes first
        assert!(server.we_initiate_next == false); // Server should NOT initiate next

        // Client completes ratchet with ciphertext
        client.complete_ratchet(epoch1, &ciphertext).unwrap();
        assert_eq!(client.epoch(), 1);
        assert!(!client.we_initiate_next); // Now server's turn

        // Both should be at epoch 1
        assert_eq!(client.epoch(), server.epoch());

        // Their chain keys should be set up for communication
        assert_eq!(client.send_msg_number(), 0);
        assert_eq!(server.send_msg_number(), 0);
    }
}
