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

//! BLAKE3-based key derivation for PQDR-QUIC double ratchet
//!
//! Key derivation design:
//! - Per-packet key: `H(chain_key, pn)` using BLAKE3 XOF producing 64 bytes
//!   - bytes [0..32]  → new chain_key (carry forward)
//!   - bytes [32..64] → encryption_key for this packet
//! - Epoch transition: `derive_epoch_chain_keys(kem_shared_secret, starting_pn)`
//!   produces independent send/recv chain keys for the new epoch

use std::sync::atomic::compiler_fence;
use std::sync::atomic::Ordering;

use zeroize::Zeroize;

use crate::Error;
use crate::Result;

/// Size of BLAKE3 hash output (256 bits = 32 bytes)
pub const BLAKE3_OUT_LEN: usize = 32;

/// A 32-byte secret key (chain key, packet key or root key) that is wiped
/// from memory when dropped.
///
/// Packet and chain keys are derived for every packet, so this wipes with a
/// single volatile store rather than `zeroize`'s byte-by-byte writes, which
/// would add a noticeable per-packet cost.
#[derive(Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct SecretKey([u8; BLAKE3_OUT_LEN]);

impl SecretKey {
    pub fn new(bytes: [u8; BLAKE3_OUT_LEN]) -> Self {
        SecretKey(bytes)
    }

    pub fn zero() -> Self {
        SecretKey([0; BLAKE3_OUT_LEN])
    }
}

impl std::ops::Deref for SecretKey {
    type Target = [u8; BLAKE3_OUT_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SecretKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Overwrites `value` with zeroes in a way the compiler cannot optimise out.
///
/// `T` must be a plain-data type for which all-zero bytes are a valid value.
pub(crate) fn wipe<T: Copy>(value: &mut T) {
    // SAFETY: `value` is valid for writes, and callers only pass plain-data
    // types (byte arrays, integer structs) for which all-zero is valid.
    unsafe { std::ptr::write_volatile(value, std::mem::zeroed()) };

    compiler_fence(Ordering::SeqCst);
}

/// HKDF-Extract using BLAKE3
///
/// Extracts a pseudorandom key from input key material and salt:
/// `BLAKE3-keyed(BLAKE3(salt), ikm)`.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> SecretKey {
    let mut salt_hasher = blake3::Hasher::new();
    salt_hasher.update(salt);
    let mut salt_hash = salt_hasher.finalize();
    salt_hasher.zeroize();

    let mut hasher = blake3::Hasher::new_keyed(salt_hash.as_bytes());
    hasher.update(ikm);
    let mut prk = hasher.finalize();
    hasher.zeroize();
    salt_hash.zeroize();

    let out = SecretKey::new(*prk.as_bytes());
    prk.zeroize();

    out
}

/// HKDF-Expand using BLAKE3 XOF
///
/// Expands a pseudorandom key into output key material.
pub fn hkdf_expand(
    prk: &[u8; BLAKE3_OUT_LEN], info: &[u8], output: &mut [u8],
) -> Result<()> {
    if output.is_empty() || output.len() > 255 * BLAKE3_OUT_LEN {
        return Err(Error::CryptoFail);
    }

    let mut hasher = blake3::Hasher::new_keyed(prk);
    hasher.update(info);

    let mut reader = hasher.finalize_xof();
    reader.fill(output);

    reader.zeroize();
    hasher.zeroize();

    Ok(())
}

/// Splits 64 bytes of key material into two keys, wiping the input.
fn split_keys(output: &mut [u8; 2 * BLAKE3_OUT_LEN]) -> (SecretKey, SecretKey) {
    let mut first = SecretKey::zero();
    let mut second = SecretKey::zero();

    first.copy_from_slice(&output[..BLAKE3_OUT_LEN]);
    second.copy_from_slice(&output[BLAKE3_OUT_LEN..]);

    wipe(output);

    (first, second)
}

/// BLAKE3 domain separation flags (BLAKE3 specification, section 2.1).
const BLAKE3_CHUNK_START: u8 = 1 << 0;
const BLAKE3_CHUNK_END: u8 = 1 << 1;
const BLAKE3_ROOT: u8 = 1 << 3;
const BLAKE3_KEYED_HASH: u8 = 1 << 4;

/// Flags for a keyed hash whose whole input is one block.
const BLAKE3_SINGLE_BLOCK_KEYED: u8 =
    BLAKE3_KEYED_HASH | BLAKE3_CHUNK_START | BLAKE3_CHUNK_END | BLAKE3_ROOT;

/// Derives the per-packet keys: `(next_chain_key, enc_key) =
/// BLAKE3-XOF(key = chain_key, input = pn)`, 64 bytes split in two.
///
/// The 8-byte input fits in a single block, so these 64 bytes are the output
/// of one BLAKE3 compression: the block is both the first and last of the
/// only chunk, which is also the root. This calls that compression directly,
/// which gives the same bytes as `blake3::Hasher` (checked by tests) at
/// lower cost: setting up a general-purpose hasher took longer than the
/// compression itself.
///
/// It holds the BLAKE3 implementation for this CPU, detected once. Keep it
/// with the state the per-packet code reads anyway: reading a separate
/// cached value (even a `static`) cost about 25 ns per packet in transfers,
/// because it was usually out of cache.
///
/// `blake3::platform` is public but undocumented and exempt from semver. A
/// new `blake3` version that changes it would most likely fail to compile;
/// `test_message_key_known_answer` catches any change in the output.
#[derive(Clone, Copy)]
pub struct MessageKdf(blake3::platform::Platform);

impl MessageKdf {
    pub fn new() -> Self {
        MessageKdf(blake3::platform::Platform::detect())
    }

    pub fn derive(
        self, chain_key: &[u8; BLAKE3_OUT_LEN], pn: u64,
    ) -> (SecretKey, SecretKey) {
        let mut key_words = [0u32; 8];

        for (word, bytes) in key_words.iter_mut().zip(chain_key.chunks_exact(4)) {
            *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }

        let input = pn.to_be_bytes();
        let mut block = [0u8; 64];
        block[..input.len()].copy_from_slice(&input);

        let mut output = self.0.compress_xof(
            &key_words,
            &block,
            input.len() as u8,
            0,
            BLAKE3_SINGLE_BLOCK_KEYED,
        );

        wipe(&mut key_words);

        split_keys(&mut output)
    }
}

impl Default for MessageKdf {
    fn default() -> Self {
        Self::new()
    }
}

/// `MessageKdf::derive`, detecting the CPU on every call.
#[cfg(test)]
pub fn derive_message_key(
    chain_key: &[u8; BLAKE3_OUT_LEN], pn: u64,
) -> (SecretKey, SecretKey) {
    MessageKdf::new().derive(chain_key, pn)
}

/// Initialize the root key from the TLS exporter secret.
pub fn init_root_key_from_handshake(handshake_secret: &[u8]) -> SecretKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(handshake_secret);
    let mut secret_hash = hasher.finalize();
    hasher.zeroize();

    let mut output = SecretKey::zero();
    hkdf_expand(secret_hash.as_bytes(), b"pqdr-quic-init", &mut output[..])
        .expect("HKDF expand should not fail");
    secret_hash.zeroize();

    output
}

/// Derive the epoch-0 chain keys from the root key.
///
/// Returns `(chain_A, chain_B)`: the client sends on A and receives on B,
/// the server the other way round.
pub fn derive_initial_chain_keys(
    root_key: &[u8; BLAKE3_OUT_LEN],
) -> (SecretKey, SecretKey) {
    let prk = hkdf_extract(root_key, b"initial");

    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-quic-chains", &mut output)
        .expect("HKDF expand should not fail");

    split_keys(&mut output)
}

/// Derive the chain keys of epoch N >= 1 from the ML-KEM shared secret,
/// bound to the pn at which the server started the epoch.
///
/// Returns `(chain_A, chain_B)`, oriented as in `derive_initial_chain_keys`.
pub fn derive_epoch_chain_keys(
    shared_secret: &[u8], starting_pn: u64,
) -> (SecretKey, SecretKey) {
    let pn_bytes = starting_pn.to_be_bytes();
    let prk = hkdf_extract(&pn_bytes, shared_secret);

    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-epoch-chains", &mut output)
        .expect("HKDF expand should not fail");

    split_keys(&mut output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_extract() {
        let salt = b"test-salt";
        let ikm = b"input-key-material";

        let prk = hkdf_extract(salt, ikm);
        assert_eq!(prk.len(), BLAKE3_OUT_LEN);

        let prk2 = hkdf_extract(salt, ikm);
        assert_eq!(prk, prk2);

        let prk3 = hkdf_extract(salt, b"different-ikm");
        assert_ne!(prk, prk3);
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; BLAKE3_OUT_LEN];
        let info = b"test-info";

        let mut output1 = vec![0u8; 64];
        hkdf_expand(&prk, info, &mut output1).unwrap();

        let mut output2 = vec![0u8; 64];
        hkdf_expand(&prk, info, &mut output2).unwrap();
        assert_eq!(output1, output2);

        let mut output3 = vec![0u8; 64];
        hkdf_expand(&prk, b"different-info", &mut output3).unwrap();
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_derive_message_key() {
        let chain_key = [0x02u8; BLAKE3_OUT_LEN];

        let (new_chain, enc_key) = derive_message_key(&chain_key, 0);

        assert_ne!(new_chain, enc_key);
        assert_ne!(*new_chain, chain_key);
        assert_ne!(*enc_key, chain_key);

        // Deterministic
        let (new_chain2, enc_key2) = derive_message_key(&chain_key, 0);
        assert_eq!(new_chain, new_chain2);
        assert_eq!(enc_key, enc_key2);

        // Different pn → different keys
        let (new_chain3, enc_key3) = derive_message_key(&chain_key, 1);
        assert_ne!(enc_key, enc_key3);
        assert_ne!(new_chain, new_chain3);
    }

    /// The keys from `blake3::Hasher`, which `derive_message_key` replaces.
    fn message_key_with_hasher(key: &[u8; 32], pn: u64) -> [u8; 64] {
        let mut out = [0u8; 64];
        blake3::Hasher::new_keyed(key)
            .update(&pn.to_be_bytes())
            .finalize_xof()
            .fill(&mut out);
        out
    }

    #[test]
    fn test_message_key_matches_hasher() {
        let mut key = [0u8; 32];

        for i in 0..2000u64 {
            // Vary every byte of the key, and pns of every length.
            key = *blake3::hash(&key).as_bytes();
            let pn = match i % 4 {
                0 => i,
                1 => u64::MAX - i,
                2 => 1 << (i % 64),
                _ => u64::from_le_bytes(key[..8].try_into().unwrap()),
            };

            let expected = message_key_with_hasher(&key, pn);
            let (chain, enc) = derive_message_key(&key, pn);

            assert_eq!(&chain[..], &expected[..32], "pn {pn}");
            assert_eq!(&enc[..], &expected[32..], "pn {pn}");
        }
    }

    #[test]
    fn test_message_key_known_answer() {
        // Fixed values, so a change in the `blake3` crate that affected both
        // `derive_message_key` and `blake3::Hasher` would still be caught.
        // Computed with an independent implementation of the BLAKE3
        // compression function written from the specification.
        const KAT_CHAIN: &str =
            "c70585b8f3f2ec5bba50c48e62b9d85570df8fa30142bf076b7821a3d8d61b72";
        const KAT_ENC: &str =
            "6a156b62975d55d5db3c5747ed55b500cbab7f55879989b0fcf0f1526213ca7e";

        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let (chain, enc) = derive_message_key(&key, 0x0102_0304_0506_0708);

        let hex = |b: &[u8]| -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        };

        assert_eq!(hex(&chain[..]), KAT_CHAIN);
        assert_eq!(hex(&enc[..]), KAT_ENC);
    }

    #[test]
    fn test_derive_message_key_chain() {
        // Verify chain advances: H(ss, 0) then H(chain_0, 1)
        let ss = [0xAAu8; BLAKE3_OUT_LEN];

        let (chain_0, enc_0) = derive_message_key(&ss, 0);
        let (chain_1, enc_1) = derive_message_key(&chain_0, 1);
        let (_, enc_2) = derive_message_key(&chain_1, 2);

        assert_ne!(enc_0, enc_1);
        assert_ne!(enc_1, enc_2);
        assert_ne!(enc_0, enc_2);
        // Chain keys advance
        assert_ne!(ss, *chain_0);
        assert_ne!(chain_0, chain_1);
    }

    #[test]
    fn test_derive_epoch_chain_keys() {
        let ss = b"kem-shared-secret-32-bytes-abcdef";
        let pn = 12345u64;

        let (s1, r1) = derive_epoch_chain_keys(ss, pn);
        let (s2, r2) = derive_epoch_chain_keys(ss, pn);
        assert_eq!(s1, s2);
        assert_eq!(r1, r2);

        // Different pn → different keys
        let (s3, _) = derive_epoch_chain_keys(ss, pn + 1);
        assert_ne!(s1, s3);

        // send and recv are different
        assert_ne!(s1, r1);
    }

    #[test]
    fn test_symmetric_send_recv_match() {
        // Verify client send = server recv for epoch 0
        let shared_secret = b"shared-tls-secret-for-testing-123";
        let root_key = init_root_key_from_handshake(shared_secret);

        // Client: (send, recv)
        let (client_send, _client_recv) = derive_initial_chain_keys(&root_key);
        // Server: swap — server_send_chain = chain_recv output
        let (chain_s, _chain_r) = derive_initial_chain_keys(&root_key);
        let server_recv = chain_s; // server recv = first output of derive_initial_chain_keys

        // Client send chain == server recv chain
        assert_eq!(client_send, server_recv);

        // Same chain state → same per-packet key
        let (_, client_enc_0) = derive_message_key(&client_send, 0);
        let (_, server_enc_0) = derive_message_key(&server_recv, 0);
        assert_eq!(client_enc_0, server_enc_0, "Encryption keys must match!");
    }

    #[test]
    fn test_outputs_match_reference() {
        // Wiping intermediate state must not change any derived value.
        // Reference values computed with the one-shot BLAKE3 functions.
        let xof = |key: &[u8; 32], input: &[u8]| {
            let mut out = [0u8; 64];
            blake3::Hasher::new_keyed(key)
                .update(input)
                .finalize_xof()
                .fill(&mut out);
            out
        };

        let secret = b"exporter-secret-for-reference-kat";
        let root: [u8; 32] = {
            let out = xof(blake3::hash(secret).as_bytes(), b"pqdr-quic-init");
            out[..32].try_into().unwrap()
        };
        assert_eq!(*init_root_key_from_handshake(secret), root);

        let prk = blake3::keyed_hash(blake3::hash(&root).as_bytes(), b"initial");
        let chains = xof(prk.as_bytes(), b"pqdr-quic-chains");
        let (a, b) = derive_initial_chain_keys(&root);
        assert_eq!(&a[..], &chains[..32]);
        assert_eq!(&b[..], &chains[32..]);

        let msg = xof(&a, &7u64.to_be_bytes());
        let (next, enc) = derive_message_key(&a, 7);
        assert_eq!(&next[..], &msg[..32]);
        assert_eq!(&enc[..], &msg[32..]);

        let prk = blake3::keyed_hash(
            blake3::hash(&100u64.to_be_bytes()).as_bytes(),
            secret,
        );
        let epoch = xof(prk.as_bytes(), b"pqdr-epoch-chains");
        let (a, b) = derive_epoch_chain_keys(secret, 100);
        assert_eq!(&a[..], &epoch[..32]);
        assert_eq!(&b[..], &epoch[32..]);
    }
}
