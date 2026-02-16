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
//! Implements HKDF-style key derivation using BLAKE3 as the hash function,
//! following the pattern from the Signal Protocol's double ratchet.

use crate::Error;
use crate::Result;

/// Size of BLAKE3 hash output (256 bits = 32 bytes)
pub const BLAKE3_OUT_LEN: usize = 32;

/// HKDF-Extract using BLAKE3
///
/// Extracts a pseudorandom key from input key material and salt.
/// Similar to HKDF-Extract but using BLAKE3 instead of SHA-256.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; BLAKE3_OUT_LEN] {
    // BLAKE3 keyed hash with salt as the key
    blake3::keyed_hash(
        blake3::hash(salt).as_bytes(),
        ikm,
    ).into()
}

/// HKDF-Expand using BLAKE3
///
/// Expands a pseudorandom key into multiple output bytes.
/// Similar to HKDF-Expand but using BLAKE3 XOF (extendable output function).
pub fn hkdf_expand(
    prk: &[u8; BLAKE3_OUT_LEN],
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if output.is_empty() || output.len() > 255 * BLAKE3_OUT_LEN {
        return Err(Error::CryptoFail);
    }

    // Use BLAKE3 in XOF (extendable output) mode
    let mut hasher = blake3::Hasher::new_keyed(prk);
    hasher.update(info);

    let mut reader = hasher.finalize_xof();
    reader.fill(output);

    Ok(())
}

/// Derive ratchet keys from root key and DH output
///
/// This is the core KDF for the double ratchet, deriving both a new root key
/// and a new chain key from the current root key and a Diffie-Hellman output.
///
/// KDF(rk, dh_out) -> (root_key, chain_key)
pub fn derive_ratchet_keys(
    root_key: &[u8; BLAKE3_OUT_LEN],
    dh_output: &[u8],
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    // Extract: combine root_key and dh_output
    let prk = hkdf_extract(root_key, dh_output);

    // Expand: derive both root_key and chain_key
    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-quic-ratchet", &mut output)
        .expect("HKDF expand should not fail");

    let mut new_root_key = [0u8; BLAKE3_OUT_LEN];
    let mut new_chain_key = [0u8; BLAKE3_OUT_LEN];

    new_root_key.copy_from_slice(&output[0..BLAKE3_OUT_LEN]);
    new_chain_key.copy_from_slice(&output[BLAKE3_OUT_LEN..BLAKE3_OUT_LEN * 2]);

    (new_root_key, new_chain_key)
}

/// Derive message key from chain key
///
/// Advances the chain key and derives an encryption key for a single message.
/// KDF_CK(ck) -> (chain_key, message_key)
pub fn derive_message_key(
    chain_key: &[u8; BLAKE3_OUT_LEN],
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    // Hash chain_key with different constants to derive two independent keys
    let new_chain_key = blake3::keyed_hash(chain_key, b"chain").into();
    let message_key = blake3::keyed_hash(chain_key, b"message").into();

    (new_chain_key, message_key)
}

/// Initialize root key from TLS handshake secret
///
/// Derives the initial root key for the double ratchet from the TLS 1.3
/// handshake shared secret.
pub fn init_root_key_from_handshake(
    handshake_secret: &[u8],
) -> [u8; BLAKE3_OUT_LEN] {
    // Simple hash for initialization
    let mut output = [0u8; BLAKE3_OUT_LEN];
    hkdf_expand(
        blake3::hash(handshake_secret).as_bytes(),
        b"pqdr-quic-init",
        &mut output,
    ).expect("HKDF expand should not fail");

    output
}

/// Derive initial send and receive chain keys from root key
///
/// Used only during initialization to derive separate send/receive chain keys.
/// Returns (send_chain_key, recv_chain_key)
pub fn derive_initial_chain_keys(
    root_key: &[u8; BLAKE3_OUT_LEN],
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    let prk = hkdf_extract(root_key, b"initial");

    // Expand to get both send and recv chain keys
    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-quic-chains", &mut output)
        .expect("HKDF expand should not fail");

    let mut send_chain_key = [0u8; BLAKE3_OUT_LEN];
    let mut recv_chain_key = [0u8; BLAKE3_OUT_LEN];

    send_chain_key.copy_from_slice(&output[0..BLAKE3_OUT_LEN]);
    recv_chain_key.copy_from_slice(&output[BLAKE3_OUT_LEN..BLAKE3_OUT_LEN * 2]);

    (send_chain_key, recv_chain_key)
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

        // Same inputs should produce same output
        let prk2 = hkdf_extract(salt, ikm);
        assert_eq!(prk, prk2);

        // Different inputs should produce different output
        let prk3 = hkdf_extract(salt, b"different-ikm");
        assert_ne!(prk, prk3);
    }

    #[test]
    fn test_hkdf_expand() {
        let prk = [0x42u8; BLAKE3_OUT_LEN];
        let info = b"test-info";

        let mut output1 = vec![0u8; 64];
        hkdf_expand(&prk, info, &mut output1).unwrap();

        // Same inputs should produce same output
        let mut output2 = vec![0u8; 64];
        hkdf_expand(&prk, info, &mut output2).unwrap();
        assert_eq!(output1, output2);

        // Different info should produce different output
        let mut output3 = vec![0u8; 64];
        hkdf_expand(&prk, b"different-info", &mut output3).unwrap();
        assert_ne!(output1, output3);
    }

    #[test]
    fn test_derive_ratchet_keys() {
        let root_key = [0x01u8; BLAKE3_OUT_LEN];
        let dh_output = b"diffie-hellman-shared-secret";

        let (new_root, new_chain) = derive_ratchet_keys(&root_key, dh_output);

        // Keys should be different from each other
        assert_ne!(new_root, new_chain);

        // Keys should be deterministic
        let (new_root2, new_chain2) = derive_ratchet_keys(&root_key, dh_output);
        assert_eq!(new_root, new_root2);
        assert_eq!(new_chain, new_chain2);
    }

    #[test]
    fn test_derive_message_key() {
        let chain_key = [0x02u8; BLAKE3_OUT_LEN];

        let (new_chain, msg_key) = derive_message_key(&chain_key);

        // Chain key and message key should be different
        assert_ne!(new_chain, msg_key);
        assert_ne!(new_chain, chain_key);

        // Should be deterministic
        let (new_chain2, msg_key2) = derive_message_key(&chain_key);
        assert_eq!(new_chain, new_chain2);
        assert_eq!(msg_key, msg_key2);

        // Advancing chain should produce different keys
        let (new_chain3, msg_key3) = derive_message_key(&new_chain);
        assert_ne!(msg_key, msg_key3);
        assert_ne!(new_chain, new_chain3);
    }

    #[test]
    fn test_init_root_key() {
        let secret1 = b"handshake-secret-1";
        let secret2 = b"handshake-secret-2";

        let root1 = init_root_key_from_handshake(secret1);
        let root2 = init_root_key_from_handshake(secret2);

        // Different secrets should produce different root keys
        assert_ne!(root1, root2);

        // Same secret should produce same root key
        let root1_again = init_root_key_from_handshake(secret1);
        assert_eq!(root1, root1_again);
    }

    #[test]
    fn test_symmetric_encryption_decryption() {
        // Test that sender and receiver derive the same keys
        let shared_secret = b"shared-tls-secret-for-testing-123";
        let root_key = init_root_key_from_handshake(shared_secret);

        // Client derives send/recv chains
        let (client_send, client_recv) = derive_initial_chain_keys(&root_key);

        // Server derives same chains but swapped
        let (server_recv, server_send) = derive_initial_chain_keys(&root_key);

        // Verify client send = server recv
        assert_eq!(client_send, server_recv);
        assert_eq!(client_recv, server_send);

        // Now derive message keys
        let (client_new_chain, client_msg_key) = derive_message_key(&client_send);
        let (server_new_chain, server_msg_key) = derive_message_key(&server_recv);

        // Message keys should match!
        assert_eq!(client_msg_key, server_msg_key, "Message keys don't match!");
        assert_eq!(client_new_chain, server_new_chain, "New chain keys don't match!");
    }
}
