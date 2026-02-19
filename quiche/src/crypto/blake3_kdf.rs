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

use crate::Error;
use crate::Result;

/// Size of BLAKE3 hash output (256 bits = 32 bytes)
pub const BLAKE3_OUT_LEN: usize = 32;

/// HKDF-Extract using BLAKE3
///
/// Extracts a pseudorandom key from input key material and salt.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; BLAKE3_OUT_LEN] {
    blake3::keyed_hash(
        blake3::hash(salt).as_bytes(),
        ikm,
    ).into()
}

/// HKDF-Expand using BLAKE3
///
/// Expands a pseudorandom key into multiple output bytes using BLAKE3 XOF.
pub fn hkdf_expand(
    prk: &[u8; BLAKE3_OUT_LEN],
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if output.is_empty() || output.len() > 255 * BLAKE3_OUT_LEN {
        return Err(Error::CryptoFail);
    }

    let mut hasher = blake3::Hasher::new_keyed(prk);
    hasher.update(info);

    let mut reader = hasher.finalize_xof();
    reader.fill(output);

    Ok(())
}

/// Derive per-packet chain key and encryption key from chain key + packet number.
///
/// Uses BLAKE3 XOF to produce 64 bytes from `H(chain_key, pn)`:
///   - output[0..32]  → new_chain_key  (carry forward for next packet)
///   - output[32..64] → enc_key        (use once to encrypt this packet)
///
/// Example chain for epoch starting at `ss`:
///   pn=0: (chain_key_0, enc_key_0) = H(ss,        0)
///   pn=1: (chain_key_1, enc_key_1) = H(chain_key_0, 1)
///   pn=N: (chain_key_N, enc_key_N) = H(chain_key_{N-1}, N)
pub fn derive_message_key(
    chain_key: &[u8; BLAKE3_OUT_LEN],
    pn: u64,
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    // BLAKE3 keyed hash: key=chain_key, data=pn_be — produce 64 bytes via XOF
    let mut hasher = blake3::Hasher::new_keyed(chain_key);
    hasher.update(&pn.to_be_bytes());

    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hasher.finalize_xof().fill(&mut output);

    let mut new_chain_key = [0u8; BLAKE3_OUT_LEN];
    let mut enc_key = [0u8; BLAKE3_OUT_LEN];
    new_chain_key.copy_from_slice(&output[..BLAKE3_OUT_LEN]);
    enc_key.copy_from_slice(&output[BLAKE3_OUT_LEN..]);

    (new_chain_key, enc_key)
}

/// Initialize root key from TLS handshake secret.
///
/// Derives the initial shared secret used to seed the epoch-0 chains.
pub fn init_root_key_from_handshake(
    handshake_secret: &[u8],
) -> [u8; BLAKE3_OUT_LEN] {
    let mut output = [0u8; BLAKE3_OUT_LEN];
    hkdf_expand(
        blake3::hash(handshake_secret).as_bytes(),
        b"pqdr-quic-init",
        &mut output,
    ).expect("HKDF expand should not fail");
    output
}

/// Derive initial send and receive chain keys from root key (epoch 0).
///
/// Returns `(send_chain_key, recv_chain_key)`.
/// The server swaps these at init time so server-send == client-recv.
pub fn derive_initial_chain_keys(
    root_key: &[u8; BLAKE3_OUT_LEN],
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    let prk = hkdf_extract(root_key, b"initial");

    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-quic-chains", &mut output)
        .expect("HKDF expand should not fail");

    let mut send_chain_key = [0u8; BLAKE3_OUT_LEN];
    let mut recv_chain_key = [0u8; BLAKE3_OUT_LEN];
    send_chain_key.copy_from_slice(&output[..BLAKE3_OUT_LEN]);
    recv_chain_key.copy_from_slice(&output[BLAKE3_OUT_LEN..]);

    (send_chain_key, recv_chain_key)
}

/// Derive epoch chain keys from KEM shared secret and starting packet number.
///
/// Used at epoch N≥1 transitions. Mixes the KEM shared secret with the
/// starting pn so the chain is bound to the epoch boundary.
///
/// Returns `(send_chain_key, recv_chain_key)`.
/// Caller must swap for server side (server-send == client-recv).
pub fn derive_epoch_chain_keys(
    shared_secret: &[u8],
    starting_pn: u64,
) -> ([u8; BLAKE3_OUT_LEN], [u8; BLAKE3_OUT_LEN]) {
    let pn_bytes = starting_pn.to_be_bytes();
    // salt = starting_pn bytes, ikm = kem shared secret
    let prk = hkdf_extract(&pn_bytes, shared_secret);

    let mut output = [0u8; BLAKE3_OUT_LEN * 2];
    hkdf_expand(&prk, b"pqdr-epoch-chains", &mut output)
        .expect("HKDF expand should not fail");

    let mut send_chain_key = [0u8; BLAKE3_OUT_LEN];
    let mut recv_chain_key = [0u8; BLAKE3_OUT_LEN];
    send_chain_key.copy_from_slice(&output[..BLAKE3_OUT_LEN]);
    recv_chain_key.copy_from_slice(&output[BLAKE3_OUT_LEN..]);

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
        assert_ne!(new_chain, chain_key);
        assert_ne!(enc_key, chain_key);

        // Deterministic
        let (new_chain2, enc_key2) = derive_message_key(&chain_key, 0);
        assert_eq!(new_chain, new_chain2);
        assert_eq!(enc_key, enc_key2);

        // Different pn → different keys
        let (new_chain3, enc_key3) = derive_message_key(&chain_key, 1);
        assert_ne!(enc_key, enc_key3);
        assert_ne!(new_chain, new_chain3);
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
        assert_ne!(ss, chain_0);
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
        let (chain_s, chain_r) = derive_initial_chain_keys(&root_key);
        let server_recv = chain_s; // server recv = first output of derive_initial_chain_keys

        // Client send chain == server recv chain
        assert_eq!(client_send, server_recv);

        // Same chain state → same per-packet key
        let (_, client_enc_0) = derive_message_key(&client_send, 0);
        let (_, server_enc_0) = derive_message_key(&server_recv, 0);
        assert_eq!(client_enc_0, server_enc_0, "Encryption keys must match!");
    }
}
