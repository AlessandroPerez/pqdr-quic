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


//! Systematic Reed-Solomon erasure code over GF(2^8).
//!
//! PQDR-QUIC uses it to spread the server's ML-KEM public key over more
//! packets than strictly needed, so the client can rebuild the key from
//! whichever of those packets arrive.
//!
//! The `k` data shards are the values at `x = 0..k` of a polynomial of
//! degree less than `k` (one polynomial per byte offset), and shard `i` of
//! the `n` coded shards is its value at `x = i`. Shards `0..k` are therefore
//! the data itself, and any `k` shards determine the polynomial, which is
//! recovered by Lagrange interpolation.

/// Field polynomial x^8 + x^4 + x^3 + x^2 + 1, with generator 2.
const FIELD_POLY: u16 = 0x11d;

/// Largest supported number of coded shards: each needs a distinct field
/// element as its evaluation point.
pub const MAX_SHARDS: usize = 256;

struct Tables {
    /// `exp[i] = 2^i`, doubled in length so `exp[log a + log b]` needs no
    /// reduction.
    exp: [u8; 512],

    log: [u8; 256],
}

const TABLES: Tables = build_tables();

const fn build_tables() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];

    let mut x: u16 = 1;
    let mut i = 0;

    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;

        x <<= 1;

        if x & 0x100 != 0 {
            x ^= FIELD_POLY;
        }

        i += 1;
    }

    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }

    Tables { exp, log }
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }

    TABLES.exp[TABLES.log[a as usize] as usize + TABLES.log[b as usize] as usize]
}

/// `a / b`, for non-zero `b`.
fn div(a: u8, b: u8) -> u8 {
    debug_assert_ne!(b, 0);

    if a == 0 {
        return 0;
    }

    TABLES.exp
        [TABLES.log[a as usize] as usize + 255 - TABLES.log[b as usize] as usize]
}

/// Returns `c` such that `P(x) = sum(c[j] * P(xs[j]))` for every polynomial
/// `P` of degree less than `xs.len()`. The `xs` must be distinct.
fn lagrange_coefficients(xs: &[u8], x: u8) -> Vec<u8> {
    xs.iter()
        .enumerate()
        .map(|(j, &xj)| {
            let mut num = 1;
            let mut den = 1;

            // In GF(2^8), subtraction is XOR.
            for (m, &xm) in xs.iter().enumerate() {
                if m != j {
                    num = mul(num, x ^ xm);
                    den = mul(den, xj ^ xm);
                }
            }

            div(num, den)
        })
        .collect()
}

/// Returns `sum(coefficients[j] * shards[j])`, byte by byte.
fn combine<const S: usize>(coefficients: &[u8], shards: &[&[u8; S]]) -> [u8; S] {
    let mut out = [0u8; S];

    for (&c, shard) in coefficients.iter().zip(shards) {
        for (o, &s) in out.iter_mut().zip(shard.iter()) {
            *o ^= mul(c, s);
        }
    }

    out
}

/// Encodes `data` (the `k` data shards) into `n` shards, the first `k` of
/// which are copies of `data`.
pub fn encode<const S: usize>(data: &[[u8; S]], n: usize) -> Vec<[u8; S]> {
    let k = data.len();

    assert!(k <= n && n <= MAX_SHARDS);

    let xs: Vec<u8> = (0..k).map(|i| i as u8).collect();
    let data_refs: Vec<&[u8; S]> = data.iter().collect();

    let mut shards = data.to_vec();

    for i in k..n {
        let coefficients = lagrange_coefficients(&xs, i as u8);
        shards.push(combine(&coefficients, &data_refs));
    }

    shards
}

/// Rebuilds the `k` data shards from any `k` of the coded shards, where
/// `shards[i]` is shard `i` if it was received.
///
/// Returns `None` if fewer than `k` shards were received.
pub fn decode<const S: usize>(
    shards: &[Option<[u8; S]>], k: usize,
) -> Option<Vec<[u8; S]>> {
    assert!(shards.len() <= MAX_SHARDS);

    let (xs, received): (Vec<u8>, Vec<&[u8; S]>) = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| Some((i as u8, s.as_ref()?)))
        .take(k)
        .unzip();

    if xs.len() < k {
        return None;
    }

    let data = (0..k)
        .map(|i| match shards[i] {
            Some(shard) => shard,

            None =>
                combine(&lagrange_coefficients(&xs, i as u8), &received),
        })
        .collect();

    Some(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: usize = 19;
    const N: usize = 4 * K;

    fn test_data() -> Vec<[u8; 64]> {
        (0..K)
            .map(|i| {
                let mut shard = [0u8; 64];
                crate::rand::rand_bytes(&mut shard);
                shard[0] = i as u8;
                shard
            })
            .collect()
    }

    /// Keeps only the shards whose index is in `keep`.
    fn erase(shards: &[[u8; 64]], keep: &[usize]) -> Vec<Option<[u8; 64]>> {
        (0..shards.len())
            .map(|i| keep.contains(&i).then_some(shards[i]))
            .collect()
    }

    #[test]
    fn field_arithmetic() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, 1), a);
            assert_eq!(div(a, a), 1);

            for b in 1..=255u8 {
                assert_eq!(div(mul(a, b), b), a);
            }
        }

        // x^8 = x^4 + x^3 + x^2 + 1
        assert_eq!(mul(0x80, 2), 0x1d);
    }

    #[test]
    fn systematic() {
        let data = test_data();
        let shards = encode(&data, N);

        assert_eq!(shards.len(), N);
        assert_eq!(&shards[..K], &data[..]);
    }

    #[test]
    fn decode_from_any_k_shards() {
        let data = test_data();
        let shards = encode(&data, N);

        let only_parity: Vec<usize> = (N - K..N).collect();
        let every_fourth: Vec<usize> = (0..N).step_by(4).collect();
        let last_data_and_parity: Vec<usize> = (K - 5..2 * K - 5).collect();

        for keep in [only_parity, every_fourth, last_data_and_parity] {
            assert_eq!(keep.len(), K);
            assert_eq!(decode(&erase(&shards, &keep), K), Some(data.clone()));
        }

        // Random subsets of exactly K shards.
        for _ in 0..200 {
            let mut keep: Vec<usize> = (0..N).collect();

            for i in (1..N).rev() {
                let j = crate::rand::rand_u64_uniform(i as u64 + 1) as usize;
                keep.swap(i, j);
            }

            keep.truncate(K);

            assert_eq!(decode(&erase(&shards, &keep), K), Some(data.clone()));
        }
    }

    #[test]
    fn too_few_shards() {
        let shards = encode(&test_data(), N);
        let keep: Vec<usize> = (0..K - 1).collect();

        assert_eq!(decode(&erase(&shards, &keep), K), None);
    }

    #[test]
    fn all_shards() {
        let data = test_data();
        let shards: Vec<_> = encode(&data, N).into_iter().map(Some).collect();

        assert_eq!(decode(&shards, K), Some(data));
    }
}
