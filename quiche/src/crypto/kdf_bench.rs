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

//! Micro-benchmarks for the per-packet PQDR crypto: the chain step (BLAKE3
//! against SHA-2 based alternatives) and the AEAD setup.
//!
//! BoringSSL uses the CPU's SHA extensions when it has them, so running this
//! on such a machine shows whether SHA-2 would be faster there:
//!
//! ```text
//! cargo test --release -p quiche --lib -- --ignored --nocapture kdf_bench
//! ```

use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use libc::c_int;
use libc::c_uint;

use super::blake3_kdf;
use super::*;

extern "C" {
    fn SHA256(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
    fn SHA512(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
    fn HMAC(
        md: *const EVP_MD, key: *const c_void, key_len: usize, data: *const u8,
        data_len: usize, out: *mut u8, out_len: *mut c_uint,
    ) -> *mut u8;
    fn HMAC_CTX_new() -> *mut c_void;
    fn HMAC_CTX_free(ctx: *mut c_void);
    fn HMAC_Init_ex(
        ctx: *mut c_void, key: *const c_void, key_len: usize, md: *const EVP_MD,
        engine: *mut c_void,
    ) -> c_int;
    fn HMAC_Update(ctx: *mut c_void, data: *const u8, len: usize) -> c_int;
    fn HMAC_Final(ctx: *mut c_void, out: *mut u8, out_len: *mut c_uint) -> c_int;
    fn HKDF_expand(
        out: *mut u8, out_len: usize, md: *const EVP_MD, prk: *const u8,
        prk_len: usize, info: *const u8, info_len: usize,
    ) -> c_int;
    fn CRYPTO_poly1305_init(state: *mut [u8; 512], key: *const u8);
    fn CRYPTO_poly1305_update(state: *mut [u8; 512], data: *const u8, len: usize);
    fn CRYPTO_poly1305_finish(state: *mut [u8; 512], mac: *mut u8);
}

const N: u64 = 300_000;

const PKT_LEN: usize = 1350;

fn sha_extensions() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::arch::is_x86_feature_detected!("sha");

    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("sha2");

    #[allow(unreachable_code)]
    false
}

/// Reads the time-stamp counter, which ticks at a fixed rate, if there is one.
fn ticks() -> Option<u64> {
    #[cfg(target_arch = "x86_64")]
    // SAFETY: RDTSC is available on every x86_64 CPU.
    return Some(unsafe { core::arch::x86_64::_rdtsc() });

    #[allow(unreachable_code)]
    None
}

fn time(name: &str, mut f: impl FnMut()) {
    // Warm up.
    for _ in 0..N / 10 {
        f();
    }

    let start = Instant::now();
    let start_ticks = ticks();

    for _ in 0..N {
        f();
    }

    let ns = start.elapsed().as_nanos() as f64 / N as f64;

    match (start_ticks, ticks()) {
        (Some(a), Some(b)) => println!(
            "BENCH {name:52} {ns:7.1} ns {:6.0} TSC ticks",
            (b - a) as f64 / N as f64
        ),

        _ => println!("BENCH {name:52} {ns:7.1} ns"),
    }
}

/// Times a chain step: (chain key, pn) -> next chain key || packet key.
fn time_chain_step(
    name: &str, mut step: impl FnMut(&[u8; 32], u64, &mut [u8; 64]),
) {
    let mut chain = [7u8; 32];
    let mut out = [0u8; 64];
    let mut pn = 0;

    time(name, || {
        step(&chain, pn, &mut out);
        chain.copy_from_slice(&out[..32]);
        black_box(&out[32..]);
        pn += 1;
    });
}

#[test]
#[ignore]
fn kdf_bench() {
    println!("CPU SHA extensions: {}", sha_extensions());

    println!("Chain step (64 bytes of output):");

    let kdf = blake3_kdf::MessageKdf::new();

    time_chain_step("BLAKE3, one compression (current)", |ck, pn, out| {
        let (chain, key) = kdf.derive(ck, pn);
        out[..32].copy_from_slice(&chain[..]);
        out[32..].copy_from_slice(&key[..]);
    });

    time_chain_step("BLAKE3 via blake3::Hasher", |ck, pn, out| {
        blake3::Hasher::new_keyed(ck)
            .update(&pn.to_be_bytes())
            .finalize_xof()
            .fill(out);
    });

    time_chain_step(
        "SHA-256 x2, secret prefix: SHA256(ck||i||pn)",
        |ck, pn, out| {
            let mut input = [0u8; 41];
            input[..32].copy_from_slice(ck);
            input[33..].copy_from_slice(&pn.to_be_bytes());

            for (i, half) in out.chunks_exact_mut(32).enumerate() {
                input[32] = i as u8;
                unsafe { SHA256(input.as_ptr(), input.len(), half.as_mut_ptr()) };
            }
        },
    );

    time_chain_step(
        "SHA-512 x1, secret prefix: SHA512(ck||pn)",
        |ck, pn, out| {
            let mut input = [0u8; 40];
            input[..32].copy_from_slice(ck);
            input[32..].copy_from_slice(&pn.to_be_bytes());

            unsafe { SHA512(input.as_ptr(), input.len(), out.as_mut_ptr()) };
        },
    );

    time_chain_step("HMAC-SHA256 x2 (Signal's KDF_CK)", |ck, pn, out| {
        let mut msg = [0u8; 9];
        msg[1..].copy_from_slice(&pn.to_be_bytes());
        let mut len = 0;

        for (i, half) in out.chunks_exact_mut(32).enumerate() {
            msg[0] = i as u8;

            unsafe {
                HMAC(
                    EVP_sha256(),
                    ck.as_ptr().cast(),
                    ck.len(),
                    msg.as_ptr(),
                    msg.len(),
                    half.as_mut_ptr(),
                    &mut len,
                )
            };
        }
    });

    let ctx = unsafe { HMAC_CTX_new() };

    time_chain_step("HMAC-SHA256 x2, sharing the key setup", |ck, pn, out| {
        let mut msg = [0u8; 9];
        msg[1..].copy_from_slice(&pn.to_be_bytes());
        let mut len = 0;

        unsafe {
            HMAC_Init_ex(
                ctx,
                ck.as_ptr().cast(),
                ck.len(),
                EVP_sha256(),
                std::ptr::null_mut(),
            )
        };

        for (i, half) in out.chunks_exact_mut(32).enumerate() {
            msg[0] = i as u8;

            unsafe {
                // A null key reuses the key set up above.
                HMAC_Init_ex(
                    ctx,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                );
                HMAC_Update(ctx, msg.as_ptr(), msg.len());
                HMAC_Final(ctx, half.as_mut_ptr(), &mut len);
            }
        }
    });

    unsafe { HMAC_CTX_free(ctx) };

    time_chain_step("HKDF-Expand-SHA256(ck, info = pn)", |ck, pn, out| {
        let info = pn.to_be_bytes();

        unsafe {
            HKDF_expand(
                out.as_mut_ptr(),
                out.len(),
                EVP_sha256(),
                ck.as_ptr(),
                ck.len(),
                info.as_ptr(),
                info.len(),
            )
        };
    });

    println!("One compression, for reference:");

    let input = [3u8; 41];
    let mut digest = [0u8; 32];

    time("SHA-256 of 41 bytes", || {
        unsafe {
            SHA256(black_box(input.as_ptr()), input.len(), digest.as_mut_ptr())
        };
        black_box(&digest);
    });

    let key = [9u8; 32];
    let mut pn = 0u64;

    time("BLAKE3 keyed hash of 8 bytes, 32-byte output", || {
        black_box(blake3::keyed_hash(&key, &pn.to_be_bytes()));
        pn += 1;
    });

    println!("AEAD, {PKT_LEN}-byte packet:");

    let key = [5u8; 32];

    let mut aead = PqdrAead::new();
    assert!(aead.rekeyable.is_some());

    let mut aead_per_packet = PqdrAead { rekeyable: None };

    time("key: written into a kept context, wiped (current)", || {
        black_box(aead.with_key(&key, black_box).unwrap());
    });

    time("key: context set up, cleaned up, wiped", || {
        black_box(aead_per_packet.with_key(&key, black_box).unwrap());
    });

    let ad = [0u8; 20];
    let mut buf = vec![0u8; PKT_LEN + 16];

    time("seal, BoringSSL ChaCha20-Poly1305 AEAD (current)", || {
        black_box(aead.seal(&key, &ad, &mut buf, PKT_LEN).unwrap());
    });

    time("seal, with a context set up per packet", || {
        black_box(aead_per_packet.seal(&key, &ad, &mut buf, PKT_LEN).unwrap());
    });

    // The same construction (RFC 8439) from the separate primitives.
    time("seal, separate ChaCha20 and Poly1305 calls", || {
        let nonce = [0u8; 12];
        let pad = [0u8; 15];
        let mut poly_key = [0u8; 64];
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(ad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(PKT_LEN as u64).to_le_bytes());
        let mut state = [0u8; 512];

        unsafe {
            CRYPTO_chacha_20(
                poly_key.as_mut_ptr(),
                poly_key.as_ptr(),
                poly_key.len(),
                key.as_ptr(),
                nonce.as_ptr(),
                0,
            );
            CRYPTO_chacha_20(
                buf.as_mut_ptr(),
                buf.as_ptr(),
                PKT_LEN,
                key.as_ptr(),
                nonce.as_ptr(),
                1,
            );

            CRYPTO_poly1305_init(&mut state, poly_key.as_ptr());
            CRYPTO_poly1305_update(&mut state, ad.as_ptr(), ad.len());
            CRYPTO_poly1305_update(
                &mut state,
                pad.as_ptr(),
                (16 - ad.len() % 16) % 16,
            );
            CRYPTO_poly1305_update(&mut state, buf.as_ptr(), PKT_LEN);
            CRYPTO_poly1305_update(
                &mut state,
                pad.as_ptr(),
                (16 - PKT_LEN % 16) % 16,
            );
            CRYPTO_poly1305_update(&mut state, lens.as_ptr(), lens.len());
            CRYPTO_poly1305_finish(&mut state, buf[PKT_LEN..].as_mut_ptr());
        }

        black_box(&buf);
    });
}
