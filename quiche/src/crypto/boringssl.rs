use super::*;

use std::convert::TryFrom;

use std::mem::MaybeUninit;

use libc::c_int;
use libc::c_uint;
use libc::c_void;

use zeroize::Zeroize;
use zeroize::Zeroizing;

// NOTE: This structure is copied from <openssl/aead.h> in order to be able to
// statically allocate it. While it is not often modified upstream, it needs to
// be kept in sync.
#[repr(C)]
pub struct EVP_AEAD_CTX_ST {
    aead: libc::uintptr_t,
    opaque: [u8; 580],
    alignment: u64,
    tag_len: u8,
}

// Internal alias for backwards compat
type EVP_AEAD_CTX = EVP_AEAD_CTX_ST;

#[derive(Clone)]
#[repr(C)]
pub(crate) struct AES_KEY {
    rd_key: [u32; 4 * (14 + 1)],
    rounds: c_int,
}

// ML-KEM-768 opaque types. These must match the size and alignment of the
// BoringSSL structs in <openssl/mlkem.h>, which are unions of the byte array
// with a uint16_t (BoringSSL casts them to structs of uint16_t internally).
#[repr(C, align(2))]
pub struct MLKEM768_public_key {
    opaque: [u8; 512 * (3 + 9) + 32 + 32],
}

#[repr(C, align(2))]
pub struct MLKEM768_private_key {
    opaque: [u8; 512 * (3 + 3 + 9) + 32 + 32 + 32],
}

// ML-KEM-768 constants
pub const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
pub const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;

// Common ML-KEM constants
pub const MLKEM_SHARED_SECRET_BYTES: usize = 32;

// BoringSSL CBS (CRYPTO ByteString) — used for MLKEM parse functions.
// Must match the cbs_st layout in <openssl/bytestring.h>: { data: *const u8, len: usize }
#[repr(C)]
struct CBS {
    data: *const u8,
    len: usize,
}

impl Algorithm {
    fn get_evp_aead(self) -> *const EVP_AEAD {
        match self {
            Algorithm::AES128_GCM => unsafe { EVP_aead_aes_128_gcm_tls13() },
            Algorithm::AES256_GCM => unsafe { EVP_aead_aes_256_gcm_tls13() },
            Algorithm::ChaCha20_Poly1305 => unsafe {
                EVP_aead_chacha20_poly1305()
            },
        }
    }
}

pub(crate) struct PacketKey {
    alg: Algorithm,

    ctx: EVP_AEAD_CTX,

    nonce: Vec<u8>,
}

impl PacketKey {
    pub fn new(
        alg: Algorithm, key: Vec<u8>, iv: Vec<u8>, _enc: u32,
    ) -> Result<Self> {
        Ok(Self {
            alg,
            ctx: make_aead_ctx(alg, &key)?,
            nonce: iv,
        })
    }

    pub fn from_secret(aead: Algorithm, secret: &[u8], enc: u32) -> Result<Self> {
        let key_len = aead.key_len();
        let nonce_len = aead.nonce_len();

        let mut key = vec![0; key_len];
        let mut iv = vec![0; nonce_len];

        derive_pkt_key(aead, secret, &mut key)?;
        derive_pkt_iv(aead, secret, &mut iv)?;

        let pkt_key = Self::new(aead, key, iv, enc)?;

        // Dummy seal operation to prime the AEAD context with the nonce mask.
        //
        // This is needed because BoringCrypto requires the first counter (i.e.
        // packet number) to be zero, which would not be the case for packet
        // number spaces after Initial as the same packet number sequence is
        // shared.
        let _ = pkt_key.seal_with_u64_counter(0, b"", &mut [0_u8; 16], 0, None);

        Ok(pkt_key)
    }

    pub fn open_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8],
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_len = match buf.len().checked_sub(tag_len) {
            Some(n) => n,
            None => return Err(Error::CryptoFail),
        };

        let max_out_len = out_len;

        let nonce = make_nonce(&self.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_open(
                &self.ctx,          // ctx
                buf.as_mut_ptr(),   // out
                &mut out_len,       // out_len
                max_out_len,        // max_out_len
                nonce[..].as_ptr(), // nonce
                nonce.len(),        // nonce_len
                buf.as_ptr(),       // inp
                buf.len(),          // in_len
                ad.as_ptr(),        // ad
                ad.len(),           // ad_len
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(out_len)
    }

    pub fn seal_with_u64_counter(
        &self, counter: u64, ad: &[u8], buf: &mut [u8], in_len: usize,
        extra_in: Option<&[u8]>,
    ) -> Result<usize> {
        let tag_len = self.alg.tag_len();

        let mut out_tag_len = tag_len;

        let (extra_in_ptr, extra_in_len) = match extra_in {
            Some(v) => (v.as_ptr(), v.len()),

            None => (std::ptr::null(), 0),
        };

        // Make sure all the outputs combined fit in the buffer.
        if in_len + tag_len + extra_in_len > buf.len() {
            return Err(Error::CryptoFail);
        }

        let nonce = make_nonce(&self.nonce, counter);

        let rc = unsafe {
            EVP_AEAD_CTX_seal_scatter(
                &self.ctx,                  // ctx
                buf.as_mut_ptr(),           // out
                buf[in_len..].as_mut_ptr(), // out_tag
                &mut out_tag_len,           // out_tag_len
                tag_len + extra_in_len,     // max_out_tag_len
                nonce[..].as_ptr(),         // nonce
                nonce.len(),                // nonce_len
                buf.as_ptr(),               // inp
                in_len,                     // in_len
                extra_in_ptr,               // extra_in
                extra_in_len,               // extra_in_len
                ad.as_ptr(),                // ad
                ad.len(),                   // ad_len
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(in_len + out_tag_len)
    }
}

#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum HeaderProtectionKey {
    Aes(AES_KEY),

    ChaCha(Vec<u8>),
}

impl HeaderProtectionKey {
    pub fn new(alg: Algorithm, hp_key: Vec<u8>) -> Result<Self> {
        match alg {
            Algorithm::AES128_GCM | Algorithm::AES256_GCM => unsafe {
                let key_len_bits = alg.key_len() as u32 * 8;

                let mut aes_key = MaybeUninit::<AES_KEY>::uninit();

                let rc = AES_set_encrypt_key(
                    hp_key.as_ptr(),
                    key_len_bits,
                    aes_key.as_mut_ptr(),
                );

                if rc != 0 {
                    return Err(Error::CryptoFail);
                }

                let aes_key = aes_key.assume_init();
                Ok(Self::Aes(aes_key))
            },

            Algorithm::ChaCha20_Poly1305 => Ok(Self::ChaCha(hp_key)),
        }
    }

    pub fn new_mask(&self, sample: &[u8]) -> Result<HeaderProtectionMask> {
        match self {
            Self::Aes(aes_key) => {
                let mut block = [0_u8; 16];

                unsafe {
                    AES_ecb_encrypt(
                        sample.as_ptr(),
                        block.as_mut_ptr(),
                        aes_key as _,
                        1,
                    )
                };

                // Downsize the encrypted block to the size of the header
                // protection mask.
                //
                // The length of the slice will always match the size of
                // `HeaderProtectionMask` so the `unwrap()` is safe.
                let new_mask =
                    HeaderProtectionMask::try_from(&block[..HP_MASK_LEN])
                        .unwrap();
                Ok(new_mask)
            },

            Self::ChaCha(key) => {
                const PLAINTEXT: &[u8; HP_MASK_LEN] = &[0_u8; HP_MASK_LEN];

                let mut new_mask = HeaderProtectionMask::default();

                let counter = u32::from_le_bytes([
                    sample[0], sample[1], sample[2], sample[3],
                ]);

                unsafe {
                    CRYPTO_chacha_20(
                        new_mask.as_mut_ptr(),
                        PLAINTEXT.as_ptr(),
                        PLAINTEXT.len(),
                        key.as_ptr(),
                        sample[size_of::<u32>()..].as_ptr(),
                        counter,
                    );
                };

                Ok(new_mask)
            },
        }
    }
}

fn make_aead_ctx(alg: Algorithm, key: &[u8]) -> Result<EVP_AEAD_CTX> {
    let mut ctx = MaybeUninit::uninit();

    let ctx = unsafe {
        let aead = alg.get_evp_aead();

        let rc = EVP_AEAD_CTX_init(
            ctx.as_mut_ptr(),
            aead,
            key.as_ptr(),
            alg.key_len(),
            alg.tag_len(),
            std::ptr::null_mut(),
        );

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        ctx.assume_init()
    };

    Ok(ctx)
}

pub(crate) fn hkdf_extract(
    alg: Algorithm, out: &mut [u8], secret: &[u8], salt: &[u8],
) -> Result<()> {
    let mut out_len = out.len();

    let rc = unsafe {
        HKDF_extract(
            out.as_mut_ptr(),
            &mut out_len,
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

pub(crate) fn hkdf_expand(
    alg: Algorithm, out: &mut [u8], secret: &[u8], info: &[u8],
) -> Result<()> {
    let rc = unsafe {
        HKDF_expand(
            out.as_mut_ptr(),
            out.len(),
            alg.get_evp_digest(),
            secret.as_ptr(),
            secret.len(),
            info.as_ptr(),
            info.len(),
        )
    };

    if rc != 1 {
        return Err(Error::CryptoFail);
    }

    Ok(())
}

extern "C" {
    fn EVP_aead_aes_128_gcm_tls13() -> *const EVP_AEAD;

    pub fn EVP_aead_aes_256_gcm_tls13() -> *const EVP_AEAD;

    pub fn EVP_aead_chacha20_poly1305() -> *const EVP_AEAD;

    // HKDF
    fn HKDF_extract(
        out_key: *mut u8, out_len: *mut usize, digest: *const EVP_MD,
        secret: *const u8, secret_len: usize, salt: *const u8, salt_len: usize,
    ) -> c_int;

    fn HKDF_expand(
        out_key: *mut u8, out_len: usize, digest: *const EVP_MD, prk: *const u8,
        prk_len: usize, info: *const u8, info_len: usize,
    ) -> c_int;

   // EVP_AEAD_CTX
    pub fn EVP_AEAD_CTX_init(
        ctx: *mut EVP_AEAD_CTX, aead: *const EVP_AEAD, key: *const u8,
        key_len: usize, tag_len: usize, engine: *mut c_void,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_open(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_len: *mut usize,
        max_out_len: usize, nonce: *const u8, nonce_len: usize, inp: *const u8,
        in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_seal_scatter(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_tag: *mut u8,
        out_tag_len: *mut usize, max_out_tag_len: usize, nonce: *const u8,
        nonce_len: usize, inp: *const u8, in_len: usize, extra_in: *const u8,
        extra_in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_seal(
        ctx: *const EVP_AEAD_CTX, out: *mut u8, out_len: *mut usize,
        max_out_len: usize, nonce: *const u8, nonce_len: usize,
        inp: *const u8, in_len: usize, ad: *const u8, ad_len: usize,
    ) -> c_int;

    pub fn EVP_AEAD_CTX_cleanup(ctx: *mut EVP_AEAD_CTX);

    // AES
    fn AES_set_encrypt_key(
        key: *const u8, bits: c_uint, aeskey: *mut AES_KEY,
    ) -> c_int;

    fn AES_ecb_encrypt(
        inp: *const u8, out: *mut u8, key: *const AES_KEY, enc: c_int,
    ) -> c_void;

    // ChaCha20
    pub fn CRYPTO_chacha_20(
        out: *mut u8, inp: *const u8, in_len: usize, key: *const u8,
        nonce: *const u8, counter: u32,
    ) -> c_void;

    // ML-KEM-768
    fn MLKEM768_generate_key(
        out_encoded_public_key: *mut u8,
        optional_out_seed: *mut u8,
        out_private_key: *mut MLKEM768_private_key,
    );

    fn MLKEM768_encap(
        out_ciphertext: *mut u8,
        out_shared_secret: *mut u8,
        public_key: *const MLKEM768_public_key,
    );

    fn MLKEM768_decap(
        out_shared_secret: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: usize,
        private_key: *const MLKEM768_private_key,
    ) -> c_int;

    // BoringSSL CBS (CRYPTO ByteString) — needed for *_parse_public_key
    fn MLKEM768_parse_public_key(
        out_public_key: *mut MLKEM768_public_key,
        cbs: *mut CBS,
    ) -> c_int;

}

// ML-KEM-768 Rust API wrappers
impl MLKEM768_public_key {
    /// Parse a public key from its encoded form
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MLKEM768_PUBLIC_KEY_BYTES {
            return Err(Error::CryptoFail);
        }
        let mut key = MLKEM768_public_key {
            opaque: [0; 512 * (3 + 9) + 32 + 32],
        };
        // CBS_init is inline in BoringSSL headers, so initialize the struct directly.
        // Layout matches cbs_st: { data: *const u8, len: usize }
        let mut cbs = CBS {
            data: bytes.as_ptr(),
            len: bytes.len(),
        };
        let rc = unsafe {
            MLKEM768_parse_public_key(&mut key as *mut _, &mut cbs)
        };
        if rc != 1 {
            return Err(Error::CryptoFail);
        }
        Ok(key)
    }
}

impl MLKEM768_private_key {
    /// Generate a new ML-KEM768 keypair.
    ///
    /// The private key is generated directly on the heap, so no copy of it
    /// is left behind on the stack; it is wiped when dropped.
    pub fn generate() -> (Box<Self>, Vec<u8>) {
        let mut private_key = Box::<Self>::new_uninit();
        let mut encoded_public_key = vec![0u8; MLKEM768_PUBLIC_KEY_BYTES];

        unsafe {
            MLKEM768_generate_key(
                encoded_public_key.as_mut_ptr(),
                std::ptr::null_mut(), // No seed output needed
                private_key.as_mut_ptr(),
            );

            (private_key.assume_init(), encoded_public_key)
        }
    }

    /// Encapsulate to encoded public key bytes
    /// Returns (shared_secret, ciphertext)
    pub fn encapsulate_to_bytes(
        encoded_pubkey: &[u8],
    ) -> Result<(Zeroizing<[u8; MLKEM_SHARED_SECRET_BYTES]>, Vec<u8>)> {
        // Parse the encoded public key into the proper expanded struct layout.
        // MLKEM768_encap requires the decoded/NTT-expanded form, NOT the raw bytes.
        let public_key = MLKEM768_public_key::from_bytes(encoded_pubkey)?;

        let mut ciphertext = vec![0u8; MLKEM768_CIPHERTEXT_BYTES];
        let mut shared_secret = Zeroizing::new([0u8; MLKEM_SHARED_SECRET_BYTES]);

        unsafe {
            MLKEM768_encap(
                ciphertext.as_mut_ptr(),
                shared_secret.as_mut_ptr(),
                &public_key as *const _,
            );
        }

        Ok((shared_secret, ciphertext))
    }

    /// Decapsulate: extract shared secret from ciphertext
    pub fn decapsulate(
        &self, ciphertext: &[u8],
    ) -> Result<Zeroizing<[u8; MLKEM_SHARED_SECRET_BYTES]>> {
        if ciphertext.len() != MLKEM768_CIPHERTEXT_BYTES {
            return Err(Error::CryptoFail);
        }

        let mut shared_secret = Zeroizing::new([0u8; MLKEM_SHARED_SECRET_BYTES]);

        let rc = unsafe {
            MLKEM768_decap(
                shared_secret.as_mut_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                self as *const _,
            )
        };

        if rc != 1 {
            return Err(Error::CryptoFail);
        }

        Ok(shared_secret)
    }
}

impl Drop for MLKEM768_private_key {
    fn drop(&mut self) {
        self.opaque.zeroize();
    }
}

/// Size of the key that a ChaCha20-Poly1305 context stores.
const CHACHA20_POLY1305_KEY_LEN: usize = 32;

impl EVP_AEAD_CTX_ST {
    /// Wipes the copy of the key held by a ChaCha20-Poly1305 context. Call
    /// after `EVP_AEAD_CTX_cleanup()`.
    ///
    /// BoringSSL's ChaCha20-Poly1305 context holds nothing but its key, at
    /// the start of the state (checked by the
    /// `chacha20_poly1305_ctx_holds_only_the_key` test), so only those bytes
    /// are wiped: wiping the whole 608-byte struct took longer than setting
    /// up the context.
    pub(crate) fn wipe_chacha20_poly1305_key(ctx: *mut Self) {
        // SAFETY: the caller passes a valid context, and the state is larger
        // than the key.
        unsafe {
            let key = std::ptr::addr_of_mut!((*ctx).opaque)
                .cast::<[u8; CHACHA20_POLY1305_KEY_LEN]>();

            std::ptr::write_volatile(key, [0; CHACHA20_POLY1305_KEY_LEN]);
        }

        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Size of an `EVP_AEAD_CTX_ST` in 64-bit words.
const CTX_WORDS: usize = size_of::<EVP_AEAD_CTX_ST>() / 8;

/// A ChaCha20-Poly1305 context that takes a new key by having it written
/// into its state, instead of being set up again.
///
/// The context is held in a zeroed buffer of words, so that all of its
/// bytes can be compared, including any that BoringSSL leaves unset.
pub(crate) struct RekeyableChaCha20Poly1305 {
    buf: [u64; CTX_WORDS],
}

impl RekeyableChaCha20Poly1305 {
    /// Sets up a context, if writing a key into it is the same as setting it
    /// up with that key. It then holds no key.
    ///
    /// That is the case while BoringSSL's context stores nothing but a copy
    /// of the key (see `wipe_chacha20_poly1305_key()`). This checks it at run
    /// time, by comparing every byte of two contexts, and not just in a test:
    /// a context that kept its old key would protect every packet with that
    /// key and the same nonce.
    pub(crate) fn new() -> Option<Self> {
        let key_a = [0xa5; CHACHA20_POLY1305_KEY_LEN];
        let key_b = [0x5a; CHACHA20_POLY1305_KEY_LEN];

        let a = Self::init(&key_a)?;
        let mut b = Self::init(&key_b)?;

        b.write_key(&key_a);

        if a.bytes() != b.bytes() || a.bytes()[Self::key_range()] != key_a {
            return None;
        }

        b.wipe_key();

        Some(b)
    }

    fn init(key: &[u8; CHACHA20_POLY1305_KEY_LEN]) -> Option<Self> {
        let mut ctx = RekeyableChaCha20Poly1305 {
            buf: [0; CTX_WORDS],
        };

        // If this fails, BoringSSL leaves the context empty, and dropping it
        // is still safe.
        let rc = unsafe {
            EVP_AEAD_CTX_init(
                ctx.ptr_mut(),
                EVP_aead_chacha20_poly1305(),
                key.as_ptr(),
                key.len(),
                16, // tag length
                std::ptr::null_mut(),
            )
        };

        (rc == 1).then_some(ctx)
    }

    /// Runs `f` with the context keyed with `key`, then wipes the key from
    /// the context.
    #[inline]
    pub(crate) fn with_key<T>(
        &mut self, key: &[u8; CHACHA20_POLY1305_KEY_LEN],
        f: impl FnOnce(*const EVP_AEAD_CTX_ST) -> T,
    ) -> T {
        self.write_key(key);

        let out = f(self.buf.as_ptr().cast());

        self.wipe_key();

        out
    }

    fn key_range() -> std::ops::Range<usize> {
        let start = std::mem::offset_of!(EVP_AEAD_CTX_ST, opaque);

        start..start + CHACHA20_POLY1305_KEY_LEN
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the buffer is plain integers, fully initialized.
        unsafe {
            std::slice::from_raw_parts(self.buf.as_ptr().cast(), CTX_WORDS * 8)
        }
    }

    #[inline]
    fn write_key(&mut self, key: &[u8; CHACHA20_POLY1305_KEY_LEN]) {
        // SAFETY: the key range lies within the buffer.
        unsafe {
            self.buf
                .as_mut_ptr()
                .cast::<u8>()
                .add(Self::key_range().start)
                .cast::<[u8; CHACHA20_POLY1305_KEY_LEN]>()
                .write_unaligned(*key);
        }
    }

    #[inline]
    fn wipe_key(&mut self) {
        EVP_AEAD_CTX_ST::wipe_chacha20_poly1305_key(self.ptr_mut());
    }

    fn ptr_mut(&mut self) -> *mut EVP_AEAD_CTX_ST {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for RekeyableChaCha20Poly1305 {
    fn drop(&mut self) {
        unsafe { EVP_AEAD_CTX_cleanup(self.ptr_mut()) };

        self.wipe_key();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed buffer to hold a context, so that all of its bytes
    /// (including padding) can be read.
    type CtxBuf = [u64; CTX_WORDS];

    fn ctx_ptr(buf: &mut CtxBuf) -> *mut EVP_AEAD_CTX_ST {
        buf.as_mut_ptr().cast()
    }

    fn ctx_bytes(buf: &CtxBuf) -> &[u8] {
        // SAFETY: the buffer is plain integers, fully initialized.
        unsafe { std::slice::from_raw_parts(buf.as_ptr().cast(), CTX_WORDS * 8) }
    }

    fn init_ctx(key: &[u8; CHACHA20_POLY1305_KEY_LEN]) -> CtxBuf {
        let mut buf = [0; CTX_WORDS];

        let rc = unsafe {
            EVP_AEAD_CTX_init(
                ctx_ptr(&mut buf),
                EVP_aead_chacha20_poly1305(),
                key.as_ptr(),
                key.len(),
                16,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(rc, 1);

        buf
    }

    #[test]
    fn chacha20_poly1305_ctx_holds_only_the_key() {
        assert_eq!(size_of::<EVP_AEAD_CTX_ST>() % 8, 0);

        let key_a = [0xa5; CHACHA20_POLY1305_KEY_LEN];
        let key_b = [0x5a; CHACHA20_POLY1305_KEY_LEN];

        let mut a = init_ctx(&key_a);
        let mut b = init_ctx(&key_b);

        // Bytes that depend on the key are the only ones that differ
        // between the two contexts: they must all be in the range that
        // `wipe_chacha20_poly1305_key()` wipes. If BoringSSL starts storing
        // more (e.g. a key schedule), the wipe must change too.
        let state = std::mem::offset_of!(EVP_AEAD_CTX_ST, opaque);
        let key_range = state..state + CHACHA20_POLY1305_KEY_LEN;

        assert_eq!(ctx_bytes(&a)[key_range.clone()], key_a);

        for (i, (x, y)) in ctx_bytes(&a).iter().zip(ctx_bytes(&b)).enumerate() {
            assert!(
                x == y || key_range.contains(&i),
                "byte {i} depends on the key"
            );
        }

        for buf in [&mut a, &mut b] {
            unsafe { EVP_AEAD_CTX_cleanup(ctx_ptr(buf)) };
            EVP_AEAD_CTX_ST::wipe_chacha20_poly1305_key(ctx_ptr(buf));
        }

        // Nothing that depends on the key is left.
        assert_eq!(ctx_bytes(&a), ctx_bytes(&b));
        assert!(ctx_bytes(&a)[key_range].iter().all(|&x| x == 0));
    }

    #[test]
    fn rekeyable_context_holds_key_only_while_in_use() {
        // Fails if BoringSSL's context starts holding more than the key;
        // PQDR would then set up a context per packet, which is slower.
        let mut ctx = RekeyableChaCha20Poly1305::new().unwrap();

        let key = [0x3c; CHACHA20_POLY1305_KEY_LEN];
        let no_key = [0; CHACHA20_POLY1305_KEY_LEN];

        let range = RekeyableChaCha20Poly1305::key_range();

        assert_eq!(ctx.bytes()[range.clone()], no_key);

        // While in use, it is the context that setting it up with the key
        // gives.
        let fresh = init_ctx(&key);

        ctx.with_key(&key, |ptr| {
            // SAFETY: `ptr` points to the context's buffer, which is
            // borrowed for this closure.
            let bytes = unsafe {
                std::slice::from_raw_parts(ptr.cast::<u8>(), CTX_WORDS * 8)
            };

            assert_eq!(bytes, ctx_bytes(&fresh));
        });

        assert_eq!(ctx.bytes()[range], no_key);
    }
}
