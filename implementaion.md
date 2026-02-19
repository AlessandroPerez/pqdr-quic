# PQDR-QUIC Implementation Guide (quiche-based)
**Server-segmented KEM public key · Client ciphertext via CRYPTO stream · Per-packet symmetric ratchet · QUIC Key Phase signaling**

This document provides a complete, consistent implementation guide for integrating your design into a fork of **quiche** (Rust). The system consists of:

- **Epoch-based PQ asymmetric ratchet**
  - Epoch duration: **60 seconds**
  - Overlap retention: **5 seconds**
  - **Server sends its KEM public key fragmented (19 packets)**
  - **Client sends ciphertext via QUIC CRYPTO stream at ~55s**
  - Server decapsulates locally
  - Epoch switch at boundary (no more than 2 epochs stored)

- **Symmetric per-packet ratchet**
  - Two directional chains (C→S and S→C)
  - Fresh AEAD key per packet number
  - ChaCha20-Poly1305 packet protection

- **Epoch signaling**
  - Use QUIC **Key Phase bit**
  - `key_phase = epoch_id mod 2`

This guide assumes you are modifying quiche internals (fork-based approach).

# 1. System Overview

## 1.1 Epoch Timeline

Let epoch `e` run from:

```
t = 0s → 60s
```

### During Epoch e:

| Time | Action |
|------|--------|
| 0s | Server generates `(pkS[e+1], skS[e+1])` |
| First 19 packets | Server sends `pkS[e+1]` fragments |
| Before 55s | Client encapsulates using `pkS[e+1]` |
| ~55s | Client sends `ct[e+1]` via QUIC CRYPTO stream |
| 60s | Both sides switch to epoch `e+1` keys |
| 60s–65s | Previous epoch retained for reordering |
| ≥65s | Epoch `e` keys deleted |

**Invariant:** At most **two epochs** exist in memory at any time.

# 2. Asymmetric PQ Epoch Ratchet

## 2.1 Server Behavior

### At Start of Epoch e

Generate next-epoch KEM keypair:

```
(pkS[e+1], skS[e+1]) = KEM.KeyGen()
```

Store `skS[e+1]` securely.

### First 19 Packets of Epoch e

Prepend a 64-byte pubkey chunk to each packet's plaintext before encryption:

```
packet_plaintext = pubkey_chunk[frag_idx] || application_payload
```

- `frag_idx` 0..18 (in packet-number order)
- Each chunk is exactly 64 bytes; chunk 18 is zero-padded to 64 bytes (ML-KEM-768 pubkey = 1184 bytes = 18×64 + 32)
- No separate wire frame — the chunk is authenticated and encrypted as part of the packet payload
- Receiver reassembles chunks ordered by packet number and strips them from the decrypted plaintext

## 2.2 Client Behavior

### Upon Receiving All 19 Fragments

Reassemble:

```
pkS[e+1]
```

Then compute:

```
(ct[e+1], ssPQ[e+1]) = KEM.Encaps(pkS[e+1])
```

Store `ssPQ[e+1]`.

### At ~55s of Epoch e

Send the ciphertext as raw bytes via the QUIC **CRYPTO stream** (application epoch):

```
CRYPTO stream payload = ct[e+1]   (1088 bytes, ML-KEM-768 ciphertext)
```

Only one ciphertext is sent. No custom frame type — standard QUIC CRYPTO frame carries the bytes.

## 2.3 Server Upon Receiving Ciphertext

Upon reading 1088 bytes from the QUIC CRYPTO stream (application epoch):

Compute:

```
ssPQ[e+1] = KEM.Decaps(skS[e+1], ct[e+1])
```

Decapsulation is local computation only.

# 3. Epoch Secret Derivation

At boundary `t = 60s`, with `starting_pn` = first QUIC packet number of the new epoch:

```
prk = BLAKE3-HKDF-Extract(
    salt = starting_pn (8 bytes, big-endian),
    ikm  = ssPQ[e+1]
)

(CK_send, CK_recv) = BLAKE3-HKDF-Expand(prk, "pqdr-epoch-chains", 64 bytes)
    CK_send = output[0..32]
    CK_recv = output[32..64]
```

Server swaps: `server_send = CK_recv`, `server_recv = CK_send` (so server-send == client-recv).

There is **no chaining from the previous epoch's shared secret** — the KEM `ssPQ[e+1]` alone seeds the new chains, bound to the epoch boundary via `starting_pn`.

# 4. Symmetric Per-Packet Ratchet

Two independent chains:

- `CK_c2s`
- `CK_s2c`

## 4.1 Initialization

**Epoch 0** (from TLS handshake secret):

```
root = BLAKE3-HKDF-Expand(BLAKE3(handshake_secret), "pqdr-quic-init", 32 bytes)
prk  = BLAKE3-HKDF-Extract(salt=root, ikm=b"initial")

(CK_a, CK_b) = BLAKE3-HKDF-Expand(prk, "pqdr-quic-chains", 64 bytes)
    CK_a = output[0..32]
    CK_b = output[32..64]

Client: send=CK_a, recv=CK_b
Server: send=CK_b, recv=CK_a   (swapped so server-send == client-recv)
```

**Epoch N≥1** (from KEM shared secret; see Section 3):

```
Client: send=CK_a, recv=CK_b    (same orientation as epoch 0)
Server: send=CK_b, recv=CK_a
```

Chain PN cursors are **not** reset symmetrically at epoch boundaries:
- Server→client direction resets to `starting_pn`
- Client→server direction continues from epoch N-1 (independent pn space)

## 4.2 Per-Packet Derivation

For packet number `pn`:

```
output = BLAKE3-keyed-XOF(key=CK_dir, data=BE64(pn), output_len=64)

CK_next = output[0..32]
PK[pn]  = output[32..64]
```

Update:

```
CK_dir = CK_next
```

Use `PK[pn]` as ChaCha20-Poly1305 key.

Notes:
- `pn` is encoded as **8-byte big-endian** (no direction label, no "STEP" prefix)
- `CK_dir` is used as the 32-byte BLAKE3 keyed-hash key
- The XOF produces 64 bytes via `finalize_xof().fill()`

## 4.3 Nonce

```
nonce = [0x00; 12]   (12 zero bytes, always)
```

The nonce is fixed at zero because **the key itself changes every packet**. Nonce reuse is only dangerous when the same key is reused; since every packet uses a unique `PK[pn]`, the `(key, nonce)` pair is never repeated.

This differs from the original design intent (`encode96(pn)`). The security guarantee is equivalent — each `(key=PK[pn], nonce=0)` pair is unique.

## 4.4 Out-of-Order Receive

Maintain per direction:

```
max_derived_pn
cache[pn] -> PK[pn]
```

Algorithm:

1. If `pn <= max_derived_pn`:
   - Use cached key (if exists)
2. If `pn > max_derived_pn`:
   - If `pn - max_derived_pn > MAX_SKIP_PN` → drop
   - Else derive sequentially up to `pn`
   - Cache intermediate keys

Deletion:
- Remove cached keys when outside reordering window
- Remove entire cache when epoch expires

# 5. Packet Protection (AEAD)

Use:

```
ChaCha20-Poly1305
```

Encrypt:

```
ciphertext = AEAD_Seal(
    key   = PK[pn],
    nonce = nonce,
    aad   = authenticated_header,
    pt    = payload
)
```

Decrypt:

```
plaintext = AEAD_Open(...)
```

Failure behavior must be constant-time and uniform.

# 6. Epoch Management State

## 6.1 Structures

```
RatchetState {
    is_server: bool

    // Send chain (own outgoing direction)
    send_chain_key: [u8; 32]
    send_chain_pn:  u64

    // Receive chain (peer's outgoing direction)
    recv_chain_key: [u8; 32]
    recv_chain_pn:  u64

    // Skipped receive keys for out-of-order packets
    skipped_recv_keys:  HashMap<(epoch, pn), [u8; 32]>

    // Previous epoch receive state (5s TTL)
    prev_epoch_recv: Option<PrevEpochRecv {
        chain_key, chain_pn, skipped, expires
    }>

    // Pre-computed next epoch (activated at t=60s)
    precomputed_next_epoch: Option<{epoch, shared_secret}>

    // KEM state
    pending_ratchet: Option<WaitingForCiphertext | WaitingToActivate>
    incoming_pubkey_chunks: HashMap<pkt_num, chunk>
    outgoing_chunks: Option<Vec<chunk>>
    pending_ciphertext_response: Option<(epoch, ciphertext)>
}
```


At `t >= start_time + 60s`:

1. `previous = current`
2. Activate `current = new_epoch`
3. Flip Key Phase bit
4. Schedule deletion of `previous` at `+5s`

At `t >= start_time_new + 5s`:

- Securely delete `previous`

# 7. QUIC Key Phase Integration

Define:

```
key_phase = epoch_id mod 2
```

## Sender

- Set short header Key Phase bit accordingly.

## Receiver

Upon receiving packet:

1. If KP matches current → try current keys
2. Else if matches previous → try previous keys
3. Else drop

Never allow more than 1 future epoch in memory.

# 8. Integration into quiche

## 8.1 Modify Packet Protection

Replace standard 1-RTT key derivation with:

```
EpochKeyManager::derive_packet_key(dir, pn)
```

Hook into:
- encrypt path
- decrypt path
- key update logic

## 8.2 KEM Material Integration

Pubkey chunks arrive as **plaintext prefixes** on the first 19 incoming application packets each epoch:
- After PQDR decryption, strip the leading 64 bytes and pass to `ratchet.receive_pubkey_chunk(pkt_num, chunk)`
- Once all 19 chunks are collected, `respond_to_ratchet()` is called to encapsulate

Ciphertext is sent/received via the standard **QUIC CRYPTO stream** (application epoch):
- Client: write 1088 raw bytes to `crypto_stream.send` at t≈55s
- Server: read from `crypto_stream.recv` and call `store_and_precompute_from_ciphertext()`

No custom frame type is needed.

## 8.3 Add Epoch Timer

Hook into quiche timer system:

- Check boundary condition
- Perform epoch transition
- Flip Key Phase

# 9. Security Bounds

Define hard limits:

```
MAX_SKIP_PN
MAX_CACHED_KEYS
MAX_FRAGMENTS = 19
MAX_EPOCHS_IN_MEMORY = 2
```

Reject:
- Unexpected epoch IDs
- Duplicate fragment indices
- Overlarge ciphertext
- Out-of-range PN jumps

Zeroize:
- SS
- CK values
- skS
- Cached packet keys

# 10. Guarantees Achieved

- Per-packet key separation
- Forward secrecy across epochs
- No standalone MAC oracle surface
- Bounded memory usage
- Deterministic epoch signaling
- Maximum two-epoch key retention