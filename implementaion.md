# Implementation guide (quiche-based): PQDR-QUIC epochs + per-packet symmetric ratchet + QUIC Key Phase signaling

This guide assumes your current codebase uses **quiche** as the QUIC stack (Rust crate or C FFI). quiche is a **low-level QUIC transport + HTTP/3** implementation where your application drives I/O and timers. :contentReference[oaicite:0]{index=0}

The system you described has three main pieces:

1) **Symmetric per-packet ratchet (two directional chains):**
   - C→S chain and S→C chain.
   - Packet keys are derived *per packet number* and used with **ChaCha20-Poly1305** AEAD.
   - Out-of-order handling uses bounded skip + cached gap keys.

2) **Asymmetric PQ “epoch pipeline” (server encapsulates one epoch ahead):**
   - Epoch length = 60s.
   - Client sends **pk for epoch e+1** early in epoch e (fragmented over first 19 packets).
   - Server encapsulates during epoch e and sends **ct for epoch e+1** early in epoch e+1 (fragmented over first 19 packets).
   - Client locally decapsulates once ct is complete (decapsulation is *not a message*, it is local computation in KEM-based protocols). :contentReference[oaicite:1]{index=1}
   - Client sends a **key-confirm / commit** around 55s (CRYPTO frame) so the server has ~5s to retry missing fragments.

3) **Epoch switch signaling via QUIC Key Phase bit:**
   - Use QUIC’s Key Phase bit (short header) as the on-wire signal “I’m using the next epoch keys now”.
   - Your “≤ 2 epochs stored” invariant holds because you retain old keys for only 5s.

---

## 0) Before you code: decide where crypto lives

You have two implementation paths:

### Path A (recommended for research/prototype): fork quiche
You modify quiche’s packet protection logic to:
- derive traffic keys from *your* epoch+ratchet state instead of standard QUIC TLS secrets/key updates.

Pros: correct Key Phase behavior, minimal duplication, clean integration with QUIC internals.  
Cons: maintenance + you must keep the fork rebased.

### Path B (application overlay, no quiche fork): run your ratchet above QUIC streams
You leave QUIC packet protection unchanged and instead:
- add an “inner AEAD” that encrypts stream payloads with your per-packet keys.

Pros: no fork, fastest to integrate.  
Cons: you don’t actually change QUIC packet protection (Key Phase bit becomes less meaningful), and your security story becomes “double encryption” not “new QUIC crypto”.

**Given you want to use the Key Phase bit and QUIC packet-level semantics, you want Path A.** The rest of this guide assumes **Path A**.

---

## 1) Define your wire format (frames) + negotiation

QUIC allows new frame types, but you must avoid collisions and negotiate support (e.g., transport parameter, ALPN, or version). Start simple:

### 1.1 Frame types
Define 3 extension frames:

- `PQR_PK_FRAG` (client → server): fragments of `pkC[e+1]`
- `PQR_CT_FRAG` (server → client): fragments of `ct[e+1]`
- `PQR_KEY_CONFIRM` (client → server): small confirmation token for epoch e+1

### 1.2 Encode fields
For all fragments:
- `epoch_id` (varint)
- `frag_idx` (varint)
- `frag_len` (varint)
- `frag_bytes` (frag_len bytes)

For KEY_CONFIRM:
- `epoch_id` (varint)
- `kc_len` (varint)
- `kc_bytes` (kc_len bytes)

### 1.3 Negotiation
Pick one:
- custom QUIC version (research-friendly), or
- a transport parameter “pqr_enabled=1”, or
- ALPN suffix (e.g., `h3-pqdr`).

Do not accept these frames unless negotiated.

---

## 2) Data structures you’ll need

### 2.1 Epoch manager (per connection)
Keep only two epochs worth of secrets:

```text
EpochState {
  epoch_id: u64
  start_time: Instant
  ss_epoch: [u8; 32]          // or 64, depends on your KDF
  ck_c2s: [u8; 32]
  ck_s2c: [u8; 32]
  recv_cache_c2s: Map<pn, pk> // bounded
  recv_cache_s2c: Map<pn, pk> // bounded
  max_derived_pn_c2s: u64
  max_derived_pn_s2c: u64
}
ConnectionEpochs {
  current: EpochState
  previous: Option<EpochState> // retained <= 5 seconds
  next_ready: Option<NextEpochMaterial> // computed but not active
}
```

### 2.2 PQ pipeline buffers

```
PkReassembly[e+1]: fragments[0..18] -> pkC[e+1]
CtReassembly[e+1]: fragments[0..18] -> ct[e+1]
```

Hard limits (important for DoS):

- `MAX_EPOCHS_IN_FLIGHT = 2`
- `MAX_FRAG_BYTES_TOTAL_PER_EPOCH`
- `MAX_SKIP_PN` for ratchet fast-forward
- `MAX_CACHED_KEYS` per direction

Cloudflare has published multiple reminders that QUIC stacks must defensively validate peer signals (e.g., ACK ranges) to avoid resource attacks; apply the same mindset to your custom frames.

## 3 Cryptographic spec you implement (concrete)
### 3.1 Per-packet symmetric ratchet (directional)

Two independent chains: `ck_c2s` and `ck_s2c`.

Per packet number `pn` (for a given direction):
- `step = BLAKE3(key=ck, input="STEP" || dir_id || LE64(pn))` → 64 bytes
- `ck_next = step[0..31]`
- `pk[pn] = step[32..63]` (32B ChaCha20-Poly1305 key)
- update `ck = ck_next` after deriving

Receiver out-of-order:
- if `pn > max_derived_pn`: derive sequentially up to `pn`, caching gap keys (bounded).
- if `pn - max_derived_pn > MAX_SKIP_PN`: drop.

Nonce:
- `nonce = encode96(pn)` (12 bytes) is sufficient since each packet has a fresh key.

AEAD:
- ChaCha20-Poly1305 with `AAD = QUIC header fields you authenticate` (decide exactly which ones, consistently).
- Use a single constant-time failure path.

### 3.2 Epoch derivation
Epoch length = 60s. Overlap retention = 5s.
- At epoch start, `ss_epoch` seeds both chains:
    - `ck_c2s = KDF(ss_epoch, "CK0" || "c2s")`
    - `ck_s2c = KDF(ss_epoch, "CK0" || "s2c")`

When PQ pipeline for epoch e+1 completes:
- `ss_pq[e+1]` comes from KEM:
    - server: `Encaps(pkC[e+1]) -> (ct[e+1], ss_pq[e+1])`
    - client: `Decaps(skC[e+1], ct[e+1]) -> ss_pq[e+1]` (local)

Then finalize next epoch secret:
- `ss_epoch[e+1] = KDF(ss_epoch[e], "EPOCH" || (e+1) || ss_pq[e+1])`

## 4 Timeline: what runs when (the pipeline)
### 4.1 Client actions (epoch e)

**At start of epoch e:**
1. Generate `(pkC[e+1], skC[e+1])`

**Packets 0..18 of epoch e:**
2. Send `PQR_PK_FRAG(epoch=e+1, frag_idx=i, frag=pk_fragment_i)`

**At ~55s of epoch e+1 (not e):**
3. After you have decapsulated `ct[e+1]`, send `PQR_KEY_CONFIRM(epoch=e+1, KC)` inside a QUIC CRYPTO frame (as you planned).

Key confirm:
- `KC = KDF(ss_pq[e+1], "KC" || (e+1) || transcript_hash)[0..31]`
- transcript_hash should cover:
    - all pk and ct fragments (or hashes thereof),
    - connection identifiers relevant to bind to this connection,
    - epoch_id.

### 4.2 Server actions (epoch e)
**Upon receiving all pk fragments for epoch e+1:**
1. Reassemble `pkC[e+1]`
2. Compute `(ct[e+1], ss_pq[e+1]) = Encaps(pkC[e+1])`
3. Store `(ct[e+1], ss_pq[e+1])` until epoch e+1.

**Packets 0..18 of epoch e+1:**
4. Send `PQR_CT_FRAG(epoch=e+1, frag_idx=i, frag=ct_fragment_i)`

**At ~55s of epoch e+1:**
5. Expect KEY_CONFIRM. If missing, retransmit missing ct fragments (or all 19) during last 5 seconds.

## 5 Using QUIC Key Phase bit for epoch switch
Define:
- `key_phase(epoch e) = e mod 2`

**Sender rule (both sides):**
- At time boundary start(epoch e+1), start encrypting with epoch e+1 keys and set Key Phase bit accordingly.

**Receiver rule:**
- If Key Phase matches current epoch: try decrypt with `current`.
- Else: try decrypt with `previous ` (late packet).
- If both fail, drop.

Because you delete keys older than 5s, you’ll never have more than two epochs resident (previous/current), and Key Phase parity stays unambiguous.

(QUIC Key Phase is header-protected and used exactly to indicate which 1-RTT keys protect the packet. See RFC 9001 for QUIC/TLS packet protection and key update behavior.)

## 6 Where to hook this into quiche (fork plan)
quiche’s public API gives you `conn.recv()` and `conn.send()` loops; packet protection happens inside quiche.
So you’ll be editing quiche internals roughly like this:

### 6.1 Locate crypto / packet protection module
In the quiche source tree, find the module(s) that:
- derive traffic keys (from TLS secrets),
- apply header protection,
- apply payload protection (AEAD),
- manage key updates (Key Phase flipping).

(If you’re using the Rust crate, start by browsing `src/crypto/` and packet handling paths in the repo.)

### 6.2 Replace/extend traffic key schedule
Implement a new key schedule backend:
- `EpochKeyManager` that owns `ConnectionEpochs`.
- Expose methods:
  - `protect_packet(pn, header, plaintext) -> ciphertext`
  - `unprotect_packet(pn, header, ciphertext) -> plaintext or fail`
  - `on_epoch_boundary(now)`
  - `on_pk_frag(...)`, `on_ct_frag(...)`, `on_key_confirm(...)`

### 6.3 Add parsing/emission for extension frames
- Add frame parsing cases for your frame types.
- Ensure they are only accepted post-negotiation.
- Feed fragments into `PkReassembly `/ `CtReassembly`.

### 6.4 Connect CRYPTO-frame carriage
You said KEY_CONFIRM will go inside a CRYPTO frame. Two approaches:
- simplest: make KEY_CONFIRM an extension frame carried like any other (STREAM/Datagram payload) rather than true TLS CRYPTO.
- if you insist on CRYPTO frame: you must inject it into QUIC’s CRYPTO stream machinery (which is normally TLS handshake). This is doable but invasive; you must ensure you don’t break TLS handshake parsing.

For a thesis prototype, I strongly recommend: make KEY_CONFIRM a regular extension frame, not CRYPTO. It achieves the same “reliable, retransmittable, ordered” behavior if you send it on a reliable stream or QUIC DATAGRAM with your own retry logic.

### 6.5 Key Phase bit control
Ensure the short header Key Phase bit is set based on `epoch_id mod 2` for 1-RTT packets.
- quiche already knows how to set/protect this bit; you just control the “current phase” variable based on your epoch timer.

## 7 Timers and state machine (what to implement)
### 7.1 Epoch timer
Maintain:
- `epoch_start_time`
- `epoch_id`

On tick:
- if `now >= epoch_start + 60s`: advance epoch:
  - move `current -> previous`
  - activate `next_ready` as new `current`
  - clear `next_ready`
  - schedule deletion of `previous` at `epoch_start + 5s`

### 7.2 Retry windows
- `t=0..(small)` of epoch e: pk/ct fragments
- `t≈55s`: KEY_CONFIRM should be sent/received
- `t=55..60s`: retransmit missing fragments if needed

### 7.3 Key deletion
At `now >= start(epoch e) + 5s`:
- delete all secrets + caches for epoch e-1.

## 8 Testing plan (do this early)
### 8.1 Deterministic unit tests
- Ratchet derivation:
  - known `ss_epoch` and pn sequence -> exact keys.
  - out-of-order receives produce identical keys and correct cache behavior.

- Epoch transitions:
  - epoch parity -> Key Phase bit mapping.
  - two-epoch invariant.

### 8.2 Integration tests with loss/reordering
Simulate network:
- reorder first 19 packets, drop random fragments, delay them into overlap window.
- verify:
  - ct reassembly completes before 55s with high probability,
  - retransmission recovers failures,
  - decryption works across boundary, and old epoch packets decrypt for ≤5s.

### 8.3 qlog / tracing
Add logs for:
- epoch changes
- key phase changes
- fragment reception bitmap (19 bits)
- KEY_CONFIRM sent/received
- ratchet skip count and cache size

## 9 Security checklist (quick but non-negotiable)
- **Uniform AEAD failure behavior**: same error path, no differing alerts.
- **Bounds everywhere**: MAX_SKIP_PN, MAX_CACHE_KEYS, MAX_FRAG_BYTES, MAX_EPOCHS_IN_FLIGHT.
- **Transcript binding**: KEY_CONFIRM must bind epoch_id + fragments to prevent replay across epochs/connections.
- **Erase secrets**: zeroize ss/ck/pk buffers on deletion.
- **No epoch fast-forward**: never allow skipping >1 epoch ahead; parity would become ambiguous.

## 10 Practical “first milestone” implementation order
1. Implement symmetric ratchet (derive keys, AEAD encrypt/decrypt) in isolation.
2. Integrate ratchet into quiche packet protection (fork), without PQ pipeline:
  - epoch 0 only, fixed ss_epoch.
  - Key Phase stays constant.

3. Add epoch timer + Key Phase flip + two-epoch retention.
4. Add PK/CT fragmentation frames + reassembly.
5. Add server encapsulation pipeline (epoch e computes epoch e+1).
6. Add KEY_CONFIRM and retry logic.
7. Harden bounds + run loss/reorder integration tests.
8. Write down the final state machine + frame specs for the thesis.

**Notes on references**
- quiche low-level design and API shape (app-driven I/O loop) ([https://github.com/cloudflare/quiche?utm_source=chatgpt.com])
- QUIC/TLS packet protection and key update concepts (RFC 9001) ([https://datatracker.ietf.org/doc/rfc9001/?utm_source=chatgpt.com])
- decapsulation is local (KEM integration pattern) ([https://datatracker.ietf.org/doc/rfc9001/?utm_source=chatgpt.com])
- defensive validation mindset for QUIC inputs (ACK-range issue postmortem) ([https://blog.cloudflare.com/defending-quic-from-acknowledgement-based-ddos-attacks/?utm_source=chatgpt.com])

```
If you tell me whether you’re using **Rust quiche directly** or the **C FFI** (quiche.h), I can add a short “project skeleton” section that matches your build style (Cargo workspace vs CMake) and point to the exact spots in the quiche send/recv loop where you’ll instrument epoch timers and logs.
::contentReference[oaicite:10]{index=10}
```