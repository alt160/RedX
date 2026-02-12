# Zifika

Zifika is an experimental cryptographic, deterministic, keyed **path‑walking** cipher.

It walks a keyed 2D permutation grid, using a Blake3‑driven jump stream to move the cursor, and emits a **row‑encoded action stream** as ciphertext. Decryption replays the same walk to recover plaintext.

Zifika ships in two modes:

- **Symmetric mode**: full‑key encrypt and decrypt.
- **Mint and Verify mode**: an origin‑locked mode where a **minting key** produces ciphertext and a **verifier key** can decrypt and verify provenance, while the verifier key is intentionally unable to mint ciphertext that passes verification.

## Status

This is an experimental construction.

- No formal security proof.
- Not positioned as a drop‑in replacement for AES or ChaCha.
- Published to invite analysis, including attempts to develop distinguishers and practical attacks.

## Core Ideas

### Keyed permutation grid

A full key is `keyBlockSize` rows of 256 bytes each.

- Each row is a Fisher–Yates shuffle of the byte values 0..255.
- Rows are concatenated into `keyBytes`.
- An inverse table `rkd[row][byte] -> column` is maintained for fast lookup.

### Jump stream

A Blake3‑derived generator emits 16‑bit jumps (`NextJump16`).

- High byte selects a row delta modulo `keyBlockSize`.
- Low byte selects a column delta modulo 256.

### Distance encoding (row‑encoded)

For each plaintext byte, the walker:

1. Applies a jump to move `(row, col)` within the active Zifika key.
2. Finds the column where the current plaintext byte appears in that row.
3. Computes the **forward wrapped distance** from the current column to that target column.
4. **Encodes that distance through the current key row** and emits the resulting value as the ciphertext byte.
5. Advances to the target column and increments the row.

The raw distance is **never emitted directly**. The value placed on the wire is the byte found at `keyRow[distance]`. During decryption, the inverse row mapping recovers the distance before replaying the walk.

### Ciphertext as an action stream

A useful mental model is that ciphertext bytes are **actions** (row‑encoded relative movements) emitted from a keyed state machine. They are not transformed plaintext values.

Below is a vertical sketch focused on **what happens** (not how). Time increases upward.

- The **SECRET** column is the hidden cursor state (the landing position after the jump).
- The **CIPHER** column is what appears on the wire: a symbol corresponding to a **row‑encoded step** from that landing position.

```text
(time / byte index increases upward)
                ▲

PLAIN      SECRET           CIPHER (row‑encoded action)
─────      ──────           ───────────────────────────

  C        land(r,c)  ───►    #    (encoded step)
  ▲          ▲                 ▲
  │          │                 │
  B        land(r,c)  ───►    j    (encoded step)
  ▲          ▲                 ▲
  │          │                 │
  A        land(r,c)  ───►    2    (encoded step)

(seeded by key + startLoc + intCat)
```

Key point: the wire byte represents an **encoded action**, not a numeric distance. Without the keyed walk state and row permutation, these bytes are not directly interpretable.

An encoded step is the value obtained by indexing the active key row with the forward wrapped distance (`encodedStep = keyRow[distance]`). It is a row-permutation value that indirectly represents how far the cursor must move, but reveals neither the distance nor the target column without the inverse row mapping and the current walk state.

Without the keyed walk state and row permutation, these bytes are not directly interpretable.
### Interference catalyst

A per‑message byte array called the **interference catalyst** (`intCat`) is a random‑length quantity of random bytes carried in the ciphertext header.

- Encrypt side: `plain = (plain + i + intCat[i % intCatLen]) mod 256`
- Decrypt side: `plain = (plain - i - intCat[i % intCatLen]) mod 256`

`intCat` has several distinct roles in Zifika:

1. **Ciphertext length variability**: it introduces a variable‑length header contribution so ciphertext length is not equal to plaintext length.
2. **Per‑message walk diversification**: it is fed into the jump generator, causing the path‑walk to differ per message even under the same key.
3. **Index‑dependent payload mixing**: it perturbs each payload byte by its position `i` and the catalyst byte, so the same plaintext value at different positions maps differently.
4. **Payload boundary obscuring**: because `intCatLen` varies and the catalyst bytes are present early in the encrypted header, it becomes harder to infer where the payload begins from structure alone.
5. **Per‑message key reshaping**: `intCat` is used to reshuffle the base Zifika key (via Fisher–Yates) before payload processing, producing a message‑specific ephemeral key that is not reused across encryptions.

`intCat` is also included in the optional integrity seal computation.

## Integrity seal

When enabled, Zifika appends an encrypted integrity seal to the ciphertext.

- Seal length: **32 bytes (256 bits)** in the current implementation.
- Seal material: `integritySeal32B = Blake3(enc(startLocation1Bit) || rowEncodedStream || intCat)`.
- The seal bytes are appended **in mapped (encrypted) form**.

Decryption recomputes the expected seal and compares it to the decrypted seal. If the integrity check fails, decryption returns `null`. Plaintext is not materialized internally unless verification succeeds.

This provides tamper and corruption detection with a fail‑closed decryption behavior: modified ciphertext is rejected before any plaintext is released.

## Key Types

### `ZifikaKey`

Full key used for symmetric mode and for deriving verifier keys.

- Holds the permutation rows (`keyBytes`), inverse rows (`rkd`), and a 64‑byte Blake3 digest of the key bytes (`keyHash`).

### `ZifikaMintingKey`

Minting composite key.

- Contains a `ZifikaKey` plus an **authority** ECDSA P‑256 keypair (private PKCS#8 + public SPKI).
- Can mint signed ciphertext and derive a verifier key.

### `ZifikaVerifierKey`

Verifier composite key.

- Contains a verifier decryption key plus the **authority public key** (SPKI).
- Can verify provenance and decrypt Mint and Verify ciphertext.

### Verifier decryption key internals

The verifier decryption key is derived from a full key but does not retain the permutation bytes.

It stores:

- `keyHash` (64 bytes)
- `nonces[flatIndex]` (ushort per index)
- `map[h32] -> byte` where `h32 = Blake3(keyHash[0..8] || index || nonce) truncated to 32 bits`

This supports decryption by lookup without exposing the full permutation.



## Quick Start

### Symmetric encrypt and decrypt

```csharp
using ZifikaLib;
using System.Text;

var key = Zifika.CreateKey();
var plaintext = Encoding.UTF8.GetBytes("hello");

using var cipher = Zifika.Encrypt(plaintext, key);
using var recovered = Zifika.Decrypt(cipher, key);

var text = Encoding.UTF8.GetString(recovered.AsReadOnlySpan);
```

### Mint and Verify encrypt then verify and decrypt

```csharp
using ZifikaLib;
using System.Text;

var (minting, verifier) = Zifika.CreateMintingKeyPair();
var data = Encoding.UTF8.GetBytes("hello");

using var cipher = Zifika.Mint(data, minting);
using var recovered = Zifika.VerifyAndDecrypt(cipher, verifier);

var text = Encoding.UTF8.GetString(recovered.AsReadOnlySpan);
```

## Wire Layout

### Symmetric mode layout

Symmetric ciphertext is:

- `enc(startLocation1Bit)`
- `enc(intCatLen)`
- `enc(intCat)`
- `rowOffsetStream`
- optional: `enc(integritySeal32B)`

Where `enc(...)` means Zifika mapping using the full key.

Integrity seal, when enabled:

- `integritySeal32B = Blake3(enc(startLocation1Bit) || rowOffsetStream || intCat) (32 bytes)`
- It is appended in encrypted form.

### Mint and Verify mode layout

Mint and Verify ciphertext is:

- `vKeyLock4` plain bytes
- `enc_v(startLocation1Bit)`
- `enc_v(checkpointCount32)`
- `enc_v(signature64) * N`
- `enc_v(intCatLen)`
- `enc_v(intCat)`
- `rowOffsetStream`
- optional: `enc_v(integritySeal32B)`

Where `enc_v(...)` means header mapping that is decryptable by the verifier key.

Notes:

- The verifier-header mapping may use a compact marker encoding for small blobs.
- Authority signatures are ECDSA P-256 in IEEE-P1363 fixed concatenation format (64 bytes).

## Authority checkpoints

Mint and Verify binds provenance by signing a 32-byte **observer state** at one or more checkpoints.

- For payloads up to 4 KiB, Zifika uses a single accumulator signature.
- For larger payloads, it computes a checkpoint plan capped by `maxCheckpoints`.

Verification recomputes observer state while replaying the ciphertext walk and requires all signatures to verify before returning plaintext.

## Determinism

Given:

- identical key bytes
- identical `startLocation`
- identical `intCat`

Zifika produces identical ciphertext.

Although the payload key is reshuffled per message, the reshuffle is fully determined by `intCat`; therefore determinism still holds when `startLocation` and `intCat` are identical.

In normal use, `startLocation` and `intCat` are randomized per message, which makes ciphertext vary in length and content between encryptions over the same plaintext.

## What to review

If you are reviewing Zifika, these are the questions that matter:

- Are there practical distinguishers enabled by the distance stream representation
- Does the jump replay create exploitable structure across positions
- Does the interference catalyst mixing meaningfully reduce replay and structural leakage
- Does Mint and Verify actually enforce origin-locking as intended, or does it collapse under attack
- Is the authority checkpoint design binding the right transcript and at the right granularity

## Non claims

Zifika does not claim:

- to be a proven secure cipher
- to replace standardized ciphers
- to be post‑quantum secure

## License

Licensed under the Apache License, Version 2.0.
See the LICENSE file for details.

## Build

- .NET 8

```bash
dotnet build
```
