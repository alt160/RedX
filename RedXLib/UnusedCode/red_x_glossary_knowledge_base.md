## RedX key — what it is

### Serialized / on-wire

- A RedX key is represented as a **two-dimensional grid of bytes**.
- Each row in the grid is **exactly 256 bytes** wide.
- A key consists of **one or more rows**, stacked vertically.
- Each row is a **permutation of the values 0–255**.
- Rows are **independent permutations**.
- The stacked rows together constitute the key’s **base data**.
- The serialized form is a **complete representation** of the key’s traversal definition.

### Execution form

- A RedX key in execution form is **not** a reversible mathematical transform.
- It is **not** a block cipher state.
- It is **not** a stream cipher seed.
- It is **not** interpreted as a per-byte transform.
- It does **not** operate on plaintext as structured records or fields.
- It does **not** alter traversal behavior based on plaintext content.


## Cipherbytes — what they are

- RedX produces output as **cipherbytes**.
- Each cipherbyte is a **byte-sized distance value**.
- A cipherbyte represents a **forward wrapped distance** between two byte positions **within the same 256-byte key row**.
- Distances are computed by treating each row as a **conceptual circular buffer**.
- Cipherbytes encode **relative movement within key rows**, not transformed plaintext.
- Both plaintext-derived values and structural values are mapped into cipherbytes.

## Cipherbytes — what they are not

- Cipherbytes are **not** the result of a mathematical transform of plaintext.
- They are **not** produced by direct per-byte transforms (no XOR, bit shifts, S-boxes).
- They do **not** directly encode plaintext bytes or plaintext blocks.
- They do **not** preserve or expose message structure.
- They are **not** self-describing without traversal replay.

## Jump stream — what it is

- The jump stream is an **internal deterministic sequence of movement values**.
- It is derived from **key base data** and **per-execution inputs**.
- Each step in the jump stream yields a **fixed-width jump value**.
- Each jump value is interpreted as a **row movement** and a **column movement**.
- Row and column movements are **relative deltas**, not absolute positions.
- Both rows and columns are treated as **circular dimensions** (wrap-around).
- One jump value is consumed **per input byte processed**.
- The jump stream exists **only during execution** and is regenerated during decryption.

## Jump stream — what it is not

- The jump stream is **not stored** in the output.
- It is **not** encoded in cipherbytes.
- It does **not** embed plaintext bytes.
- It does **not** embed key permutation values.
- It does **not** select rows or columns directly.
- It is **not** observable or reconstructable from cipherbytes alone.

## Landing & offset semantics — what they are

- Each step begins by consuming one jump value and updating the current row and column, producing a **landing position** in the key grid.
- A **plainbyte** is then consumed after landing.
- A plainbyte is any byte that participates in traversal, including user input bytes and per-execution injected bytes.
- The plainbyte value is used as a **lookup value** within the landed row to locate a target column.
- A cipherbyte is emitted as the **forward wrapped distance** from the landing column to the target column.
- After emission, the current column is updated to the target column.
- After emission, the current row is advanced **deterministically** (row + 1, modulo row count).
- The emitted plainbyte therefore serves two roles: selecting the distance to emit and **anchoring the starting position for the next jump**.

## Landing & offset semantics — what they are not

- Plainbytes do **not** influence jump value generation.
- Plainbytes do **not** influence the **generation** of row or column movement deltas.
- Plainbytes influence traversal state only by **anchoring the position from which subsequent deltas are applied**.
- Cipherbytes are **not** direct encodings or transformations of plainbytes.
- Landing positions are **not** derived from cipherbytes.
- Offset emission does **not** reveal absolute row or column indices.

## Random start location — what it is

- The random start location is a **per-execution value** used to establish the **initial traversal state**.
- It determines the **initial row and column origin** for traversal.
- Its bytes participate as **plainbytes** and are processed through the same landing and offset semantics as other plainbytes.
- The start location is represented as a **variable-length byte-encoded value**.
- Its encoded bytes are consumed across multiple traversal steps as **plainbytes**.
- It establishes both the traversal **origin** and early traversal **history** before user input plainbytes begin.

## Random start location — what it is not

- It is **not** derived from plaintext.
- It is **not** generated from cipherbytes.
- It does **not** change generated jump values.
- It is **not** present in clear form in the output.
- It is **not** an external header field interpreted outside traversal replay.

## Random prefix bytes — what they are

- Random prefix bytes are a **per-execution sequence** of plainbytes.
- The prefix has a **variable length** determined at execution time.
- The prefix has **random byte values** (random constitution).
- Prefix bytes are consumed **before** any user input plainbytes.
- Each prefix byte is processed as a **plainbyte**, consuming one jump value and participating fully in landing and offset semantics.

## Random prefix bytes — what they are not

- Prefix bytes are **not optional padding**.
- They are **not** derived from user plaintext.
- They do **not** alter jump generation or jump values.
- They are **not** distinguishable from user input bytes in cipherbytes.
- They do **not** introduce special-case traversal behavior.

## Input & plainbytes — what they are

- **Input** to RedX is an **ordered sequence of bytes**.
- Any byte that participates in traversal is a **plainbyte**.
- Plainbytes include user-supplied input bytes (plaintext), random prefix bytes, start location bytes, and other per-execution injected bytes.
- All plainbytes are processed **uniformly** by traversal.
- RedX does **not** distinguish between different sources of plainbytes during traversal.
- There is **no minimum or maximum quantity** of plainbytes imposed by the design.
- Traversal proceeds for as many plainbytes as are supplied.
- Variable-length injected components require **sufficient information to be recoverable during traversal replay**.

## Input & plainbytes — what they are not

- Plainbytes are **not** interpreted as structured records, fields, or blocks.
- Plainbytes are **not** required to be aligned, padded, or block-sized.
- Plainbytes do **not** receive special treatment based on origin (user input vs injected).
- RedX does **not** require or assume any particular plaintext encoding or format.
- Input is **not** required to be message-oriented; any byte stream or byte array is acceptable.

## Integrity seal — what it is

- The integrity seal is an **optional per-execution mechanism** that binds ciphertext validity to traversal replay.
- When enabled, an integrity seal is computed **after traversal**, over the emitted cipherbytes and per-execution injected values.
- The seal value is a **fixed-length byte sequence** derived from the complete traversal output and injected state.
- The seal is **mapped under the same traversal machinery** as other values and appended to the output.
- During decryption, the seal is **recomputed independently** from the recovered traversal state.
- The recomputed seal is compared against the unmapped seal value **before any plaintext is emitted**.
- If the seal does not match, decryption **stops with no output or residual state**.
- **Plaintext integrity emerges from traversal mechanics and is enforced by seal validation.**

## Integrity seal — what it is not

- The integrity seal is **not** a transformation of plaintext.
- It is **not** derived directly from plaintext bytes.
- It does **not** authenticate message structure, records, or fields.
- It does **not** identify a sender or assert external authority.
- It does **not** permit partial, malformed, or degraded plaintext output.
- It does **not** alter traversal mechanics or cipherbyte generation.

## Mint/Verify mode — overview

- Mint/Verify mode is an **optional capability mode** that separates the ability to **mint acceptable ciphertext** from the ability to **decrypt and verify ciphertext**.
- In this mode, acceptability of ciphertext is determined by **validation rules bound to traversal replay**, not by external policy or runtime checks.
- A **minting role** can generate ciphertexts that will be accepted by a corresponding verifier.
- A **verifying role** can decrypt and validate ciphertexts minted by its paired minter, but cannot mint new acceptable ciphertexts.
- This separation is enforced by cryptographic material and traversal validation, not by secrecy of verifier material.

## Mint/Verify mode — intended problem space

- Mint/Verify mode addresses situations where **creation authority** and **consumption capability** must be separated.
- In this mode, the ability to decrypt and validate data does not imply the ability to produce data that will be accepted.
- Representative application domains include:
  - software licensing and feature gating,
  - command or update distribution with controlled provenance,
  - delegated or escrowed decryption,
  - controlled content distribution with centralized minting.

## Mint/Verify mode — relationship to symmetric operation

- Mint/Verify mode builds directly on the symmetric traversal and integrity invariants defined above.
- Cipherbyte semantics, traversal mechanics, and integrity seal behavior remain unchanged.
- Mint/Verify mode introduces an additional **validity gate** that constrains which ciphertexts are considered acceptable by a verifier.

## Mint/Verify mode — what it is not

- It is **not** public-key encryption.
- It is **not** a standalone signature scheme.
- It is **not** an external access-control or policy system.
- It does **not** claim to prevent all theoretical ciphertext generation.
- It does **not** rely on verifier secrecy to enforce capability separation.
- It does **not** implement a new asymmetric primitive; Mint/Verify mode relies on an existing asymmetric signing primitive with non-reversible verification roles.

## Minting key — what it is

### Serialized / on-wire

- A minting key is represented as a **composite key artifact**.
- It contains **complete symmetric RedX key base data**, identical in form to a symmetric key.
- It additionally contains **minting authority material**.
- The serialized form fully specifies both traversal definition and minting authority.
- The serialized minting key is a **complete representation** of minting capability in Mint/Verify mode.

### Execution form

- In execution form, a minting key exists as **traversal-defining state plus attestation-generating capability**.
- Traversal mechanics in execution form are **identical** to symmetric operation.
- The execution form can generate **mint-bound traversal attestations**.
- Attestation generation is bound to traversal state, not to plaintext bytes or message structure.
- The execution form represents **capability to mint acceptable ciphertext**.

## Minting key — what it is not

### Serialized / on-wire

- A minting key is **not** a public key.
- It is **not** a verifier key.
- It is **not** a reduced or partial form of a symmetric key.
- It is **not** limited to verification-only material.
- It is **not** a standalone signing key detached from traversal semantics.
- It does **not** encode message structure, framing, or policy.

### Execution form

- A minting key in execution form is **not** used to decrypt or verify ciphertext.
- It is **not** a general-purpose signature capability.
- It does **not** alter jump generation, landing semantics, or offset emission.
- It does **not** change cipherbyte meaning or encoding.
- It is **not** equivalent to symmetric traversal alone.
- It does **not** validate acceptability of ciphertexts minted by other keys.


## Verifier key — what it is

### Serialized / on-wire

- A verifier key is represented as a **composite key artifact**.
- It contains **symmetric RedX key base data**, identical in form to a symmetric key.
- It additionally contains **verification-only authority material**.
- A verifier key is a **secret key artifact**, protected and handled as sensitive material.
- The serialized form fully specifies traversal definition and verification material required to validate mint-bound traversal attestations.
- The serialized verifier key is a **complete representation** of verifier capability in Mint/Verify mode.

### Execution form

- In execution form, a verifier key exists as **derived traversal state plus attestation-verification capability**.
- Traversal mechanics in execution form are **identical** to symmetric operation.
- Traversal replay operates on **derived traversal state**, not on serialized key representation.
- The execution form can **verify mint-bound traversal attestations** against recovered traversal state.
- The execution form represents **capability to decrypt and validate acceptable ciphertext**.

## Verifier key — what it is not

### Serialized / on-wire

- A verifier key is **not** a minting key.
- It is **not** a public key or public verification artifact.
- It does **not** contain minting authority material.
- It is **not** a reduced or partial encoding of a minting key.
- It is **not** limited to verification material alone.
- It does **not** encode message structure, framing, or policy.

### Execution form

- A verifier key in execution form is **not** capable of generating mint-bound traversal attestations.
- It is **not** capable of minting acceptable ciphertext.
- It is **not** a general-purpose signature capability.
- It does **not** alter traversal mechanics, jump generation, or offset emission.
- It does **not** validate ciphertexts minted by unrelated minting keys.
- It does **not** relax integrity or acceptability conditions during decryption.



## Claims and non-claims

### Claims

- This document defines the **mechanics, invariants, and nomenclature** of the RedX construction.
- It specifies traversal behavior, cipherbyte semantics, and capability separation as **deterministic system properties**.
- It defines Mint/Verify mode as a **capability separation mechanism** enforced by cryptographic material and traversal validation.
- It defines the structure and roles of RedX keys, minting keys, and verifier keys.
- All claims in this document are intended to be **falsifiable through analysis or implementation**.

### Non-claims

- This document does **not** present a formal security proof.
- This document does **not** claim post-quantum resistance.
- This document does **not** claim resistance to AI-assisted cryptanalysis.
- This document does **not** claim that all security properties of RedX are known or fully characterized.
- This document does **not** claim suitability for production deployment.

### Implementation posture

- The provided implementation is intended for **analysis, critique, experimentation, and validation**.
- It serves as a **reference realization** of the mechanics described in this document.
- It is not presented as hardened, audited, or production-ready software.
- The implementation exists to support **review, testing, and proof work**.
