# Contributing to RedX

Thank you for your interest in contributing to **RedX**.

RedX is an *experimental cryptographic construction* published to invite review, critique, and improvement. Contributions are welcome, but the bar is intentionally high: correctness, clarity of intent, and fidelity to the documented design matter more than feature velocity.


---

## Scope of Contributions

RedX accepts contributions in the following categories:

### 1. Cryptographic Review & Analysis (Highly Valued)
- Design critique
- Attack ideas or partial distinguishers
- Structural analysis of the walk, distance stream, or mint/verify model
- Failure modes or misuse cases

These may be submitted as:
- GitHub issues
- Markdown documents
- Code-based experiments

Negative results are acceptable and encouraged.

---

### 2. Bug Fixes
- Incorrect behavior relative to documented intent
- Determinism violations
- Verification failures
- Memory safety or logic errors

Bug reports **must** include:
- Minimal repro code
- Expected vs actual behavior
- Whether the issue affects symmetric mode, mint/verify mode, or both

---

### 3. Performance Improvements

Performance changes are welcome **only** if they:
- Preserve wire compatibility
- Preserve determinism
- Preserve cryptographic semantics

Examples:
- Allocation reduction
- Span/Memory optimizations
- Faster replay or verification paths

Benchmarks or measurements are expected.

---

### 4. Documentation Improvements
- Clarifying comments
- Correcting inaccurate descriptions
- Improving mental models without oversimplifying

Documentation should remain technically precise. Marketing language will be rejected.

---

## Out-of-Scope Contributions

The following will generally not be accepted:

- Replacing RedX with a standard cipher (AES, ChaCha, etc.)
- Claims of security proofs
- "Drop-in replacement" positioning
- Large API surface expansion without prior discussion
- Cosmetic refactors that obscure the algorithm

---

## Design Invariants (Do Not Violate)

Pull requests **must not** break the following invariants without explicit discussion:

- Deterministic encryption given identical inputs
- Wire compatibility within a major version
- Minting keys cannot produce verifier-acceptable ciphertext
- Verifier keys cannot mint ciphertext
- Failure is fail-closed (no partial plaintext on verification failure)

If a contribution challenges one of these, open an issue *before* writing code.

---

## Cryptographic Honesty Policy

RedX is published with explicit non-claims:
- No formal proof
- No standardization claim
- No post-quantum claim

Contributions must respect this posture. PRs that add misleading assurances, overclaims, or implied guarantees will be rejected.

---

## Coding Standards

- Target framework: **.NET 8**
- Use `Span<T>`, `ReadOnlySpan<T>`, and `MemoryMarshal` where appropriate
- Avoid unnecessary allocations
- Do not obscure algorithmic steps for stylistic reasons
- Keep code readable by a cryptographer, not just a compiler

Unsafe code is acceptable when it improves clarity or performance.

---

## Tests

- New behavior requires tests
- Bug fixes require regression tests
- Tests should demonstrate *behavioral intent*, not just coverage

---

## Pull Request Process

1. Open an issue first for non-trivial changes
2. Keep PRs narrowly scoped
3. Explain *why* the change exists, not just *what* it does
4. Expect technical scrutiny

---

## Security Reporting

If you believe you have found a **security-relevant issue**, please follow these guidelines:

- **Do not** open a public issue for vulnerabilities that could enable practical attacks
- Prefer a **private disclosure** via direct contact with the project author
- Include:
  - A clear description of the issue
  - A minimal reproducer or proof sketch, if available
  - The scope of impact (symmetric mode, mint/verify mode, integrity seal, etc.)

Public disclosure may be requested *after* the issue is understood and mitigated.

This project does not operate a bug bounty program. Responsible disclosure is appreciated.

---

## Licensing

By submitting a contribution, you agree that:
- Your contribution is licensed under the Apache 2.0 License
- You have the right to submit the contribution
- You grant the project the right to redistribute it

---

## Trademark Notice

Use of the name **RedX** is governed by `TRADEMARKS.md`.

Forks and derivatives must clearly distinguish themselves and must not present as "official RedX".

---

## Final Note

RedX is intentionally unconventional. If your instinct is to make it look like existing crypto, you may be solving the wrong problem.

Thoughtful disagreement is welcome. Superficial conformity is not.

