# xsoc-sig-3p

QSIG-3P: zero-broadcast three-party transferable designated-verifier signature
mode for QSIG.

## What this is

Three-party extension of QSIG that achieves the same security goals as the
SILMARILS three-party broadcast mode (Khodaiemehr, Bagheri, Feng, Porechna,
arXiv 2605.03230, May 2026) without requiring an authenticated broadcast
channel. Two point-to-point messages, deterministic key derivation, built-in
replay protection, 2^-256 forgery bound from underlying MAC unforgeability.

## Roles and trust model

| Role | Knows | Acts |
|------|-------|------|
| P1 (signer)   | K12 (with P2), K13 (with P3) | sign |
| P2 (holder)   | K12 (with P1)                 | verify QSIG, forward |
| P3 (verifier) | K13 (with P1)                 | verify IC tag, accept |

Pairwise keys are DSKAG roots derived from network bootstrap; they never
appear on the wire.

## Wire format

```
[ message length (8 bytes BE)
| message bytes
| QSIG signature (30 bytes)
| wave-MAC IC tag (32 bytes)
| tx_seq (4 bytes BE) ]
```

For a 64-byte payload: 8 + 64 + 30 + 32 + 4 = 138 bytes total wire size.

## Properties

- **Zero broadcast**: two point-to-point messages, P1 to P2 and P2 to P3.
- **Replay protection**: tx_seq strict monotonicity per (signer, verifier) pair.
- **Forgery bound**: 2^-256 from underlying MAC unforgeability.
- **Per-pair capacity**: u32 tx_seq supports approximately 4.3 x 10^9 signatures
  per epoch with no cryptographic degradation; epoch rotation MUST occur before
  exhaustion.
- **Secrecy**: P3's view in signing phase is empty, so secrecy is trivially
  perfect rather than statistical.

## Comparison to SILMARILS three-party

| Property | SILMARILS 3-party | QSIG-3P |
|----------|-------------------|---------|
| Channel model | Authenticated broadcast | Point-to-point only |
| Rounds | 4 broadcast + several P2P | 2 P2P |
| Key derivation | Fresh (k1, k2, x', k2') per message | Deterministic from pair root + tx_seq |
| Replay protection | None inherent | Built in via tx_seq monotonicity |
| Forgery bound | 1/p (~2^-256) | 2^-256 |
| Setup | Per-pair shared randomness | Pairwise DSKAG roots |

## Layout

```
src/
  lib.rs          Public API, traits (QsigSignBackend, MacBackend)
  protocol.rs     PairKey, Signature, IcTag, TxSeq, SignedTransfer wire format
  signer.rs       P1 implementation
  holder.rs       P2 implementation
  verifier.rs     P3 implementation
  error.rs        Qsig3pError enum
  mock.rs         HMAC-SHA256 mock backends for testing
tests/
  integration.rs  12 end-to-end tests (happy path, replay, forgery, wire format)
benches/
  qsig_3p_bench.rs Criterion sign / verify / roundtrip benches
```

## Integration into xsoc-sig

Two backend traits to implement against the production primitives:

```rust
impl QsigSignBackend for ProductionQsig {
    fn sign(&self, key: &PairKey, message: &[u8]) -> Signature {
        // Real 30-byte QSIG sign using DSKAG-rooted key.
    }
    fn verify(&self, key: &PairKey, message: &[u8], sig: &Signature) -> bool {
        // Real 30-byte QSIG verify, constant-time.
    }
}

impl MacBackend for WaveMac {
    fn mac(&self, key: &PairKey, data: &[u8]) -> IcTag {
        // Wave-engine 5-round HMAC iteration over key, then HMAC-SHA256.
    }
    fn verify(&self, key: &PairKey, data: &[u8], tag: &IcTag) -> bool {
        // Constant-time verify.
    }
}
```

Then wire them into Signer / Holder / Verifier as in `tests/integration.rs`.

## Building and testing

```bash
cargo build --release
cargo test
cargo bench
```

Note: bench numbers from `mock` backends are meaningless. Replace with
production backends to obtain authoritative figures and add to the
`xsoc-sig-core` criterion harness.

## Deployment checklist

- [ ] Implement `QsigSignBackend` against production QSIG.
- [ ] Implement `MacBackend` against wave-engine MAC.
- [ ] Add `xsoc-sig-3p` as workspace member in `xsoc-sig` Cargo.toml.
- [ ] Wire `tx_seq_next` and `last_seen_seq` to persistent storage
      (Cosmos / Postgres / file). Both MUST survive restart.
- [ ] Add integration tests to `xsoc-sig` CI alongside existing QSIG tests.
- [ ] Add criterion benches to `xsoc-sig-core/benches/qsig_3p_bench.rs`.
- [ ] Update `xsoc-corp/xsoc-qsig-release` SECURITY.md to extend the bug bounty
      scope to QSIG-3P (recommend mirroring the existing 0.05 BTC pool).
- [ ] Update Zenodo companion paper with criterion numbers for QSIG-3P.

## Status

Reference implementation, mock backends. Not yet integrated against production
DSKAG or wave-engine. All 12 protocol tests pass.

## License

Proprietary, XSOC CORP. Compiled-binary OEM model. Source not for redistribution.
