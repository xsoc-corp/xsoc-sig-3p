# xsoc-sig-3p

Reference library for the XSOC-QSIG three-party transferable transaction signature protocol (QSIG-3P).

## What this repository is

This is the public, Apache-2.0 reference implementation of the QSIG-3P protocol. It contains the full protocol logic, the role state machines (`Signer`, `Holder`, `Verifier`), pair-scoped transaction sequencing (`PairSequencer`), and the transferability construction that binds an originator's authorization to a verifier who does not hold the originator's pairwise key.

The cryptographic backends in this repository are mock backends by design. `MockSign` and `MockMac` in `src/mock.rs` are HMAC-SHA256 placeholders, isolated to a single module and used only by the tests and benchmarks. They exist so that this repository can be public, cloned, built, and exercised by anyone without access to XSOC's proprietary cryptographic core.

The protocol logic in this repository is real. The cryptographic backends in this repository are not the production primitives. See the boundary below.

## Sequencing and verification scope

Two scopes govern this protocol, and they are deliberately different.

**Replay protection is scoped to the P1-P3 pair.** P3 holds the P1-P3 pairwise
root and one highest-accepted `tx_seq`, and accepts a transfer only when its
sequence strictly exceeds that value. A single P1 may serve several holders over
one P3, and every one of those transfers competes in that same replay namespace.

Allocation therefore belongs to `PairSequencer`, which is constructed once per
P1-P3 pair and shared across every holder channel on that pair. `Signer` carries
no counter and takes the sequencer at signing time, so the shared allocator is
explicit at each call site:

```rust
// One sequencer per P1-P3 pair, shared by every holder channel on it.
let mut pair_seq = PairSequencer::fresh();

let signer_a = Signer::new(k12_a, k13.clone(), sign_backend, mac_backend);
let signer_b = Signer::new(k12_b, k13, sign_backend, mac_backend);

let ta = signer_a.sign(&mut pair_seq, message_a)?;  // tx_seq 1
let tb = signer_b.sign(&mut pair_seq, message_b)?;  // tx_seq 2
```

The sequencer MUST be persisted per pair across process restarts. Use
`PairSequencer::resuming_at` to continue an epoch from stored state, and treat a
value that moves backward as a replay window reopening.

**Verification is scoped to the P1-P3 pair as well.** P3 holds no K12, so it
establishes that P1 authorized a transfer rather than which holder forwarded it.
Holder provenance is carried as application context and is not an authorization
boundary at P3. The property is pinned by a named test in
`tests/pair_sequence_scope.rs`.

## Conformance to XSOC-QSIG-3P v1.0

This crate implements the published specification, DOI 10.5281/zenodo.20078816,
with two deliberate departures. Each strengthens the published construction, and
each is raised as an erratum against the specification rather than carried
silently.

**Sequence allocation is scoped to the P1-P3 pair.** Sections 3.1 and 3.3 step 1
allocate from a counter keyed to the P1-P2 channel while section 3.5 enforces
against one keyed to the P1-P3 pair. Where a single P1 serves several holders
over one P3, those two scopes disagree and two holders receive the same
`tx_seq`. Allocation here belongs to `PairSequencer`, which is pair scoped, so
the allocation namespace and the enforcement namespace are the same object.

**The verifier authenticates before it checks the sequence.** Section 3.5 orders
the replay check first, which lets an unauthenticated sender tell a replay
rejection from a tag rejection and recover the verifier's high-water mark by
search. `Verifier::accept` checks the IC tag first, so every unauthenticated
transfer yields the same error whatever sequence number it carries.

Everything else follows the specification as published: the wire format of
section 3.2 and 6.4, the signature input `m || seq4` of 3.3 step 2 and 3.4 step
1, the IC tag input `DST_IC || m || sigma || seq4` of 3.3 step 3 and 3.5 step 2,
and the domain-separation constants of section 4.4.

## Trade-secret boundary

| Component | Status |
|---|---|
| QSIG-3P protocol logic, role state machines, sequencing, transferability construction | Public, Apache-2.0, in this repository |
| `QsigSignBackend` and `MacBackend` trait definitions | Public, Apache-2.0, in this repository |
| `MockSign` / `MockMac` (HMAC-SHA256 test backends) | Public, test-only, in this repository |
| DSKAG wave engine, key-derivation construction, and the production backends that implement the traits above | Proprietary trade secret. Not in this repository. Available under license from XSOC. |

The production cryptographic backends implement the same `QsigSignBackend` and `MacBackend` traits defined here, over the DSKAG-rooted construction. They are maintained in a separate, private repository and are subject to export control (ECCN 5D002.C1) and licensing. The mock backends in this repository produce structurally valid output for protocol testing but are not the production primitives and must not be used in production or cited for production performance or security characteristics.

## Production capability

The full production QSIG-3P capability, with the DSKAG-rooted signing and wave-engine MAC backends, is implemented, tested, and available under license from XSOC. Production deployment substitutes the licensed backends for the mock backends in this repository by implementing the same two traits, with no change to the protocol logic. Contact licensing@xsoccorp.com.

## Building and testing

Minimum supported Rust version is 1.75, declared as `rust-version` in
`Cargo.toml` and enforced by a dedicated CI job.

```
cargo build
cargo test
cargo bench
```

`cargo test` runs the integration suites and the doctests. Two of the doctests
are `compile_fail` guards asserting that `PairSequencer` implements neither
`Clone` nor `Default`, because either would reopen the duplication the type
exists to prevent. Running `cargo test --all-targets` skips doctests and
therefore skips those guards.

Tests and benchmarks run against the mock backends. Benchmark numbers from this repository reflect the HMAC-SHA256 mocks and must not be cited as production figures.

## Security claim

XSOC-QSIG is a post-quantum symmetric transaction signature primitive. The signing path contains no asymmetric primitive and therefore has no Shor exposure. The construction is computationally secure, with an EUF-CMA forgery bound of 2^-128 in standard mode and 2^-256 in extended mode. It is a designated-verifier construction: verification is performed by a party holding the pairwise key rather than a published public key. It is not a public-key digital signature and does not provide non-repudiation against arbitrary third parties.

The formal security analysis, including the security model, reductions, and assumptions, is in the DSKAG-IT-SIG specification: https://doi.org/10.5281/zenodo.19639166

## License

Apache-2.0. See LICENSE.

The Apache-2.0 license applies to the contents of this repository. It does not extend to the DSKAG construction or the production backends, which are proprietary to XSOC and licensed separately.
