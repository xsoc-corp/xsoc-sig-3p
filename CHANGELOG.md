# Changelog

All notable changes to `xsoc-sig-3p` are recorded here. The format follows
Keep a Changelog, and this project uses semantic versioning.

## [0.2.0] - 2026-10-04

Security release. Source breaking for library consumers. No wire format change,
no MAC transcript change, and no change to the cryptographic construction.

### Security

- `tx_seq` allocation is now scoped to the P1-P3 pair rather than to a holder
  channel. Replay protection is enforced by P3 over the P1-P3 pairwise channel,
  and the counter that allocated it previously lived inside `Signer`, which is
  constructed per holder channel. Two holder channels on one pair each held a
  private counter, each started at `TxSeq::FIRST`, and each issued `tx_seq=1`.
  P3 accepted whichever arrived first and rejected the other as
  `SequenceReplay`, refusing a transfer P1 had validly authorized.

  Allocation now belongs to the new `PairSequencer`, which is constructed once
  per pair and shared across every holder channel on it. The previously
  vulnerable construction no longer compiles.

  Reported by tokenistq (https://github.com/tokenistq) on 2026-10-04 with a
  reproducing proof of concept, and triaged as Moderate.

- `Verifier::accept` now verifies the IC tag before comparing `tx_seq`, which is
  the order its documentation already specified. The previous order let an
  unauthenticated sender distinguish `SequenceReplay` from `InvalidIcTag` and so
  learn `last_seen_seq`.

### Added

- `PairSequencer`, the pair-scoped monotonic `tx_seq` allocator, with
  `fresh`, `resuming_at`, `exhausted`, `allocate` and `peek_next`.
- Six regression tests in `tests/pair_sequence_scope.rs` covering cross-holder
  distinctness, an eight-channel allocation check, sequencer persistence across
  restart, the stated pair-scoped verification property, rejection under a
  different pairwise root, and confirmation that a forged transfer returns the
  same error below, at, and above the counter.
- `rust-version = "1.75"` declared in `Cargo.toml`, matching the MSRV the CI
  job already enforced.

### Changed

- `Signer::new` no longer takes a `tx_seq_start`. It takes
  `(k_p2, k_p3, sign_backend, mac_backend)`.
- `Signer::sign` takes `&mut PairSequencer` as its first argument and now
  borrows the signer immutably.
- `Signer::peek_next_seq` is replaced by `PairSequencer::peek_next`.
- Scoping language is now consistent across the crate. `Signer`, `Holder` and
  `Verifier` each state the pairwise channel they are scoped to, and the
  designated-verifier scope is stated explicitly: P3 holds no K12 and so
  establishes that P1 authorized a transfer rather than which holder forwarded
  it.

### Migration from 0.1.x

Construct one `PairSequencer` per P1-P3 pair, share it across every holder
channel on that pair, and pass it to each `sign` call. Persist it per pair.

```rust
// 0.1.x
let mut signer = Signer::new(k12, k13, TxSeq::FIRST, sign_backend, mac_backend);
let transfer = signer.sign(message)?;

// 0.2.0
let mut pair_seq = PairSequencer::fresh();            // once per P1-P3 pair
let signer = Signer::new(k12, k13, sign_backend, mac_backend);
let transfer = signer.sign(&mut pair_seq, message)?;
```

Where 0.1.x state was persisted, load it with `PairSequencer::resuming_at(next)`
rather than starting a second counter at `TxSeq::FIRST`. Deployments that
already allocated `tx_seq` from a single per-pair allocator outside this crate
were not exposed to the defect above, and the migration formalizes what they
were already doing.

## [0.1.0]

Initial reference implementation of the QSIG-3P protocol: role state machines,
wire format, `tx_seq` replay protection, and the `QsigSignBackend` and
`MacBackend` trait abstractions with HMAC-SHA256 mock backends for testing.
