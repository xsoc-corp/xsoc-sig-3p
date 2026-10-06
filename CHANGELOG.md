# Changelog

All notable changes to `xsoc-sig-3p` are recorded here. The format follows
Keep a Changelog, and this project uses semantic versioning.

## [0.4.0] - 2026-10-06

Conformance release. Breaking on the wire and in the transcript: payloads and
tags produced by 0.3.0 and earlier do not verify under 0.4.0, and the reverse.
Every peer on a pair must move together.

### Security

- The signature now covers `m || seq4`, per specification 3.3 step 2 and 3.4
  step 1. It previously covered the message alone, so `tx_seq` sat outside what
  P1 authorized. A sequence number altered in transit left the signature valid
  and P2 accepted a transfer whose sequence nobody had authenticated. P3 still
  rejected it on the IC tag, which bounded the impact, but P2's acceptance
  carried less than it appeared to.
- The IC tag input is now prefixed with `DST_IC`, per 3.3 step 3 and 3.5 step 2.
  Without domain separation a tag solicited under another context keyed to the
  same root could be presented here.
- `Signature` equality is constant time. It derived `PartialEq`, which compares
  a 30-byte authenticator byte by byte with early exit. Nothing in the protocol
  path used it, and `IcTag` already had a written implementation; this closes
  the same hole on the type beside it.
- `PairKey` zeroizes on drop. It held a 32-byte pairwise root in a plain array
  with no `Drop`, and derives `Clone`, so copies accumulated and none were
  wiped.
- `SignedTransfer::to_bytes` returns `Result` and refuses a message above
  `MAX_MESSAGE_LEN` rather than truncating the length prefix. The struct has
  public fields, so an oversized message reaches the encoder without passing
  through `Signer::sign`.

### Changed

- Wire length prefix is 4 bytes, big endian, per 3.2 and 6.4. Fixed overhead is
  70 bytes: 4 + 30 + 32 + 4. It was 8 bytes and 74. A payload carrying the old
  8-byte prefix is rejected rather than misread, which is covered by a test.
- Signer and verifier build each transcript through one function,
  `protocol::signing_input` and `protocol::ic_tag_input`. The signer previously
  built the IC tag input inline while `protocol.rs` held a second copy. Two
  constructions of one transcript that happen to agree is how they come to
  disagree.
- `DST_IC` and `DST_SIG` are exported as crate constants with the values fixed
  in specification 4.4. `DST_SIG` is applied by the signature backend, matching
  the production construction in 5.2; the protocol layer passes `m || seq4`.
- The two `PairSequencer` guards pin the expected error as
  `compile_fail,E0277`. An unpinned `compile_fail` passes when the snippet fails
  for any reason, including a typo, which is a guard that can go green while
  testing nothing.

### Added

- `LICENSE`, the Apache-2.0 text. The README, the published specification and
  reference [3] of that specification all state this repository is Apache-2.0;
  the manifest said `Proprietary` and no license file existed.
- `NOTICE`, scoping the grant to the contents of this repository and naming what
  sits outside it: DSKAG, SP-VERSA, the wave engine, `xsoc-sig-core`, and the
  `xsoc-sig-3p-production` adapter, with its ECCN 5D002.C1 classification.
- Tests for each conformance point: the 70-byte overhead and 4-byte prefix,
  rejection of the legacy 8-byte prefix, distinct signatures across sequence
  numbers with holder-side rejection of an altered `tx_seq`, and the presence
  and exact value of the domain-separation constants.

### Fixed

- `Cargo.toml` declares `license = "Apache-2.0"`.

### Known departures from XSOC-QSIG-3P v1.0

Two, both deliberate, both raised as errata against the specification. They are
stated in the crate documentation and the README rather than carried silently.

1. Sequence allocation is scoped to the P1-P3 pair. Sections 3.1 and 3.3 step 1
   allocate from a counter keyed to P1-P2 while 3.5 enforces against one keyed
   to P1-P3. Where one P1 serves several holders over one P3 those scopes
   disagree and two holders receive the same `tx_seq`.
2. The verifier authenticates before it checks the sequence. Section 3.5 orders
   the replay check first, which leaks the high-water mark through error
   selection to an unauthenticated sender.

### Migration from 0.3.x

`to_bytes` now returns `Result`. Signatures and IC tags change value, so a pair
cannot run mixed versions: upgrade signer, holder and verifier together, and
drain any transfer in flight before cutting over. Backends implementing
`QsigSignBackend` apply `DST_SIG` themselves; the protocol layer does not.

## [0.3.0] - 2026-10-06

Security release. Source breaking for library consumers. No wire format change,
no MAC transcript change, and no change to the cryptographic construction.

### Security

- `PairSequencer` no longer derives `Clone`, and no longer implements
  `Default`. 0.2.0 moved `tx_seq` allocation into `PairSequencer` so that one
  P1-P3 pair could not hold two counters, but the type itself could still be
  duplicated. `clone()` produced a second allocator carrying the same epoch,
  and `default()` produced a fresh one through a path that is reachable
  implicitly from container derives, struct-update syntax and generic bounds.
  Either route handed one pair two allocators that both issued `tx_seq = 1`,
  which is the condition 0.2.0 was released to remove: P3 accepts whichever
  transfer arrives first and rejects the other as `SequenceReplay`, refusing a
  transfer P1 validly authorized.

  The 0.2.0 regression suite did not catch this, because all six tests pass one
  shared allocator by `&mut`, which is the usage that works.

  Reported externally on 2026-10-06 with a reproducing probe, and triaged as
  Moderate.

### Added

- Two `compile_fail` doctests on `PairSequencer` asserting that it satisfies
  neither a `Clone` nor a `Default` bound. They run under `cargo test` and add
  no dependency. 0.2.0 asserted this property in prose; it is now tested.

### Changed

- `benches/qsig_3p_bench.rs` constructed a new `PairSequencer` on every call at
  three sites, two of them inside measured loops, and one line of
  `tests/pair_sequence_scope.rs` did the same. All now hold one allocator per
  pair, which is the documented usage and what an integrator reading the
  benches will copy.
- The sequencer module documentation now states the one duplication path the
  type cannot close: calling `PairSequencer::fresh` a second time for a pair
  that has already issued. Construct the allocator where the pair's persistent
  state is loaded, and pass `&mut` from there.

### Migration from 0.2.x

Replace any `sequencer.clone()` with a `&mut` borrow of the one allocator the
pair owns, and replace `PairSequencer::default()` with `PairSequencer::fresh()`
for a pair that has issued nothing, or `PairSequencer::resuming_at(next)` for
one continuing a persisted epoch.

```rust
// 0.2.x
let mut a = PairSequencer::default();
let mut b = a.clone();                       // two allocators, one pair

// 0.3.0
let mut pair_seq = PairSequencer::fresh();   // once per P1-P3 pair
let t1 = signer_one.sign(&mut pair_seq, m1)?;
let t2 = signer_two.sign(&mut pair_seq, m2)?;
```

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
