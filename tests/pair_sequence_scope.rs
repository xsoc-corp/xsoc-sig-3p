//! Regression tests for the cross-holder tx_seq namespace finding
//! (reported 2026-10-04).
//!
//! The reported defect: `Signer` owned a `tx_seq` counter while being
//! instantiated per holder channel, but P3 enforces replay over the P1-P3
//! pair. Two holders on one pair each started at `TxSeq::FIRST`, both were
//! issued tx_seq 1, and P3 accepted whichever arrived first and rejected the
//! other as `SequenceReplay` despite it being validly authorized by P1.
//!
//! The fix moves allocation into `PairSequencer`, which is scoped to the pair
//! and shared across holder channels, so the allocation namespace and the
//! enforcement namespace are the same object.

use xsoc_sig_3p::{
    mock::{MockMac, MockSign},
    Holder, IcTag, PairKey, PairSequencer, Qsig3pError, SignedTransfer, Signer, TxSeq, Verifier,
};

fn key(byte: u8) -> PairKey {
    PairKey::from_bytes([byte; 32])
}

/// The reported scenario, now fixed.
///
/// One P1 serves two holders over one P3. Both transfers must be accepted.
#[test]
fn two_holders_on_one_pair_do_not_collide() {
    let k12_a = key(0xA1);
    let k12_b = key(0xB2);
    let k13 = key(0x13);

    // One sequencer for the P1-P3 pair, shared by both holder channels.
    let mut pair_seq = PairSequencer::fresh();

    let signer_a = Signer::new(k12_a.clone(), k13.clone(), MockSign, MockMac);
    let signer_b = Signer::new(k12_b.clone(), k13.clone(), MockSign, MockMac);
    let holder_a = Holder::new(k12_a, MockSign);
    let holder_b = Holder::new(k12_b, MockSign);

    let ta = signer_a
        .sign(&mut pair_seq, b"authorized via holder A")
        .expect("sign A");
    let tb = signer_b
        .sign(&mut pair_seq, b"authorized via holder B")
        .expect("sign B");

    // Distinct sequence numbers, because both drew from the pair's allocator.
    assert_eq!(ta.tx_seq, TxSeq(1));
    assert_eq!(tb.tx_seq, TxSeq(2));
    assert_ne!(ta.tx_seq, tb.tx_seq);

    holder_a
        .accept(&ta)
        .expect("holder A accepts its own transfer");
    holder_b
        .accept(&tb)
        .expect("holder B accepts its own transfer");

    // P3 accepts both. Neither holder can consume the other's sequence.
    let mut verifier = Verifier::new(k13, 0, MockMac);
    let recovered_a = verifier.accept(&ta).expect("P3 accepts A");
    let recovered_b = verifier.accept(&tb).expect("P3 accepts B");

    assert_eq!(recovered_a, b"authorized via holder A");
    assert_eq!(recovered_b, b"authorized via holder B");
    assert_eq!(verifier.last_seen(), TxSeq(2));
}

/// Order of arrival does not matter beyond ordinary monotonicity: whichever
/// holder P1 served first holds the lower sequence, and P3 accepts them in
/// issue order.
#[test]
fn many_holders_on_one_pair_receive_distinct_sequences() {
    let k13 = key(0x13);
    let mut pair_seq = PairSequencer::fresh();

    let mut issued = Vec::new();
    for holder_byte in 0u8..8 {
        let signer = Signer::new(key(0xC0 + holder_byte), k13.clone(), MockSign, MockMac);
        let t = signer
            .sign(&mut pair_seq, b"same message from every holder")
            .expect("sign");
        issued.push(t.tx_seq.0);
    }

    let mut sorted = issued.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        issued.len(),
        "a shared pair sequencer must never issue a duplicate across holder channels"
    );
    assert_eq!(issued, (1u32..=8).collect::<Vec<_>>());
}

/// A sequencer resumed from persisted state continues the pair's epoch rather
/// than restarting it. Restarting at FIRST on a live pair is the failure this
/// finding was about.
#[test]
fn resumed_sequencer_does_not_restart_the_epoch() {
    let k13 = key(0x13);
    let signer = Signer::new(key(0xA1), k13.clone(), MockSign, MockMac);

    let mut before = PairSequencer::fresh();
    let t1 = signer.sign(&mut before, b"one").expect("sign");
    let t2 = signer.sign(&mut before, b"two").expect("sign");
    let persisted = before.peek_next();
    assert_eq!(persisted, Some(TxSeq(3)));

    // Process restart: reload from persisted state.
    let mut after = PairSequencer::resuming_at(persisted.expect("not exhausted"));
    let t3 = signer.sign(&mut after, b"three").expect("sign");

    let mut verifier = Verifier::new(k13, 0, MockMac);
    verifier.accept(&t1).expect("t1");
    verifier.accept(&t2).expect("t2");
    verifier.accept(&t3).expect("t3 after restart");
    assert_eq!(verifier.last_seen(), TxSeq(3));
}

/// Stated property, pinned deliberately rather than left ambiguous.
///
/// P3's verification is scoped to the P1-P3 pair. P3 does not hold K12 and
/// therefore establishes that P1 authorized the transfer, not which holder
/// forwarded it. A transfer issued for one holder channel verifies at P3 under
/// the shared pairwise root.
///
/// This is the designated-verifier model the library documents. If holder
/// provenance is ever required to be an authorization boundary at P3, the IC
/// tag transcript must bind an explicit channel identifier and this test must
/// be replaced, not merely deleted.
#[test]
fn verification_is_pair_scoped_and_holder_identity_is_not_bound() {
    let k13 = key(0x13);
    let mut pair_seq = PairSequencer::fresh();

    let signer_a = Signer::new(key(0xA1), k13.clone(), MockSign, MockMac);
    let ta = signer_a
        .sign(&mut pair_seq, b"authorized via holder A")
        .expect("sign A");

    // A verifier for the same P1-P3 pair accepts it, independent of which
    // holder channel it was issued for.
    let mut verifier = Verifier::new(k13, 0, MockMac);
    let recovered = verifier.accept(&ta).expect("pair-scoped acceptance");
    assert_eq!(recovered, b"authorized via holder A");
}

/// A different P1-P3 pairwise root rejects, and does not advance replay state.
#[test]
fn a_different_pair_root_rejects_without_advancing_state() {
    let mut pair_seq = PairSequencer::fresh();
    let signer = Signer::new(key(0xA1), key(0x13), MockSign, MockMac);
    let t = signer.sign(&mut pair_seq, b"for pair 0x13").expect("sign");

    let mut other_pair = Verifier::new(key(0x23), 0, MockMac);
    let err = other_pair
        .accept(&t)
        .expect_err("a different pairwise root must reject");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
    assert_eq!(other_pair.last_seen(), TxSeq(0));
}

/// The verifier authenticates before it acts on any field of the transfer, so
/// an unauthenticated sender cannot use the returned error to learn
/// `last_seen_seq`. A forged transfer reports `InvalidIcTag` whether its
/// sequence is below, at, or above the verifier's counter.
#[test]
fn a_forged_transfer_reveals_nothing_about_the_counter() {
    let k13 = key(0x13);
    let mut pair_seq = PairSequencer::fresh();
    let signer = Signer::new(key(0xA1), k13.clone(), MockSign, MockMac);
    let mut verifier = Verifier::new(k13, 0, MockMac);

    // Advance the counter to 3 with genuine transfers.
    for msg in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
        let t = signer.sign(&mut pair_seq, msg).expect("sign");
        verifier.accept(&t).expect("accept");
    }
    assert_eq!(verifier.last_seen(), TxSeq(3));

    // Probe below, at, and above the counter with an unauthenticated tag.
    for probe in [1u32, 3, 4, 9_999] {
        let forged = SignedTransfer {
            message: b"probe".to_vec(),
            signature: signer
                .sign(&mut PairSequencer::fresh(), b"probe")
                .expect("sig material")
                .signature,
            ic_tag: IcTag::from_bytes([0xAA; 32]),
            tx_seq: TxSeq(probe),
        };
        assert_eq!(
            verifier.accept(&forged).expect_err("forged must reject"),
            Qsig3pError::InvalidIcTag,
            "probe at {} must be indistinguishable from any other forged probe",
            probe
        );
    }

    // State untouched throughout.
    assert_eq!(verifier.last_seen(), TxSeq(3));
}
