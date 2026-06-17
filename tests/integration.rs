//! End-to-end protocol tests for QSIG-3P.

use xsoc_sig_3p::{
    mock::{MockMac, MockSign},
    Holder, IcTag, PairKey, Qsig3pError, QsigSignBackend, Signature, SignedTransfer, Signer, TxSeq,
    Verifier,
};

fn pair_key(byte: u8) -> PairKey {
    PairKey::from_bytes([byte; 32])
}

fn fixture() -> (
    Signer<MockSign, MockMac>,
    Holder<MockSign>,
    Verifier<MockMac>,
) {
    let k12 = pair_key(0x12);
    let k13 = pair_key(0x13);
    let signer = Signer::new(k12.clone(), k13.clone(), TxSeq::FIRST, MockSign, MockMac);
    let holder = Holder::new(k12, MockSign);
    let verifier = Verifier::new(k13, 0, MockMac);
    (signer, holder, verifier)
}

#[test]
fn happy_path() {
    let (mut signer, holder, mut verifier) = fixture();

    let msg = b"transfer-001: USD 1,000,000 to account 9988";
    let transfer = signer.sign(msg).expect("sign");

    holder.accept(&transfer).expect("holder accepts");
    let recovered = verifier.accept(&transfer).expect("verifier accepts");

    assert_eq!(recovered, msg);
    assert_eq!(verifier.last_seen(), TxSeq(1));
    assert_eq!(signer.peek_next_seq(), Some(TxSeq(2)));
}

#[test]
fn three_signatures_in_order() {
    let (mut signer, holder, mut verifier) = fixture();

    for i in 1u32..=3 {
        let msg = format!("payload {}", i);
        let transfer = signer.sign(msg.as_bytes()).expect("sign");
        holder.accept(&transfer).expect("holder accepts");
        let recovered = verifier.accept(&transfer).expect("verifier accepts");
        assert_eq!(recovered, msg.as_bytes());
        assert_eq!(verifier.last_seen(), TxSeq(i));
    }
}

#[test]
fn replay_same_seq_rejected() {
    let (mut signer, holder, mut verifier) = fixture();

    let transfer = signer.sign(b"first").expect("sign");
    holder.accept(&transfer).expect("holder accepts");
    verifier.accept(&transfer).expect("first acceptance");

    let err = verifier
        .accept(&transfer)
        .expect_err("replay should be rejected");
    match err {
        Qsig3pError::SequenceReplay {
            received,
            last_seen,
        } => {
            assert_eq!(received, 1);
            assert_eq!(last_seen, 1);
        }
        other => panic!("expected SequenceReplay, got {:?}", other),
    }
    // last_seen MUST NOT regress on a replay attempt.
    assert_eq!(verifier.last_seen(), TxSeq(1));
}

#[test]
fn out_of_order_replay_rejected() {
    let (mut signer, holder, mut verifier) = fixture();

    let t1 = signer.sign(b"first").expect("sign");
    let t2 = signer.sign(b"second").expect("sign");

    holder.accept(&t1).expect("holder t1");
    holder.accept(&t2).expect("holder t2");

    // P3 sees t2 first, then a malicious replay of t1.
    verifier.accept(&t2).expect("t2 accepted");
    let err = verifier.accept(&t1).expect_err("t1 must now be rejected");
    assert!(matches!(err, Qsig3pError::SequenceReplay { .. }));
    assert_eq!(verifier.last_seen(), TxSeq(2));
}

#[test]
fn p2_modifies_message_rejected_by_p3() {
    let (mut signer, holder, mut verifier) = fixture();

    let mut transfer = signer.sign(b"original").expect("sign");
    holder.accept(&transfer).expect("holder accepts original");

    // Malicious P2 swaps the message before forwarding.
    transfer.message = b"swapped".to_vec();

    let err = verifier
        .accept(&transfer)
        .expect_err("verifier must reject");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
    // last_seen must not have advanced.
    assert_eq!(verifier.last_seen(), TxSeq(0));
}

#[test]
fn p2_modifies_signature_rejected_by_p3() {
    let (mut signer, holder, mut verifier) = fixture();

    let mut transfer = signer.sign(b"original").expect("sign");
    holder.accept(&transfer).expect("holder accepts original");

    // Malicious P2 mangles the signature.
    let mut sig_bytes = *transfer.signature.as_bytes();
    sig_bytes[0] ^= 0xFF;
    transfer.signature = Signature::from_bytes(sig_bytes);

    let err = verifier
        .accept(&transfer)
        .expect_err("verifier must reject");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
}

#[test]
fn p2_forges_with_unknown_k13_rejected() {
    let (mut signer, holder, mut verifier) = fixture();

    // P2 has K12 (and can produce QSIG signatures), but does not have K13.
    let _real = signer.sign(b"real").expect("sign");
    holder.accept(&_real).expect("holder real");

    // P2 forges a fresh transfer for a NEW message, using K12 to produce
    // a valid QSIG signature, but is forced to guess the IC tag.
    let p2_only_sign = MockSign;
    let forged_msg = b"forged transfer";
    let forged_sig = p2_only_sign.sign(&pair_key(0x12), forged_msg);
    let forged_tag = IcTag::from_bytes([0xAA; 32]); // P2 has to guess.
    let forged = SignedTransfer {
        message: forged_msg.to_vec(),
        signature: forged_sig,
        ic_tag: forged_tag,
        tx_seq: TxSeq(99),
    };

    let err = verifier
        .accept(&forged)
        .expect_err("forgery must be rejected");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
    assert_eq!(verifier.last_seen(), TxSeq(0));
}

#[test]
fn invalid_qsig_signature_caught_at_holder() {
    let (mut signer, holder, _verifier) = fixture();

    let mut transfer = signer.sign(b"hello").expect("sign");
    let mut sig_bytes = *transfer.signature.as_bytes();
    sig_bytes[5] ^= 0x01;
    transfer.signature = Signature::from_bytes(sig_bytes);

    let err = holder.accept(&transfer).expect_err("holder must reject");
    assert_eq!(err, Qsig3pError::InvalidSignature);
}

#[test]
fn wire_roundtrip_is_lossless() {
    let (mut signer, _holder, _verifier) = fixture();
    let transfer = signer.sign(b"wire test payload").expect("sign");

    let bytes = transfer.to_bytes();
    let parsed = SignedTransfer::from_bytes(&bytes).expect("parse");

    assert_eq!(parsed.message, transfer.message);
    assert_eq!(parsed.signature, transfer.signature);
    assert_eq!(parsed.tx_seq, transfer.tx_seq);
    assert_eq!(parsed.ic_tag.as_bytes(), transfer.ic_tag.as_bytes());
}

#[test]
fn wire_truncation_rejected() {
    let (mut signer, _h, _v) = fixture();
    let transfer = signer.sign(b"x").expect("sign");
    let bytes = transfer.to_bytes();

    let truncated = &bytes[..bytes.len() - 1];
    let err = SignedTransfer::from_bytes(truncated).expect_err("truncation rejected");
    assert!(matches!(err, Qsig3pError::MalformedPayload(_)));
}

#[test]
fn wrong_k13_at_verifier_rejected() {
    // Signer thinks K13 = 0x13, verifier was provisioned with 0x99.
    // Models a misconfiguration or a swap attack on the verifier's pair.
    let mut signer = Signer::new(
        pair_key(0x12),
        pair_key(0x13),
        TxSeq::FIRST,
        MockSign,
        MockMac,
    );
    let mut verifier = Verifier::new(pair_key(0x99), 0, MockMac);

    let transfer = signer.sign(b"misconfig").expect("sign");
    let err = verifier
        .accept(&transfer)
        .expect_err("verifier must reject");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
}

#[test]
fn signer_overflow_at_u32_max() {
    let mut signer = Signer::new(
        pair_key(0x12),
        pair_key(0x13),
        TxSeq(u32::MAX),
        MockSign,
        MockMac,
    );
    // First sign at u32::MAX should succeed (it's still a valid sequence).
    signer.sign(b"last seq").expect("u32::MAX is valid");
    // Next attempt overflows.
    let err = signer.sign(b"would overflow").expect_err("must overflow");
    assert_eq!(err, Qsig3pError::SequenceOverflow);
}

// SMT08 regression: from_bytes must reject a length prefix that overflows the
// buffer, closing the parser DoS fixed in 5926a05.
#[test]
fn from_bytes_rejects_overflow_length_prefix() {
    let buf_len = 16usize;
    let msg_len: u64 = (buf_len as u64).wrapping_sub(74);
    let mut payload = vec![0u8; buf_len];
    payload[0..8].copy_from_slice(&msg_len.to_be_bytes());
    let err = SignedTransfer::from_bytes(&payload).expect_err("overflow must reject");
    assert!(matches!(err, Qsig3pError::MalformedPayload(_)));
}
