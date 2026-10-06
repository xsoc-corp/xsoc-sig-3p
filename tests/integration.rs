//! End-to-end protocol tests for QSIG-3P.

use xsoc_sig_3p::{
    mock::{MockMac, MockSign},
    Holder, IcTag, PairKey, PairSequencer, Qsig3pError, QsigSignBackend, Signature, SignedTransfer,
    Signer, TxSeq, Verifier,
};

fn pair_key(byte: u8) -> PairKey {
    PairKey::from_bytes([byte; 32])
}

fn fixture() -> (
    Signer<MockSign, MockMac>,
    PairSequencer,
    Holder<MockSign>,
    Verifier<MockMac>,
) {
    let k12 = pair_key(0x12);
    let k13 = pair_key(0x13);
    let signer = Signer::new(k12.clone(), k13.clone(), MockSign, MockMac);
    let seq = PairSequencer::fresh();
    let holder = Holder::new(k12, MockSign);
    let verifier = Verifier::new(k13, 0, MockMac);
    (signer, seq, holder, verifier)
}

#[test]
fn happy_path() {
    let (signer, mut seq, holder, mut verifier) = fixture();

    let msg = b"transfer-001: USD 1,000,000 to account 9988";
    let transfer = signer.sign(&mut seq, msg).expect("sign");

    holder.accept(&transfer).expect("holder accepts");
    let recovered = verifier.accept(&transfer).expect("verifier accepts");

    assert_eq!(recovered, msg);
    assert_eq!(verifier.last_seen(), TxSeq(1));
    assert_eq!(seq.peek_next(), Some(TxSeq(2)));
}

#[test]
fn three_signatures_in_order() {
    let (signer, mut seq, holder, mut verifier) = fixture();

    for i in 1u32..=3 {
        let msg = format!("payload {}", i);
        let transfer = signer.sign(&mut seq, msg.as_bytes()).expect("sign");
        holder.accept(&transfer).expect("holder accepts");
        let recovered = verifier.accept(&transfer).expect("verifier accepts");
        assert_eq!(recovered, msg.as_bytes());
        assert_eq!(verifier.last_seen(), TxSeq(i));
    }
}

#[test]
fn replay_same_seq_rejected() {
    let (signer, mut seq, holder, mut verifier) = fixture();

    let transfer = signer.sign(&mut seq, b"first").expect("sign");
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
    let (signer, mut seq, holder, mut verifier) = fixture();

    let t1 = signer.sign(&mut seq, b"first").expect("sign");
    let t2 = signer.sign(&mut seq, b"second").expect("sign");

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
    let (signer, mut seq, holder, mut verifier) = fixture();

    let mut transfer = signer.sign(&mut seq, b"original").expect("sign");
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
    let (signer, mut seq, holder, mut verifier) = fixture();

    let mut transfer = signer.sign(&mut seq, b"original").expect("sign");
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
    let (signer, mut seq, holder, mut verifier) = fixture();

    // P2 has K12 (and can produce QSIG signatures), but does not have K13.
    let _real = signer.sign(&mut seq, b"real").expect("sign");
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
    let (signer, mut seq, holder, _verifier) = fixture();

    let mut transfer = signer.sign(&mut seq, b"hello").expect("sign");
    let mut sig_bytes = *transfer.signature.as_bytes();
    sig_bytes[5] ^= 0x01;
    transfer.signature = Signature::from_bytes(sig_bytes);

    let err = holder.accept(&transfer).expect_err("holder must reject");
    assert_eq!(err, Qsig3pError::InvalidSignature);
}

#[test]
fn wire_roundtrip_is_lossless() {
    let (signer, mut seq, _holder, _verifier) = fixture();
    let transfer = signer.sign(&mut seq, b"wire test payload").expect("sign");

    let bytes = transfer.to_bytes().expect("encode");
    let parsed = SignedTransfer::from_bytes(&bytes).expect("parse");

    // Section 3.2 and 6.4: fixed overhead is 70 bytes (4 + 30 + 32 + 4).
    assert_eq!(bytes.len() - transfer.message.len(), 70);
    assert_eq!(
        u32::from_be_bytes(bytes[..4].try_into().expect("prefix")),
        transfer.message.len() as u32
    );

    assert_eq!(parsed.message, transfer.message);
    assert_eq!(parsed.signature, transfer.signature);
    assert_eq!(parsed.tx_seq, transfer.tx_seq);
    assert_eq!(parsed.ic_tag.as_bytes(), transfer.ic_tag.as_bytes());
}

#[test]
fn wire_truncation_rejected() {
    let (signer, mut seq, _h, _v) = fixture();
    let transfer = signer.sign(&mut seq, b"x").expect("sign");
    let bytes = transfer.to_bytes().expect("encode");

    let truncated = &bytes[..bytes.len() - 1];
    let err = SignedTransfer::from_bytes(truncated).expect_err("truncation rejected");
    assert!(matches!(err, Qsig3pError::MalformedPayload(_)));
}

#[test]
fn wrong_k13_at_verifier_rejected() {
    // Signer thinks K13 = 0x13, verifier was provisioned with 0x99.
    // Models a misconfiguration or a swap attack on the verifier's pair.
    let signer = Signer::new(pair_key(0x12), pair_key(0x13), MockSign, MockMac);
    let mut seq = PairSequencer::fresh();
    let mut verifier = Verifier::new(pair_key(0x99), 0, MockMac);

    let transfer = signer.sign(&mut seq, b"misconfig").expect("sign");
    let err = verifier
        .accept(&transfer)
        .expect_err("verifier must reject");
    assert_eq!(err, Qsig3pError::InvalidIcTag);
}

#[test]
fn signer_overflow_at_u32_max() {
    let signer = Signer::new(pair_key(0x12), pair_key(0x13), MockSign, MockMac);
    let mut seq = PairSequencer::resuming_at(TxSeq(u32::MAX));
    // First sign at u32::MAX should succeed (it's still a valid sequence).
    signer
        .sign(&mut seq, b"last seq")
        .expect("u32::MAX is valid");
    // Next attempt overflows.
    let err = signer
        .sign(&mut seq, b"would overflow")
        .expect_err("must overflow");
    assert_eq!(err, Qsig3pError::SequenceOverflow);
}

// SMT08 regression: from_bytes must reject a length prefix that overflows the
// buffer, closing the parser DoS fixed in 5926a05.
#[test]
fn from_bytes_rejects_overflow_length_prefix() {
    let buf_len = 16usize;
    let msg_len: u32 = (buf_len as u32).wrapping_sub(70);
    let mut payload = vec![0u8; buf_len];
    payload[0..4].copy_from_slice(&msg_len.to_be_bytes());
    let err = SignedTransfer::from_bytes(&payload).expect_err("overflow must reject");
    assert!(matches!(err, Qsig3pError::MalformedPayload(_)));
}

// Section 3.2 fixes the length prefix at 4 bytes. A payload carrying the
// pre-0.4.0 8-byte prefix must not parse, so a stale sender is rejected rather
// than silently misread.
#[test]
fn legacy_eight_byte_prefix_is_rejected() {
    let (signer, mut seq, _h, _v) = fixture();
    let transfer = signer.sign(&mut seq, b"legacy").expect("sign");
    let good = transfer.to_bytes().expect("encode");

    let mut legacy = Vec::with_capacity(good.len() + 4);
    legacy.extend_from_slice(&(transfer.message.len() as u64).to_be_bytes());
    legacy.extend_from_slice(&good[4..]);

    let err = SignedTransfer::from_bytes(&legacy).expect_err("8-byte prefix must reject");
    assert!(matches!(err, Qsig3pError::MalformedPayload(_)));
}

// Section 3.3 step 2 places seq4 inside the signed input, so two transfers of
// the same message at different sequence numbers carry different signatures,
// and a tx_seq altered in transit fails at the holder.
#[test]
fn signature_binds_tx_seq() {
    let (signer, mut seq, holder, _v) = fixture();

    let t1 = signer.sign(&mut seq, b"same-message").expect("sign");
    let t2 = signer.sign(&mut seq, b"same-message").expect("sign");
    assert_ne!(t1.tx_seq, t2.tx_seq);
    assert_ne!(
        t1.signature, t2.signature,
        "equal signatures would mean seq4 is outside the signed input"
    );

    let tampered = SignedTransfer {
        message: t1.message.clone(),
        signature: t1.signature.clone(),
        ic_tag: t1.ic_tag.clone(),
        tx_seq: TxSeq(0xFFFF_FFFE),
    };
    assert_eq!(
        holder.accept(&tampered).expect_err("holder must reject"),
        Qsig3pError::InvalidSignature
    );
}

// Section 3.3 step 3 prefixes the IC tag input with DST_IC, so a tag solicited
// under another domain cannot be replayed into this one.
#[test]
fn ic_tag_input_carries_the_domain_separator() {
    let (signer, mut seq, _h, _v) = fixture();
    let transfer = signer.sign(&mut seq, b"dst probe").expect("sign");

    let input = transfer.mac_input();
    assert!(input.starts_with(xsoc_sig_3p::DST_IC));
    assert_eq!(
        input.len(),
        xsoc_sig_3p::DST_IC.len() + transfer.message.len() + 30 + 4
    );
    assert_eq!(xsoc_sig_3p::DST_IC, b"XSOC-QSIG-3P-IC-v1:");
    assert_eq!(xsoc_sig_3p::DST_SIG, b"XSOC-QSIG-3P-SIG-v1:");
}
