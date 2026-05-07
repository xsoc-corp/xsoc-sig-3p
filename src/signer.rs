//! Signer (P1) state and operations.

use crate::{
    protocol::{IcTag, PairKey, Signature, SignedTransfer, TxSeq},
    MacBackend, Qsig3pError, QsigSignBackend,
};

/// State for P1 over a single (P1, P2, P3) triple.
///
/// `tx_seq_next` is the next sequence number to issue, or `None` once the
/// epoch has been exhausted (after issuing at u32::MAX). It MUST be persisted
/// across process restarts; reusing a tx_seq under the same pairwise root is a
/// security failure (replay vector for P2).
pub struct Signer<S: QsigSignBackend, M: MacBackend> {
    /// Pairwise root with P2.
    k_p2: PairKey,
    /// Pairwise root with P3.
    k_p3: PairKey,
    /// Next tx_seq to issue, or None if exhausted.
    tx_seq_next: Option<TxSeq>,
    /// QSIG sign backend.
    sign_backend: S,
    /// Wave-MAC backend.
    mac_backend: M,
}

impl<S: QsigSignBackend, M: MacBackend> Signer<S, M> {
    /// Construct a fresh signer state.
    ///
    /// `tx_seq_start` should be loaded from persistent state if continuing
    /// an existing epoch. Use `TxSeq::FIRST` for a fresh pair.
    pub fn new(
        k_p2: PairKey,
        k_p3: PairKey,
        tx_seq_start: TxSeq,
        sign_backend: S,
        mac_backend: M,
    ) -> Self {
        Self {
            k_p2,
            k_p3,
            tx_seq_next: Some(tx_seq_start),
            sign_backend,
            mac_backend,
        }
    }

    /// Sign a message and produce the transfer payload P2 will hold.
    ///
    /// Internally:
    /// 1. Allocate the next tx_seq (or fail with [`Qsig3pError::SequenceOverflow`]
    ///    if the epoch is exhausted).
    /// 2. Produce a 30-byte QSIG signature under K12.
    /// 3. Compute the wave-MAC IC tag over (message, signature, tx_seq) under K13.
    /// 4. Advance the counter; mark exhausted if we just issued at u32::MAX.
    pub fn sign(&mut self, message: &[u8]) -> Result<SignedTransfer, Qsig3pError> {
        let tx_seq = self.tx_seq_next.ok_or(Qsig3pError::SequenceOverflow)?;

        let signature: Signature = self.sign_backend.sign(&self.k_p2, message);

        // IC tag binds (message, signature, tx_seq) to K13.
        let mut mac_input = Vec::with_capacity(message.len() + 30 + 4);
        mac_input.extend_from_slice(message);
        mac_input.extend_from_slice(signature.as_bytes());
        mac_input.extend_from_slice(&tx_seq.0.to_be_bytes());
        let ic_tag: IcTag = self.mac_backend.mac(&self.k_p3, &mac_input);

        // Advance; if we just issued at u32::MAX, leave tx_seq_next = None.
        self.tx_seq_next = tx_seq.increment().ok();

        Ok(SignedTransfer {
            message: message.to_vec(),
            signature,
            ic_tag,
            tx_seq,
        })
    }

    /// Inspect the next tx_seq the signer will issue, or `None` if exhausted.
    pub fn peek_next_seq(&self) -> Option<TxSeq> {
        self.tx_seq_next
    }
}
