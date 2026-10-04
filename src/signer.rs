//! Signer (P1) state and operations.

use crate::{
    protocol::{IcTag, PairKey, Signature, SignedTransfer, TxSeq},
    MacBackend, PairSequencer, Qsig3pError, QsigSignBackend,
};

/// P1's keying state for one holder channel, that is, for one (P1, P2, P3)
/// triple.
///
/// The signer holds the two pairwise roots it needs and nothing else. It
/// deliberately does **not** own a `tx_seq` counter.
///
/// `tx_seq` is scoped to the (P1, P3) pairwise channel, not to the triple,
/// because that is the namespace [`crate::Verifier`] enforces. A single P1 may
/// serve several holders over one P3, and all of those transfers share one
/// replay namespace. Allocation therefore belongs to a [`PairSequencer`] that
/// is shared across every holder channel on the same P1-P3 pair, and is passed
/// to [`Signer::sign`] at each call.
///
/// Giving each holder channel its own counter would hand two holders the same
/// `tx_seq`; P3 would accept the first to arrive and reject the second as a
/// replay, refusing a transfer P1 had validly authorized.
pub struct Signer<S: QsigSignBackend, M: MacBackend> {
    /// Pairwise root with P2.
    k_p2: PairKey,
    /// Pairwise root with P3.
    k_p3: PairKey,
    /// QSIG sign backend.
    sign_backend: S,
    /// Wave-MAC backend.
    mac_backend: M,
}

impl<S: QsigSignBackend, M: MacBackend> Signer<S, M> {
    /// Construct the signer state for one holder channel.
    ///
    /// Sequence allocation is supplied separately at signing time. See
    /// [`PairSequencer`].
    pub fn new(k_p2: PairKey, k_p3: PairKey, sign_backend: S, mac_backend: M) -> Self {
        Self {
            k_p2,
            k_p3,
            sign_backend,
            mac_backend,
        }
    }

    /// Sign a message and produce the transfer payload P2 will hold.
    ///
    /// `sequencer` MUST be the allocator for this signer's P1-P3 pair, shared
    /// with every other holder channel P1 serves to the same P3.
    ///
    /// Internally:
    /// 1. Allocate the next tx_seq from the pair's sequencer, or fail with
    ///    [`Qsig3pError::SequenceOverflow`] if the epoch is exhausted.
    /// 2. Produce a 30-byte QSIG signature under K12.
    /// 3. Compute the wave-MAC IC tag over (message, signature, tx_seq) under K13.
    ///
    /// The sequence number is consumed only when allocation succeeds, and the
    /// allocator advances before the transfer is built, so a failure later in
    /// this function cannot cause the same `tx_seq` to be issued twice.
    pub fn sign(
        &self,
        sequencer: &mut PairSequencer,
        message: &[u8],
    ) -> Result<SignedTransfer, Qsig3pError> {
        let tx_seq: TxSeq = sequencer.allocate()?;

        let signature: Signature = self.sign_backend.sign(&self.k_p2, message);

        // IC tag binds (message, signature, tx_seq) to K13.
        let mut mac_input = Vec::with_capacity(message.len() + 30 + 4);
        mac_input.extend_from_slice(message);
        mac_input.extend_from_slice(signature.as_bytes());
        mac_input.extend_from_slice(&tx_seq.0.to_be_bytes());
        let ic_tag: IcTag = self.mac_backend.mac(&self.k_p3, &mac_input);

        Ok(SignedTransfer {
            message: message.to_vec(),
            signature,
            ic_tag,
            tx_seq,
        })
    }
}
