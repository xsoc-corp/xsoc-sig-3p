//! Holder (P2) state and operations.

use crate::{
    protocol::{signing_input, PairKey, SignedTransfer},
    Qsig3pError, QsigSignBackend,
};

/// P2's state for one (P1, P2) pairwise channel.
///
/// The holder carries the P1-P2 pairwise root and nothing else, so its scope is
/// that pair. P2 verifies the QSIG signature under K12, and forwards the
/// transfer payload to P3 verbatim. It does not verify the IC tag, because K13
/// belongs to the P1-P3 channel and P2 never holds it.
pub struct Holder<S: QsigSignBackend> {
    /// Pairwise root with P1.
    k_p1: PairKey,
    /// QSIG sign backend.
    sign_backend: S,
}

impl<S: QsigSignBackend> Holder<S> {
    /// Construct a holder.
    pub fn new(k_p1: PairKey, sign_backend: S) -> Self {
        Self { k_p1, sign_backend }
    }

    /// Verify P2's view, per XSOC-QSIG-3P v1.0 section 3.4 step 1.
    ///
    /// Confirms the 30-byte QSIG signature under K12 over `m || seq4`. Because
    /// the sequence number is inside the signed input, a `tx_seq` altered in
    /// transit fails here rather than reaching P3, so P2's acceptance covers
    /// the whole of what P1 authorized.
    ///
    /// The IC tag is checked by P3. P2 does not hold K13 and validates what it
    /// can validate.
    pub fn accept(&self, transfer: &SignedTransfer) -> Result<(), Qsig3pError> {
        let signed = signing_input(&transfer.message, transfer.tx_seq);
        if !self
            .sign_backend
            .verify(&self.k_p1, &signed, &transfer.signature)
        {
            return Err(Qsig3pError::InvalidSignature);
        }
        Ok(())
    }
}
