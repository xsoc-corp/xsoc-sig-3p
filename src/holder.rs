//! Holder (P2) state and operations.

use crate::{
    protocol::{PairKey, SignedTransfer},
    Qsig3pError, QsigSignBackend,
};

/// State for P2 over a single (P1, P2, P3) triple.
///
/// P2 verifies the QSIG signature against its pairwise key with P1 (K12), but
/// cannot verify the IC tag because it does not know K13. P2 forwards the
/// transfer payload verbatim to P3.
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

    /// Verify P2's view: confirms the 30-byte QSIG signature is well-formed
    /// under K12. Returns the same payload on success so the caller can
    /// forward it to P3.
    ///
    /// P2 cannot detect a malicious P1 who substitutes an inconsistent IC
    /// tag for P3; that case is caught by P3's verification step. P2 only
    /// validates what it can validate.
    pub fn accept(&self, transfer: &SignedTransfer) -> Result<(), Qsig3pError> {
        if !self
            .sign_backend
            .verify(&self.k_p1, &transfer.message, &transfer.signature)
        {
            return Err(Qsig3pError::InvalidSignature);
        }
        Ok(())
    }
}
