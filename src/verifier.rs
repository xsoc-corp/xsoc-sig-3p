//! Verifier (P3) state and operations.

use crate::{
    protocol::{PairKey, SignedTransfer, TxSeq},
    MacBackend, Qsig3pError,
};

/// P3's state for one (P1, P3) pairwise channel.
///
/// The verifier holds the P1 pairwise root and the highest `tx_seq` accepted on
/// that pair. Its scope is the **pair**, not a (P1, P2, P3) triple: P3 does not
/// hold K12 and so does not distinguish which holder forwarded a transfer. One
/// verifier instance therefore serves every holder channel P1 operates to this
/// P3, and the matching [`crate::PairSequencer`] on P1's side must be shared
/// across those same channels.
///
/// `last_seen_seq` MUST be persisted across process restarts; rolling it back
/// enables replay.
pub struct Verifier<M: MacBackend> {
    /// Pairwise root with P1.
    k_p1: PairKey,
    /// Last tx_seq accepted on this pair (0 means none yet).
    last_seen_seq: u32,
    /// Wave-MAC backend.
    mac_backend: M,
}

impl<M: MacBackend> Verifier<M> {
    /// Construct a verifier for one P1-P3 pair. `last_seen_start` should be
    /// loaded from persistent state; pass 0 for a pair that has accepted
    /// nothing yet.
    pub fn new(k_p1: PairKey, last_seen_start: u32, mac_backend: M) -> Self {
        Self {
            k_p1,
            last_seen_seq: last_seen_start,
            mac_backend,
        }
    }

    /// Accept a transfer.
    ///
    /// Verifier accepts iff:
    /// 1. The IC tag matches the recomputed wave-MAC over (message, signature,
    ///    tx_seq) under K13.
    /// 2. The tx_seq strictly exceeds `last_seen_seq`.
    ///
    /// The checks run in that order, which departs from XSOC-QSIG-3P v1.0
    /// section 3.5 deliberately. The specification orders the replay check
    /// first; that lets an unauthenticated sender tell a replay rejection from
    /// a tag rejection and recover `last_seen_seq` by search. Authenticating
    /// first means every unauthenticated transfer yields the same error
    /// regardless of its sequence number. Raised as an erratum against 3.5.
    ///
    /// On success, the verifier returns the message and advances
    /// `last_seen_seq`. On failure, state is not mutated, so a forged or
    /// replayed transfer cannot poison the verifier's counter.
    pub fn accept(&mut self, transfer: &SignedTransfer) -> Result<Vec<u8>, Qsig3pError> {
        let mac_input = transfer.mac_input();
        if !self
            .mac_backend
            .verify(&self.k_p1, &mac_input, &transfer.ic_tag)
        {
            return Err(Qsig3pError::InvalidIcTag);
        }

        if transfer.tx_seq.0 <= self.last_seen_seq {
            return Err(Qsig3pError::SequenceReplay {
                received: transfer.tx_seq.0,
                last_seen: self.last_seen_seq,
            });
        }

        // Commit only after both checks pass.
        self.last_seen_seq = transfer.tx_seq.0;
        Ok(transfer.message.clone())
    }

    /// Read-only view of the last tx_seq accepted.
    pub fn last_seen(&self) -> TxSeq {
        TxSeq(self.last_seen_seq)
    }
}
