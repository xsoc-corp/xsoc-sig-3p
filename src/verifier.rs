//! Verifier (P3) state and operations.

use crate::{
    protocol::{PairKey, SignedTransfer, TxSeq},
    MacBackend, Qsig3pError,
};

/// State for P3 over a single (P1, P2, P3) triple.
///
/// `last_seen_seq` is the highest tx_seq accepted on this pair. It MUST be
/// persisted across process restarts; rolling it back enables replay.
pub struct Verifier<M: MacBackend> {
    /// Pairwise root with P1.
    k_p1: PairKey,
    /// Last tx_seq accepted on this pair (0 means none yet).
    last_seen_seq: u32,
    /// Wave-MAC backend.
    mac_backend: M,
}

impl<M: MacBackend> Verifier<M> {
    /// Construct a verifier. `last_seen_start` should be loaded from
    /// persistent state; pass 0 for a fresh pair.
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
    /// 1. The IC tag matches the recomputed wave-MAC over (message, signature, tx_seq) under K13.
    /// 2. The tx_seq strictly exceeds `last_seen_seq`.
    ///
    /// On success, the verifier returns the message and advances `last_seen_seq`.
    /// On failure, state is not mutated, so a forged or replayed transfer cannot
    /// poison the verifier's counter.
    pub fn accept(&mut self, transfer: &SignedTransfer) -> Result<Vec<u8>, Qsig3pError> {
        if transfer.tx_seq.0 <= self.last_seen_seq {
            return Err(Qsig3pError::SequenceReplay {
                received: transfer.tx_seq.0,
                last_seen: self.last_seen_seq,
            });
        }

        let mac_input = transfer.mac_input();
        if !self
            .mac_backend
            .verify(&self.k_p1, &mac_input, &transfer.ic_tag)
        {
            return Err(Qsig3pError::InvalidIcTag);
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
