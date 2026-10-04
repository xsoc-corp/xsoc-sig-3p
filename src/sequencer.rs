//! Pair-scoped transaction sequence allocation.
//!
//! `tx_seq` replay protection is scoped to the **(P1, P3) pairwise channel**,
//! because that is the namespace P3 enforces: a [`crate::Verifier`] holds the
//! P1-P3 pairwise root and one `last_seen_seq`, and rejects any transfer whose
//! `tx_seq` does not strictly exceed it.
//!
//! One P1 may serve several holders (P2, P2', P2'') while sharing a single P3.
//! Every one of those transfers competes in the same P1-P3 replay namespace, so
//! every one of them MUST draw from a single allocator. If each holder channel
//! kept a private counter, two holders would each be issued the same `tx_seq`,
//! and P3 would accept whichever arrived first and reject the other as a replay
//! even though both were validly authorized by P1.
//!
//! [`PairSequencer`] exists so that the allocation namespace and the enforcement
//! namespace are the same object. A [`crate::Signer`] carries no counter of its
//! own and must be handed a sequencer at signing time, which makes the shared
//! allocator visible at every call site.
//!
//! ## Persistence
//!
//! The sequencer MUST be persisted per (P1, P3) pair across process restarts.
//! Reissuing a `tx_seq` already consumed on a pair is a security failure, and
//! rolling the value backward reopens the replay window.

use crate::{protocol::TxSeq, Qsig3pError};

/// Monotonic `tx_seq` allocator for one (P1, P3) pairwise channel.
///
/// Construct exactly one per pair and share it across every holder channel that
/// P1 serves to that same P3. See the module documentation for why.
///
/// `next` is the sequence number that will be issued by the next call to
/// [`PairSequencer::allocate`], or `None` once the epoch is exhausted (after
/// issuing at `u32::MAX`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairSequencer {
    next: Option<TxSeq>,
}

impl PairSequencer {
    /// Allocator for a pair that has never issued a transfer.
    ///
    /// Starts at [`TxSeq::FIRST`]. Use [`PairSequencer::resuming_at`] to
    /// continue an epoch loaded from persistent state.
    pub fn fresh() -> Self {
        Self {
            next: Some(TxSeq::FIRST),
        }
    }

    /// Allocator continuing an existing epoch from persisted state.
    ///
    /// `next` is the first sequence number this allocator will issue. It MUST
    /// be strictly greater than every `tx_seq` already issued on this pair.
    pub fn resuming_at(next: TxSeq) -> Self {
        Self { next: Some(next) }
    }

    /// Allocator for an epoch that is already exhausted.
    ///
    /// Every call to [`PairSequencer::allocate`] returns
    /// [`Qsig3pError::SequenceOverflow`]. Rotate the pairwise epoch.
    pub fn exhausted() -> Self {
        Self { next: None }
    }

    /// Consume and return the next `tx_seq` for this pair.
    ///
    /// Returns [`Qsig3pError::SequenceOverflow`] once the epoch is exhausted,
    /// which happens after a value has been issued at `u32::MAX`.
    pub fn allocate(&mut self) -> Result<TxSeq, Qsig3pError> {
        let seq = self.next.ok_or(Qsig3pError::SequenceOverflow)?;
        self.next = seq.increment().ok();
        Ok(seq)
    }

    /// The sequence number the next [`PairSequencer::allocate`] will issue, or
    /// `None` if the epoch is exhausted. Does not consume.
    pub fn peek_next(&self) -> Option<TxSeq> {
        self.next
    }
}

impl Default for PairSequencer {
    fn default() -> Self {
        Self::fresh()
    }
}
