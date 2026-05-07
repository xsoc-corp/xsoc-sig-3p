//! Error types for QSIG-3P.

use thiserror::Error;

/// All failure modes in the QSIG-3P protocol.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Qsig3pError {
    /// The 30-byte QSIG signature did not verify against the holder's pairwise key.
    #[error("invalid QSIG signature under pairwise key")]
    InvalidSignature,

    /// The wave-MAC IC tag did not match the verifier's recomputation.
    #[error("invalid IC tag (forgery or modification detected)")]
    InvalidIcTag,

    /// The transfer's tx_seq did not strictly exceed the verifier's last-seen value.
    /// This catches replays and out-of-order delivery.
    #[error("tx_seq replay or out-of-order: received {received}, last seen {last_seen}")]
    SequenceReplay {
        /// The tx_seq carried in the transfer payload.
        received: u32,
        /// The last tx_seq accepted by this verifier on this pair.
        last_seen: u32,
    },

    /// Wire-format payload was malformed (length mismatch, truncation).
    #[error("malformed wire payload: {0}")]
    MalformedPayload(&'static str),

    /// The signer's tx_seq counter would overflow u32 (4.3B signatures per epoch).
    /// Application MUST rotate to a new pairwise root before this occurs.
    #[error("tx_seq overflow: epoch exhausted, rotate pairwise root")]
    SequenceOverflow,
}
