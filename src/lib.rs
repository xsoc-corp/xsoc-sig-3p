//! # QSIG-3P
//!
//! Three-party transferable designated-verifier signature mode for QSIG.
//!
//! ## Roles
//!
//! - **P1 (signer)** holds pairwise DSKAG roots with both P2 and P3.
//! - **P2 (holder)** holds a pairwise DSKAG root with P1.
//! - **P3 (verifier)** holds a pairwise DSKAG root with P1.
//!
//! ## Wire format (transfer payload)
//!
//! ```text
//! [ message length (8 bytes, BE)
//! | message bytes
//! | signature (30 bytes)
//! | ic_tag (32 bytes)
//! | tx_seq (4 bytes, BE) ]
//! ```
//!
//! ## Properties
//!
//! - Zero broadcast: two point-to-point messages (P1 -> P2, P2 -> P3).
//! - Replay protection: tx_seq strict monotonicity per (signer, verifier) pair.
//! - Forgery bound: 2^-256 from underlying MAC unforgeability.
//! - Setup: pairwise DSKAG roots, derived from network bootstrap; no shared
//!   broadcast channel required.
//!
//! ## Trait abstractions
//!
//! [`QsigSignBackend`] and [`MacBackend`] are pluggable. The mock backends in
//! [`mock`] use HMAC-SHA256 (truncated to 30 bytes for the signature), which
//! is a placeholder for the production wave-engine and DSKAG-rooted QSIG.
//!
//! Integration into `xsoc-sig`: implement `QsigSignBackend` over the existing
//! 30-byte QSIG primitive and `MacBackend` over the wave-engine MAC, then
//! wire them into [`Signer`], [`Holder`], and [`Verifier`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod mock;
pub mod protocol;

mod holder;
mod signer;
mod verifier;

pub use error::Qsig3pError;
pub use holder::Holder;
pub use protocol::{IcTag, PairKey, Signature, SignedTransfer, TxSeq};
pub use signer::Signer;
pub use verifier::Verifier;

/// Length of a 30-byte QSIG signature.
pub const QSIG_SIG_LEN: usize = 30;

/// Length of the wave-MAC IC tag.
pub const IC_TAG_LEN: usize = 32;

/// Length of a pairwise DSKAG root.
pub const PAIR_KEY_LEN: usize = 32;

/// Backend for the underlying 30-byte QSIG signature primitive.
///
/// Implementations should use the production QSIG sign and verify routines
/// keyed by the P1-P2 pairwise DSKAG root.
pub trait QsigSignBackend {
    /// Produce a 30-byte signature on `message` under `key`.
    fn sign(&self, key: &PairKey, message: &[u8]) -> Signature;

    /// Verify a 30-byte signature on `message` under `key`.
    /// Implementations MUST be constant-time with respect to the signature.
    fn verify(&self, key: &PairKey, message: &[u8], sig: &Signature) -> bool;
}

/// Backend for the wave-engine MAC used to bind (signature, message, tx_seq)
/// to the P1-P3 pairwise key.
///
/// Implementations should run the wave engine's full derivation chain on
/// the pairwise key before HMAC, yielding a 32-byte tag.
pub trait MacBackend {
    /// Produce a 32-byte IC tag over `data` under `key`.
    fn mac(&self, key: &PairKey, data: &[u8]) -> IcTag;

    /// Constant-time verify that `tag` matches the MAC of `data` under `key`.
    fn verify(&self, key: &PairKey, data: &[u8], tag: &IcTag) -> bool;
}
