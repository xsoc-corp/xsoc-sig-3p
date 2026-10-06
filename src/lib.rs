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
//! [ message length (4 bytes, BE)
//! | message bytes
//! | signature (30 bytes)
//! | ic_tag (32 bytes)
//! | tx_seq (4 bytes, BE) ]
//! ```
//!
//! Fixed overhead is 70 bytes: 4 + 30 + 32 + 4. Specified by XSOC-QSIG-3P
//! v1.0 sections 3.2 and 6.4.
//!
//! ## Transcripts
//!
//! Two inputs are bound, and both carry `tx_seq`:
//!
//! - signature, section 3.3 step 2 and 3.4 step 1: `m || seq4`
//! - IC tag, section 3.3 step 3 and 3.5 step 2: `DST_IC || m || sigma || seq4`
//!
//! Each is built in exactly one place, [`protocol::signing_input`] and
//! [`protocol::ic_tag_input`], and used by every role.
//!
//! ## Properties
//!
//! - Zero broadcast: two point-to-point messages (P1 -> P2, P2 -> P3).
//! - Replay protection: tx_seq strict monotonicity per (signer, verifier) pair.
//!   The replay namespace is the P1-P3 pair, so a single P1 serving several
//!   holders over one P3 MUST allocate every tx_seq from one shared
//!   [`PairSequencer`]. See its module documentation.
//! - Designated-verifier scope: P3 verifies that P1 authorized the transfer.
//!   P3 does not hold K12 and therefore does not establish which holder
//!   forwarded it. Holder provenance is not an authorization boundary at P3.
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
//!
//! ## Conformance to XSOC-QSIG-3P v1.0
//!
//! This crate implements XSOC-QSIG-3P v1.0 (DOI 10.5281/zenodo.20078816) with
//! two deliberate departures, each of which strengthens the published
//! construction. Both are raised as errata against the specification.
//!
//! 1. **Sequence allocation is scoped to the P1-P3 pair.** Sections 3.1 and
//!    3.3 step 1 allocate from `seq_next` keyed to the P1-P2 channel while
//!    section 3.5 enforces against `seq_seen` keyed to the P1-P3 pair. Where a
//!    single P1 serves several holders over one P3, those scopes disagree and
//!    two holders are issued the same `tx_seq`. Allocation here belongs to
//!    [`PairSequencer`], which is pair scoped, so the allocation namespace and
//!    the enforcement namespace are the same object.
//!
//! 2. **The verifier authenticates before it checks the sequence.** Section
//!    3.5 orders the replay check first. That lets an unauthenticated sender
//!    distinguish a replay rejection from a tag rejection and recover
//!    `seq_seen` by search. [`Verifier::accept`] verifies the IC tag first, so
//!    every unauthenticated transfer yields the same error regardless of its
//!    sequence number.
//!
//! Everything else follows the specification as published.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod mock;
pub mod protocol;
pub mod sequencer;

mod holder;
mod signer;
mod verifier;

pub use error::Qsig3pError;
pub use holder::Holder;
pub use protocol::{
    ic_tag_input, signing_input, IcTag, PairKey, Signature, SignedTransfer, TxSeq, MAX_MESSAGE_LEN,
};
pub use sequencer::PairSequencer;
pub use signer::Signer;
pub use verifier::Verifier;

/// Length of a 30-byte QSIG signature.
pub const QSIG_SIG_LEN: usize = 30;

/// Length of the wave-MAC IC tag.
pub const IC_TAG_LEN: usize = 32;

/// Length of a pairwise DSKAG root.
pub const PAIR_KEY_LEN: usize = 32;

/// Domain-separation string for the IC tag path, section 4.4.
///
/// Prefixed to the MAC input by the protocol layer in
/// [`protocol::ic_tag_input`]. Distinct from every constant in the underlying
/// `xsoc-sig-core` crate, so a tag solicited in one context cannot be reused
/// in another.
pub const DST_IC: &[u8] = b"XSOC-QSIG-3P-IC-v1:";

/// Domain-separation string for the signature path, section 4.4.
///
/// Applied inside the [`QsigSignBackend`] implementation rather than by the
/// protocol layer, matching the production construction in section 5.2, which
/// derives a session key and then computes `MAC(session, DST_SIG || message)`.
/// A backend implementing this trait is responsible for applying it; the
/// protocol layer passes `m || seq4` and nothing more.
pub const DST_SIG: &[u8] = b"XSOC-QSIG-3P-SIG-v1:";

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
