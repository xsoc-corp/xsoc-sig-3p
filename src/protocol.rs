//! Protocol-level types: keys, signatures, IC tags, sequences, and the
//! wire-format transfer payload.

use crate::{Qsig3pError, DST_IC, IC_TAG_LEN, PAIR_KEY_LEN, QSIG_SIG_LEN};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Operational ceiling on the message length carried in a transfer.
///
/// The wire length prefix is a big-endian `u32` (paper 3.2), so the format
/// admits up to 4 GiB. This crate refuses anything above 16 MiB on both the
/// encode and the decode path, which keeps a hostile length prefix from
/// driving an allocation.
pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

/// Canonical input to the QSIG signature: `m || seq4`.
///
/// Specified by XSOC-QSIG-3P v1.0 section 3.3 step 2 and verified against the
/// same construction in section 3.4 step 1. `seq4` is the big-endian encoding
/// of `tx_seq`. The variable-length message leads and the fixed 4-byte
/// sequence trails, so the encoding is unambiguous.
///
/// `DST_SIG` is applied by the signature backend, not here. See
/// [`crate::DST_SIG`].
pub fn signing_input(message: &[u8], tx_seq: TxSeq) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + 4);
    out.extend_from_slice(message);
    out.extend_from_slice(&tx_seq.0.to_be_bytes());
    out
}

/// Canonical input to the IC tag MAC: `DST_IC || m || sigma || seq4`.
///
/// Specified by XSOC-QSIG-3P v1.0 section 3.3 step 3 and recomputed by the
/// verifier in section 3.5 step 2. The variable-length message sits between a
/// fixed prefix and a fixed 34-byte suffix, so the encoding is unambiguous.
///
/// Signer and verifier both build the transcript here. Holding one
/// construction rather than two is deliberate: two copies of a transcript that
/// happen to agree is how they come to disagree.
pub fn ic_tag_input(message: &[u8], signature: &Signature, tx_seq: TxSeq) -> Vec<u8> {
    let mut out = Vec::with_capacity(DST_IC.len() + message.len() + QSIG_SIG_LEN + 4);
    out.extend_from_slice(DST_IC);
    out.extend_from_slice(message);
    out.extend_from_slice(signature.as_bytes());
    out.extend_from_slice(&tx_seq.0.to_be_bytes());
    out
}

/// A pairwise DSKAG root, 32 bytes.
///
/// In production this is derived from the DSKAG bootstrap; the bytes never
/// appear on the wire. In tests it is constructed directly from raw bytes.
#[derive(Clone)]
pub struct PairKey([u8; PAIR_KEY_LEN]);

impl PairKey {
    /// Construct a pairwise key from 32 bytes.
    pub fn from_bytes(b: [u8; PAIR_KEY_LEN]) -> Self {
        Self(b)
    }

    /// Borrow the underlying bytes (caller MUST NOT serialize over the wire).
    pub fn as_bytes(&self) -> &[u8; PAIR_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for PairKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairKey(<redacted>)")
    }
}

impl Drop for PairKey {
    /// Wipes the pairwise root when the key goes out of scope.
    ///
    /// `zeroize` performs a volatile write the optimizer is not permitted to
    /// elide. Each clone owns its own buffer and wipes it independently.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A 30-byte QSIG signature.
///
/// Equality is constant time. A 30-byte authenticator compared byte by byte
/// with early exit is a timing oracle for forgery, so `PartialEq` is written
/// rather than derived.
#[derive(Clone, Debug)]
pub struct Signature([u8; QSIG_SIG_LEN]);

impl Signature {
    /// Construct a signature from 30 bytes.
    pub fn from_bytes(b: [u8; QSIG_SIG_LEN]) -> Self {
        Self(b)
    }

    /// Underlying 30 bytes.
    pub fn as_bytes(&self) -> &[u8; QSIG_SIG_LEN] {
        &self.0
    }
}

impl PartialEq for Signature {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Signature {}

/// A 32-byte wave-MAC IC tag.
#[derive(Clone, Debug)]
pub struct IcTag([u8; IC_TAG_LEN]);

impl IcTag {
    /// Construct an IC tag from 32 bytes.
    pub fn from_bytes(b: [u8; IC_TAG_LEN]) -> Self {
        Self(b)
    }

    /// Underlying 32 bytes.
    pub fn as_bytes(&self) -> &[u8; IC_TAG_LEN] {
        &self.0
    }
}

impl PartialEq for IcTag {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for IcTag {}

/// Per-pair monotonic transaction counter.
///
/// u32 yields approximately 4.3 x 10^9 signatures per epoch with no
/// cryptographic degradation; epoch rotation MUST occur before exhaustion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxSeq(pub u32);

impl TxSeq {
    /// First valid tx_seq on a P1-P3 pair that has issued nothing yet.
    ///
    /// Allocation is the responsibility of [`crate::PairSequencer`], which is
    /// scoped to the pair. Do not start a second counter at `FIRST` for another
    /// holder channel on the same pair.
    pub const FIRST: TxSeq = TxSeq(1);

    /// Increment, returning [`Qsig3pError::SequenceOverflow`] at u32::MAX.
    pub fn increment(self) -> Result<TxSeq, Qsig3pError> {
        self.0
            .checked_add(1)
            .map(TxSeq)
            .ok_or(Qsig3pError::SequenceOverflow)
    }
}

/// The wire payload P2 forwards to P3.
///
/// `<len4, m, sigma30, tau32, seq4>` per XSOC-QSIG-3P v1.0 section 3.2, where
/// `len` is the big-endian 32-bit length of the message. Fixed overhead is
/// 70 bytes: 4 + 30 + 32 + 4. The pairwise keys never appear here.
#[derive(Clone, Debug)]
pub struct SignedTransfer {
    /// The signed message.
    pub message: Vec<u8>,
    /// The 30-byte QSIG signature under K12.
    pub signature: Signature,
    /// The 32-byte wave-MAC IC tag under K13.
    pub ic_tag: IcTag,
    /// Strict-monotonic per-pair transaction counter.
    pub tx_seq: TxSeq,
}

impl SignedTransfer {
    /// Serialize to the wire format in section 3.2.
    ///
    /// Fails rather than truncating when the message exceeds
    /// [`MAX_MESSAGE_LEN`]. `SignedTransfer` has public fields, so an
    /// oversized message can reach this function without passing through
    /// [`crate::Signer::sign`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Qsig3pError> {
        if self.message.len() > MAX_MESSAGE_LEN {
            return Err(Qsig3pError::MalformedPayload("message too large to encode"));
        }
        let len = self.message.len() as u32;
        let mut out = Vec::with_capacity(4 + self.message.len() + QSIG_SIG_LEN + IC_TAG_LEN + 4);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.message);
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(self.ic_tag.as_bytes());
        out.extend_from_slice(&self.tx_seq.0.to_be_bytes());
        Ok(out)
    }

    /// Parse from wire bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Qsig3pError> {
        if b.len() < 4 {
            return Err(Qsig3pError::MalformedPayload("missing length prefix"));
        }
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&b[..4]);
        let msg_len_u32 = u32::from_be_bytes(len_buf);
        if msg_len_u32 as u64 > MAX_MESSAGE_LEN as u64 {
            return Err(Qsig3pError::MalformedPayload("message too large"));
        }
        let msg_len = msg_len_u32 as usize;

        let need = 4usize
            .checked_add(msg_len)
            .and_then(|n| n.checked_add(QSIG_SIG_LEN))
            .and_then(|n| n.checked_add(IC_TAG_LEN))
            .and_then(|n| n.checked_add(4))
            .ok_or(Qsig3pError::MalformedPayload("length overflow"))?;
        if b.len() != need {
            return Err(Qsig3pError::MalformedPayload("payload length mismatch"));
        }

        let mut cursor = 4;
        let message = b[cursor..cursor + msg_len].to_vec();
        cursor += msg_len;

        let mut sig = [0u8; QSIG_SIG_LEN];
        sig.copy_from_slice(&b[cursor..cursor + QSIG_SIG_LEN]);
        cursor += QSIG_SIG_LEN;

        let mut tag = [0u8; IC_TAG_LEN];
        tag.copy_from_slice(&b[cursor..cursor + IC_TAG_LEN]);
        cursor += IC_TAG_LEN;

        let mut seq = [0u8; 4];
        seq.copy_from_slice(&b[cursor..cursor + 4]);

        Ok(SignedTransfer {
            message,
            signature: Signature::from_bytes(sig),
            ic_tag: IcTag::from_bytes(tag),
            tx_seq: TxSeq(u32::from_be_bytes(seq)),
        })
    }

    /// Canonical input to [`crate::MacBackend::mac`] for the IC tag.
    ///
    /// Delegates to [`ic_tag_input`], which is the single construction of this
    /// transcript used by the signer and the verifier alike.
    pub fn mac_input(&self) -> Vec<u8> {
        ic_tag_input(&self.message, &self.signature, self.tx_seq)
    }

    /// Canonical input to the QSIG signature for this transfer.
    ///
    /// Delegates to [`signing_input`].
    pub fn signing_input(&self) -> Vec<u8> {
        signing_input(&self.message, self.tx_seq)
    }
}
