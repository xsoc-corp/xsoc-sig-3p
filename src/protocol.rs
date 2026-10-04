//! Protocol-level types: keys, signatures, IC tags, sequences, and the
//! wire-format transfer payload.

use crate::{Qsig3pError, IC_TAG_LEN, PAIR_KEY_LEN, QSIG_SIG_LEN};
use subtle::ConstantTimeEq;

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

/// A 30-byte QSIG signature.
#[derive(Clone, Debug, PartialEq, Eq)]
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
/// Wire format is length-prefixed message, signature, IC tag, tx_seq.
/// The pairwise keys never appear here.
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
    /// Serialize to the wire format described in the crate docs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.message.len() + QSIG_SIG_LEN + IC_TAG_LEN + 4);
        out.extend_from_slice(&(self.message.len() as u64).to_be_bytes());
        out.extend_from_slice(&self.message);
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(self.ic_tag.as_bytes());
        out.extend_from_slice(&self.tx_seq.0.to_be_bytes());
        out
    }

    /// Parse from wire bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Qsig3pError> {
        if b.len() < 8 {
            return Err(Qsig3pError::MalformedPayload("missing length prefix"));
        }
        let mut len_buf = [0u8; 8];
        len_buf.copy_from_slice(&b[..8]);
        const MAX_MESSAGE_LEN: u64 = 16 * 1024 * 1024; // 16 MiB operational cap
        let msg_len_u64 = u64::from_be_bytes(len_buf);
        if msg_len_u64 > MAX_MESSAGE_LEN {
            return Err(Qsig3pError::MalformedPayload("message too large"));
        }
        let msg_len = msg_len_u64 as usize;

        let need = 8usize
            .checked_add(msg_len)
            .and_then(|n| n.checked_add(QSIG_SIG_LEN))
            .and_then(|n| n.checked_add(IC_TAG_LEN))
            .and_then(|n| n.checked_add(4))
            .ok_or(Qsig3pError::MalformedPayload("length overflow"))?;
        if b.len() != need {
            return Err(Qsig3pError::MalformedPayload("payload length mismatch"));
        }

        let mut cursor = 8;
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

    /// Bind input for the wave-MAC: message || signature || tx_seq.
    /// This is the canonical input to [`crate::MacBackend::mac`] for the IC tag.
    pub fn mac_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.message.len() + QSIG_SIG_LEN + 4);
        out.extend_from_slice(&self.message);
        out.extend_from_slice(self.signature.as_bytes());
        out.extend_from_slice(&self.tx_seq.0.to_be_bytes());
        out
    }
}
