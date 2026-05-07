//! Mock backends for local testing.
//!
//! These are HMAC-SHA256 placeholders. In production, [`MockSign`] is
//! replaced by the real 30-byte QSIG primitive keyed by DSKAG, and
//! [`MockMac`] is replaced by the wave-engine MAC (5-round HMAC iteration).
//!
//! These mocks are deliberately deterministic and cryptographically sound
//! enough to exercise the full protocol logic, but are NOT a substitute for
//! the production primitives.

use crate::{
    protocol::{IcTag, PairKey, Signature},
    MacBackend, QsigSignBackend, IC_TAG_LEN, QSIG_SIG_LEN,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Mock 30-byte signing backend using HMAC-SHA256 truncated to 30 bytes.
#[derive(Clone, Default, Debug)]
pub struct MockSign;

impl QsigSignBackend for MockSign {
    fn sign(&self, key: &PairKey, message: &[u8]) -> Signature {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(b"QSIG-3P-MOCK-SIGN-v1");
        mac.update(message);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; QSIG_SIG_LEN];
        out.copy_from_slice(&tag[..QSIG_SIG_LEN]);
        Signature::from_bytes(out)
    }

    fn verify(&self, key: &PairKey, message: &[u8], sig: &Signature) -> bool {
        let expected = self.sign(key, message);
        sig.as_bytes().ct_eq(expected.as_bytes()).into()
    }
}

/// Mock wave-MAC backend using HMAC-SHA256.
#[derive(Clone, Default, Debug)]
pub struct MockMac;

impl MacBackend for MockMac {
    fn mac(&self, key: &PairKey, data: &[u8]) -> IcTag {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key.as_bytes())
            .expect("HMAC accepts any key length");
        mac.update(b"QSIG-3P-MOCK-MAC-v1");
        mac.update(data);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; IC_TAG_LEN];
        out.copy_from_slice(&tag);
        IcTag::from_bytes(out)
    }

    fn verify(&self, key: &PairKey, data: &[u8], tag: &IcTag) -> bool {
        let expected = self.mac(key, data);
        expected.as_bytes().ct_eq(tag.as_bytes()).into()
    }
}
