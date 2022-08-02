use borsh::{BorshDeserialize, BorshSerialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(feature = "common")]
use core::fmt;

use crate::Utilities;

pub type ByteArray32 = [u8; 32];
pub type RandomID = [u8; 32];
pub type MessageID = [u8; 32];
pub type Blake3Hash = [u8; 32];
pub type TaiTimestampBytes = [u8; 12];
pub type TimestampSeconds = i64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct TaiTimestamp(pub TaiTimestampBytes);

#[cfg(feature = "tai64")]
impl TaiTimestamp {
    pub fn now() -> Self {
        TaiTimestamp(tai64::Tai64N::now().to_bytes())
    }

    pub fn new() -> Self {
        TaiTimestamp(tai64::Tai64N::UNIX_EPOCH.to_bytes())
    }
}

#[cfg(feature = "tai64")]
impl fmt::Debug for TaiTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use monotonic_time::DateTime;

        match Utilities::bytes_to_tai64n(&self.0) {
            Ok(timestamp) => match Utilities::tai64_get_secs(timestamp) {
                Ok(duration) => {
                    let mut datetime = DateTime::new();

                    write!(f, "{}", datetime.to_datetime(duration))
                }
                Err(error) => write!(f, "{:?}", error),
            },
            Err(error) => write!(f, "{:?}", error),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Ed25519Public(pub [u8; 32]);

impl Default for Ed25519Public {
    fn default() -> Self {
        Ed25519Public([0u8; 32])
    }
}

#[cfg(feature = "base58")]
impl fmt::Debug for Ed25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519Public")
            .field(&bs58::encode(&self.0).into_string())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Default for Ed25519Signature {
    fn default() -> Self {
        Ed25519Signature([0u8; 64])
    }
}

#[cfg(feature = "base58")]
impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519Signature")
            .field(&bs58::encode(&self.0).into_string())
            .finish()
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Sr25519Public(pub [u8; 32]);

impl Default for Sr25519Public {
    fn default() -> Self {
        Sr25519Public([0u8; 32])
    }
}

#[cfg(feature = "base58")]
impl fmt::Debug for Sr25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sr25519Public")
            .field(&bs58::encode(&self.0).into_string())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Sr25519Signature(pub [u8; 64]);

impl Default for Sr25519Signature {
    fn default() -> Self {
        Sr25519Signature([0u8; 64])
    }
}

#[cfg(feature = "base58")]
impl fmt::Debug for Sr25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Sr25519Signature")
            .field(&bs58::encode(&self.0).into_string())
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct X25519Public(pub [u8; 32]);

impl Default for X25519Public {
    fn default() -> Self {
        X25519Public([0u8; 32])
    }
}

#[cfg(feature = "hex")]
impl fmt::Debug for X25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("X25519Public")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Secret32Bytes(pub [u8; 32]);

impl Zeroize for Secret32Bytes {
    fn zeroize(&mut self) {
        self.0 = Secret32Bytes::default().0;
    }
}

impl ZeroizeOnDrop for Secret32Bytes {}

#[cfg(feature = "debug_secret")]
impl Secret32Bytes {
    pub fn dangerous_debug(&self) -> String {
        hex::encode(&self.0)
    }
}

#[cfg(feature = "clonable_secret")]
impl Clone for Secret32Bytes {
    fn clone(&self) -> Self {
        Secret32Bytes(self.0)
    }
}

impl Default for Secret32Bytes {
    fn default() -> Self {
        Secret32Bytes([0u8; 32])
    }
}

#[cfg(feature = "hex")]
impl fmt::Debug for Secret32Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret32Bytes").field(&"[REDACTED]").finish()
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadNonce(pub [u8; 12]);

#[cfg(feature = "hex")]
impl fmt::Debug for AeadNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadNonce")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadXNonce(pub [u8; 24]);

#[cfg(feature = "hex")]
impl fmt::Debug for AeadXNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadXNonce")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadTag(pub [u8; 16]);

#[cfg(feature = "hex")]
impl fmt::Debug for AeadTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadTag")
            .field(&hex::encode(&self.0))
            .finish()
    }
}
