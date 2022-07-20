use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "common")]
use core::fmt;

pub type ByteArray32 = [u8; 32];
pub type RandomID = [u8; 32];
pub type MessageID = [u8; 32];
pub type Blake3Hash = [u8; 32];
pub type TaiTimestamp = [u8; 12];
pub type TimestampSeconds = i64;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Ed25519Public(pub [u8; 32]);

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

#[cfg(feature = "hex")]
impl fmt::Debug for X25519Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("X25519Public")
            .field(&hex::encode(&self.0))
            .finish()
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
