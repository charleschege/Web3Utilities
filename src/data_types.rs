use borsh::{BorshDeserialize, BorshSerialize};
use constant_time_eq::constant_time_eq_n;
use zeroize::{Zeroize, ZeroizeOnDrop};

use core::fmt;

/// An array of 12 bytes.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray12 = [u8; 12];
/// An array of 16 bytes common for ChaCha symmetric encryption AEAD tags.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray16 = [u8; 16];
/// An array of 24 bytes common for 192 bit cryptographic keys.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray24 = [u8; 24];
/// An array of 32 bytes common for 256 bit private and public keys.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray32 = [u8; 32];
/// An array of 64 bytes common for 512 bit private and public keys.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray64 = [u8; 64];
/// An array of 128 bytes common for 1024 bit private and public keys.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray128 = [u8; 128];
/// An array of 256 bytes common for 2048 bit private and public keys.
/// This does not implement hex or base58 fmt::Debug  or constant time equality checks.
pub type ByteArray256 = [u8; 256];

/// Common Unix timestamps are represented as u64
pub type UnixTimestamp = u64;
/// Common Unix timestamps are represented as i64
pub type UnixTimestampSigned = i64;

/// A representation of Blake3 hash byte representation with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Blake3Hash(pub ByteArray32);

impl PartialEq for Blake3Hash {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Blake3Hash {}

impl Default for Blake3Hash {
    fn default() -> Self {
        Blake3Hash([0u8; 32])
    }
}

#[cfg(feature = "hex")]
impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Blake3Hash")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

/// A representation of 12 byte Tai64N monotonic timestamp byte with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct TaiTimestamp(pub ByteArray12);

impl PartialEq for TaiTimestamp {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for TaiTimestamp {}

#[cfg(feature = "tai64")]
impl TaiTimestamp {
    /// Get the byte representation of a Tai64N timestamp representing the current system time
    pub fn now() -> Self {
        TaiTimestamp(tai64::Tai64N::now().to_bytes())
    }

    /// Get the default Tai64N UNIX EPOCH in bytes
    pub fn new() -> Self {
        TaiTimestamp(tai64::Tai64N::UNIX_EPOCH.to_bytes())
    }
}

#[cfg(feature = "tai64")]
impl Default for TaiTimestamp {
    fn default() -> Self {
        TaiTimestamp::new()
    }
}

#[cfg(feature = "tai64")]
impl fmt::Debug for TaiTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::Utilities;
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

/// A representation of a 32 byte Ed25519 public key with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Ed25519Public(pub [u8; 32]);

impl PartialEq for Ed25519Public {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Ed25519Public {}

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

/// A representation of a 64 byte Ed25519 signature with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Ed25519Signature(pub [u8; 64]);

impl PartialEq for Ed25519Signature {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Ed25519Signature {}

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

/// A representation of a 32 byte Sr25519 public key with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Sr25519Public(pub [u8; 32]);

impl PartialEq for Sr25519Public {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Sr25519Public {}

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

/// A representation of a 64 byte Sr25519 signature with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Sr25519Signature(pub [u8; 64]);

impl PartialEq for Sr25519Signature {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Sr25519Signature {}

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

/// A representation of a 32 byte X25519 public key with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct X25519Public(pub [u8; 32]);

impl PartialEq for X25519Public {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for X25519Public {}

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

/// A representation of a 32 byte secret key with
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// implementation for zeroize for zeroing memory when the value is dropped
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct Secret32Bytes(pub [u8; 32]);

impl PartialEq for Secret32Bytes {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for Secret32Bytes {}

impl Zeroize for Secret32Bytes {
    fn zeroize(&mut self) {
        self.0 = Secret32Bytes::default().0;
    }
}

impl ZeroizeOnDrop for Secret32Bytes {}

#[cfg(feature = "debug_secret")]
impl Secret32Bytes {
    /// Debug the secret key. This is a dangerous operation since
    /// it returns the hex of the secret key which can be logged
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

impl fmt::Debug for Secret32Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Secret32Bytes").field(&"[REDACTED]").finish()
    }
}

/// A representation of a 12 byte ChaCha AEAD Nonce
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadNonce(pub ByteArray12);

impl PartialEq for AeadNonce {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for AeadNonce {}

#[cfg(feature = "hex")]
impl fmt::Debug for AeadNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadNonce")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

/// A representation of a 24 byte ChaCha AEAD Extended Nonce
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadXNonce(pub ByteArray24);

impl PartialEq for AeadXNonce {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for AeadXNonce {}

#[cfg(feature = "hex")]
impl fmt::Debug for AeadXNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadXNonce")
            .field(&hex::encode(&self.0))
            .finish()
    }
}

/// A representation of a 16 byte ChaCha AEAD Tag
/// default constant time equality checks, hex `fmt::Debug` and hex `fmt::Display`,
/// and an implementation for Borsh encoding that ensure
/// no two binary representations that deserialize into the same object
/// and a possibly smaller code size compared to serde binary representations.
#[derive(Clone, Copy, PartialOrd, Ord, Hash, BorshDeserialize, BorshSerialize)]
pub struct AeadTag(pub ByteArray16);

impl PartialEq for AeadTag {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq_n(&self.0, &other.0)
    }
}

impl Eq for AeadTag {}

#[cfg(feature = "hex")]
impl fmt::Debug for AeadTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeadTag")
            .field(&hex::encode(&self.0))
            .finish()
    }
}
