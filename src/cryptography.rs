#[cfg(feature = "common")]
use crate::{Utilities, UtilitiesError, UtilitiesResult};

#[cfg(feature = "ed25519")]
use ed25519_dalek::{
    Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, Signature as Ed25519Signature,
};

#[cfg(feature = "sr25519")]
use schnorrkel::{
    Keypair as Sr25519Keypair, PublicKey as Sr25519PublicKey, Signature as Sr25519Signature,
};

#[cfg(feature = "common")]
impl Utilities {
    #[cfg(feature = "ed25519")]
    pub fn to_ed25519_keypair(bytes: &[u8]) -> UtilitiesResult<Ed25519Keypair> {
        match Ed25519Keypair::from_bytes(bytes) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(UtilitiesError::InvalidBytesForEd25519Keypair),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn to_ed25519_publickey(bytes: &[u8]) -> UtilitiesResult<Ed25519PublicKey> {
        match Ed25519PublicKey::from_bytes(bytes) {
            Ok(public_key) => Ok(public_key),
            Err(_) => Err(UtilitiesError::InvalidBytesForEd25519PublicKey),
        }
    }

    #[cfg(feature = "ed25519")]
    pub fn to_ed25519_sig(bytes: &[u8]) -> UtilitiesResult<Ed25519Signature> {
        match Ed25519Signature::from_bytes(bytes) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(UtilitiesError::InvalidBytesForEd25519Signature),
        }
    }

    #[cfg(feature = "sr25519")]
    pub fn to_sr25519_keypair(bytes: &[u8]) -> UtilitiesResult<Sr25519Keypair> {
        match Sr25519Keypair::from_bytes(bytes) {
            Ok(keypair) => Ok(keypair),
            Err(_) => Err(UtilitiesError::InvalidBytesForSr25519Keypair),
        }
    }

    #[cfg(feature = "sr25519")]
    pub fn to_sr25519_publickey(bytes: &[u8]) -> UtilitiesResult<Sr25519PublicKey> {
        match Sr25519PublicKey::from_bytes(bytes) {
            Ok(public_key) => Ok(public_key),
            Err(_) => Err(UtilitiesError::InvalidBytesForSr25519PublicKey),
        }
    }

    #[cfg(feature = "sr25519")]
    pub fn to_sr25519_sig(bytes: &[u8]) -> UtilitiesResult<Sr25519Signature> {
        match Sr25519Signature::from_bytes(bytes) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(UtilitiesError::InvalidBytesForSr25519Signature),
        }
    }
}
