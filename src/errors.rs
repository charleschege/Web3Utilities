#[cfg(feature = "common")]
use borsh::{BorshDeserialize, BorshSerialize};

#[cfg(feature = "common")]
pub type UtilitiesResult<T> = Result<T, UtilitiesError>;

#[cfg(feature = "common")]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum UtilitiesError {
    LengthLessThan12Bytes,
    LengthGreaterThan12Bytes,
    LengthLessThan24Bytes,
    LengthGreaterThan24Bytes,
    LengthLessThan32Bytes,
    LengthGreaterThan32Bytes,
    LengthLessThan64Bytes,
    LengthGreaterThan64Bytes,
    InvalidBytesForEd25519Keypair,
    InvalidBytesForEd25519PublicKey,
    InvalidBytesForEd25519Signature,
    InvalidBytesForSr25519Keypair,
    InvalidBytesForSr25519PublicKey,
    InvalidBytesForSr25519Signature,
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    /// or `A...F`.
    HexInvalidHexCharacter {
        c: String,
        index: usize,
    },

    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    HexOddLength,

    /// If the hex string is decoded into a fixed sized container, such as an
    /// array, the hex string's length * 2 has to match the container's
    /// length.
    HexInvalidStringLength,
    Base58BufferTooSmall,
    Base58InvalidCharacter {
        character: String,
        index: usize,
    },
    Base58NonAsciiCharacter {
        index: usize,
    },
    Tai64LengthInvalid,
    Tai64NanosInvalid,
    /// The duration provided is smaller than the UNIX_EPOCH.
    /// This operation is currently not supported
    Tai64InvalidEarlierDuaration,
    UnsupportedBase58Error,
}

#[cfg(feature = "tai64")]
impl From<tai64::Error> for UtilitiesError {
    fn from(error: tai64::Error) -> Self {
        match error {
            tai64::Error::LengthInvalid => UtilitiesError::Tai64LengthInvalid,
            tai64::Error::NanosInvalid => UtilitiesError::Tai64NanosInvalid,
        }
    }
}

#[cfg(feature = "base58")]
impl From<bs58::decode::Error> for UtilitiesError {
    fn from(error: bs58::decode::Error) -> Self {
        use bs58::decode::Error as Bs58Error;

        match error {
            Bs58Error::BufferTooSmall => UtilitiesError::Base58BufferTooSmall,
            Bs58Error::InvalidCharacter { character, index } => {
                UtilitiesError::Base58InvalidCharacter {
                    character: character.to_string(),
                    index,
                }
            }
            Bs58Error::NonAsciiCharacter { index } => {
                UtilitiesError::Base58NonAsciiCharacter { index }
            }
            _ => UtilitiesError::UnsupportedBase58Error,
        }
    }
}

#[cfg(feature = "base58")]
impl From<bs58::encode::Error> for UtilitiesError {
    fn from(error: bs58::encode::Error) -> Self {
        use bs58::encode::Error as Bs58Error;

        match error {
            Bs58Error::BufferTooSmall => UtilitiesError::Base58BufferTooSmall,
            _ => UtilitiesError::UnsupportedBase58Error,
        }
    }
}

#[cfg(feature = "hex")]
impl From<hex::FromHexError> for UtilitiesError {
    fn from(error: hex::FromHexError) -> Self {
        match error {
            hex::FromHexError::OddLength => UtilitiesError::HexOddLength,
            hex::FromHexError::InvalidStringLength => UtilitiesError::HexInvalidStringLength,
            hex::FromHexError::InvalidHexCharacter { c, index } => {
                UtilitiesError::HexInvalidHexCharacter {
                    c: c.to_string(),
                    index,
                }
            }
        }
    }
}
