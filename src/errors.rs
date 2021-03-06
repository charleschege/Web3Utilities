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
    #[cfg(feature = "tai64")]
    /// Utilizes std::time
    SystemtimeInvalidEarlierDuaration,
    #[cfg(feature = "tai64")]
    Tai64LengthInvalid,
    #[cfg(feature = "tai64")]
    Tai64NanosInvalid,
    #[cfg(feature = "tai64")]
    /// The duration provided is smaller than the UNIX_EPOCH.
    /// This operation is currently not supported
    Tai64InvalidEarlierDuaration,
    #[cfg(feature = "base58")]
    UnsupportedBase58Error,
    InvalidEd25519Signature,
    /// The bytes provided could not be encrypted
    XChaCha8Poly1305EncryptionError,
    /// The encrypted bytes provided could not be decrypted
    XChaCha8Poly1305DecryptionError,
    /// The bytes provided for the `ed25519_dalek::Keypair` are invalid
    InvalidBytesForKeyPair,
    /// The bytes provided for the `ed25519_dalek::PublicKey` are invalid
    InvalidBytesForPublicKey,
    /// The bytes provided for the `ed25519_dalek::SecretKey` are invalid
    InvalidBytesForSecretKey,
    /// Could not sign the message. The actual error is opaque
    /// to prevent side-channel attacks
    SigningError,
    /// The memory occupied by `ed25519_dalek::Keypair` stored in `Ed25519Vault`
    /// could not be wiped
    MemoryCouldNotbeZeroized,
    Io(IoErrorKind),
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

impl From<std::io::Error> for UtilitiesError {
    fn from(error: std::io::Error) -> Self {
        use std::io::ErrorKind;

        match error.kind() {
            ErrorKind::NotFound => UtilitiesError::Io(IoErrorKind::NotFound),
            ErrorKind::PermissionDenied => UtilitiesError::Io(IoErrorKind::PermissionDenied),
            ErrorKind::ConnectionRefused => UtilitiesError::Io(IoErrorKind::ConnectionRefused),
            ErrorKind::ConnectionReset => UtilitiesError::Io(IoErrorKind::ConnectionReset),
            ErrorKind::ConnectionAborted => UtilitiesError::Io(IoErrorKind::ConnectionAborted),
            ErrorKind::NotConnected => UtilitiesError::Io(IoErrorKind::NotConnected),
            ErrorKind::AddrInUse => UtilitiesError::Io(IoErrorKind::AddrInUse),
            ErrorKind::AddrNotAvailable => UtilitiesError::Io(IoErrorKind::AddrNotAvailable),
            ErrorKind::BrokenPipe => UtilitiesError::Io(IoErrorKind::BrokenPipe),
            ErrorKind::AlreadyExists => UtilitiesError::Io(IoErrorKind::AlreadyExists),
            ErrorKind::WouldBlock => UtilitiesError::Io(IoErrorKind::WouldBlock),
            ErrorKind::InvalidInput => UtilitiesError::Io(IoErrorKind::InvalidInput),
            ErrorKind::InvalidData => UtilitiesError::Io(IoErrorKind::InvalidData),
            ErrorKind::TimedOut => UtilitiesError::Io(IoErrorKind::TimedOut),
            ErrorKind::WriteZero => UtilitiesError::Io(IoErrorKind::WriteZero),
            ErrorKind::Interrupted => UtilitiesError::Io(IoErrorKind::Interrupted),
            ErrorKind::Other => UtilitiesError::Io(IoErrorKind::Other),
            ErrorKind::UnexpectedEof => UtilitiesError::Io(IoErrorKind::UnexpectedEof),
            _ => UtilitiesError::Io(IoErrorKind::Unsupported),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum IoErrorKind {
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    Interrupted,
    Other,
    UnexpectedEof,
    Unsupported,
}
