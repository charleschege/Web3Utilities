use borsh::{BorshDeserialize, BorshSerialize};

/// This data structure  implements From <T> for error types of the
/// dependencies of this crate
pub type UtilitiesResult<T> = Result<T, UtilitiesError>;

/// Common Errors
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum UtilitiesError {
    /// The byte length is less than 12 bytes
    LengthLessThan12Bytes,
    /// The byte length is greater than 12 bytes
    LengthGreaterThan12Bytes,
    /// The byte length is less than 16 bytes
    LengthLessThan16Bytes,
    /// The byte length is greater than 16 bytes
    LengthGreaterThan16Bytes,
    /// The byte length is less than 24 bytes
    LengthLessThan24Bytes,
    /// The byte length is greater than 12 bytes
    LengthGreaterThan24Bytes,
    /// The byte length is less than 32 bytes
    LengthLessThan32Bytes,
    /// The byte length is greater than 12 bytes
    LengthGreaterThan32Bytes,
    /// The byte length is less than 64 bytes
    LengthLessThan64Bytes,
    /// The byte length is greater than 64 bytes
    LengthGreaterThan64Bytes,
    /// The byte length is less than 128 bytes
    LengthLessThan128Bytes,
    /// The byte length is greater than 128 bytes
    LengthGreaterThan128Bytes,
    /// The bytes provided for the Ed25519 Keypair are invalid
    InvalidBytesForEd25519Keypair,
    /// The bytes provided for the Ed25519 Public Key are invalid
    InvalidBytesForEd25519PublicKey,
    /// The bytes provided for the Ed25519 Signature are invalid
    InvalidBytesForEd25519Signature,
    /// The bytes provided for the SR25519 Keypair are invalid
    InvalidBytesForSr25519Keypair,
    /// The bytes provided for the SR25519 Public Key are invalid
    InvalidBytesForSr25519PublicKey,
    /// The bytes provided for the Sr25519 Signature are invalid
    InvalidBytesForSr25519Signature,
    /// An invalid character was found. Valid ones are: `0...9`, `a...f`
    /// or `A...F`.
    HexInvalidHexCharacter {
        /// The invalid hex character
        c: String,
        /// The index of the invalid hex character
        index: usize,
    },

    /// A hex string's length needs to be even, as two digits correspond to
    /// one byte.
    HexOddLength,

    /// If the hex string is decoded into a fixed sized container, such as an
    /// array, the hex string's length * 2 has to match the container's
    /// length.
    HexInvalidStringLength,
    /// Buffer
    Base58BufferTooSmall,
    /// Mirros the error for `bs58` crate
    Base58InvalidCharacter {
        /// The invalid Base58 character
        character: String,
        /// The index of the invalid character
        index: usize,
    },
    /// Mirros the error for `bs58` crate
    Base58NonAsciiCharacter {
        /// The index of the non ASCII character
        index: usize,
    },
    /// Base58 error encountered is not supported
    #[cfg(feature = "base58")]
    UnsupportedBase58Error,
    #[cfg(feature = "tai64")]
    /// Occurs when trying to compare an error duration
    /// with the current duration. The current duration shoud
    /// always be later than the earlier duration.
    /// Utilizes std::time
    SystemtimeInvalidEarlierDuaration,
    #[cfg(feature = "tai64")]
    /// Mirros Errors for Tai64 crate
    Tai64LengthInvalid,
    /// Mirros Errors for Tai64 crate
    #[cfg(feature = "tai64")]
    Tai64NanosInvalid,
    /// Mirros Errors for Tai64 crate
    #[cfg(feature = "tai64")]
    /// The duration provided is smaller than the UNIX_EPOCH.
    /// This operation is currently not supported
    Tai64InvalidEarlierDuaration,
    /// The public key did not sign the provided signature
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
    /// `std::io::ErrorKind` conversion
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

/// Implemetation for `From<std::io::ErrorKind>` for this crate
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum IoErrorKind {
    /// An entity was not found, often a file.
    NotFound,
    /// The operation lacked the necessary privileges to complete.
    PermissionDenied,
    /// The connection was refused by the remote server.
    ConnectionRefused,
    /// The connection was reset by the remote server.
    ConnectionReset,
    /// The connection was aborted (terminated) by the remote server.
    ConnectionAborted,
    ///The network operation failed because it was not connected yet.
    NotConnected,
    /// A socket address could not be bound because the address is already in use elsewhere.
    AddrInUse,
    /// A nonexistent interface was requested or the requested address was not local.
    AddrNotAvailable,
    /// The operation failed because a pipe was closed.
    BrokenPipe,
    /// An entity already exists, often a file.
    AlreadyExists,
    /// The operation needs to block to complete, but the blocking operation was requested to not occur.
    WouldBlock,
    /// A parameter was incorrect.
    InvalidInput,
    /// Data not valid for the operation were encountered.
    /// Unlike InvalidInput, this typically means that the operation parameters were valid, however the error was caused by malformed input data.
    ///
    /// For example, a function that reads a file into a string will error with InvalidData if the file's
    /// contents are not valid UTF-8.
    InvalidData,
    /// The I/O operation's timeout expired, causing it to be canceled.
    TimedOut,
    /// An error returned when an operation could not be completed because a call to write returned Ok(0).
    WriteZero,
    /// An error returned when an operation could not be completed because a call to write returned Ok(0).
    ///
    /// This typically means that an operation could only succeed if it wrote a particular number of bytes but only a smaller number of bytes could be written.
    Interrupted,
    /// Any I/O error not part of this list.
    ///
    /// Errors that are Other now may move to a different or a new ErrorKind variant in the future. It is not recommended to match an error against Other and to expect any additional characteristics, e.g., a specific Error::raw_os_error return value.
    Other,
    /// An error returned when an operation could not be completed because an "end of file" was reached prematurely.
    ///
    /// This typically means that an operation could only succeed if it read a particular number of bytes but only a smaller number of bytes could be read.
    UnexpectedEof,
    /// The error is not supported
    Unsupported,
}
