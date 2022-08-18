#[cfg(feature = "common")]
use crate::{Utilities, UtilitiesError, UtilitiesResult};

#[cfg(feature = "tai64")]
use std::time::SystemTime;

#[cfg(feature = "common")]
impl Utilities {
    /// Convert some bytes to a 12 byte array
    pub fn to_12byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 12]> {
        if bytes.len() < 12 {
            return Err(UtilitiesError::LengthLessThan12Bytes);
        }

        if bytes.len() > 12 {
            return Err(UtilitiesError::LengthGreaterThan12Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// Convert some bytes to a 16 byte array
    pub fn to_16byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 16]> {
        if bytes.len() < 16 {
            return Err(UtilitiesError::LengthLessThan16Bytes);
        }

        if bytes.len() > 16 {
            return Err(UtilitiesError::LengthGreaterThan16Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// Convert some bytes to a 24 byte array
    pub fn to_24byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 24]> {
        if bytes.len() < 24 {
            return Err(UtilitiesError::LengthLessThan24Bytes);
        }

        if bytes.len() > 24 {
            return Err(UtilitiesError::LengthGreaterThan24Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// Convert some bytes to a 32 byte array
    pub fn to_32byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 32]> {
        if bytes.len() < 32 {
            return Err(UtilitiesError::LengthLessThan32Bytes);
        }

        if bytes.len() > 32 {
            return Err(UtilitiesError::LengthGreaterThan32Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// Convert some bytes to a 64 byte array
    pub fn to_64byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 64]> {
        if bytes.len() < 64 {
            return Err(UtilitiesError::LengthLessThan64Bytes);
        }

        if bytes.len() > 64 {
            return Err(UtilitiesError::LengthGreaterThan64Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// Convert some bytes to a 128 byte array
    pub fn to_128byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 128]> {
        if bytes.len() < 128 {
            return Err(UtilitiesError::LengthLessThan128Bytes);
        }

        if bytes.len() > 128 {
            return Err(UtilitiesError::LengthGreaterThan128Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    /// decode hex to bytes
    #[cfg(feature = "hex")]
    pub fn hex_to_bytes(value: &str) -> UtilitiesResult<Vec<u8>> {
        Ok(hex::decode(value)?)
    }

    /// Decode a hex string to a buffer
    #[cfg(feature = "hex")]
    pub fn hex_to_buffer(value: &str, buffer: &mut [u8]) -> UtilitiesResult<()> {
        Ok(hex::decode_to_slice(value, buffer)?)
    }

    /// Decode base58 string
    #[cfg(feature = "base58")]
    pub fn base58_to_bytes(value: &str) -> UtilitiesResult<Vec<u8>> {
        Ok(bs58::decode(value).into_vec()?)
    }

    /// Convert given bytes to a Tai64N structure
    #[cfg(feature = "tai64")]
    pub fn bytes_to_tai64n(value: &[u8]) -> UtilitiesResult<tai64::Tai64N> {
        Ok(tai64::Tai64N::from_slice(value)?)
    }

    /// Convert a `SystemTime` to Tai64N
    #[cfg(feature = "tai64")]
    pub fn systemtime_to_tai64(value: &SystemTime) -> tai64::Tai64N {
        tai64::Tai64N::from_system_time(value)
    }

    /// Get the seconds since `Tai64N::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn tai64_get_secs(value: tai64::Tai64N) -> UtilitiesResult<u64> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_secs()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    /// Get the milliseconds since `Tai64N::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn tai64_get_millis(value: tai64::Tai64N) -> UtilitiesResult<u128> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_millis()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    /// Get the nanoseconds since `Tai64N::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn tai64_get_nanos(value: tai64::Tai64N) -> UtilitiesResult<u128> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_nanos()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    /// Get the seconds since `std::time::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn systemtime_get_secs(value: SystemTime) -> UtilitiesResult<u64> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_secs()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }

    /// Get the milliseconds since `std::time::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn systemtime_get_millis(value: SystemTime) -> UtilitiesResult<u128> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_millis()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }

    /// Get the nanoseconds since `std::time::UNIX_EPOCH`
    #[cfg(feature = "tai64")]
    pub fn systemtime_get_nanos(value: SystemTime) -> UtilitiesResult<u128> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_nanos()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }
}
