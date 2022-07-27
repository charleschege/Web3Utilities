#[cfg(feature = "common")]
use crate::{Utilities, UtilitiesError, UtilitiesResult};

#[cfg(feature = "systemtime")]
use std::time::SystemTime;

#[cfg(feature = "common")]
impl Utilities {
    pub fn to_12byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 12]> {
        if bytes.len() < 12 {
            return Err(UtilitiesError::LengthLessThan12Bytes);
        }

        if bytes.len() > 12 {
            return Err(UtilitiesError::LengthGreaterThan12Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    pub fn to_24byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 24]> {
        if bytes.len() < 24 {
            return Err(UtilitiesError::LengthLessThan24Bytes);
        }

        if bytes.len() > 24 {
            return Err(UtilitiesError::LengthGreaterThan24Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    pub fn to_32byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 32]> {
        if bytes.len() < 32 {
            return Err(UtilitiesError::LengthLessThan32Bytes);
        }

        if bytes.len() > 32 {
            return Err(UtilitiesError::LengthGreaterThan32Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    pub fn to_64byte_array(bytes: &[u8]) -> UtilitiesResult<[u8; 64]> {
        if bytes.len() < 64 {
            return Err(UtilitiesError::LengthLessThan64Bytes);
        }

        if bytes.len() > 64 {
            return Err(UtilitiesError::LengthGreaterThan64Bytes);
        }

        Ok(bytes.try_into().unwrap()) // Never fails due to checks above
    }

    #[cfg(feature = "hex")]
    pub fn hex_to_bytes(value: &str) -> UtilitiesResult<Vec<u8>> {
        Ok(hex::decode(value)?)
    }

    #[cfg(feature = "hex")]
    pub fn hex_to_buffer(value: &str, buffer: &mut [u8]) -> UtilitiesResult<()> {
        Ok(hex::decode_to_slice(value, buffer)?)
    }

    #[cfg(feature = "base58")]
    pub fn base58_to_bytes(value: &str) -> UtilitiesResult<Vec<u8>> {
        Ok(bs58::decode(value).into_vec()?)
    }

    #[cfg(feature = "tai64")]
    pub fn bytes_to_tai64n(value: &[u8]) -> UtilitiesResult<tai64::Tai64N> {
        Ok(tai64::Tai64N::from_slice(value)?)
    }

    #[cfg(feature = "tai64")]
    pub fn tai64_get_secs(value: tai64::Tai64N) -> UtilitiesResult<u64> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_secs()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    #[cfg(feature = "tai64")]
    pub fn tai64_get_millis(value: tai64::Tai64N) -> UtilitiesResult<u128> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_millis()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    #[cfg(feature = "tai64")]
    pub fn tai64_get_nanos(value: tai64::Tai64N) -> UtilitiesResult<u128> {
        match value.duration_since(&tai64::Tai64N::UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_nanos()),
            Err(_) => Err(UtilitiesError::Tai64InvalidEarlierDuaration),
        }
    }

    #[cfg(feature = "systemtime")]
    pub fn systemtime_get_secs(value: SystemTime) -> UtilitiesResult<u64> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_secs()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }

    #[cfg(feature = "systemtime")]
    pub fn systemtime_get_millis(value: SystemTime) -> UtilitiesResult<u128> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_millis()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }

    #[cfg(feature = "systemtime")]
    pub fn systemtime_get_nanos(value: SystemTime) -> UtilitiesResult<u128> {
        use std::time::UNIX_EPOCH;

        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(duration.as_nanos()),
            Err(_) => Err(UtilitiesError::SystemtimeInvalidEarlierDuaration),
        }
    }
}
