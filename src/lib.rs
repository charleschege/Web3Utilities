mod cryptography;
pub use cryptography::*;

mod formats;
pub use formats::*;

mod errors;
pub use errors::*;

mod data_types;
pub use data_types::*;

#[cfg(feature = "random")]
mod random;
#[cfg(feature = "random")]
pub use random::*;

#[cfg(feature = "common")]
pub struct Utilities;

#[cfg(test)]
mod sanity_tests {
    use crate::*;

    #[test]
    fn tests_12byte() {
        let byte8 = [0u8; 8];
        let byte12 = [0u8; 12];
        let byte24 = [1u8; 24];

        assert!(Utilities::to_12byte_array(&byte12).is_ok());
        assert!(Utilities::to_12byte_array(&byte24).is_err());
        assert_eq!(Ok(byte12), Utilities::to_12byte_array(&byte12));
        assert_eq!(
            Err(UtilitiesError::LengthLessThan12Bytes),
            Utilities::to_12byte_array(&byte8)
        );
        assert_eq!(
            Err(UtilitiesError::LengthGreaterThan12Bytes),
            Utilities::to_12byte_array(&byte24)
        );
    }

    #[test]
    fn test_24bytes() {
        let byte12 = [0u8; 12];
        let byte24 = [1u8; 24];
        let byte32 = [2u8; 32];

        assert!(Utilities::to_24byte_array(&byte24).is_ok());
        assert!(Utilities::to_24byte_array(&byte12).is_err());
        assert_eq!(Ok(byte24), Utilities::to_24byte_array(&byte24));
        assert_eq!(
            Err(UtilitiesError::LengthLessThan24Bytes),
            Utilities::to_24byte_array(&byte12)
        );
        assert_eq!(
            Err(UtilitiesError::LengthGreaterThan24Bytes),
            Utilities::to_24byte_array(&byte32)
        );
    }

    #[test]
    fn test_32byte() {
        let byte12 = [0u8; 12];
        let byte24 = [1u8; 24];
        let byte32 = [2u8; 32];
        let byte64 = [3u8; 64];

        assert!(Utilities::to_32byte_array(&byte32).is_ok());
        assert!(Utilities::to_32byte_array(&byte12).is_err());
        assert_eq!(Ok(byte32), Utilities::to_32byte_array(&byte32));
        assert_eq!(
            Err(UtilitiesError::LengthLessThan32Bytes),
            Utilities::to_32byte_array(&byte24)
        );
        assert_eq!(
            Err(UtilitiesError::LengthGreaterThan32Bytes),
            Utilities::to_32byte_array(&byte64)
        );
    }

    #[test]
    fn test_64byte() {
        let byte32 = [2u8; 32];
        let byte64 = [3u8; 64];
        let byte65 = [4u8; 65];

        assert!(Utilities::to_64byte_array(&byte64).is_ok());
        assert!(Utilities::to_64byte_array(&byte32).is_err());
        assert_eq!(Ok(byte64), Utilities::to_64byte_array(&byte64));
        assert_eq!(
            Err(UtilitiesError::LengthLessThan64Bytes),
            Utilities::to_64byte_array(&byte32)
        );
        assert_eq!(
            Err(UtilitiesError::LengthGreaterThan64Bytes),
            Utilities::to_64byte_array(&byte65)
        );
    }

    #[test]
    fn test_hex() {
        let byte12 = [0u8; 12];

        let encode = hex::encode(&byte12);
        let decode = Utilities::hex_to_bytes(&encode);
        assert!(decode.is_ok());
        assert_eq!(Utilities::to_12byte_array(&decode.unwrap()), Ok(byte12));

        let mut odd_length_hex = String::new();
        odd_length_hex.push_str(&encode);
        odd_length_hex.push_str("Kvx");
        assert!(Utilities::hex_to_bytes(&odd_length_hex).is_err());
        assert_eq!(
            Utilities::hex_to_bytes(&odd_length_hex),
            Err(UtilitiesError::HexOddLength)
        );

        let mut invalid_hex = String::new();
        invalid_hex.push_str(&encode);
        invalid_hex.push_str("Kx");
        dbg!(&invalid_hex);
        assert!(Utilities::hex_to_bytes(&invalid_hex).is_err());
        assert_eq!(
            Utilities::hex_to_bytes(&invalid_hex),
            Err(UtilitiesError::HexInvalidHexCharacter {
                c: "K".to_owned(),
                index: 24
            })
        );

        let mut decode_buffer = [1u8; 12];
        let decode = Utilities::hex_to_buffer(&encode, &mut decode_buffer);
        assert!(decode.is_ok());
        assert_eq!(Utilities::to_12byte_array(&decode_buffer), Ok(byte12));

        let mut decode_buffer = [1u8; 10];
        let decode = Utilities::hex_to_buffer(&encode, &mut decode_buffer);
        assert!(decode.is_err());
        assert_eq!(Err(UtilitiesError::HexInvalidStringLength), decode);
    }

    #[test]
    fn test_cryptography() {
        let keypair_bytes = [
            192, 124, 112, 245, 179, 102, 114, 187, 193, 108, 248, 172, 161, 233, 191, 205, 55,
            190, 61, 187, 204, 196, 248, 14, 179, 123, 158, 48, 21, 133, 68, 241, 236, 213, 78,
            168, 143, 154, 134, 46, 186, 56, 185, 164, 74, 25, 225, 48, 50, 122, 62, 65, 74, 163,
            240, 233, 213, 239, 45, 217, 152, 14, 1, 151,
        ];
        let keypair = Utilities::to_ed25519_keypair(&keypair_bytes);
        assert!(keypair.is_ok());
        let bad_keypair = Utilities::to_ed25519_keypair(&keypair_bytes[0..32]);
        assert!(bad_keypair.is_err());

        let keypair = keypair.unwrap();
        let public_key_bytes = keypair.public.to_bytes();
        let public_key = Utilities::to_ed25519_publickey(&public_key_bytes);
        assert!(public_key.is_ok());
        let bad_keypair = Utilities::to_ed25519_publickey(&public_key_bytes[0..30]);
        assert!(bad_keypair.is_err());

        let signature_bytes = [
            118, 244, 145, 231, 188, 52, 181, 134, 7, 116, 115, 129, 28, 98, 114, 167, 68, 185, 54,
            113, 55, 49, 194, 14, 179, 41, 126, 28, 179, 116, 169, 159, 78, 110, 141, 248, 189, 74,
            81, 224, 151, 46, 230, 53, 135, 60, 139, 21, 125, 69, 187, 200, 2, 138, 201, 22, 255,
            185, 192, 234, 176, 31, 219, 15,
        ];

        let signature = Utilities::to_ed25519_sig(&signature_bytes);
        assert!(signature.is_ok());
        let bad_signature = Utilities::to_ed25519_sig(&signature_bytes[0..32]);
        assert!(bad_signature.is_err());
        assert_eq!(signature_bytes, signature.unwrap().to_bytes())
    }

    #[test]
    fn test_random() {
        assert_eq!(24usize, Utilities::rand24().len());
        assert_eq!(32usize, Utilities::rand32().len());
        assert_eq!(64usize, Utilities::rand64().len());

        assert_eq!(24usize, Utilities::rand24_chacha12().len());
        assert_eq!(32usize, Utilities::rand32_chacha12().len());
        assert_eq!(64usize, Utilities::rand64_chacha12().len());

        assert_eq!(24usize, Utilities::rand24_chacha20().len());
        assert_eq!(32usize, Utilities::rand32_chacha20().len());
        assert_eq!(64usize, Utilities::rand64_chacha20().len());
    }
}
