use crate::Utilities;
use nanorand::{BufferedRng, ChaCha12, ChaCha20, ChaCha8, Rng};

impl Utilities {
    /// Generate 24 bytes of random data using `ChaCha8`
    pub fn rand24() -> [u8; 24] {
        let mut buffer = [0u8; 24];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 32 bytes of random data using `ChaCha8`
    pub fn rand32() -> [u8; 32] {
        let mut buffer = [0u8; 32];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 64 bytes of random data using `ChaCha8`
    pub fn rand64() -> [u8; 64] {
        let mut buffer = [0u8; 64];
        let mut rng = BufferedRng::new(ChaCha8::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 24 bytes of random data using `ChaCha12`
    pub fn rand24_chacha12() -> [u8; 24] {
        let mut buffer = [0u8; 24];
        let mut rng = BufferedRng::new(ChaCha12::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 32 bytes of random data using `ChaCha12`
    pub fn rand32_chacha12() -> [u8; 32] {
        let mut buffer = [0u8; 32];
        let mut rng = BufferedRng::new(ChaCha12::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 64 bytes of random data using `ChaCha12`
    pub fn rand64_chacha12() -> [u8; 64] {
        let mut buffer = [0u8; 64];
        let mut rng = BufferedRng::new(ChaCha12::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 24 bytes of random data using `ChaCha20`
    pub fn rand24_chacha20() -> [u8; 24] {
        let mut buffer = [0u8; 24];
        let mut rng = BufferedRng::new(ChaCha20::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 24 bytes of random data using `ChaCha20`
    pub fn rand32_chacha20() -> [u8; 32] {
        let mut buffer = [0u8; 32];
        let mut rng = BufferedRng::new(ChaCha20::new());
        rng.fill(&mut buffer);

        buffer
    }

    /// Generate 24 bytes of random data using `ChaCha20`
    pub fn rand64_chacha20() -> [u8; 64] {
        let mut buffer = [0u8; 64];
        let mut rng = BufferedRng::new(ChaCha20::new());
        rng.fill(&mut buffer);

        buffer
    }
}
