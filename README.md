### Web3Utilities

`web3utilities` crate is a library offering commonly used cryptographic and timestamp data structures common in Web3, asymmetric cryptography, symmetric cryptography and timestamps.

This crate has implementations for constant-time equality by default for all data structures that involve symmetric, timestamp and asymmetric cryptography. There are also `fmt::Debug` implementations using Base58 encoding for `Ed25519` and `SR25519` data structures and hex encoding for `X25519` and hashing data structures.

`Utilities` struct is also provided for commonly methods for conversions.
