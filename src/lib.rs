//! # NQV (Quasigroup Vector Cipher)
//!
//! **NQV** is a high-throughput, hardware-accelerated symmetric cipher implemented in pure Rust.
//! It utilizes Quasigroup Vector math, 256-bit AVX2 SIMD intrinsics, and adaptive multi-core parallelism.
//!
//! - **Author**: Muhammad Iqbal Rifai ([GitHub: py7hon](https://github.com/py7hon))
//! - **License**: Apache-2.0
//!
//! ## Key Features
//! - **Zero External Dependencies**: Core algorithm runs without third-party crates.
//! - **AVX2 Acceleration**: Hardware-level 256-bit SIMD register operations processing 8 blocks (256 bytes) simultaneously.
//! - **Adaptive Multi-Core Parallelism**: Dynamic chunk allocation across available logical CPU cores.
//! - **Automatic Fallback**: Transparently dispatches to a pure scalar execution path on non-AVX2 CPUs.
//!
//! ## Quick Start
//! ```rust
//! use nqv::Nqv;
//!
//! let key = [0x42u8; 32]; // 256-bit key
//! let iv  = [0x99u8; 32]; // 256-bit IV / Nonce
//! let rounds = 8;
//!
//! let cipher = Nqv::new(&key, rounds);
//!
//! let plaintext = b"High performance Quasigroup Vector cryptography in pure Rust.";
//!
//! // Encrypt using adaptive multi-threaded transform
//! let ciphertext = cipher.stream_transform_parallel(plaintext, &iv);
//!
//! // Decrypt (CTR mode stream cipher is self-inverse)
//! let decrypted = cipher.stream_transform_parallel(&ciphertext, &iv);
//!
//! assert_eq!(plaintext.as_slice(), decrypted.as_slice());
//! ```

#![deny(missing_docs)]

pub mod cipher;
pub mod constants;
pub mod counter;
pub mod parallel;
pub mod scalar;
pub mod simd;

pub use cipher::{Nqv, NQV};
pub use constants::*;
pub use counter::{advance_counter, offset_counter};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_advance() {
        let mut ctr = [0u8; 32];
        advance_counter(&mut ctr);
        assert_eq!(ctr[31], 1);
        ctr[31] = 255;
        advance_counter(&mut ctr);
        assert_eq!(ctr[31], 0);
        assert_eq!(ctr[30], 1);
    }

    #[test]
    fn test_counter_offset() {
        let mut ctr = [0u8; 32];
        offset_counter(&mut ctr, 0x0102);
        assert_eq!(ctr[30], 1);
        assert_eq!(ctr[31], 2);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0xAAu8; 32];
        let iv = [0x55u8; 32];
        let cipher = Nqv::new(&key, 8);

        let data = b"The quick brown fox jumps over the lazy dog";
        let ct = cipher.stream_transform_parallel(data, &iv);
        let pt = cipher.stream_transform_parallel(&ct, &iv);

        assert_eq!(data.as_slice(), pt.as_slice());
    }

    #[test]
    fn test_scalar_vs_avx2_parity() {
        if std::is_x86_feature_detected!("avx2") {
            let key = [0x12u8; 32];
            let iv = [0x34u8; 32];
            let cipher = Nqv::new(&key, 8);

            for &len in &[256, 512, 1024, 65536] {
                let buf = vec![0x77u8; len];
                let scalar_out = cipher.stream_transform_scalar(&buf, &iv);
                let avx2_out = unsafe { cipher.stream_transform_avx2(&buf, &iv) };
                assert_eq!(scalar_out, avx2_out, "Mismatch at len {}", len);
            }
        }
    }

    #[test]
    fn test_test_vector() {
        let key = [0x77u8; 32];
        let iv = [0x22u8; 32];
        let cipher = Nqv::new(&key, 8);
        let ct = cipher.stream_transform_x16(&[0u8; 32], &iv);
        let hex_str: String = ct.iter().map(|b| format!("{:02x}", b)).collect();
        println!("TEST VECTOR CT HEX: {}", hex_str);
    }
}
