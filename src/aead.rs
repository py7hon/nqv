//! Authenticated Encryption with Associated Data (AEAD) module for NQV.

use crate::cipher::Nqv;
use crate::constants::{C_E, C_PI, C_SQ2, C_SQ3};
use std::error::Error;
use std::fmt;

/// Authentication error returned when AEAD tag verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NqvAeadError {
    /// Verification failed: MAC tag mismatch or payload tampered.
    Unauthenticated,
}

impl fmt::Display for NqvAeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NqvAeadError::Unauthenticated => write!(f, "NQV-AEAD Authentication Failed: MAC tag mismatch or payload tampered"),
        }
    }
}

impl Error for NqvAeadError {}

/// Constant-time 16-byte tag equality comparison to prevent timing side-channels.
#[inline(always)]
fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

impl Nqv {
    /// Computes 16-byte Quasigroup Vector MAC (QVM-MAC) over AAD and Ciphertext.
    pub fn compute_mac(&self, aad: &[u8], ciphertext: &[u8], iv: &[u8; 32]) -> [u8; 16] {
        let schedule = self.schedule();
        let mut acc = [
            u64::from_le_bytes(iv[0..8].try_into().unwrap()) ^ C_PI,
            u64::from_le_bytes(iv[8..16].try_into().unwrap()) ^ C_E,
            u64::from_le_bytes(iv[16..24].try_into().unwrap()) ^ C_SQ2,
            u64::from_le_bytes(iv[24..32].try_into().unwrap()) ^ C_SQ3,
        ];

        // Process Associated Data (AAD) in 32-byte blocks
        for chunk in aad.chunks(32) {
            let mut block = [0u8; 32];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..4 {
                let w = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
                acc[i] = acc[i].rotate_left(13) ^ w ^ schedule[0][i];
                acc[i] = acc[i].wrapping_add(schedule[self.rounds - 1][i]);
            }
        }

        // Process Ciphertext in 32-byte blocks
        for chunk in ciphertext.chunks(32) {
            let mut block = [0u8; 32];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..4 {
                let w = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
                acc[i] = acc[i].rotate_left(17) ^ w ^ schedule[i % self.rounds][i];
                acc[i] = acc[i].wrapping_add(schedule[(i + 1) % self.rounds][i]);
            }
        }

        // Fold AAD length and Ciphertext length
        let len_block_0 = (aad.len() as u64).wrapping_mul(C_PI) ^ (ciphertext.len() as u64);
        let len_block_1 = (ciphertext.len() as u64).wrapping_mul(C_E) ^ (aad.len() as u64);
        acc[0] ^= len_block_0;
        acc[1] ^= len_block_1;

        // Non-linear MAC finalization squeeze
        for r in 0..self.rounds {
            let rk = schedule[r];
            acc[0] = (acc[0].rotate_left(11) ^ rk[0]).wrapping_add(C_PI);
            acc[1] = (acc[1].rotate_left(17) ^ rk[1]).wrapping_add(C_E);
            acc[2] = (acc[2].rotate_left(23) ^ rk[2]).wrapping_add(C_SQ2);
            acc[3] = (acc[3].rotate_left(29) ^ rk[3]).wrapping_add(C_SQ3);

            let t = acc[0] ^ acc[1] ^ acc[2] ^ acc[3];
            acc[0] = acc[0].wrapping_add(t);
            acc[1] ^= t.rotate_left(19);
        }

        let tag_word0 = acc[0] ^ acc[2];
        let tag_word1 = acc[1] ^ acc[3];

        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&tag_word0.to_le_bytes());
        tag[8..16].copy_from_slice(&tag_word1.to_le_bytes());
        tag
    }

    /// Authenticated Encryption (AEAD Seal)
    /// Encrypts plaintext and returns `(ciphertext, 16-byte authentication tag)`.
    pub fn seal_aead(&self, plaintext: &[u8], aad: &[u8], iv: &[u8; 32]) -> (Vec<u8>, [u8; 16]) {
        let ciphertext = self.stream_transform_parallel(plaintext, iv);
        let tag = self.compute_mac(aad, &ciphertext, iv);
        (ciphertext, tag)
    }

    /// Authenticated Decryption (AEAD Open)
    /// Verifies authentication tag in constant time. Returns plaintext if valid,
    /// or `NqvAeadError::Unauthenticated` if tampered.
    pub fn open_aead(
        &self,
        ciphertext: &[u8],
        tag: &[u8; 16],
        aad: &[u8],
        iv: &[u8; 32],
    ) -> Result<Vec<u8>, NqvAeadError> {
        let expected_tag = self.compute_mac(aad, ciphertext, iv);
        if !constant_time_eq_16(tag, &expected_tag) {
            return Err(NqvAeadError::Unauthenticated);
        }
        Ok(self.stream_transform_parallel(ciphertext, iv))
    }
}
