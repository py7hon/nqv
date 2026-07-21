//! Core Nqv cipher struct definition, constructor, and single-thread feature dispatcher.

/// The NQV cipher instance holding the pre-calculated round key schedule.
#[derive(Debug, Clone)]
pub struct Nqv {
    schedule: Vec<[u64; 4]>,
    /// Master 256-bit round keys derived from the master key.
    pub round_keys: [u64; 4],
    /// Total number of rounds configured for this cipher instance.
    pub rounds: usize,
}

/// Convenient uppercase alias for the [`Nqv`] cipher struct.
pub type NQV = Nqv;

impl Nqv {
    /// Creates a new NQV cipher instance given a 256-bit (32-byte) key and round count.
    ///
    /// # Arguments
    /// * `key` - A 32-byte array containing the 256-bit secret key.
    /// * `rounds` - The number of permutation rounds (typically 8 for standard security/speed tradeoff).
    ///
    /// # Example
    /// ```rust
    /// use nqv::Nqv;
    /// let key = [0x01u8; 32];
    /// let cipher = Nqv::new(&key, 8);
    /// assert_eq!(cipher.rounds, 8);
    /// ```
    pub fn new(key: &[u8; 32], rounds: usize) -> Self {
        let mut rk = [0u64; 4];
        for i in 0..4 {
            rk[i] = u64::from_le_bytes(key[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let schedule = (0..rounds)
            .map(|r| {
                let mut s = [0u64; 4];
                for i in 0..4 {
                    let rot = ((r as u32 * 11) + (i as u32 * 17)) % 64;
                    s[i] = rk[i].rotate_left(rot);
                }
                s
            })
            .collect();
        Self { schedule, round_keys: rk, rounds }
    }

    /// Internal accessor for the pre-calculated round key schedule.
    #[inline(always)]
    pub(crate) fn schedule(&self) -> &[[u64; 4]] {
        &self.schedule
    }

    /// Single-threaded stream transformation with automatic target feature detection.
    ///
    /// Automatically selects the hardware-accelerated AVX2 SIMD path if available on the current CPU,
    /// falling back to scalar processing otherwise.
    ///
    /// # Arguments
    /// * `data` - Byte slice to transform (encrypt or decrypt).
    /// * `iv` - 256-bit (32-byte) initialization vector / counter start value.
    ///
    /// # Example
    /// ```rust
    /// use nqv::Nqv;
    /// let cipher = Nqv::new(&[0x07u8; 32], 8);
    /// let iv = [0x12u8; 32];
    /// let ct = cipher.stream_transform_x16(b"Secret Data", &iv);
    /// let pt = cipher.stream_transform_x16(&ct, &iv);
    /// assert_eq!(pt, b"Secret Data");
    /// ```
    pub fn stream_transform_x16(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            if std::is_x86_feature_detected!("avx2") {
                return unsafe { self.stream_transform_avx2(data, iv) };
            }
        }
        self.stream_transform_scalar(data, iv)
    }
}
