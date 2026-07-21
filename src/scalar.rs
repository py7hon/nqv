//! Scalar Quasigroup Vector execution path and block permutation logic.

use crate::cipher::Nqv;
use crate::constants::{C_E, C_PI, C_SQ2, C_SQ3};
use crate::counter::advance_counter;

impl Nqv {
    #[inline(always)]
    fn qvm_mix(s: &mut [u64; 4], rk: &[u64; 4]) {
        s[0] = (s[0].rotate_left(11) ^ rk[0].rotate_right(7)).wrapping_add(C_PI);
        s[1] = (s[1].rotate_left(17) ^ rk[1].rotate_right(13)).wrapping_add(C_E);
        s[2] = (s[2].rotate_left(23) ^ rk[2].rotate_right(19)).wrapping_add(C_SQ2);
        s[3] = (s[3].rotate_left(29) ^ rk[3].rotate_right(23)).wrapping_add(C_SQ3);

        let t0 = s[0].rotate_left(31) ^ s[0].rotate_right(17);
        let t1 = s[1].rotate_left(37) ^ s[1].rotate_right(19);
        let t2 = s[2].rotate_left(41) ^ s[2].rotate_right(23);
        let t3 = s[3].rotate_left(43) ^ s[3].rotate_right(29);

        s[0] = s[0].wrapping_add(t0);
        s[1] = s[1].wrapping_add(t1);
        s[2] = s[2].wrapping_add(t2);
        s[3] = s[3].wrapping_add(t3);
    }

    #[inline(always)]
    fn qvm_diffuse(s: &mut [u64; 4]) {
        let (a, b, c, d) = (s[0], s[1], s[2], s[3]);
        s[0] = (a.rotate_left(13) ^ b.rotate_right(5)).wrapping_add(C_SQ3);
        s[1] = (b.rotate_left(19) ^ c.rotate_right(11)).wrapping_add(C_SQ2);
        s[2] = (c.rotate_left(23) ^ d.rotate_right(17)).wrapping_add(C_E);
        s[3] = (d.rotate_left(31) ^ a.rotate_right(29)).wrapping_add(C_PI);
    }

    #[inline(always)]
    fn load(b: &[u8; 32]) -> [u64; 4] {
        [
            u64::from_le_bytes(b[0..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
            u64::from_le_bytes(b[16..24].try_into().unwrap()),
            u64::from_le_bytes(b[24..32].try_into().unwrap()),
        ]
    }

    #[inline(always)]
    fn xor_store(out: &mut [u8; 32], s: &[u64; 4], plain: &[u8; 32]) {
        for lane in 0..4 {
            let ks = s[lane].to_le_bytes();
            let base = lane * 8;
            out[base]     = plain[base]     ^ ks[0];
            out[base + 1] = plain[base + 1] ^ ks[1];
            out[base + 2] = plain[base + 2] ^ ks[2];
            out[base + 3] = plain[base + 3] ^ ks[3];
            out[base + 4] = plain[base + 4] ^ ks[4];
            out[base + 5] = plain[base + 5] ^ ks[5];
            out[base + 6] = plain[base + 6] ^ ks[6];
            out[base + 7] = plain[base + 7] ^ ks[7];
        }
    }

    /// Permutes a 32-byte block in-place using the NQV Quasigroup Vector round schedule.
    ///
    /// Useful for generating nonces, raw keystreams, or block-level cryptographic primitives.
    ///
    /// # Example
    /// ```rust
    /// use nqv::Nqv;
    /// let key = [0x42u8; 32];
    /// let cipher = Nqv::new(&key, 8);
    /// let mut block = [0u8; 32];
    /// cipher.permute(&mut block);
    /// assert_ne!(block, [0u8; 32]);
    /// ```
    pub fn permute(&self, block: &mut [u8; 32]) {
        let mut s = Self::load(block);
        for rk in self.schedule() {
            Self::qvm_mix(&mut s, rk);
            Self::qvm_diffuse(&mut s);
        }
        block[0..8].copy_from_slice(&s[0].to_le_bytes());
        block[8..16].copy_from_slice(&s[1].to_le_bytes());
        block[16..24].copy_from_slice(&s[2].to_le_bytes());
        block[24..32].copy_from_slice(&s[3].to_le_bytes());
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    fn round_x16(
        s00: &mut [u64;4], s01: &mut [u64;4], s02: &mut [u64;4], s03: &mut [u64;4],
        s04: &mut [u64;4], s05: &mut [u64;4], s06: &mut [u64;4], s07: &mut [u64;4],
        s08: &mut [u64;4], s09: &mut [u64;4], s10: &mut [u64;4], s11: &mut [u64;4],
        s12: &mut [u64;4], s13: &mut [u64;4], s14: &mut [u64;4], s15: &mut [u64;4],
        rk: &[u64; 4],
    ) {
        Self::qvm_mix(s00, rk); Self::qvm_mix(s01, rk);
        Self::qvm_mix(s02, rk); Self::qvm_mix(s03, rk);
        Self::qvm_mix(s04, rk); Self::qvm_mix(s05, rk);
        Self::qvm_mix(s06, rk); Self::qvm_mix(s07, rk);
        Self::qvm_mix(s08, rk); Self::qvm_mix(s09, rk);
        Self::qvm_mix(s10, rk); Self::qvm_mix(s11, rk);
        Self::qvm_mix(s12, rk); Self::qvm_mix(s13, rk);
        Self::qvm_mix(s14, rk); Self::qvm_mix(s15, rk);

        Self::qvm_diffuse(s00); Self::qvm_diffuse(s01);
        Self::qvm_diffuse(s02); Self::qvm_diffuse(s03);
        Self::qvm_diffuse(s06); Self::qvm_diffuse(s07);
        Self::qvm_diffuse(s04); Self::qvm_diffuse(s05);
        Self::qvm_diffuse(s08); Self::qvm_diffuse(s09);
        Self::qvm_diffuse(s10); Self::qvm_diffuse(s11);
        Self::qvm_diffuse(s12); Self::qvm_diffuse(s13);
        Self::qvm_diffuse(s14); Self::qvm_diffuse(s15);
    }

    /// Single-threaded scalar implementation processing data in 512-byte blocks.
    ///
    /// Used as standard fallback when AVX2 features are unavailable on target host CPU.
    pub fn stream_transform_scalar(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = *iv;
        let mut it = data.chunks_exact(512);

        for big in &mut it {
            let mut ctr = [[0u8; 32]; 16];
            for c in &mut ctr {
                *c = counter;
                advance_counter(&mut counter);
            }

            let mut s00 = Self::load(&ctr[0]); let mut s01 = Self::load(&ctr[1]);
            let mut s02 = Self::load(&ctr[2]); let mut s03 = Self::load(&ctr[3]);
            let mut s04 = Self::load(&ctr[4]); let mut s05 = Self::load(&ctr[5]);
            let mut s06 = Self::load(&ctr[6]); let mut s07 = Self::load(&ctr[7]);
            let mut s08 = Self::load(&ctr[8]); let mut s09 = Self::load(&ctr[9]);
            let mut s10 = Self::load(&ctr[10]); let mut s11 = Self::load(&ctr[11]);
            let mut s12 = Self::load(&ctr[12]); let mut s13 = Self::load(&ctr[13]);
            let mut s14 = Self::load(&ctr[14]); let mut s15 = Self::load(&ctr[15]);

            for rk in self.schedule() {
                Self::round_x16(
                    &mut s00, &mut s01, &mut s02, &mut s03,
                    &mut s04, &mut s05, &mut s06, &mut s07,
                    &mut s08, &mut s09, &mut s10, &mut s11,
                    &mut s12, &mut s13, &mut s14, &mut s15,
                    rk,
                );
            }

            let mut out = [0u8; 512];
            let states = [
                s00, s01, s02, s03, s04, s05, s06, s07,
                s08, s09, s10, s11, s12, s13, s14, s15,
            ];
            for b in 0..16 {
                let offset = b * 32;
                let plain: &[u8; 32] = big[offset..offset+32].try_into().unwrap();
                let out32: &mut [u8; 32] = (&mut out[offset..offset+32]).try_into().unwrap();
                Self::xor_store(out32, &states[b], plain);
            }
            result.extend_from_slice(&out);
        }

        let rem = it.remainder();
        if !rem.is_empty() {
            let mut out_buf = [0u8; 32];
            for chunk in rem.chunks(32) {
                let mut ks = counter;
                self.permute(&mut ks);
                advance_counter(&mut counter);
                if chunk.len() == 32 {
                    for i in 0..32 { out_buf[i] = chunk[i] ^ ks[i]; }
                    result.extend_from_slice(&out_buf);
                } else {
                    for i in 0..chunk.len() { result.push(chunk[i] ^ ks[i]); }
                }
            }
        }
        result
    }
}
