//! 256-bit AVX2 SIMD hardware acceleration path.

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use crate::cipher::Nqv;
use crate::constants::{C_E, C_PI, C_SQ2, C_SQ3};
use crate::counter::advance_counter;

impl Nqv {
    /// Single-threaded hardware-accelerated AVX2 256-bit SIMD implementation.
    ///
    /// Processes 8 blocks (256 bytes) concurrently per loop iteration.
    ///
    /// # Safety
    /// This function directly calls target-specific AVX2 intrinsics (`_mm256_*`).
    /// The caller must ensure that the CPU supports AVX2 target features.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    pub unsafe fn stream_transform_avx2(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        let mut counter = *iv;

        let mut it = data.chunks_exact(256);

        let c_nums_mix = _mm256_set_epi64x(C_SQ3 as i64, C_SQ2 as i64, C_E as i64, C_PI as i64);
        let c_nums_diff = _mm256_set_epi64x(C_PI as i64, C_E as i64, C_SQ2 as i64, C_SQ3 as i64);

        let mix_sl = _mm256_set_epi64x(29, 23, 17, 11);
        let mix_sl_inv = _mm256_set_epi64x(64 - 29, 64 - 23, 64 - 17, 64 - 11);
        let mix_rk_sr = _mm256_set_epi64x(23, 19, 13, 7);
        let mix_rk_sr_inv = _mm256_set_epi64x(64 - 23, 64 - 19, 64 - 13, 64 - 7);

        let casc_sl = _mm256_set_epi64x(43, 41, 37, 31);
        let casc_sl_inv = _mm256_set_epi64x(64 - 43, 64 - 41, 64 - 37, 64 - 31);
        let casc_sr = _mm256_set_epi64x(29, 23, 19, 17);
        let casc_sr_inv = _mm256_set_epi64x(64 - 29, 64 - 23, 64 - 19, 64 - 17);

        let diff_sl = _mm256_set_epi64x(31, 23, 19, 13);
        let diff_sl_inv = _mm256_set_epi64x(64 - 31, 64 - 23, 64 - 19, 64 - 13);
        let diff_b_sr = _mm256_set_epi64x(29, 17, 11, 5);
        let diff_b_sr_inv = _mm256_set_epi64x(64 - 29, 64 - 17, 64 - 11, 64 - 5);

        for big in &mut it {
            let mut ctr = [[0u8; 32]; 8];
            for c in &mut ctr {
                *c = counter;
                advance_counter(&mut counter);
            }

            let mut s0 = _mm256_loadu_si256(ctr[0].as_ptr() as *const __m256i);
            let mut s1 = _mm256_loadu_si256(ctr[1].as_ptr() as *const __m256i);
            let mut s2 = _mm256_loadu_si256(ctr[2].as_ptr() as *const __m256i);
            let mut s3 = _mm256_loadu_si256(ctr[3].as_ptr() as *const __m256i);
            let mut s4 = _mm256_loadu_si256(ctr[4].as_ptr() as *const __m256i);
            let mut s5 = _mm256_loadu_si256(ctr[5].as_ptr() as *const __m256i);
            let mut s6 = _mm256_loadu_si256(ctr[6].as_ptr() as *const __m256i);
            let mut s7 = _mm256_loadu_si256(ctr[7].as_ptr() as *const __m256i);

            for rk_array in self.schedule() {
                let rk = _mm256_loadu_si256(rk_array.as_ptr() as *const __m256i);

                let rk_rot_r = _mm256_or_si256(
                    _mm256_srlv_epi64(rk, mix_rk_sr),
                    _mm256_sllv_epi64(rk, mix_rk_sr_inv),
                );

                macro_rules! do_mix {
                    ($s:ident) => {
                        let sl = _mm256_or_si256(
                            _mm256_sllv_epi64($s, mix_sl),
                            _mm256_srlv_epi64($s, mix_sl_inv),
                        );
                        $s = _mm256_xor_si256(sl, rk_rot_r);
                        $s = _mm256_add_epi64($s, c_nums_mix);
                    };
                }
                do_mix!(s0);
                do_mix!(s1);
                do_mix!(s2);
                do_mix!(s3);
                do_mix!(s4);
                do_mix!(s5);
                do_mix!(s6);
                do_mix!(s7);

                macro_rules! do_casc {
                    ($s:ident) => {
                        let cl = _mm256_or_si256(
                            _mm256_sllv_epi64($s, casc_sl),
                            _mm256_srlv_epi64($s, casc_sl_inv),
                        );
                        let cr = _mm256_or_si256(
                            _mm256_srlv_epi64($s, casc_sr),
                            _mm256_sllv_epi64($s, casc_sr_inv),
                        );
                        let t = _mm256_xor_si256(cl, cr);
                        $s = _mm256_add_epi64($s, t);
                    };
                }
                do_casc!(s0);
                do_casc!(s1);
                do_casc!(s2);
                do_casc!(s3);
                do_casc!(s4);
                do_casc!(s5);
                do_casc!(s6);
                do_casc!(s7);

                macro_rules! do_diff {
                    ($s:ident) => {
                        let b_vec = _mm256_permute4x64_epi64($s, 0x39);
                        let sl = _mm256_or_si256(
                            _mm256_sllv_epi64($s, diff_sl),
                            _mm256_srlv_epi64($s, diff_sl_inv),
                        );
                        let b_sr = _mm256_or_si256(
                            _mm256_srlv_epi64(b_vec, diff_b_sr),
                            _mm256_sllv_epi64(b_vec, diff_b_sr_inv),
                        );
                        $s = _mm256_xor_si256(sl, b_sr);
                        $s = _mm256_add_epi64($s, c_nums_diff);
                    };
                }
                do_diff!(s0);
                do_diff!(s1);
                do_diff!(s2);
                do_diff!(s3);
                do_diff!(s4);
                do_diff!(s5);
                do_diff!(s6);
                do_diff!(s7);
            }

            let mut out = [0u8; 256];
            macro_rules! store_block {
                ($s:ident, $idx:expr) => {
                    let offset = $idx * 32;
                    let p_block = _mm256_loadu_si256(big[offset..].as_ptr() as *const __m256i);
                    let c_block = _mm256_xor_si256($s, p_block);
                    _mm256_storeu_si256(out[offset..].as_mut_ptr() as *mut __m256i, c_block);
                };
            }
            store_block!(s0, 0);
            store_block!(s1, 1);
            store_block!(s2, 2);
            store_block!(s3, 3);
            store_block!(s4, 4);
            store_block!(s5, 5);
            store_block!(s6, 6);
            store_block!(s7, 7);

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
                    for i in 0..32 {
                        out_buf[i] = chunk[i] ^ ks[i];
                    }
                    result.extend_from_slice(&out_buf);
                } else {
                    for i in 0..chunk.len() {
                        result.push(chunk[i] ^ ks[i]);
                    }
                }
            }
        }
        result
    }
}
