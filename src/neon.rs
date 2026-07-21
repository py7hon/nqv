//! ARM 64-bit NEON SIMD acceleration module for NQV.

use crate::cipher::Nqv;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

impl Nqv {
    /// ARM 64-bit NEON SIMD stream transformation.
    /// Executes vectorized 128-bit NEON registers (`uint64x2_t`) processing 2 blocks (64 bytes) per iteration.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon")]
    pub unsafe fn stream_transform_neon(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
        let schedule = self.schedule();
        let num_blocks = (data.len() + 31) / 32;
        let mut out = vec![0u8; data.len()];

        let mut current_ctr = *iv;

        // Process 2 blocks (64 bytes) per NEON iteration
        let chunks_2 = num_blocks / 2;
        let remainder = num_blocks % 2;

        for chunk_idx in 0..chunks_2 {
            let offset_bytes = chunk_idx * 64;

            // Load counter states for 2 blocks into NEON 128-bit registers (4 uint64x2_t registers)
            let mut ctr0 = current_ctr;
            crate::counter::advance_counter(&mut current_ctr);
            let mut ctr1 = current_ctr;
            crate::counter::advance_counter(&mut current_ctr);

            let mut v0 = vld1q_u64(ctr0[0..16].as_ptr() as *const u64);
            let mut v1 = vld1q_u64(ctr0[16..32].as_ptr() as *const u64);
            let mut v2 = vld1q_u64(ctr1[0..16].as_ptr() as *const u64);
            let mut v3 = vld1q_u64(ctr1[16..32].as_ptr() as *const u64);

            // Execute QVM round iterations
            for r in 0..self.rounds {
                let rk = schedule[r];
                let rk_v0 = vld1q_u64([rk[0], rk[1]].as_ptr());
                let rk_v1 = vld1q_u64([rk[2], rk[3]].as_ptr());

                // Round function: ADD round keys and EOR (XOR)
                v0 = vaddq_u64(v0, rk_v0);
                v1 = veorq_u64(v1, rk_v1);
                v2 = vaddq_u64(v2, rk_v0);
                v3 = veorq_u64(v3, rk_v1);
            }

            // Store output block 0
            vst1q_u64(ctr0[0..16].as_mut_ptr() as *mut u64, v0);
            vst1q_u64(ctr0[16..32].as_mut_ptr() as *mut u64, v1);
            // Store output block 1
            vst1q_u64(ctr1[0..16].as_mut_ptr() as *mut u64, v2);
            vst1q_u64(ctr1[16..32].as_mut_ptr() as *mut u64, v3);

            // XOR keystream with data
            let len0 = std::cmp::min(32, data.len() - offset_bytes);
            for i in 0..len0 {
                out[offset_bytes + i] = data[offset_bytes + i] ^ ctr0[i];
            }

            if offset_bytes + 32 < data.len() {
                let len1 = std::cmp::min(32, data.len() - (offset_bytes + 32));
                for i in 0..len1 {
                    out[offset_bytes + 32 + i] = data[offset_bytes + 32 + i] ^ ctr1[i];
                }
            }
        }

        // Tail handling for remainder blocks using scalar path
        if remainder > 0 {
            let tail_offset = chunks_2 * 64;
            let tail_data = &data[tail_offset..];
            let tail_out = self.stream_transform_scalar(tail_data, &current_ctr);
            out[tail_offset..].copy_from_slice(&tail_out);
        }

        out
    }

    /// Non-ARM fallback stub for non-aarch64 targets.
    #[cfg(not(target_arch = "aarch64"))]
    pub unsafe fn stream_transform_neon(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
        self.stream_transform_scalar(data, iv)
    }
}
