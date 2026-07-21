//! Adaptive multi-threaded parallel execution dispatcher.

use crate::cipher::Nqv;
use crate::constants::MIN_PARALLEL_CHUNK;
use crate::counter::offset_counter;

impl Nqv {
    /// Multi-threaded stream transformation with adaptive workload distribution.
    ///
    /// Dynamically scales chunk size based on available CPU cores and input size, aligning chunk boundaries
    /// to 512-byte vector blocks. If input size is below 256 KB, skips thread overhead and routes directly
    /// to single-threaded AVX2/scalar execution.
    ///
    /// # Arguments
    /// * `data` - Byte slice to transform (encrypt or decrypt).
    /// * `iv` - 256-bit (32-byte) initialization vector / counter start value.
    ///
    /// # Example
    /// ```rust
    /// use nqv::Nqv;
    /// let cipher = Nqv::new(&[0x55u8; 32], 8);
    /// let iv = [0x33u8; 32];
    /// let data = vec![0xABu8; 1_000_000];
    /// let encrypted = cipher.stream_transform_parallel(&data, &iv);
    /// assert_eq!(encrypted.len(), data.len());
    /// ```
    pub fn stream_transform_parallel(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8>
    where
        Self: Sync,
    {
        if data.len() < MIN_PARALLEL_CHUNK {
            return self.stream_transform_x16(data, iv);
        }

        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        let ideal_chunk = data.len() / cores;
        let mut chunk_size = ideal_chunk.max(MIN_PARALLEL_CHUNK);
        chunk_size = ((chunk_size + 511) / 512) * 512;

        let mut result = vec![0u8; data.len()];

        std::thread::scope(|s| {
            for (i, (in_chunk, out_chunk)) in data
                .chunks(chunk_size)
                .zip(result.chunks_mut(chunk_size))
                .enumerate()
            {
                let mut chunk_iv = *iv;
                let blocks_offset = (i as u64) * (chunk_size as u64 / 32);
                offset_counter(&mut chunk_iv, blocks_offset);

                s.spawn(move || {
                    let processed = self.stream_transform_x16(in_chunk, &chunk_iv);
                    out_chunk.copy_from_slice(&processed);
                });
            }
        });
        result
    }
}
