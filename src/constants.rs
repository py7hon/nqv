//! Nothing-Up-My-Sleeve (NUMS) mathematical constants and execution parameters.

/// Minimum input size threshold (256 KB) required before spawning multi-threaded workers.
pub const MIN_PARALLEL_CHUNK: usize = 256 * 1024;

/// Nothing-Up-My-Sleeve (NUMS) constant derived from fractional bits of Pi.
pub const C_PI: u64 = 0x243F6A8885A308D3;

/// Nothing-Up-My-Sleeve (NUMS) constant derived from fractional bits of e.
pub const C_E: u64 = 0x14254DEE8513B0A1;

/// Nothing-Up-My-Sleeve (NUMS) constant derived from fractional bits of sqrt(2).
pub const C_SQ2: u64 = 0x6A09E667F3BCC908;

/// Nothing-Up-My-Sleeve (NUMS) constant derived from fractional bits of sqrt(3).
pub const C_SQ3: u64 = 0xBB67AE8584CAA73B;
