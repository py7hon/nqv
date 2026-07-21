//! 256-bit big-endian counter arithmetic utilities for CTR mode stream transformation.

/// Increments a 256-bit (32-byte) big-endian counter by 1 in-place.
///
/// # Arguments
/// * `counter` - Mutable 32-byte array representing the 256-bit counter state.
///
/// # Example
/// ```rust
/// use nqv::advance_counter;
/// let mut ctr = [0u8; 32];
/// advance_counter(&mut ctr);
/// assert_eq!(ctr[31], 1);
/// ```
pub fn advance_counter(counter: &mut [u8; 32]) {
    for byte in counter.iter_mut().rev() {
        let (v, overflow) = byte.overflowing_add(1);
        *byte = v;
        if !overflow {
            break;
        }
    }
}

/// Offsets a 256-bit (32-byte) big-endian counter in-place by a 64-bit block count amount.
///
/// # Arguments
/// * `counter` - Mutable 32-byte array representing the counter state.
/// * `amount` - 64-bit integer specifying the number of 32-byte block steps to advance.
///
/// # Example
/// ```rust
/// use nqv::offset_counter;
/// let mut ctr = [0u8; 32];
/// offset_counter(&mut ctr, 10);
/// assert_eq!(ctr[31], 10);
/// ```
pub fn offset_counter(counter: &mut [u8; 32], mut amount: u64) {
    let mut idx = 31usize;
    loop {
        let sum = counter[idx] as u64 + (amount & 0xFF);
        counter[idx] = sum as u8;
        amount = (amount >> 8) + (sum >> 8);
        if amount == 0 || idx == 0 {
            break;
        }
        idx -= 1;
    }
}
