# NQV Proof of Concept (PoC) & Test Vectors

**Author**: Muhammad Iqbal Rifai ([GitHub: @py7hon](https://github.com/py7hon))  
**License**: Apache-2.0  

---

## 1. Runnable Proof of Concept Examples

### 1.1 Basic Stream Cipher Encryption & Decryption
Demonstrates CTR-mode stream transformation (CTR mode is self-inverse):

```rust
use nqv::Nqv;

fn main() {
    // 256-bit Key (32 bytes) & 256-bit IV (32 bytes)
    let key = [0x42u8; 32];
    let iv  = [0x99u8; 32];

    // Instantiate NQV cipher with default 8 rounds
    let cipher = Nqv::new(&key, 8);

    let plaintext = b"Confidential data protected by NQV Quasigroup Vector cipher.";

    // Encrypt
    let ciphertext = cipher.stream_transform_x16(plaintext, &iv);
    assert_ne!(plaintext.as_slice(), ciphertext.as_slice());

    // Decrypt using same key and IV
    let decrypted = cipher.stream_transform_x16(&ciphertext, &iv);
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    println!("PoC 1: Basic encryption and decryption verified!");
}
```

---

### 1.2 Multi-Threaded Parallel Execution Engine
Demonstrates parallel execution across logical CPU cores for large payloads:

```rust
use nqv::Nqv;

fn main() {
    let key = [0x55u8; 32];
    let iv  = [0x33u8; 32];
    let cipher = Nqv::new(&key, 8);

    // 1 MB payload triggers multi-core parallel worker threads
    let payload = vec![0xABu8; 1_000_000];

    let ciphertext = cipher.stream_transform_parallel(&payload, &iv);
    assert_eq!(ciphertext.len(), payload.len());

    let decrypted = cipher.stream_transform_parallel(&ciphertext, &iv);
    assert_eq!(payload, decrypted);

    println!("PoC 2: Parallel multi-core stream transformation verified!");
}
```

---

### 1.3 In-Place Block Permutation
Demonstrates low-level 32-byte block transformation using Quasigroup Vector mixing:

```rust
use nqv::Nqv;

fn main() {
    let key = [0x77u8; 32];
    let cipher = Nqv::new(&key, 8);

    let mut block = [0x00u8; 32];
    println!("Before: {:02x?}", &block[..8]);

    // Apply QVM permutation in-place
    cipher.permute(&mut block);
    println!("After:  {:02x?}", &block[..8]);

    assert_ne!(block, [0x00u8; 32]);
    println!("PoC 3: Block permutation verified!");
}
```

---

### 1.4 256-bit Counter Arithmetic
Demonstrates big-endian 256-bit counter increments and offset jumps:

```rust
use nqv::{advance_counter, offset_counter};

fn main() {
    let mut ctr = [0u8; 32];

    // Single step increment
    advance_counter(&mut ctr);
    assert_eq!(ctr[31], 1);

    // Jump counter ahead by 258 32-byte blocks
    offset_counter(&mut ctr, 258);
    assert_eq!(ctr[30], 1);
    assert_eq!(ctr[31], 3);

    println!("PoC 4: 256-bit counter arithmetic verified!");
}
```

---

## 2. Official Verified Test Vectors

The following test vector was verified via `cargo test test_test_vector`:

### Test Vector #1 (8 Rounds)
- **Key (hex)**:
  `7777777777777777777777777777777777777777777777777777777777777777`
- **Nonce / IV (hex)**:
  `2222222222222222222222222222222222222222222222222222222222222222`
- **Plaintext (32 bytes zero block)**:
  `0000000000000000000000000000000000000000000000000000000000000000`
- **Expected Ciphertext Output (hex)**:
  `0f7dff18f2fa98638543900dd0d39a66e1b3cd7853dca37c7e5850881e1d3510`
