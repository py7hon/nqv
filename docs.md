# NQV API Reference & Developer Manual

**Author**: Muhammad Iqbal Rifai ([GitHub: @py7hon](https://github.com/py7hon))  
**License**: Apache-2.0  

---

## 1. Module Overview

The `nqv` library crate is structured into sub-modules separating responsibilities cleanly:

```text
nqv (crate root)
├── cipher     ── Struct Nqv definition, constructor, and single-thread dispatcher
├── constants  ── NUMS mathematical constants and execution thresholds
├── counter    ── 256-bit big-endian counter arithmetic helpers
├── parallel   ── Adaptive multi-core parallel dispatch engine
├── scalar     ── Pure scalar fallback and in-place block permutation
└── simd       ── Hardware-accelerated 256-bit AVX2 SIMD intrinsics
```

---

## 2. API Reference

### 2.1 Struct `Nqv` & Type Alias `NQV`

The primary cipher struct managing round key schedules.

```rust
use nqv::{Nqv, NQV};

// Convenient alias for capitalized notation
pub type NQV = Nqv;
```

#### `Nqv::new(key: &[u8; 32], rounds: usize) -> Self`
Initializes an NQV cipher instance by expanding a 256-bit (32-byte) key into per-round rotated subkeys.

- **Parameters**:
  - `key`: 32-byte array containing the 256-bit secret key.
  - `rounds`: Integer round count (default recommendation: `8`).
- **Example**:
  ```rust
  let key = [0x42u8; 32];
  let cipher = Nqv::new(&key, 8);
  assert_eq!(cipher.rounds, 8);
  ```

---

#### `Nqv::stream_transform_parallel(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8>`
Multi-threaded CTR-mode stream transformation across available logical CPU cores.

- **Behavior**:
  - Automatically calculates optimal chunk size based on `std::thread::available_parallelism()`.
  - Input payloads $< 256\text{ KB}$ route directly to single-threaded AVX2/scalar mode.
  - Aligns chunk boundaries to 512-byte vector blocks.
- **Example**:
  ```rust
  let data = vec![0x00u8; 1_000_000];
  let iv = [0x11u8; 32];
  let ciphertext = cipher.stream_transform_parallel(&data, &iv);
  ```

---

#### `Nqv::stream_transform_x16(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8>`
Single-threaded stream transformation with runtime target-feature detection.

- **Behavior**:
  - Automatically selects `stream_transform_avx2` if host CPU supports AVX2.
  - Falls back to `stream_transform_scalar` on non-AVX2 hosts.

---

#### `Nqv::stream_transform_avx2(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8>`
Direct hardware-accelerated 256-bit AVX2 SIMD transformation path.

- **Safety**: Marked `pub unsafe fn`. Requires host CPU to support AVX2 features (`std::is_x86_feature_detected!("avx2")`).
- **Concurrency**: Processes 8 blocks (256 bytes) simultaneously per iteration.

---

#### `Nqv::stream_transform_scalar(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8>`
Pure scalar fallback mode processing 16 blocks (512 bytes) per iteration using 64-bit integer ALU instructions.

---

#### `Nqv::permute(&self, block: &mut [u8; 32])`
Applies in-place 32-byte block permutation using Quasigroup Vector mixing and diffusion layers.

- **Example**:
  ```rust
  let mut block = [0u8; 32];
  cipher.permute(&mut block);
  ```

---

### 2.2 Counter Utility Functions

#### `nqv::advance_counter(counter: &mut [u8; 32])`
Increments a 256-bit big-endian counter array by 1 in-place.

#### `nqv::offset_counter(counter: &mut [u8; 32], amount: u64)`
Advances a 256-bit big-endian counter in-place by `amount` 32-byte blocks.

---

### 2.3 Constants

- **`MIN_PARALLEL_CHUNK`** (`usize = 262_144`): Minimum 256 KB threshold for parallel thread spawning.
- **`C_PI`** (`u64 = 0x243F6A8885A308D3`): NUMS constant derived from $\pi$.
- **`C_E`** (`u64 = 0x14254DEE8513B0A1`): NUMS constant derived from $e$.
- **`C_SQ2`** (`u64 = 0x6A09E667F3BCC908`): NUMS constant derived from $\sqrt{2}$.
- **`C_SQ3`** (`u64 = 0xBB67AE8584CAA73B`): NUMS constant derived from $\sqrt{3}$.

---

## 3. Generating Offline Documentation

To build and open local HTML API documentation in your web browser:

```bash
cargo doc --no-deps --open
```
