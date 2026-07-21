# NQV (Quasigroup Vector Cipher)

[![Rust](https://img.shields.io/badge/rust-2021-brightgreen.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**NQV** (Non-commutative Quasigroup Vector cipher) is a high-throughput, hardware-accelerated symmetric stream cipher implemented in pure Rust. It combines algebraic quasigroup mixing structures with 256-bit AVX2 SIMD intrinsics, adaptive multi-core parallel processing, and an automatic scalar fallback for non-AVX2 CPUs.

## Author

- **Muhammad Iqbal Rifai**
- **GitHub**: [@py7hon](https://github.com/py7hon)

---

## Documentation Index

The technical details, benchmarks, and guides are organized into dedicated documentation files:

- 📐 **[Architecture Specification](architecture.md)** — Deep-dive into Quasigroup Vector algebra, QVM round function layers, AVX2 SIMD register mapping, and parallel thread allocation.
- 🧪 **[Proof of Concept (PoC) & Test Vectors](poc.md)** — Runnable Rust examples for stream transformation, block permutation, counter math, and official hex test vectors.
- 📊 **[Cryptographic & Benchmark Analysis](analysis.md)** — Empirical evaluations of avalanche bit diffusion (~50.06%), Chi-Square keystream uniformity ($\chi^2 = 248.78$), SIMD throughput scaling, and security claims.
- 📖 **[API Reference & Developer Manual](docs.md)** — Module breakdown, `Nqv` struct methods, utility functions, safety invariants, and Rustdoc HTML generation instructions.
- 📄 **[Academic Research Paper](PAPER.md)** — Formal publication-ready paper specification.
- 📈 **[Benchmark Results](RESULTS.md)** — Comprehensive execution logs and comparative throughput tables (NQV vs AES-256-GCM vs ChaCha20-Poly1305).

---

## Core Features

- **Zero External Dependencies**: Core cipher engine operates strictly with Rust `core` and `std`.
- **256-bit SIMD Acceleration**: Uses hand-vectorized AVX2 `_mm256_*` intrinsics to process 8 independent blocks (256 bytes) simultaneously.
- **Adaptive Multi-Core Engine**: Dynamically calculates optimal chunk allocation based on logical core count (`std::thread::available_parallelism`).
- **CTR Mode Stream Transformation**: CTR mode stream transformation provides symmetric self-inverse encryption and decryption operations.
- **Modular Codebase Architecture**: Clean separation into `cipher`, `constants`, `counter`, `parallel`, `scalar`, and `simd` sub-modules.

---

## Quick Start Example

Add `nqv` to your `Cargo.toml`:

```toml
[dependencies]
nqv = { path = "." }
```

Encryption and decryption in Rust:

```rust
use nqv::Nqv;

fn main() {
    // 256-bit (32-byte) key and initialization vector (IV)
    let key = [0x42u8; 32];
    let iv  = [0x99u8; 32];
    let rounds = 8;

    // Instantiate NQV cipher
    let cipher = Nqv::new(&key, rounds);

    let plaintext = b"High-throughput Quasigroup Vector cipher in pure Rust!";

    // Encrypt using adaptive parallel stream transformation
    let ciphertext = cipher.stream_transform_parallel(plaintext, &iv);

    // Decrypt (CTR mode stream transformation is self-inverse)
    let decrypted = cipher.stream_transform_parallel(&ciphertext, &iv);

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    println!("Encryption and decryption verified successfully!");
}
```

---

## Build & Test Commands

To run unit tests, doctests, and scalar/AVX2 parity checks:

```bash
cargo test
```

To run the performance benchmark suite (`benches/nqv_benchmark.rs`):

```bash
cargo bench --bench nqv_benchmark
```

To run the full NIST SP 800-22 statistical test suite (`benches/nist_sp800_22.rs`):

```bash
cargo bench --bench nist_sp800_22
```

To run the cryptanalytic evaluation suite (`benches/cryptanalysis.rs`):

```bash
cargo bench --bench cryptanalysis
```

To run the formal constant-time side-channel verification (`benches/constant_time.rs`):

```bash
cargo bench --bench constant_time
```

To generate local HTML API documentation:

```bash
cargo doc --no-deps --open
```

---

## License

Licensed under the **Apache License, Version 2.0**. See the [LICENSE](LICENSE) file for the full license text.
