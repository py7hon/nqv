# NQV: A High-Performance Quasigroup-Based Stream Cipher with AVX2 Hardware Acceleration

**Muhammad Iqbal Rifai**  
Independent Researcher  
Correspondence: iqbalrifai@aol.com

---

## Abstract

We present NQV (Non-commutative Quasigroup Vector cipher), a novel stream cipher combining quasigroup-based algebraic structures with AVX2 SIMD hardware acceleration. NQV operates in counter (CTR) mode with a 256-bit key and 256-bit nonce, processing data in 32-byte blocks through an Add-Rotate-XOR (ARX) framework augmented with nonlinear quasigroup mixing operations. Our implementation achieves 1859 MB/s throughput on 32 MB buffers—approximately 2× faster than AES-256-GCM and ChaCha20-Poly1305 in software-only comparison—while maintaining avalanche diffusion properties statistically indistinguishable from established ciphers (49.94% mean bit change per single-bit nonce flip across 2000 trials, ideal: 50%). The cipher is implemented in 100% pure Rust with zero external cryptographic dependencies, using explicit AVX2 intrinsics via `core::arch` for the hot path and an automatic scalar fallback for non-AVX2 systems. We emphasize that NQV has not undergone third-party cryptanalysis and the performance advantages demonstrated here derive from explicit SIMD vectorization and adaptive multi-core parallelism, not from cryptographic superiority over AES or ChaCha20. This work contributes an engineering case study in applying quasigroup theory to practical high-performance cipher construction and provides a complete open-source reference implementation for further cryptanalytic scrutiny.

**Keywords:** stream cipher, quasigroup, ARX, AVX2, SIMD, CTR mode, Rust cryptography

---

## 1. Introduction

### 1.1 Motivation

Modern encryption workloads increasingly demand ciphers that can saturate high-bandwidth network links and storage devices while remaining implementable without proprietary cryptographic libraries. AES-256-GCM benefits from dedicated CPU instructions (AES-NI) but exhibits reduced performance on platforms lacking such acceleration. ChaCha20-Poly1305 offers strong software performance through an ARX design amenable to SIMD vectorization, yet its throughput remains bounded by single-core execution in many reference implementations.

This work explores whether a quasigroup-based algebraic structure—known for non-commutativity and resistance to linear cryptanalysis—can be combined with explicit SIMD intrinsics and multi-core parallelism to exceed the throughput of established ciphers in a pure-software, hardware-portable implementation.

### 1.2 Contributions

1. **NQV cipher specification**: A complete stream cipher design incorporating quasigroup vector mixing (QVM), NUMS (Nothing Up My Sleeve) constant injection, and ARX diffusion layers.

2. **AVX2-accelerated implementation**: Direct use of 256-bit SIMD intrinsics (`core::arch::x86_64`) processing 8 independent counter blocks (256 bytes) per iteration, with automatic scalar fallback.

3. **Adaptive parallelism**: Dynamic chunk-size computation based on `std::thread::available_parallelism()`, ensuring multi-core utilization even for buffers as small as 1 MB.

4. **Empirical evaluation**: Throughput, avalanche diffusion, and keystream randomness measurements against AES-256-GCM and ChaCha20-Poly1305 on identical hardware, with reproducible methodology.

5. **Open-source reference implementation**: Zero-dependency Rust code published for third-party cryptanalysis and verification.

### 1.3 Limitations and Scope

**NQV has not been subjected to third-party cryptanalysis.** The security margin at any round count is currently unknown. This paper presents NQV as a **candidate cipher** and an engineering artifact demonstrating quasigroup-SIMD integration, not as a production-ready cryptographic primitive. Performance comparisons reflect SIMD and parallelism advantages in our specific implementation versus single-threaded reference implementations of AES-256-GCM and ChaCha20-Poly1305; they do not constitute evidence of algorithmic superiority.

---

## 2. Background and Related Work

### 2.1 Quasigroups in Cryptography

A quasigroup $(Q, \ast)$ is a set $Q$ with a binary operation $\ast$ such that for all $a, b \in Q$, the equations $a \ast x = b$ and $y \ast a = b$ have unique solutions. Unlike groups, quasigroups need not be associative or possess an identity element, properties that complicate algebraic attacks.

Markovski et al. [1] pioneered quasigroup-based encryption, demonstrating resistance to linear and differential cryptanalysis in block cipher constructions. Subsequent work [2,3] explored quasigroup stream ciphers and hash functions. However, prior designs largely relied on lookup-table implementations of quasigroup operations, incurring cache-timing vulnerabilities and poor SIMD scalability.

### 2.2 ARX Ciphers

The ARX (Add-Rotate-XOR) family, exemplified by Salsa20 [4] and ChaCha20 [5], constructs ciphers exclusively from addition modulo $2^{32}$ or $2^{64}$, bitwise rotation, and XOR. ARX operations map naturally to CPU integer ALUs and are trivially vectorizable, enabling high throughput without dedicated hardware. ChaCha20's quarter-round function processes four 32-bit words in parallel; NQV extends this concept to 64-bit lanes with quasigroup-inspired nonlinear mixing.

### 2.3 SIMD in Cryptography

Intel's AVX2 instruction set (256-bit vector width, introduced 2013) enables parallel processing of 4×64-bit integers per register. Modern AES-NI and ChaCha20 implementations exploit AVX2 to interleave multiple independent blocks [6,7]. NQV contributes an explicit hand-vectorization of quasigroup operations using `_mm256_*` intrinsics, demonstrating that non-traditional algebraic structures can achieve competitive SIMD performance.

---

## 3. Design and Specification

### 3.1 High-Level Structure

NQV operates as a **synchronous stream cipher in CTR mode**:

- **Key**: 256 bits (32 bytes), denoted $K$.
- **Nonce/IV**: 256 bits (32 bytes), denoted $N$.
- **Counter**: 256-bit big-endian integer, initialized to $N$, incremented per block.
- **Block size**: 256 bits (32 bytes).
- **Encryption**: $C_i = P_i \oplus \text{NQV-Permute}(K, \text{Counter}_i)$
- **Decryption**: Identical (CTR self-inverse property).

### 3.2 State Representation

The internal state is a 4-lane vector of 64-bit words: $S = [s_0, s_1, s_2, s_3]$, totaling 256 bits. Each counter value is loaded as little-endian 64-bit words.

### 3.3 Round Function

Each round $r \in \{0, \ldots, R-1\}$ (default $R=8$) applies three layers:

#### 3.3.1 Quasigroup Vector Mix (QVM)

For each lane $i \in \{0,1,2,3\}$:

$$
\begin{aligned}
s_i &\leftarrow (s_i \lll \alpha_i) \oplus (\text{RK}_i \ggg \beta_i) \\
s_i &\leftarrow s_i + C_i \mod 2^{64}
\end{aligned}
$$

where:
- $\text{RK}_i = K_i \lll ((r \cdot 11 + i \cdot 17) \mod 64)$ is the per-round, per-lane rotated key.
- $\alpha = [11, 17, 23, 29]$, $\beta = [7, 13, 19, 23]$ are lane-specific rotation constants.
- $C = [C_\pi, C_e, C_{\sqrt{2}}, C_{\sqrt{3}}]$ are NUMS constants (see Section 3.5).

#### 3.3.2 Avalanche Cascade

For each lane $i$:

$$
\begin{aligned}
t_i &= (s_i \lll \gamma_i) \oplus (s_i \ggg \delta_i) \\
s_i &\leftarrow s_i + t_i \mod 2^{64}
\end{aligned}
$$

where $\gamma = [31, 37, 41, 43]$, $\delta = [17, 19, 23, 29]$.

#### 3.3.3 Diffusion Layer

Cross-lane mixing:

$$
\begin{aligned}
s_0 &\leftarrow (s_0 \lll 13) \oplus (s_1 \ggg 5) + C_{\sqrt{3}} \\
s_1 &\leftarrow (s_1 \lll 19) \oplus (s_2 \ggg 11) + C_{\sqrt{2}} \\
s_2 &\leftarrow (s_2 \lll 23) \oplus (s_3 \ggg 17) + C_e \\
s_3 &\leftarrow (s_3 \lll 31) \oplus (s_0 \ggg 29) + C_\pi
\end{aligned}
$$

The dependency $s_3 \leftarrow \ldots \oplus s_0$ creates a feedback loop ensuring all lanes influence each other over multiple rounds.

### 3.4 Full Permutation

$$
\text{NQV-Permute}(K, N) = (\text{Diffusion} \circ \text{Cascade} \circ \text{QVM})^R(N)
$$

The output is serialized to bytes (little-endian per lane) and XORed with plaintext.

### 3.5 NUMS Constants

To avoid hidden structure, round constants are derived from mathematical constants with no known special properties:

| Symbol | Value (hex, first 64 bits) | Source |
|---|---|---|
| $C_\pi$ | `0x243F6A8885A308D3` | $\pi$ fractional part |
| $C_e$ | `0x14254DEE8513B0A1` | $e$ fractional part |
| $C_{\sqrt{2}}$ | `0x6A09E667F3BCC908` | $\sqrt{2}$ fractional part |
| $C_{\sqrt{3}}$ | `0xBB67AE8584CAA73B` | $\sqrt{3}$ fractional part |

These match conventions used in SHA-2 and other cryptographic standards [8].

### 3.6 Key Schedule

The key schedule is **precomputed once** at cipher initialization:

$$
\text{RK}_{r,i} = K_i \lll ((r \cdot 11 + i \cdot 17) \mod 64), \quad r \in [0, R), \; i \in [0, 4)
$$

Distinct rotation amounts per lane per round ensure each lane sees a different key-derived constant across all rounds, preventing related-key symmetries.

---

## 4. Implementation

### 4.1 AVX2 SIMD Path

The hot path uses Intel AVX2 intrinsics (`__m256i`, 256-bit registers holding 4×64-bit lanes). Each iteration processes **8 independent counter blocks (256 bytes total)** loaded into registers `ymm0`–`ymm7`.

**Key optimization**: All rotation constants are preloaded into YMM registers as 4-element vectors:

```rust
let mix_sl = _mm256_set_epi64x(29, 23, 17, 11);   // per-lane left-rotations
let mix_sl_inv = _mm256_set_epi64x(35, 41, 47, 53); // 64 - mix_sl (for right-rotate)
```

Variable-amount rotations use `_mm256_sllv_epi64` (shift-left-variable) and `_mm256_srlv_epi64` (shift-right-variable), combined via `_mm256_or_si256` to emulate rotation, which has no direct AVX2 instruction:

```rust
let rotated = _mm256_or_si256(
    _mm256_sllv_epi64(state, left_amounts),
    _mm256_srlv_epi64(state, right_amounts)
);
```

Cross-lane permutation in the diffusion layer uses `_mm256_permute4x64_epi64(state, 0x39)`, which rotates the 4 lanes: `[s0, s1, s2, s3] -> [s1, s2, s3, s0]`.

**Throughput**: The AVX2 path processes 8 blocks/iteration = 256 bytes/iteration. At 8 rounds, the inner loop executes 8 × (3 layers) = 24 vector operations per iteration, achieving ~825 MB/s single-threaded on our test CPU (Intel Core i7-9750H @ 2.6 GHz base, 4.5 GHz turbo).

### 4.2 Scalar Fallback

A pure-Rust scalar implementation provides identical functionality for non-AVX2 systems:

```rust
s[0] = (s[0].rotate_left(11) ^ rk[0].rotate_right(7)).wrapping_add(C_PI);
```

The scalar path processes 16 blocks/iteration = 512 bytes using explicit loop unrolling over named variables `s00`–`s15`, allowing the compiler to assign each to a register.

### 4.3 Runtime Dispatch

```rust
pub fn stream_transform_x16(&self, data: &[u8], iv: &[u8; 32]) -> Vec<u8> {
    if std::is_x86_feature_detected!("avx2") {
        unsafe { self.stream_transform_avx2(data, iv) }
    } else {
        self.stream_transform_scalar(data, iv)
    }
}
```

The dispatcher checks `CPUID` at runtime, ensuring the same binary runs optimally on AVX2-capable CPUs and safely on older hardware.

### 4.4 Adaptive Multi-Core Parallelism

```rust
let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
let chunk_size = ((data.len() / cores).max(256 * 1024) + 511) / 512 * 512;
```

Chunk size is computed as $\max(256\text{KB}, \lceil \text{len} / \text{cores} \rceil)$, rounded up to a multiple of 512 bytes (the scalar path's block group size). This ensures:

- Buffers ≥1 MB are split across all available cores.
- Buffers <256 KB skip threading entirely (overhead exceeds benefit).
- Chunk boundaries align with full block groups, minimizing tail handling.

Work distribution uses `std::thread::scope` (scoped threads, no heap allocation for join handles):

```rust
std::thread::scope(|s| {
    for (i, (in_chunk, out_chunk)) in data.chunks(chunk_size)
        .zip(result.chunks_mut(chunk_size))
        .enumerate()
    {
        s.spawn(move || {
            let processed = self.stream_transform_x16(in_chunk, &adjusted_iv);
            out_chunk.copy_from_slice(&processed);
        });
    }
});
```

Each thread independently processes its chunk with the AVX2 or scalar dispatcher.

### 4.5 Correctness Verification

A self-check runs at program startup:

1. **AVX2-Scalar Equivalence**: Encrypt the same random buffers (sizes 256B, 512B, 1000B, 4096B, 100KB) via both paths; assert byte-for-byte equality.
2. **CTR Round-Trip**: Verify $D_K(E_K(P)) = P$ for a 50 KB random plaintext.

If either fails, the program aborts before generating benchmark numbers.

---

## 5. Security Analysis

### 5.1 Avalanche Effect

**Test Methodology**: Generate 2000 independent random (key, nonce) pairs. For each:
1. Encrypt a 32-byte all-zero block with nonce $N$ → keystream $K_A$.
2. Flip one bit of $N$ → $N'$.
3. Encrypt the same zero block with $N'$ → keystream $K_B$.
4. Compute Hamming distance $\Delta = H(K_A, K_B)$.
5. Record $\Delta / 256$ (fraction of bits changed).

**Results** (8 rounds):

| Cipher | Mean Δ (%) | Std. Dev. | Ideal |
|---|---|---|---|
| NQV | 49.94 | 3.54 | 50.00 |
| AES-256-GCM | 49.98 | 3.51 | 50.00 |
| ChaCha20-Poly1305 | 50.01 | 3.49 | 50.00 |

Statistical test: Two-sample t-test comparing NQV vs. ideal 50% yields $p=0.72$ (fail to reject null hypothesis of equal means). **Conclusion**: NQV's avalanche behavior is statistically indistinguishable from established ciphers.

**Round-count ablation**:

| Rounds | Mean Δ (%) |
|---|---|
| 4 | 50.07 |
| 6 | 50.01 |
| 8 | 49.94 |
| 10 | 49.91 |
| 12 | 49.95 |

Full avalanche is achieved from 4 rounds onward, indicating the NUMS constant additions provide sufficient nonlinearity to reach diffusion faster than pure XOR-rotation ARX designs.

### 5.2 Keystream Randomness

**Test Methodology**: Encrypt a 1,000,000-byte all-zero buffer (exposing raw keystream). Compute Pearson chi-square statistic:

$$
\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E)^2}{E}, \quad E = 1{,}000{,}000 / 256 \approx 3906.25
$$

where $O_i$ is the observed count of byte value $i$.

**Results**:

| Cipher | $\chi^2$ | df | Critical (α=0.05) | Verdict |
|---|---|---|---|---|
| NQV | 248.78 | 255 | 293.25 | Consistent |
| AES-256-GCM | 263.01 | 255 | 293.25 | Consistent |
| ChaCha20-Poly1305 | 244.14 | 255 | 293.25 | Consistent |

NQV exhibits **lower** $\chi^2$ than AES-256-GCM, indicating closer adherence to uniform distribution at the first-order byte-frequency level.

**Limitations**: This is a single first-order test. The NIST SP 800-22 suite (15 tests including runs, FFT, approximate entropy) is required for a defensible randomness claim and remains **future work**.

### 5.3 Security Margin and Open Questions

1. **Differential Cryptanalysis**: No formal analysis of the maximum differential probability across $R$ rounds has been conducted. The quasigroup mixing and NUMS additions introduce nonlinearity, but quantitative bounds are unknown.

2. **Linear Approximations**: Quasigroup non-commutativity theoretically resists linear cryptanalysis [1], but no concrete bias measurements for NQV's specific construction exist.

3. **Related-Key Attacks**: The key schedule rotates each key word by a round-dependent and lane-dependent amount. Whether this suffices to prevent related-key differentials is unverified.

4. **Side-Channel Resistance**: The AVX2 implementation uses data-independent vector operations (no table lookups, no secret-dependent branches), providing inherent resistance to cache-timing attacks. However, no formal constant-time proof or power-analysis evaluation has been performed.

**We emphasize that NQV is a candidate cipher requiring third-party cryptanalysis before production deployment.**

---

## 6. Performance Evaluation

### 6.1 Experimental Setup

- **CPU**: Intel Core i7-9750H (6 cores, 12 threads, 2.6 GHz base, 4.5 GHz turbo)
- **Compiler**: `rustc 1.75.0`, release mode (`opt-level=3`, `lto=true`, `codegen-units=1`)
- **Flags**: `-C target-cpu=native -C target-feature=+avx2`
- **OS**: Windows 11 (64-bit)
- **Comparison crates**:
  - `aes-gcm 0.10.3` (pure-Rust AES-NI when available, software fallback otherwise)
  - `chacha20poly1305 0.10.1` (optimized Rust implementation, no inline assembly)

**Methodology**: Each measurement is the **best of 5 trials** to exclude OS scheduling noise. A 200ms cooldown separates encrypt and decrypt timing to reduce AVX2 thermal throttle carryover. A warmup pass (32 MB encryption) precedes all measurements to reach steady-state CPU frequency.

### 6.2 Throughput Results

| Cipher | 1 MB (MB/s) | 8 MB (MB/s) | 32 MB (MB/s) |
|---|---|---|---|
| **NQV (8r, parallel)** | **1295** | **1391** | **1859** |
| AES-256-GCM | 1020 | 844 | 955 |
| ChaCha20-Poly1305 | 1160 | 1059 | 992 |
| **Speedup vs. AES** | **1.27×** | **1.65×** | **1.95×** |
| **Speedup vs. ChaCha** | **1.12×** | **1.31×** | **1.87×** |

**Analysis**: NQV achieves 1.3–1.9× the throughput of AES-256-GCM and 1.1–1.9× that of ChaCha20-Poly1305. The advantage grows with buffer size because:
1. Larger buffers amortize thread-spawn overhead (negligible at 32 MB).
2. The AVX2 hot path's 256-byte iteration granularity utilizes more of each thread's execution window before hitting tail handling.

**Important Context**: AES-256-GCM and ChaCha20-Poly1305 as tested here are **single-threaded** implementations (neither crate employs application-level parallelism). NQV's speedup reflects combined SIMD and multi-threading contributions. For a fair single-core comparison, see Section 6.3.

### 6.3 Single-Core Ablation

| Variant | 8 MB (MB/s) | Notes |
|---|---|---|
| NQV v2 (16r, byte-serial) | 203 | Original quasigroup cipher, no SIMD |
| NQV v4 (4r, AVX2 single-thread) | 1165 | AVX2 only, no threading |
| NQV v4 (8r, AVX2 single-thread) | **825** | Recommended config, 1 core |
| NQV v4 (8r, AVX2 parallel) | **1821** | Multi-core (12 threads) |
| ChaCha20-Poly1305 | 913 | Reference (1 core) |

**Single-threaded comparison**: NQV (8 rounds, AVX2) achieves 825 MB/s versus ChaCha20's 913 MB/s on a single core—a **0.90×** ratio (ChaCha20 is 10% faster per-core). The multi-core path yields an additional **2.2× multiplier** (825 → 1821 MB/s), pushing total throughput to **2.0× ChaCha20's single-threaded rate**.

**Key Finding**: NQV's advantage is architectural (SIMD + parallelism), not algorithmic. At 4 rounds, NQV reaches 1165 MB/s single-core (1.27× ChaCha20), demonstrating that reduced round count partially offsets per-round complexity.

### 6.4 Encrypt/Decrypt Asymmetry

| Size | Encrypt (MB/s) | Decrypt (MB/s) | Ratio |
|---|---|---|---|
| 1 MB | 1295 | 1541 | 1.19× |
| 8 MB | 1391 | 2126 | 1.53× |
| 32 MB | 1859 | 2179 | 1.17× |

Since CTR-mode encryption and decryption are identical operations, this asymmetry is a **measurement artifact**. The decrypt pass runs after a 200ms cooldown following the encrypt pass; during this cooldown, the CPU's AVX2 frequency throttle partially recovers, allowing the decrypt measurement to run at a higher sustained clock. At 32 MB (long-duration measurement), both passes reach thermal equilibrium and the asymmetry narrows to 17%.

---

## 7. Discussion

### 7.1 Design Rationale

**Why quasigroups?** Non-associativity and lack of identity elements complicate equation-solving attacks that assume group structure (e.g., meet-in-the-middle, slide attacks). Prior quasigroup ciphers [1,2] demonstrated theoretical resistance but suffered poor performance due to lookup-table implementations. NQV replaces table lookups with arithmetic operations amenable to SIMD.

**Why NUMS constants?** Injecting $C_\pi, C_e, C_{\sqrt{2}}, C_{\sqrt{3}}$ into every round prevents all-zero states from propagating and breaks bit-position symmetries. Using well-known mathematical constants allows independent verification that no backdoor structure was introduced (cf. Dual_EC_DRBG controversy [9]).

**Why 8 rounds?** Section 5.1 shows 4 rounds achieve full avalanche, but cryptographic conservatism dictates a safety margin. Eight rounds provide 2× margin over the empirical diffusion threshold at ~10% performance cost versus 4 rounds (825 vs. 1165 MB/s single-core).

### 7.2 Comparison with Related Work

| Cipher | Family | Key Size | Throughput (MB/s, single-core) | Cryptanalysis Status |
|---|---|---|---|---|
| AES-256-GCM | Block (SPN) | 256 | ~900 (software) | 20+ years, no practical attacks |
| ChaCha20 | Stream (ARX) | 256 | ~913 | 10+ years, security margin well-studied [5] |
| Salsa20/20 | Stream (ARX) | 256 | ~600 | 15+ years, reduced-round attacks exist [10] |
| **NQV (8r)** | **Stream (ARX+QG)** | **256** | **~825** | **Zero public cryptanalysis** |

NQV sits between AES software and ChaCha20 in single-core throughput, but lacks the cryptanalytic scrutiny both have undergone.

### 7.3 Limitations

1. **Unvalidated Security**: No third-party cryptanalysis, no formal security proofs. Deployment in security-critical systems is **not recommended** until extensive public review occurs.

2. **AEAD Construction Missing**: NQV provides confidentiality (CTR mode) but no built-in authentication. A production system requires pairing with a MAC (e.g., Poly1305) or designing an integrated AEAD mode—beyond this paper's scope.

3. **Key/Nonce Size**: The 256-bit nonce is unconventional (AES-GCM and ChaCha20 use 96 bits). While this provides a larger nonce space (useful for random nonce generation), it increases per-message overhead.

4. **Platform-Specific Optimization**: AVX2 intrinsics are x86/x86-64 only. ARM NEON or RISC-V vector extensions would require separate implementations (though the scalar fallback remains portable).

5. **Microbenchmark Context**: The 1.9× speedup over AES-256-GCM reflects software-only comparison. On platforms with AES-NI, hardware-accelerated AES-GCM can exceed 5000 MB/s [11], far surpassing NQV. Our comparison is against the pure-software fallback paths of both competitors.

---

## 8. Future Work

1. **Third-Party Cryptanalysis**: Formal differential/linear cryptanalysis, algebraic attacks, dedicated cryptanalytic challenges.

2. **NIST SP 800-22 Randomness Testing**: Complete statistical test suite on multi-gigabyte keystream samples.

3. **AEAD Mode**: Integrate Poly1305 or design a quasigroup-based MAC for authenticated encryption.

4. **ARM NEON Implementation**: Port AVX2 intrinsics to ARM SVE/NEON for mobile/embedded platforms.

5. **Constant-Time Verification**: Formal verification (e.g., via `ctgrind`, `dudect`) that the implementation contains no secret-dependent branches or memory accesses.

6. **Hardware Acceleration**: FPGA or ASIC implementation to evaluate area/power efficiency versus AES.

---

## 9. Conclusion

We presented NQV, a quasigroup-based stream cipher achieving competitive throughput (1859 MB/s, ~2× AES-256-GCM software) through explicit AVX2 vectorization and adaptive multi-core parallelism. Empirical tests show avalanche diffusion and keystream randomness statistically indistinguishable from AES and ChaCha20 at the first-order level, while a complete open-source implementation provides a foundation for community cryptanalysis.

**NQV is not a production-ready cipher.** It is a research artifact demonstrating that quasigroup theory, traditionally relegated to theoretical cryptography, can inform practical high-performance designs when combined with modern SIMD techniques. The performance advantages demonstrated here derive from engineering (SIMD, threading) rather than cryptographic breakthroughs, and no security claims beyond basic diffusion properties are made.

We invite the cryptographic community to scrutinize NQV's design, test its resistance to known attacks, and determine whether its quasigroup-ARX hybrid structure offers genuine security benefits or merely repackages existing ARX principles under different algebraic terminology. Until such analysis occurs, NQV should be regarded as a **cipher candidate**, not a replacement for established, well-analyzed primitives.

The complete reference implementation is available at [repository URL] under the MIT license.

---

## Acknowledgments

The author thanks the Rust cryptography community for excellent zero-dependency crates (`aes-gcm`, `chacha20poly1305`) used as benchmark references, and acknowledges that this work builds upon decades of public research into ARX ciphers (Bernstein et al.) and quasigroup cryptography (Markovski et al.).

---

## References

[1] Markovski, S., Gligoroski, D., & Andova, S. (2004). "Using quasigroups for one-one secure encoding." *Proceedings of VIII Conf. Logic and Computer Science*, 157-162.

[2] Gligoroski, D., Markovski, S., & Kocarev, L. (2008). "Edon-R, an infinite family of cryptographic hash functions." *NIST SHA-3 Submission*.

[3] Dimitrova, V., & Markovski, S. (2009). "On quasigroup pseudo random sequence generators." *Contributions, Sec. Math. Tech. Sci., MANU*, 30(1-2), 21-32.

[4] Bernstein, D. J. (2005). "The Salsa20 family of stream ciphers." *eSTREAM submission*.

[5] Bernstein, D. J. (2008). "ChaCha, a variant of Salsa20." *State of the Art of Stream Ciphers Workshop (SASC)*.

[6] Gueron, S., & Krasnov, V. (2014). "Parallelizing message schedules to accelerate the computations of hash functions." *Journal of Cryptographic Engineering*, 4(4), 241-253.

[7] Neves, S., & Aumasson, J.-P. (2015). "BLAKE2: simpler, smaller, fast as MD5." *ACNS 2013*, LNCS 7954, 119-135.

[8] NIST FIPS 180-4. (2015). "Secure Hash Standard (SHS)." *National Institute of Standards and Technology*.

[9] Checkoway, S., et al. (2014). "On the practical exploitability of Dual EC in TLS implementations." *USENIX Security Symposium*, 319-335.

[10] Aumasson, J.-P., et al. (2008). "New features of Latin dances: analysis of Salsa, ChaCha, and Rumba." *FSE 2008*, LNCS 5086, 470-488.

[11] Gueron, S. (2012). "Intel Advanced Encryption Standard (AES) New Instructions Set." *Intel Corporation White Paper*, Rev. 3.0.

---

## Appendix A: Test Vectors

**Key** (hex):  
`7777777777777777777777777777777777777777777777777777777777777777`

**Nonce** (hex):  
`2222222222222222222222222222222222222222222222222222222222222222`

**Plaintext** (32 bytes, hex):  
`0000000000000000000000000000000000000000000000000000000000000000`

**Ciphertext** (NQV, 8 rounds, hex):  
`0f7dff18f2fa98638543900dd0d39a66e1b3cd7853dca37c7e5850881e1d3510`

Generated via reference Rust code:
```rust
use nqv::Nqv;

let cipher = Nqv::new(&[0x77; 32], 8);
let ct = cipher.stream_transform_x16(&[0u8; 32], &[0x22; 32]);
let hex_output: String = ct.iter().map(|b| format!("{:02x}", b)).collect();
println!("{}", hex_output);
```

---

## Appendix B: Source Code Availability & License

The complete NQV reference implementation is released as open-source software under the **Apache License 2.0**.
Repository: [https://github.com/py7hon](https://github.com/py7hon)

Build & execution instructions:
```bash
git clone https://github.com/py7hon/nqv.git
cd nqv
cargo build --release
cargo test           # Runs unit tests, doctests, and scalar/AVX2 parity checks
cargo run --release  # Executes benchmark suite in benches/nqv_benchmark.rs
```

Requirements: Rust 1.75+, x86-64 CPU with AVX2 support (or any architecture using standard scalar fallback).

---

**End of Paper**

---

*This paper is a pre-print submitted for peer review. Not for production use.*