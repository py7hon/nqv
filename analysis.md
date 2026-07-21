# NQV Cryptographic & Benchmark Analysis

**Author**: Muhammad Iqbal Rifai ([GitHub: @py7hon](https://github.com/py7hon))  
**License**: Apache-2.0  

---

## 1. Statistical Evaluation Overview

This document presents empirical cryptographic properties and performance evaluations of the **NQV** stream cipher. All measurements were conducted using the benchmark suite in `benches/nqv_benchmark.rs` with native AVX2 SIMD acceleration (`target-cpu=native`).

---

## 2. Avalanche Bit Diffusion Analysis

The **Strict Avalanche Criterion (SAC)** requires that flipping a single input bit (in key, IV, or nonce) causes each output keystream bit to invert with a probability of exactly $50\%$.

### Methodology
Across 2,000 independent trials, a 256-bit IV ($N_A$) was randomly generated, and a second IV ($N_B$) was created by inverting a single bit ($N_B = N_A \oplus 0x01$). Keystreams $K_A$ and $K_B$ were computed by permuting $N_A$ and $N_B$, and the Hamming distance (number of bit inversions) was measured:

$$\text{Bit Flip Percentage} = \frac{\text{HammingDistance}(K_A, K_B)}{256} \times 100\%$$

### Results
| Cipher / Variant | Rounds | Block Size | Mean Bits Inverted (%) | Status |
| :--- | :---: | :---: | :---: | :---: |
| **NQV** | 8 | 32 Bytes (256 bits) | **50.06%** | Ideal (~50%) |
| **AES-256-GCM** | 14 | 12 Bytes (96 bits) | **50.04%** | Ideal (~50%) |
| **ChaCha20-Poly1305** | 20 | 12 Bytes (96 bits) | **50.05%** | Ideal (~50%) |

**Conclusion**: At 8 rounds, NQV achieves full non-linear avalanche diffusion statistically indistinguishable from AES-256 and ChaCha20.

---

## 3. Keystream Uniformity ($\chi^2$ Goodness-of-Fit)

Evaluates whether the distribution of output byte values ($0 \dots 255$) in a $1,000,000$ byte sample deviates from a uniform random distribution.

### Test Statistic
$$\chi^2 = \sum_{i=0}^{255} \frac{(O_i - E)^2}{E} \quad \text{where } E = \frac{1,000,000}{256} = 3906.25$$

At degrees of freedom $\text{df} = 255$ and significance level $\alpha = 0.05$, the critical upper threshold is $\chi_{\text{critical}}^2 \approx 293.25$.

### Results
| Cipher | Sample Size | $\chi^2$ Statistic | Verdict |
| :--- | :---: | :---: | :---: |
| **NQV (8 rounds)** | 1,000,000 Bytes | **248.78** | Consistent with Uniform |
| **AES-256-GCM** | 1,000,000 Bytes | **263.01** | Consistent with Uniform |
| **ChaCha20-Poly1305** | 1,000,000 Bytes | **244.14** | Consistent with Uniform |

**Conclusion**: NQV passes first-order byte frequency uniformity testing with zero measurable bias.

---

## 4. Scalability & SIMD Throughput Benchmark

Throughput (MB/s) measured across $1\text{ MB}$, $8\text{ MB}$, and $32\text{ MB}$ payload buffers (best of 5 trials with 200ms cooldown):

| Cipher | Payload Size | Encrypt Throughput | Decrypt Throughput |
| :--- | :---: | :---: | :---: |
| **NQV (8 rounds)** | **1 MB** | **1847.06 MB/s** | **1947.04 MB/s** |
| AES-256-GCM | 1 MB | 934.58 MB/s | 553.46 MB/s |
| ChaCha20-Poly1305 | 1 MB | 771.72 MB/s | 1003.81 MB/s |
| **NQV (8 rounds)** | **8 MB** | **2041.96 MB/s** | **1918.74 MB/s** |
| AES-256-GCM | 8 MB | 803.01 MB/s | 847.35 MB/s |
| ChaCha20-Poly1305 | 8 MB | 961.76 MB/s | 965.87 MB/s |
| **NQV (8 rounds)** | **32 MB** | **2227.20 MB/s** | **2748.48 MB/s** |
| AES-256-GCM | 32 MB | 783.68 MB/s | 781.66 MB/s |
| ChaCha20-Poly1305 | 32 MB | 979.57 MB/s | 921.81 MB/s |

---

## 5. Ablation Study: Round Count vs Performance

Performance and diffusion metrics across varying round counts ($R \in \{4, 6, 8, 10, 12\}$) on an $8\text{ MB}$ payload:

| Round Count | Execution Path | Throughput (MB/s) | Avalanche Diffusion (%) |
| :---: | :--- | :---: | :---: |
| **4 Rounds** | Single-Thread AVX2 | 1299.36 MB/s | 49.96% |
| **6 Rounds** | Single-Thread AVX2 | 1143.05 MB/s | 49.89% |
| **8 Rounds** | Single-Thread AVX2 | 909.04 MB/s | 49.88% |
| **10 Rounds** | Single-Thread AVX2 | 693.20 MB/s | 50.08% |
| **12 Rounds** | Single-Thread AVX2 | 674.52 MB/s | 50.09% |
| **8 Rounds** | **Multi-Thread Parallel AVX2** | **2098.97 MB/s** | **50.04%** |

---

## 6. Security Claims & Cryptanalytic Disclaimers

> **IMPORTANT Cryptographic Disclaimer**: NQV's throughput speedup is an **engineering result** derived from explicit 256-bit SIMD hardware vectorization and thread scheduling, rather than a cryptographic algorithm breakthrough. NQV has **not undergone third-party cryptanalysis**. It is published as an academic candidate cipher for cryptanalytic review.
