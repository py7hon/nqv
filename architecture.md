# NQV Technical Architecture Specification

**Author**: Muhammad Iqbal Rifai ([GitHub: @py7hon](https://github.com/py7hon))  
**License**: Apache-2.0  

---

## 1. High-Level Design Overview

**NQV** (Non-commutative Quasigroup Vector cipher) is a high-throughput, hardware-accelerated symmetric stream cipher operating in **Counter (CTR) mode**. It combines algebraic quasigroup mixing structures with an Add-Rotate-XOR (ARX) framework, 256-bit AVX2 SIMD intrinsics, and adaptive multi-core parallel execution.

### Cryptographic Parameters
- **Master Key Length**: 256 bits (32 bytes), $K = [K_0, K_1, K_2, K_3]$ (four 64-bit words).
- **Nonce / Initialization Vector (IV)**: 256 bits (32 bytes), $N = [N_0, N_1, N_2, N_3]$.
- **Counter State**: 256-bit big-endian integer initialized to $N$ and incremented per 32-byte block.
- **Block Size**: 256 bits (32 bytes).
- **Default Round Count**: 8 rounds.

---

## 2. State Representation & Key Schedule

### 2.1 State Representation
The cipher state $S$ is modeled as a 4-lane vector of 64-bit unsigned integers:
$$S = [s_0, s_1, s_2, s_3] \in (\mathbb{Z} / 2^{64}\mathbb{Z})^4$$

When transforming a 32-byte block, the block bytes are parsed as little-endian 64-bit words into $S$.

### 2.2 Round Key Derivation
For each round $r \in \{0, 1, \dots, R-1\}$ (where default $R = 8$), a 256-bit round key vector $\text{RK}^{(r)} = [\text{RK}_0^{(r)}, \text{RK}_1^{(r)}, \text{RK}_2^{(r)}, \text{RK}_3^{(r)}]$ is computed from the master key lanes:
$$\text{RK}_i^{(r)} = K_i \lll ((r \cdot 11 + i \cdot 17) \bmod 64) \quad \text{for } i \in \{0, 1, 2, 3\}$$

---

## 3. Round Function Pipeline

Each round $r$ consists of three distinct mathematical layers applied sequentially to the state vector $S$:

```text
       Input State (S) & Round Key (RK)
                    │
   ┌────────────────┴────────────────┐
   │  1. Quasigroup Vector Mix (QVM) │
   └────────────────┬────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │    2. Avalanche Cascade (AC)    │
   └────────────────┬────────────────┘
                    │
   ┌────────────────┴────────────────┐
   │  3. Vector Diffusion Layer (VD) │
   └────────────────┬────────────────┘
                    │
       Output State (S') to Next Round
```

### 3.1 Layer 1: Quasigroup Vector Mix (QVM)
The QVM layer injects round keys and Nothing-Up-My-Sleeve (NUMS) constants non-linearly across the four lanes:
$$s_i \leftarrow \left( (s_i \lll \alpha_i) \oplus (\text{RK}_i \ggg \beta_i) \right) + C_i \pmod{2^{64}}$$

Rotation parameters and NUMS constants per lane $i \in \{0, 1, 2, 3\}$:
- Left rotation vector: $\alpha = [11, 17, 23, 29]$
- Right rotation vector: $\beta = [7, 13, 19, 23]$
- NUMS constants $C = [C_\pi, C_e, C_{\sqrt{2}}, C_{\sqrt{3}}]$:
  - $C_\pi = \text{0x243F6A8885A308D3}$ (fractional bits of $\pi$)
  - $C_e = \text{0x14254DEE8513B0A1}$ (fractional bits of $e$)
  - $C_{\sqrt{2}} = \text{0x6A09E667F3BCC908}$ (fractional bits of $\sqrt{2}$)
  - $C_{\sqrt{3}} = \text{0xBB67AE8584CAA73B}$ (fractional bits of $\sqrt{3}$)

### 3.2 Layer 2: Avalanche Cascade (AC)
The Avalanche Cascade layer creates strong non-linear differential propagation across state lanes:
$$t_i = (s_i \lll \gamma_i) \oplus (s_i \ggg \delta_i)$$
$$s_i \leftarrow s_i + t_i \pmod{2^{64}}$$

Cascade rotation vectors:
- Left cascade rotation: $\gamma = [43, 41, 37, 31]$
- Right cascade rotation: $\delta = [29, 23, 19, 17]$

### 3.3 Layer 3: Vector Diffusion (VD)
The Vector Diffusion layer permutes lane dependencies across adjacent registers. Let $B = [s_1, s_2, s_3, s_0]$ represent the lane-shifted vector (permuted via SIMD `_mm256_permute4x64_epi64` control mask `0x39`):
$$s_i \leftarrow \left( (s_i \lll \epsilon_i) \oplus (B_i \ggg \zeta_i) \right) + C'_i \pmod{2^{64}}$$

Diffusion rotation parameters:
- Left diffusion rotation: $\epsilon = [31, 23, 19, 13]$
- Right diffusion rotation: $\zeta = [29, 17, 11, 5]$
- Inverted NUMS constants $C' = [C_{\sqrt{3}}, C_{\sqrt{2}}, C_e, C_\pi]$

---

## 4. Hardware SIMD & Parallel Dispatcher Architecture

### 4.1 AVX2 256-bit Register Vectorization (`src/simd.rs`)
On x86-64 CPUs with AVX2 support, NQV loads **8 independent counter blocks (256 bytes total)** across 8 YMM SIMD registers ($Y_0 \dots Y_7$) per iteration:
- 256-bit SIMD additions: `_mm256_add_epi64`
- Variable vector shifts: `_mm256_sllv_epi64`, `_mm256_srlv_epi64`
- Cross-lane vector permutation: `_mm256_permute4x64_epi64`
- XOR operations: `_mm256_xor_si256`

### 4.2 Adaptive Parallel Engine (`src/parallel.rs`)
For input buffers exceeding $256\text{ KB}$ (`MIN_PARALLEL_CHUNK`):
1. Reads host core count via `std::thread::available_parallelism()`.
2. Computes ideal chunk size $C_\text{size} = \text{max}(256\text{ KB}, \text{data.len()} / \text{cores})$, aligned up to 512-byte block boundaries.
3. Spawns threads inside `std::thread::scope` with counter offset calculated via `offset_counter(&mut chunk_iv, blocks_offset)`.
4. Outputs results directly into pre-allocated memory slices without lock contention.
