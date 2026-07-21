// NIST SP 800-22 Statistical Test Suite for NQV Stream Cipher
// ----------------------------------------------------------------
// Implements core statistical tests from NIST SP 800-22 Rev 1a:
//   1. Frequency (Monobit) Test
//   2. Block Frequency Test (Block Size M=128)
//   3. Cumulative Sums (Cusums) Test (Forward & Reverse)
//   4. Runs Test
//   5. Longest Run of Ones in a Block Test (M=128)
//   6. Serial Test (m=2, m=3)
//   7. Approximate Entropy Test (m=2)
//
// Significance Level alpha = 0.01 (P-value >= 0.01 indicates PASS).

use nqv::Nqv;

// ---------- Mathematical Functions for NIST SP 800-22 ----------

/// Complementary Error Function erfc(x) using Abramowitz & Stegun approximation (Formula 7.1.26).
/// Maximum error: 1.5e-7.
fn erfc(x: f64) -> f64 {
    if x < 0.0 {
        return 2.0 - erfc(-x);
    }
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * z);
    let poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let result = poly * (-z * z).exp();
    result
}

/// Incomplete Gamma Function Q(a, x) = 1 - P(a, x) = igamc(a, x).
/// Evaluates upper tail probability for Chi-Square P-value calculations.
fn igamc(a: f64, x: f64) -> f64 {
    if x <= 0.0 || a <= 0.0 {
        return 1.0;
    }
    if x < a + 1.0 {
        // Series expansion for P(a, x)
        let mut ap = a;
        let mut sum = 1.0 / a;
        let mut del = sum;
        for _ in 1..200 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-14 {
                break;
            }
        }
        let gamln = lgamma(a);
        let p = sum * (-x + a * x.ln() - gamln).exp();
        (1.0 - p).max(0.0).min(1.0)
    } else {
        // Continued fraction expansion for Q(a, x)
        let gamln = lgamma(a);
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / 1e-30;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..200 {
            let an = -(i as f64) * ((i as f64) - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < 1e-30 { d = 1e-30; }
            c = b + an / c;
            if c.abs() < 1e-30 { c = 1e-30; }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-14 {
                break;
            }
        }
        let q = (-x + a * x.ln() - gamln).exp() * h;
        q.max(0.0).min(1.0)
    }
}

/// Log Gamma Function ln(Gamma(xx)) using Lanczos approximation.
fn lgamma(xx: f64) -> f64 {
    let cof = [
        76.18009172947146,
        -86.50532032941677,
        24.01409824083091,
        -1.231739572450155,
        0.1208650973866179e-2,
        -0.5395239384953e-5,
    ];
    let mut y = xx;
    let x = xx;
    let mut tmp = x + 5.5;
    tmp -= (x + 0.5) * tmp.ln();
    let mut ser = 1.000000000190015;
    for j in 0..6 {
        y += 1.0;
        ser += cof[j] / y;
    }
    -tmp + (2.5066282746310005 * ser / x).ln()
}

// ---------- NIST SP 800-22 Test Implementation Struct ----------

struct NistTestResult {
    name: &'static str,
    p_value: f64,
    passed: bool,
    details: String,
}

struct NistTestSuite {
    results: Vec<NistTestResult>,
}

impl NistTestSuite {
    fn new() -> Self {
        Self { results: Vec::new() }
    }

    fn record(&mut self, name: &'static str, p_value: f64, details: String) {
        let passed = p_value >= 0.01 && !p_value.is_nan();
        self.results.push(NistTestResult {
            name,
            p_value,
            passed,
            details,
        });
    }

    /// 1. Frequency (Monobit) Test
    fn test_frequency(&mut self, bits: &[u8]) {
        let n = bits.len() as f64;
        let s_n: f64 = bits.iter().map(|&b| if b == 1 { 1.0 } else { -1.0 }).sum();
        let s_obs = s_n.abs() / n.sqrt();
        let p_value = erfc(s_obs / (2.0f64).sqrt());
        self.record(
            "Frequency (Monobit) Test",
            p_value,
            format!("S_n = {:.0}, s_obs = {:.4}", s_n, s_obs),
        );
    }

    /// 2. Frequency Test within a Block (Block Size M=128)
    fn test_block_frequency(&mut self, bits: &[u8], m: usize) {
        let n = bits.len();
        let num_blocks = n / m;
        if num_blocks == 0 {
            return;
        }

        let mut sum_chi2 = 0.0;
        for i in 0..num_blocks {
            let block = &bits[i * m..(i + 1) * m];
            let ones: usize = block.iter().map(|&b| b as usize).sum();
            let pi = ones as f64 / m as f64;
            let diff = pi - 0.5;
            sum_chi2 += diff * diff;
        }

        let chi2 = 4.0 * m as f64 * sum_chi2;
        let p_value = igamc(num_blocks as f64 / 2.0, chi2 / 2.0);
        self.record(
            "Block Frequency Test (M=128)",
            p_value,
            format!("chi2 = {:.4}, blocks = {}", chi2, num_blocks),
        );
    }

    /// 3. Cumulative Sums (Cusums) Test
    fn test_cusums(&mut self, bits: &[u8]) {
        let n = bits.len() as f64;
        let mut max_z_fwd = 0.0f64;
        let mut max_z_rev = 0.0f64;

        // Forward
        let mut s = 0.0f64;
        for &b in bits {
            s += if b == 1 { 1.0 } else { -1.0 };
            if s.abs() > max_z_fwd {
                max_z_fwd = s.abs();
            }
        }

        // Reverse
        s = 0.0f64;
        for &b in bits.iter().rev() {
            s += if b == 1 { 1.0 } else { -1.0 };
            if s.abs() > max_z_rev {
                max_z_rev = s.abs();
            }
        }

        let compute_p = |z: f64| -> f64 {
            let z_n = z / n.sqrt();
            let mut sum1 = 0.0;
            let k_start = ((-n / z + 1.0) / 4.0).floor() as i32;
            let k_end = ((n / z - 1.0) / 4.0).floor() as i32;
            for k in k_start..=k_end {
                let a = erfc(((4 * k + 1) as f64 * z_n) / (2.0f64).sqrt());
                let b = erfc(((4 * k - 1) as f64 * z_n) / (2.0f64).sqrt());
                sum1 += a - b;
            }

            let mut sum2 = 0.0;
            let k_start2 = ((-n / z - 3.0) / 4.0).floor() as i32;
            let k_end2 = ((n / z - 1.0) / 4.0).floor() as i32;
            for k in k_start2..=k_end2 {
                let a = erfc(((4 * k + 3) as f64 * z_n) / (2.0f64).sqrt());
                let b = erfc(((4 * k + 1) as f64 * z_n) / (2.0f64).sqrt());
                sum2 += a - b;
            }
            1.0 - sum1 + sum2
        };

        let p_fwd = compute_p(max_z_fwd);
        let p_rev = compute_p(max_z_rev);

        self.record(
            "Cumulative Sums (Cusums) Forward",
            p_fwd,
            format!("z = {:.0}", max_z_fwd),
        );
        self.record(
            "Cumulative Sums (Cusums) Reverse",
            p_rev,
            format!("z = {:.0}", max_z_rev),
        );
    }

    /// 4. Runs Test
    fn test_runs(&mut self, bits: &[u8]) {
        let n = bits.len() as f64;
        let ones: usize = bits.iter().map(|&b| b as usize).sum();
        let pi = ones as f64 / n;

        if (pi - 0.5).abs() >= (2.0 / n.sqrt()) {
            self.record(
                "Runs Test",
                0.0,
                format!("Failed pre-test: pi = {:.6} out of bounds", pi),
            );
            return;
        }

        let mut v_obs = 1.0f64;
        for i in 0..bits.len() - 1 {
            if bits[i] != bits[i + 1] {
                v_obs += 1.0;
            }
        }

        let num = (v_obs - 2.0 * n * pi * (1.0 - pi)).abs();
        let den = 2.0 * (2.0 * n).sqrt() * pi * (1.0 - pi);
        let p_value = erfc(num / den);

        self.record(
            "Runs Test",
            p_value,
            format!("V_obs = {:.0}, pi = {:.4}", v_obs, pi),
        );
    }

    /// 5. Longest Run of Ones in a Block Test (M=128)
    fn test_longest_run_ones(&mut self, bits: &[u8]) {
        let m = 128;
        let num_blocks = bits.len() / m;
        if num_blocks < 16 {
            return;
        }

        // Expected proportions for M=128 (K=3, K=4, K=5, K=6, K=7, K=8, K=9+)
        let pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124];
        let mut v = [0u64; 6];

        for b in 0..num_blocks {
            let block = &bits[b * m..(b + 1) * m];
            let mut max_run = 0usize;
            let mut current_run = 0usize;
            for &bit in block {
                if bit == 1 {
                    current_run += 1;
                    if current_run > max_run {
                        max_run = current_run;
                    }
                } else {
                    current_run = 0;
                }
            }

            let cat = if max_run <= 4 {
                0
            } else if max_run == 5 {
                1
            } else if max_run == 6 {
                2
            } else if max_run == 7 {
                3
            } else if max_run == 8 {
                4
            } else {
                5
            };
            v[cat] += 1;
        }

        let mut chi2 = 0.0f64;
        for i in 0..6 {
            let expected = num_blocks as f64 * pi[i];
            let diff = v[i] as f64 - expected;
            chi2 += (diff * diff) / expected;
        }

        let p_value = igamc(2.5, chi2 / 2.0);
        self.record(
            "Longest Run of Ones (M=128)",
            p_value,
            format!("chi2 = {:.4}, blocks = {}", chi2, num_blocks),
        );
    }

    /// 6. Serial Test (m=2)
    fn test_serial(&mut self, bits: &[u8], m: usize) {
        let n = bits.len();
        let compute_psi2 = |len: usize| -> f64 {
            let mut counts = vec![0u64; 1 << len];
            for i in 0..n {
                let mut pattern = 0usize;
                for j in 0..len {
                    pattern = (pattern << 1) | (bits[(i + j) % n] as usize);
                }
                counts[pattern] += 1;
            }
            let sum_sq: u64 = counts.iter().map(|&c| c * c).sum();
            (sum_sq as f64 * (1 << len) as f64 / n as f64) - n as f64
        };

        let psi2_m = compute_psi2(m);
        let psi2_m1 = compute_psi2(m - 1);
        let psi2_m2 = compute_psi2(m - 2);

        let d_psi2 = psi2_m - psi2_m1;
        let d2_psi2 = psi2_m - 2.0 * psi2_m1 + psi2_m2;

        let p1 = igamc((1 << (m - 2)) as f64, d_psi2 / 2.0);
        let p2 = igamc((1 << (m - 3)) as f64, d2_psi2 / 2.0);

        self.record(
            "Serial Test 1 (m=2)",
            p1,
            format!("d_psi2 = {:.4}", d_psi2),
        );
        self.record(
            "Serial Test 2 (m=2)",
            p2,
            format!("d2_psi2 = {:.4}", d2_psi2),
        );
    }

    /// 7. Approximate Entropy Test (m=2)
    fn test_approximate_entropy(&mut self, bits: &[u8], m: usize) {
        let n = bits.len();
        let compute_phi = |len: usize| -> f64 {
            let mut counts = vec![0u64; 1 << len];
            for i in 0..n {
                let mut pattern = 0usize;
                for j in 0..len {
                    pattern = (pattern << 1) | (bits[(i + j) % n] as usize);
                }
                counts[pattern] += 1;
            }
            let mut phi = 0.0f64;
            for &c in &counts {
                if c > 0 {
                    let p = c as f64 / n as f64;
                    phi += p * p.ln();
                }
            }
            phi
        };

        let phi_m = compute_phi(m);
        let phi_m1 = compute_phi(m + 1);
        let ap_en = phi_m - phi_m1;
        let chi2 = 2.0 * n as f64 * (2.0f64.ln() - ap_en);
        let p_value = igamc((1 << (m - 1)) as f64, chi2 / 2.0);

        self.record(
            "Approximate Entropy Test (m=2)",
            p_value,
            format!("ApEn = {:.6}, chi2 = {:.4}", ap_en, chi2),
        );
    }
}

fn main() {
    println!("=== NIST SP 800-22 STATISTICAL TEST SUITE FOR NQV ===");
    println!("Significance Level alpha = 0.01 (P-value >= 0.01 indicates PASS)\n");

    // 1. Generate 1,000,000 bits (125,000 bytes) of NQV keystream
    let sample_bytes = 125_000usize;
    let key = [0x77u8; 32];
    let iv  = [0x22u8; 32];
    let cipher = Nqv::new(&key, 8);

    let zero_buf = vec![0u8; sample_bytes];
    let keystream = cipher.stream_transform_x16(&zero_buf, &iv);

    // Expand bytes to individual 0/1 bits vector
    let mut bits = Vec::with_capacity(sample_bytes * 8);
    for &byte in &keystream {
        for bit_idx in (0..8).rev() {
            bits.push((byte >> bit_idx) & 1);
        }
    }

    println!("Sample Size: {} bytes ({} bits)", sample_bytes, bits.len());
    println!("Cipher: NQV (8 rounds, AVX2 / Scalar)\n");

    // 2. Execute NIST SP 800-22 Test Suite
    let mut suite = NistTestSuite::new();
    suite.test_frequency(&bits);
    suite.test_block_frequency(&bits, 128);
    suite.test_cusums(&bits);
    suite.test_runs(&bits);
    suite.test_longest_run_ones(&bits);
    suite.test_serial(&bits, 2);
    suite.test_approximate_entropy(&bits, 2);

    // 3. Print Results Table
    println!("{:<36} {:>12} {:>10}   {}", "Statistical Test", "P-Value", "Verdict", "Details");
    println!("{}", "-".repeat(80));

    let mut all_passed = true;
    for res in &suite.results {
        let verdict = if res.passed { "PASS" } else { "FAIL" };
        if !res.passed {
            all_passed = false;
        }
        println!("{:<36} {:>12.6} {:>10}   {}", res.name, res.p_value, verdict, res.details);
    }

    println!("{}", "-".repeat(80));
    if all_passed {
        println!("\nFINAL VERDICT: [PASS] All NIST SP 800-22 statistical tests passed (P-value >= 0.01).");
    } else {
        println!("\nFINAL VERDICT: [FAIL] One or more NIST SP 800-22 statistical tests failed.");
    }
}
