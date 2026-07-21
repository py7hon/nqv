// NQV Benchmark Suite (NQV vs AES-256-GCM vs ChaCha20-Poly1305)
// ------------------------------------------------
// 0. Runtime correctness self-check (AVX2 == scalar, CTR round-trip).
// 1. Throughput benchmark (encrypt/decrypt, MB/s) at several sizes.
// 2. Avalanche diffusion test (1-bit nonce flip -> % keystream bits changed).
// 3. Chi-square goodness-of-fit on keystream byte distribution.
// 4. Ablation study across round counts (4, 6, 8, 10, 12 rounds).

use nqv::Nqv;

use std::thread::sleep;
use std::time::{Duration, Instant};

use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};
use rand::RngCore;

// ---------- helpers ----------

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

fn hamming_distance_bits(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn chi_square_uniform_bytes(data: &[u8]) -> (f64, usize) {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let expected = n / 256.0;
    let chi2: f64 = counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            (d * d) / expected
        })
        .sum();
    (chi2, 255)
}

fn fmt_mbps(bytes: usize, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

/// Best-of-N timing to exclude OS scheduling noise / preemption spikes.
fn best_of<F: Fn() -> f64>(trials: usize, f: F) -> f64 {
    (0..trials).map(|_| f()).fold(f64::INFINITY, f64::min)
}

fn flip_one_bit_array32(data: &[u8; 32]) -> [u8; 32] {
    let mut out = *data;
    out[0] ^= 0x01;
    out
}

fn flip_one_bit_array12(data: &[u8; 12]) -> [u8; 12] {
    let mut out = *data;
    out[0] ^= 0x01;
    out
}

// ---------- cipher setup wrappers ----------

fn nqv_setup(rounds: usize) -> (Nqv, [u8; 32]) {
    let key = [0x77u8; 32];
    let iv = [0x22u8; 32];
    (Nqv::new(&key, rounds), iv)
}

// ---------- 0. correctness self-check ----------

fn run_correctness_check() -> bool {
    println!("=== 0. CORRECTNESS SELF-CHECK ===");
    let key = [0x42u8; 32];
    let iv = [0x99u8; 32];
    let cipher = Nqv::new(&key, 8);
    let mut all_ok = true;

    if std::is_x86_feature_detected!("avx2") {
        let mut avx2_ok = true;
        for &size in &[256usize, 512, 1000, 4096, 100_000] {
            let data = vec![0xABu8; size];
            let scalar_out = cipher.stream_transform_scalar(&data, &iv);
            let avx2_out = unsafe { cipher.stream_transform_avx2(&data, &iv) };
            if scalar_out != avx2_out {
                println!(
                    "  [FAIL] AVX2 output diverges from scalar at size {} bytes!",
                    size
                );
                avx2_ok = false;
                all_ok = false;
            }
        }
        if avx2_ok {
            println!(
                "  [PASS] AVX2 output == scalar output (sizes 256B .. 100KB, incl. tail cases)."
            );
        }
    } else {
        println!(
            "  [SKIP] AVX2 not detected on this CPU — scalar-only path will run for all tests."
        );
    }

    let plaintext = random_bytes(50_000);
    let ct = cipher.stream_transform_parallel(&plaintext, &iv);
    let pt = cipher.stream_transform_parallel(&ct, &iv);
    if pt != plaintext {
        println!("  [FAIL] Encrypt/decrypt round-trip failed — CTR mode is broken.");
        all_ok = false;
    } else {
        println!(
            "  [PASS] Encrypt/decrypt round-trip verified (CTR self-inverse property holds)."
        );
    }

    if all_ok {
        println!("  All checks passed — benchmark numbers below are trustworthy.\n");
    } else {
        println!(
            "\n  !!! CORRECTNESS FAILURE — DO NOT TRUST ANY NUMBER BELOW UNTIL FIXED !!!\n"
        );
    }
    all_ok
}

// ---------- warmup ----------

fn warmup() {
    println!("Warming up (32 MB pass per cipher, AVX2 + scalar paths both touched)...");
    let buf = random_bytes(32 * 1024 * 1024);

    let (c, iv) = nqv_setup(8);
    let _ = c.stream_transform_parallel(&buf, &iv);

    let key = AesKey::<Aes256Gcm>::from_slice(&[0x33u8; 32]);
    let cipher = Aes256Gcm::new(key);
    let nonce = AesNonce::from_slice(&[0x44u8; 12]);
    let _ = cipher.encrypt(nonce, buf.as_slice()).unwrap();

    let key = ChaKey::from_slice(&[0x55u8; 32]);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaNonce::from_slice(&[0x66u8; 12]);
    let _ = cipher.encrypt(nonce, buf.as_slice()).unwrap();

    println!("Warmup done.\n");
}

// ---------- 1. throughput ----------

fn run_throughput_benchmark() {
    println!("=== 1. THROUGHPUT BENCHMARK ===");
    println!("Best of 5 trials per measurement. 200ms cooldown between encrypt");
    println!("and decrypt timing to reduce AVX2 clock-throttle carryover.");
    println!("NQV row uses 8 rounds (AVX2-accelerated, auto-dispatch).");
    println!(
        "{:<24} {:>8} {:>16} {:>16}",
        "Cipher", "Size", "Encrypt MB/s", "Decrypt MB/s"
    );
    println!("{}", "-".repeat(68));

    let sizes = [
        (1usize * 1024 * 1024, "1 MB"),
        (8 * 1024 * 1024, "8 MB"),
        (32 * 1024 * 1024, "32 MB"),
    ];

    for &(size, label) in &sizes {
        let plaintext = random_bytes(size);

        // --- NQV ---
        {
            let (cipher, iv) = nqv_setup(8);
            let enc_secs = best_of(5, || {
                let t = Instant::now();
                let ct = cipher.stream_transform_parallel(&plaintext, &iv);
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(ct);
                s
            });
            sleep(Duration::from_millis(200));
            let ct = cipher.stream_transform_parallel(&plaintext, &iv);
            let dec_secs = best_of(5, || {
                let t = Instant::now();
                let pt = cipher.stream_transform_parallel(&ct, &iv);
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(pt);
                s
            });
            println!(
                "{:<24} {:>8} {:>16.2} {:>16.2}",
                "NQV (8 rounds)",
                label,
                fmt_mbps(size, enc_secs),
                fmt_mbps(size, dec_secs)
            );
        }

        // --- AES-256-GCM ---
        {
            let key = AesKey::<Aes256Gcm>::from_slice(&[0x33u8; 32]);
            let cipher = Aes256Gcm::new(key);
            let nonce = AesNonce::from_slice(&[0x44u8; 12]);

            let enc_secs = best_of(5, || {
                let t = Instant::now();
                let ct = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(ct);
                s
            });
            sleep(Duration::from_millis(200));
            let ct = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
            let dec_secs = best_of(5, || {
                let t = Instant::now();
                let pt = cipher.decrypt(nonce, ct.as_slice()).unwrap();
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(pt);
                s
            });
            println!(
                "{:<24} {:>8} {:>16.2} {:>16.2}",
                "AES-256-GCM",
                label,
                fmt_mbps(size, enc_secs),
                fmt_mbps(size, dec_secs)
            );
        }

        // --- ChaCha20-Poly1305 ---
        {
            let key = ChaKey::from_slice(&[0x55u8; 32]);
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = ChaNonce::from_slice(&[0x66u8; 12]);

            let enc_secs = best_of(5, || {
                let t = Instant::now();
                let ct = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(ct);
                s
            });
            sleep(Duration::from_millis(200));
            let ct = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
            let dec_secs = best_of(5, || {
                let t = Instant::now();
                let pt = cipher.decrypt(nonce, ct.as_slice()).unwrap();
                let s = t.elapsed().as_secs_f64();
                std::hint::black_box(pt);
                s
            });
            println!(
                "{:<24} {:>8} {:>16.2} {:>16.2}",
                "ChaCha20-Poly1305",
                label,
                fmt_mbps(size, enc_secs),
                fmt_mbps(size, dec_secs)
            );
        }

        println!();
    }
}

// ---------- 2. avalanche ----------

fn run_avalanche_test() {
    println!("=== 2. AVALANCHE DIFFUSION TEST (1-bit NONCE flip -> keystream) ===");
    println!("Block: 32 bytes (256 bits). Trials: 2000. Ideal: ~50.0%");
    println!("{:<24} {:>16}", "Cipher", "Mean bits changed %");
    println!("{}", "-".repeat(42));

    let trials = 2000usize;
    let block_len = 32usize;
    let zero_block = vec![0u8; block_len];

    {
        let (cipher, _) = nqv_setup(8);
        let mut total = 0.0f64;
        for _ in 0..trials {
            let iv_a: [u8; 32] = random_bytes(32).try_into().unwrap();
            let iv_b = flip_one_bit_array32(&iv_a);
            let mut ks_a = iv_a;
            let mut ks_b = iv_b;
            cipher.permute(&mut ks_a);
            cipher.permute(&mut ks_b);
            total += hamming_distance_bits(&ks_a, &ks_b) as f64 / (block_len as f64 * 8.0) * 100.0;
        }
        println!("{:<24} {:>15.2}%", "NQV (8 rounds)", total / trials as f64);
    }

    // AES-256-GCM
    {
        let key = AesKey::<Aes256Gcm>::from_slice(&[0x33u8; 32]);
        let cipher = Aes256Gcm::new(key);
        let mut total = 0.0f64;
        for _ in 0..trials {
            let na: [u8; 12] = random_bytes(12).try_into().unwrap();
            let nb = flip_one_bit_array12(&na);
            let ka = cipher
                .encrypt(AesNonce::from_slice(&na), zero_block.as_slice())
                .unwrap();
            let kb = cipher
                .encrypt(AesNonce::from_slice(&nb), zero_block.as_slice())
                .unwrap();
            total += hamming_distance_bits(&ka[..block_len], &kb[..block_len]) as f64
                / (block_len as f64 * 8.0)
                * 100.0;
        }
        println!("{:<24} {:>15.2}%", "AES-256-GCM", total / trials as f64);
    }

    // ChaCha20-Poly1305
    {
        let key = ChaKey::from_slice(&[0x55u8; 32]);
        let cipher = ChaCha20Poly1305::new(key);
        let mut total = 0.0f64;
        for _ in 0..trials {
            let na: [u8; 12] = random_bytes(12).try_into().unwrap();
            let nb = flip_one_bit_array12(&na);
            let ka = cipher
                .encrypt(ChaNonce::from_slice(&na), zero_block.as_slice())
                .unwrap();
            let kb = cipher
                .encrypt(ChaNonce::from_slice(&nb), zero_block.as_slice())
                .unwrap();
            total += hamming_distance_bits(&ka[..block_len], &kb[..block_len]) as f64
                / (block_len as f64 * 8.0)
                * 100.0;
        }
        println!(
            "{:<24} {:>15.2}%",
            "ChaCha20-Poly1305",
            total / trials as f64
        );
    }

    println!();
}

// ---------- 3. chi-square ----------

fn run_randomness_test() {
    println!("=== 3. KEYSTREAM RANDOMNESS (chi-square vs uniform) ===");
    println!("Sample: 1,000,000 bytes. df=255. Critical (alpha=0.05): ~293.25.");
    println!("{:<24} {:>16} {:>10}", "Cipher", "Chi2 statistic", "Verdict");
    println!("{}", "-".repeat(54));

    let sample_len = 1_000_000usize;
    let zero_buf = vec![0u8; sample_len];

    {
        let (cipher, iv) = nqv_setup(8);
        let ks = cipher.stream_transform_parallel(&zero_buf, &iv);
        let (chi2, _) = chi_square_uniform_bytes(&ks);
        println!(
            "{:<24} {:>16.2} {:>10}",
            "NQV (8 rounds)",
            chi2,
            if chi2 < 293.25 {
                "consistent"
            } else {
                "DEVIATES"
            }
        );
    }
    {
        let key = AesKey::<Aes256Gcm>::from_slice(&[0x33u8; 32]);
        let cipher = Aes256Gcm::new(key);
        let ct = cipher
            .encrypt(AesNonce::from_slice(&[0x44u8; 12]), zero_buf.as_slice())
            .unwrap();
        let (chi2, _) = chi_square_uniform_bytes(&ct[..sample_len]);
        println!(
            "{:<24} {:>16.2} {:>10}",
            "AES-256-GCM",
            chi2,
            if chi2 < 293.25 {
                "consistent"
            } else {
                "DEVIATES"
            }
        );
    }
    {
        let key = ChaKey::from_slice(&[0x55u8; 32]);
        let cipher = ChaCha20Poly1305::new(key);
        let ct = cipher
            .encrypt(ChaNonce::from_slice(&[0x66u8; 12]), zero_buf.as_slice())
            .unwrap();
        let (chi2, _) = chi_square_uniform_bytes(&ct[..sample_len]);
        println!(
            "{:<24} {:>16.2} {:>10}",
            "ChaCha20-Poly1305",
            chi2,
            if chi2 < 293.25 {
                "consistent"
            } else {
                "DEVIATES"
            }
        );
    }

    println!("\nNote: single first-order byte-frequency test. Run full NIST");
    println!("SP 800-22 suite for a defensible randomness claim in the paper.\n");
}

// ---------- 4. ablation ----------

fn run_v4_comparison() {
    println!("=== 4. ABLATION STUDY & SCALABILITY ===");
    let size = 8 * 1024 * 1024usize;
    let plaintext = random_bytes(size);
    let label = "8 MB";

    println!("-- Throughput (best of 5 trials) --");
    println!("{:<38} {:>8} {:>16}", "Variant", "Size", "Encrypt MB/s");
    println!("{}", "-".repeat(64));

    for &rounds in &[4usize, 6, 8, 10, 12] {
        let (cipher, iv) = nqv_setup(rounds);
        let secs = best_of(5, || {
            let t = Instant::now();
            let r = cipher.stream_transform_x16(&plaintext, &iv);
            let s = t.elapsed().as_secs_f64();
            std::hint::black_box(r);
            s
        });
        println!(
            "{:<38} {:>8} {:>16.2}",
            format!("NQV ({} rounds, single-thread AVX2)", rounds),
            label,
            fmt_mbps(size, secs)
        );
    }

    {
        let (cipher, iv) = nqv_setup(8);
        let secs = best_of(5, || {
            let t = Instant::now();
            let r = cipher.stream_transform_parallel(&plaintext, &iv);
            let s = t.elapsed().as_secs_f64();
            std::hint::black_box(r);
            s
        });
        println!(
            "{:<38} {:>8} {:>16.2}",
            "NQV (8 rounds, AVX2 parallel)",
            label,
            fmt_mbps(size, secs)
        );
    }

    {
        let key = ChaKey::from_slice(&[0x55u8; 32]);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaNonce::from_slice(&[0x66u8; 12]);
        let secs = best_of(5, || {
            let t = Instant::now();
            let r = cipher.encrypt(nonce, plaintext.as_slice()).unwrap();
            let s = t.elapsed().as_secs_f64();
            std::hint::black_box(r);
            s
        });
        println!(
            "{:<38} {:>8} {:>16.2}",
            "ChaCha20-Poly1305 (reference)",
            label,
            fmt_mbps(size, secs)
        );
    }

    println!("\n-- Avalanche (1-bit nonce flip -> keystream), 2000 trials --");
    println!("{:<38} {:>16}", "Variant", "Mean bits changed");
    println!("{}", "-".repeat(56));

    let trials = 2000;
    let block_len = 32usize;

    for &rounds in &[4usize, 6, 8, 10, 12] {
        let (cipher, _) = nqv_setup(rounds);
        let mut total = 0.0f64;
        for _ in 0..trials {
            let iv_a: [u8; 32] = random_bytes(32).try_into().unwrap();
            let iv_b = flip_one_bit_array32(&iv_a);
            let mut ks_a = iv_a;
            let mut ks_b = iv_b;
            cipher.permute(&mut ks_a);
            cipher.permute(&mut ks_b);
            total += hamming_distance_bits(&ks_a, &ks_b) as f64 / (block_len as f64 * 8.0) * 100.0;
        }
        println!(
            "{:<38} {:>15.2}%",
            format!("NQV ({} rounds)", rounds),
            total / trials as f64
        );
    }

    println!("\nNote: NQV uses AVX2 hardware intrinsics for the hot path with an");
    println!("automatic scalar fallback on non-AVX2 CPUs (see correctness self-");
    println!("check at program start). This is an engineering result about");
    println!("instruction-level/SIMD parallelism, not a cryptographic security claim.\n");
}

// ---------- 5. AEAD throughput ----------

fn run_aead_benchmark() {
    println!("=== 5. NQV-AEAD THROUGHPUT BENCHMARK ===");
    println!("Evaluates Authenticated Encryption (seal_aead) & Decryption (open_aead)");
    println!("Payload Size: 8 MB | Associated Data (AAD): 64 bytes\n");

    let size = 8 * 1024 * 1024usize;
    let plaintext = random_bytes(size);
    let aad = random_bytes(64);
    let (cipher, iv) = nqv_setup(8);

    let seal_secs = best_of(5, || {
        let t = Instant::now();
        let (ct, tag) = cipher.seal_aead(&plaintext, &aad, &iv);
        let s = t.elapsed().as_secs_f64();
        std::hint::black_box((ct, tag));
        s
    });

    let (ct, tag) = cipher.seal_aead(&plaintext, &aad, &iv);

    let open_secs = best_of(5, || {
        let t = Instant::now();
        let pt = cipher.open_aead(&ct, &tag, &aad, &iv).unwrap();
        let s = t.elapsed().as_secs_f64();
        std::hint::black_box(pt);
        s
    });

    println!(
        "{:<28} {:>16.2} MB/s",
        "NQV-AEAD Seal (Encrypt + MAC)",
        fmt_mbps(size, seal_secs)
    );
    println!(
        "{:<28} {:>16.2} MB/s\n",
        "NQV-AEAD Open (Verify + Decrypt)",
        fmt_mbps(size, open_secs)
    );
}

fn main() {
    println!("NQV Benchmark Suite (NQV vs AES-256-GCM vs ChaCha20-Poly1305)");
    println!("Zero external dependencies in NQV library crate itself.");
    println!("AVX2 available on this CPU: {}\n", std::is_x86_feature_detected!("avx2"));

    if !run_correctness_check() {
        eprintln!("Aborting: fix correctness failures before generating benchmark numbers.");
        std::process::exit(1);
    }

    warmup();
    run_throughput_benchmark();
    run_avalanche_test();
    run_randomness_test();
    run_v4_comparison();
    run_aead_benchmark();
}
