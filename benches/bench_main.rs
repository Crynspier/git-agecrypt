//! Performance benchmark matrix (harness = false).
//!
//! Layers:
//! - In-process crypto micro-benches: spool throughput, clean/smudge latency per payload size.
//! - End-to-end CLI benches: clean/smudge single file, bulk clean via git add, lock, unlock,
//!   rekey, status on a 20-file repo.
//!
//! Every metric has a generous absolute sanity ceiling (catastrophic-regression tripwire).
//! With GIT_AGECRYPT_BENCH_JSON=1 a JSON report is printed (CI archives it as an artifact).
//! With GIT_AGECRYPT_BENCH_CHECK=1, metrics are compared against benches/baseline.json
//! and regressions beyond the tolerance factor fail the run.

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct Metric {
    name: String,
    elapsed: Duration,
    detail: String,
    ceiling: Duration,
}

impl Metric {
    fn new(name: &str, elapsed: Duration, detail: String, ceiling_secs: u64) -> Self {
        Metric {
            name: name.to_string(),
            elapsed,
            detail,
            ceiling: Duration::from_secs(ceiling_secs),
        }
    }
}

fn time_it<F: FnMut()>(mut f: F) -> Duration {
    let start = Instant::now();
    f();
    start.elapsed()
}

fn median_of(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// Locates the compiled git-agecrypt binary relative to this bench executable
/// (target/<profile>/deps/bench_main-* -> target/<profile>/git-agecrypt).
fn locate_binary() -> PathBuf {
    let exe = std::env::current_exe().expect("current_exe");
    let mut dir = exe.parent().map(Path::to_path_buf).unwrap_or_default();
    loop {
        for name in ["git-agecrypt.exe", "git-agecrypt"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                return candidate;
            }
        }
        if !dir.pop() {
            panic!(
                "could not locate git-agecrypt binary near {}",
                exe.display()
            );
        }
    }
}

fn run_cmd(repo: &Path, bin: &Path, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .current_dir(repo)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_git(repo: &Path, bin_dir: &Path, args: &[&str]) {
    let mut paths = vec![bin_dir.to_path_buf()];
    if let Some(cur) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&cur));
    }
    let new_path = std::env::join_paths(paths).unwrap_or_default();
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("PATH", new_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("spawn git");
    assert!(status.success(), "git {:?} failed", args);
}
/// In-process crypto micro-benchmarks (spool / clean / smudge per payload size).
fn bench_crypto(metrics: &mut Vec<Metric>) {
    use age::secrecy::ExposeSecret;

    let sizes = [
        ("1KB", 1024usize),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("4MB", 4 * 1024 * 1024),
    ];

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let key_bytes = identity.to_string().expose_secret().as_bytes().to_vec();

    for (label, size) in sizes {
        let payload = vec![0x42u8; size];

        // Spool throughput (no crypto).
        let t = time_it(|| {
            let mut cursor = Cursor::new(&payload);
            let (spool, _) = git_agecrypt::crypto::spool_stream(&mut cursor, None, None).unwrap();
            std::hint::black_box(spool.is_in_memory());
        });
        let mbps = (size as f64 / (1024.0 * 1024.0)) / t.as_secs_f64().max(1e-9);
        metrics.push(Metric::new(
            &format!("crypto.spool.{label}"),
            t,
            format!("{mbps:.2} MB/s"),
            20,
        ));

        // Clean (encrypt) latency.
        let mut ciphertext = Vec::new();
        let t = time_it(|| {
            ciphertext.clear();
            git_agecrypt::crypto::clean_stream(
                Cursor::new(&payload),
                &mut ciphertext,
                &recipient,
                None,
                Some(&identity),
                Some(&key_bytes),
                None,
            )
            .unwrap();
        });
        let mbps = (size as f64 / (1024.0 * 1024.0)) / t.as_secs_f64().max(1e-9);
        metrics.push(Metric::new(
            &format!("crypto.clean.{label}"),
            t,
            format!("{mbps:.2} MB/s"),
            30,
        ));

        // Smudge (decrypt) latency.
        let mut plaintext = Vec::new();
        let t = time_it(|| {
            plaintext.clear();
            git_agecrypt::crypto::smudge_stream(
                Cursor::new(&ciphertext),
                &mut plaintext,
                Some(&identity),
                None,
                Some(&key_bytes),
            )
            .unwrap();
        });
        assert_eq!(plaintext, payload, "smudge roundtrip must be lossless");
        let mbps = (size as f64 / (1024.0 * 1024.0)) / t.as_secs_f64().max(1e-9);
        metrics.push(Metric::new(
            &format!("crypto.smudge.{label}"),
            t,
            format!("{mbps:.2} MB/s"),
            30,
        ));
    }
}
/// End-to-end CLI benchmarks on a 20-file secret repo.
fn bench_e2e(metrics: &mut Vec<Metric>, bin: &Path) {
    use age::secrecy::ExposeSecret;

    let bin_dir = bin.parent().unwrap().to_path_buf();
    let temp = tempfile::tempdir().expect("bench tempdir");
    let repo = temp.path();

    run_git(repo, &bin_dir, &["init"]);
    run_git(repo, &bin_dir, &["config", "user.name", "Bench"]);
    run_git(
        repo,
        &bin_dir,
        &["config", "user.email", "bench@example.com"],
    );

    assert!(run_cmd(repo, bin, &["init"]));
    let identity = age::x25519::Identity::generate();
    let sec = identity.to_string().expose_secret().to_string();
    let pub_key = identity.to_public().to_string();
    assert!(run_cmd(
        repo,
        bin,
        &["add-recipient", "-i", &pub_key, "--name", "bench"]
    ));

    std::fs::write(
        repo.join(".gitattributes"),
        "*.secret.env filter=agecrypt diff=agecrypt merge=agecrypt -text\n",
    )
    .unwrap();
    const N: usize = 20;
    for i in 0..N {
        let content = format!("BENCH_SECRET_{i}={}\n", "x".repeat(4096));
        std::fs::write(repo.join(format!("bench_{i:02}.secret.env")), content).unwrap();
    }
    run_git(repo, &bin_dir, &["add", "."]);
    run_git(repo, &bin_dir, &["commit", "-m", "bench baseline"]);

    let id_file = repo.join("bench_id.txt");
    std::fs::write(&id_file, &sec).unwrap();

    // Single-file clean via stdin pipe (median of 3).
    let mut samples = Vec::new();
    for _ in 0..3 {
        samples.push(time_it(|| {
            let mut child = Command::new(bin)
                .args(["clean", "bench_00.secret.env"])
                .current_dir(repo)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut sin = child.stdin.take().unwrap();
            sin.write_all(&[b'y'; 4096]).unwrap();
            drop(sin);
            assert!(child.wait().unwrap().success());
        }));
    }
    metrics.push(Metric::new(
        "e2e.clean_file",
        median_of(samples),
        "4 KiB via stdin".to_string(),
        30,
    ));

    // Bulk clean: modify all files, then `git add` drives the filter N times.
    for i in 0..N {
        let content = format!("BENCH_SECRET_{i}={}_v2\n", "z".repeat(4096));
        std::fs::write(repo.join(format!("bench_{i:02}.secret.env")), content).unwrap();
    }
    let t = time_it(|| run_git(repo, &bin_dir, &["add", "."]));
    metrics.push(Metric::new(
        "e2e.bulk_clean_20x4KiB",
        t,
        "git add over 20 filter files".to_string(),
        60,
    ));
    run_git(repo, &bin_dir, &["commit", "-m", "v2"]);

    let t = time_it(|| assert!(run_cmd(repo, bin, &["lock", "-f"])));
    metrics.push(Metric::new("e2e.lock", t, "20 files".to_string(), 60));

    let t = time_it(|| assert!(run_cmd(repo, bin, &["unlock", id_file.to_str().unwrap()])));
    metrics.push(Metric::new("e2e.unlock", t, "20 files".to_string(), 60));

    let t = time_it(|| assert!(run_cmd(repo, bin, &["rekey", "-f"])));
    metrics.push(Metric::new("e2e.rekey", t, "20 files".to_string(), 60));

    let t = time_it(|| assert!(run_cmd(repo, bin, &["status"])));
    metrics.push(Metric::new("e2e.status", t, "20 files".to_string(), 60));
}
fn to_json(metrics: &[Metric]) -> String {
    let mut s = String::from("{\n");
    for (i, m) in metrics.iter().enumerate() {
        let comma = if i + 1 == metrics.len() { "" } else { "," };
        s.push_str(&format!(
            "  {:?}: {{ \"micros\": {}, \"detail\": {:?} }}{comma}\n",
            m.name,
            m.elapsed.as_micros(),
            m.detail
        ));
    }
    s.push_str("}\n");
    s
}

/// Parses the flat JSON shape written by `to_json` (name -> micros). Crude by design.
fn parse_baseline(text: &str) -> std::collections::HashMap<String, u128> {
    let mut map = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('"') {
            continue;
        }
        let Some(key_end) = line[1..].find('"') else {
            continue;
        };
        let key = &line[1..1 + key_end];
        let Some(mpos) = line.find("\"micros\":") else {
            continue;
        };
        let digits: String = line[mpos + 9..]
            .chars()
            .skip_while(|c| !c.is_ascii_digit())
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(v) = digits.parse::<u128>() {
            map.insert(key.to_string(), v);
        }
    }
    map
}

fn main() {
    println!("=== Git-AgeCrypt Performance Benchmark Matrix ===");
    let mut metrics = Vec::new();
    bench_crypto(&mut metrics);
    let bin = locate_binary();
    println!("CLI binary: {}", bin.display());
    bench_e2e(&mut metrics, &bin);

    println!(
        "\n{:<26} {:>12}  {:<26} ceiling",
        "metric", "elapsed", "detail"
    );
    let mut failures: Vec<String> = Vec::new();
    for m in &metrics {
        println!(
            "{:<26} {:>12.2?}  {:<26} {:?}",
            m.name, m.elapsed, m.detail, m.ceiling
        );
        if m.elapsed > m.ceiling {
            failures.push(format!(
                "{} exceeded sanity ceiling: {:?} > {:?}",
                m.name, m.elapsed, m.ceiling
            ));
        }
    }

    let json = to_json(&metrics);
    if std::env::var("GIT_AGECRYPT_BENCH_JSON").is_ok() {
        println!("\nJSON report:\n{json}");
    }
    if let Ok(out_path) = std::env::var("GIT_AGECRYPT_BENCH_OUT") {
        std::fs::write(&out_path, &json).expect("write bench JSON");
        println!("JSON report written to {out_path}");
    }

    // Opt-in baseline-relative regression check (3x tolerance for runner variance).
    if std::env::var("GIT_AGECRYPT_BENCH_CHECK").is_ok() {
        let baseline_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("benches")
            .join("baseline.json");
        match std::fs::read_to_string(&baseline_path) {
            Ok(text) => {
                let baseline = parse_baseline(&text);
                for m in &metrics {
                    if let Some(base_us) = baseline.get(&m.name) {
                        // 3x tolerance plus 250ms absolute slack for runner jitter.
                        let limit = (*base_us as f64) * 3.0 + 250_000.0;
                        if (m.elapsed.as_micros() as f64) > limit {
                            failures.push(format!(
                                "{} regressed vs baseline: {}us > 3x {}us + 250ms slack",
                                m.name,
                                m.elapsed.as_micros(),
                                base_us
                            ));
                        }
                    }
                }
            }
            Err(_) => println!("no benches/baseline.json; skipping relative check"),
        }
    }

    if !failures.is_empty() {
        eprintln!("\nBENCHMARK FAILURES:\n{}", failures.join("\n"));
        std::process::exit(1);
    }
    println!("\nAll {} metrics within ceilings.", metrics.len());
}
