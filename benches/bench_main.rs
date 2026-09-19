use std::io::Cursor;
use std::time::Instant;

fn benchmark_throughput() {
    println!("=== Git-AgeCrypt Throughput & Latency Benchmarks ===");

    let sizes = [
        ("1 KB", 1024),
        ("100 KB", 100 * 1024),
        ("1 MB", 1024 * 1024),
        ("4 MB", 4 * 1024 * 1024),
    ];

    for (label, size) in sizes {
        let payload = vec![0x42u8; size];
        let mut cursor = Cursor::new(&payload);

        let start = Instant::now();
        let (spool, _) = git_agecrypt::crypto::spool_stream(&mut cursor, None, None).unwrap();
        let elapsed = start.elapsed();

        let mb_per_sec = (size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        println!(
            "Payload {label:>6}: elapsed = {:>8.2?}, throughput = {:>8.2} MB/s (is_memory: {})",
            elapsed,
            mb_per_sec,
            spool.is_in_memory()
        );
    }
}

fn main() {
    benchmark_throughput();
}
