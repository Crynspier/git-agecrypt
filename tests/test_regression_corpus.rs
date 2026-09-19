use std::fs;
use std::path::Path;

#[test]
fn test_permanent_regression_corpus_runner() {
    let regressions_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("regressions");

    assert!(
        regressions_dir.exists(),
        "Regression corpus directory must exist"
    );

    let entries = fs::read_dir(&regressions_dir).expect("Failed to read regressions dir");
    let mut tested_count = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();

            // Run through age magic detection
            let _ = data.starts_with(b"age-encryption.org/v1\n");

            // Run through merge semantic conflict parser
            let filename = path.file_name().unwrap().to_string_lossy();
            let _ = git_agecrypt::merge::find_semantic_conflicts(&data, &filename);

            // Ring grammar check on file names
            let stem = path.file_stem().unwrap().to_string_lossy();
            let _ = git_agecrypt::git::validate_ring_name(&stem);

            tested_count += 1;
        }
    }

    assert!(
        tested_count >= 3,
        "Must have tested at least 3 regression corpus artifacts: tested {tested_count}"
    );
}
