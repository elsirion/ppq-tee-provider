use std::{fs, path::Path};

fn main() {
    let base = std::env::var("PPQ_API_BASE").unwrap_or_else(|_| "https://api.ppq.ai".to_string());
    let out = Path::new(env!("CARGO_MANIFEST_DIR")).join("../ppq-tee/testdata");
    fs::create_dir_all(&out).expect("create testdata");

    let client = reqwest::blocking::Client::new();

    let bundle = client
        .get(format!("{base}/private/attestation"))
        .send()
        .expect("fetch attestation")
        .text()
        .expect("attestation body");
    // Pretty-print so fixture diffs are readable when PPQ redeploys.
    let parsed: serde_json::Value = serde_json::from_str(&bundle).expect("attestation is json");
    fs::write(
        out.join("attestation-bundle.json"),
        serde_json::to_string_pretty(&parsed).unwrap(),
    )
    .expect("write bundle");

    let keys = client
        .get(format!("{base}/private/.well-known/hpke-keys"))
        .send()
        .expect("fetch hpke keys")
        .bytes()
        .expect("hpke body");
    fs::write(out.join("hpke-keys.bin"), &keys).expect("write keys");

    println!(
        "captured {} byte bundle, {} byte key config",
        bundle.len(),
        keys.len()
    );
}
