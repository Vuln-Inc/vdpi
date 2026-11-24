use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use vdpi::service::parse_version_from_cli_output;
use vdpi::update::{
    compare_versions, parse_semver, parse_sha256sum_for_asset, platform_asset_name, sha256_hex,
    strip_windows_verbatim_prefix, verify_archive_sha256, VersionRelation,
};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let base = std::env::temp_dir();
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        for attempt in 0u32..64 {
            let candidate = base.join(format!("{prefix}-{pid}-{nanos}-{attempt}"));
            match fs::create_dir(&candidate) {
                Ok(()) => return Self { path: candidate },
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!(
                    "failed to create temp directory {}: {e}",
                    candidate.display()
                ),
            }
        }

        panic!(
            "failed to allocate unique temp directory under {}",
            base.display()
        );
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn semver_comparison_matrix_handles_all_relations() {
    assert_eq!(compare_versions("0.3.4", "0.3.3"), VersionRelation::Newer);
    assert_eq!(compare_versions("v0.10.0", "0.9.9"), VersionRelation::Newer);
    assert_eq!(compare_versions("1.0.0", "0.99.99"), VersionRelation::Newer);

    assert_eq!(compare_versions("0.3.4", "v0.3.4"), VersionRelation::Same);
    assert_eq!(compare_versions("V0.3.4", "0.3.4"), VersionRelation::Same);

    assert_eq!(compare_versions("0.3.2", "0.3.4"), VersionRelation::Older);
    assert_eq!(compare_versions("0.9.9", "v0.10.0"), VersionRelation::Older);

    assert_eq!(
        compare_versions("0.3.4-beta.1", "0.3.3"),
        VersionRelation::Unknown
    );
    assert_eq!(
        compare_versions("0.3.4", "0.3.4+build.1"),
        VersionRelation::Unknown
    );
    assert_eq!(
        compare_versions("not-a-version", "0.3.4"),
        VersionRelation::Unknown
    );

    assert_eq!(parse_semver("vdpi 0.3.4\r\n"), Some((0, 3, 4)));
    assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
    assert_eq!(parse_semver("0.3.4-beta.1"), None);
    assert_eq!(parse_semver("0.3"), None);
    assert_eq!(parse_semver(""), None);
}

#[test]
fn sha256_and_checksum_verification_accepts_valid_and_rejects_tampered_archive() {
    // Known RFC 6234 / FIPS 180-4 test vectors.
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let temp_dir = TempDir::new("vdpi-update-test");
    let asset_name = "vdpi-windows-x86_64.zip";
    let archive_path = temp_dir.path().join(asset_name);

    // Multi-block payload (> 64 KiB) to also exercise streaming chunked file hashing.
    let mut payload: Vec<u8> = (0u32..70_000).map(|i| (i % 251) as u8).collect();
    fs::write(&archive_path, &payload).expect("write sample archive payload");

    let win_hash = sha256_hex(&payload);
    assert_eq!(win_hash.len(), 64);

    let mac_hash = sha256_hex(b"macos-universal-archive-sample");
    let lin_x64_hash = sha256_hex(b"linux-x86_64-archive-sample");
    let lin_arm64_hash = sha256_hex(b"linux-arm64-archive-sample");
    let android_hash = sha256_hex(b"android-universal-apk-sample");
    let ios_hash = sha256_hex(b"ios-unsigned-ipa-sample");

    let mac_hash_upper = mac_hash.to_ascii_uppercase();
    let sums_text = format!(
        "{win_hash}  vdpi-windows-x86_64.zip\n\
         {mac_hash_upper} *vdpi-macos-universal.tar.gz\n\
         {lin_x64_hash}  vdpi-linux-x86_64.tar.gz\n\
         {lin_arm64_hash} *vdpi-linux-arm64.tar.gz\n\
         {android_hash}  vdpi-android-universal.apk\n\
         {ios_hash} *vdpi-ios-unsigned.ipa\n"
    );

    // Verify parsing handles both `  ` (text) and ` *` (binary) sha256sum formats
    // and normalizes uppercase hex to lowercase.
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-windows-x86_64.zip").as_deref(),
        Some(win_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-macos-universal.tar.gz").as_deref(),
        Some(mac_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-linux-x86_64.tar.gz").as_deref(),
        Some(lin_x64_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-linux-arm64.tar.gz").as_deref(),
        Some(lin_arm64_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-android-universal.apk").as_deref(),
        Some(android_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-ios-unsigned.ipa").as_deref(),
        Some(ios_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums_text, "vdpi-missing-asset.zip"),
        None
    );

    // Intact archive verifies cleanly against both `  ` and ` *` formats.
    assert!(verify_archive_sha256(&archive_path, &sums_text, asset_name).is_ok());
    let binary_mode_sums = format!("{win_hash} *{asset_name}\n");
    assert!(verify_archive_sha256(&archive_path, &binary_mode_sums, asset_name).is_ok());

    // Missing asset entry must be rejected.
    assert!(verify_archive_sha256(&archive_path, &sums_text, "vdpi-missing-asset.zip").is_err());

    // Flipping a single byte in the archive must cause verification failure.
    let mid = payload.len() / 2;
    payload[mid] ^= 0x01;
    fs::write(&archive_path, &payload).expect("write tampered archive payload");
    assert!(verify_archive_sha256(&archive_path, &sums_text, asset_name).is_err());

    // Ensure temp directory is cleaned up completely.
    let dir_path = temp_dir.path().to_path_buf();
    drop(temp_dir);
    assert!(!dir_path.exists());
}

#[test]
fn cli_version_output_parser_and_platform_asset_sanity() {
    assert_eq!(
        parse_version_from_cli_output("vdpi 0.3.4\n"),
        Some("0.3.4".to_string())
    );
    assert_eq!(
        parse_version_from_cli_output("vdpi 1.2.3\r\n"),
        Some("1.2.3".to_string())
    );
    assert_eq!(
        parse_version_from_cli_output("vdpi v2.10.0\n"),
        Some("2.10.0".to_string())
    );
    assert_eq!(parse_version_from_cli_output(""), None);
    assert_eq!(parse_version_from_cli_output("   \r\n"), None);
    assert_eq!(parse_version_from_cli_output("not a version"), None);

    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => {
            assert_eq!(platform_asset_name(), Some("vdpi-windows-x86_64.zip"));
        }
        ("macos", "x86_64" | "aarch64") => {
            assert_eq!(platform_asset_name(), Some("vdpi-macos-universal.tar.gz"));
        }
        ("linux", "x86_64") => {
            assert_eq!(platform_asset_name(), Some("vdpi-linux-x86_64.tar.gz"));
        }
        ("linux", "aarch64") => {
            assert_eq!(platform_asset_name(), Some("vdpi-linux-arm64.tar.gz"));
        }
        _ => {
            assert_eq!(platform_asset_name(), None);
        }
    }
}

#[test]
fn sha256sums_parser_handles_utf8_bom_and_crlf() {
    let win_hash = sha256_hex(b"windows-bom-crlf-sample");
    let lin_hash = sha256_hex(b"linux-bom-crlf-sample");

    let sums = format!(
        "\u{FEFF}{}  vdpi-windows-x86_64.zip\r\n{} *dist/vdpi-linux-x86_64.tar.gz\r\n",
        win_hash.to_ascii_uppercase(),
        lin_hash
    );

    assert_eq!(
        parse_sha256sum_for_asset(&sums, "vdpi-windows-x86_64.zip").as_deref(),
        Some(win_hash.as_str())
    );
    assert_eq!(
        parse_sha256sum_for_asset(&sums, "vdpi-linux-x86_64.tar.gz").as_deref(),
        Some(lin_hash.as_str())
    );
}

#[test]
fn sha256sums_parser_rejects_traversal_malformed_and_conflicting_duplicates() {
    let hash_a = sha256_hex(b"payload-a");
    let hash_b = sha256_hex(b"payload-b");

    // Empty or invalid expected asset names must be rejected.
    let valid_sums = format!("{hash_a}  vdpi-linux-x86_64.tar.gz\n");
    assert_eq!(parse_sha256sum_for_asset(&valid_sums, ""), None);
    assert_eq!(parse_sha256sum_for_asset(&valid_sums, "/"), None);
    assert_eq!(parse_sha256sum_for_asset(&valid_sums, "\\"), None);

    // Path traversal, absolute paths, drive letters/colons, NUL, and bare CR must be rejected.
    let traversal_cases = [
        format!("{hash_a}  ../vdpi-linux-x86_64.tar.gz\n"),
        format!("{hash_a}  dist/../vdpi-linux-x86_64.tar.gz\n"),
        format!("{hash_a}  /etc/vdpi-linux-x86_64.tar.gz\n"),
        format!("{hash_a}  \\server\\share\\vdpi-linux-x86_64.tar.gz\n"),
        format!("{hash_a}  C:\\temp\\vdpi-linux-x86_64.tar.gz\n"),
        format!("{hash_a}  vdpi-linux-x86_64.tar.gz\0extra\n"),
        format!("{hash_a}  foo\rvdpi-linux-x86_64.tar.gz\n"),
    ];
    for bad_sums in &traversal_cases {
        assert_eq!(
            parse_sha256sum_for_asset(bad_sums, "vdpi-linux-x86_64.tar.gz"),
            None,
            "expected rejection for malformed SHA256SUMS entry: {bad_sums:?}"
        );
    }

    // Conflicting duplicate hashes for the same asset must return None.
    let conflicting_sums = format!(
        "{hash_a}  vdpi-linux-x86_64.tar.gz\n\
         {hash_b}  dist/vdpi-linux-x86_64.tar.gz\n"
    );
    assert_eq!(
        parse_sha256sum_for_asset(&conflicting_sums, "vdpi-linux-x86_64.tar.gz"),
        None
    );

    // Identical duplicate hashes (case-insensitive) remain accepted.
    let identical_dups = format!(
        "{hash_a}  vdpi-linux-x86_64.tar.gz\n\
         {} *./vdpi-linux-x86_64.tar.gz\n",
        hash_a.to_ascii_uppercase()
    );
    assert_eq!(
        parse_sha256sum_for_asset(&identical_dups, "vdpi-linux-x86_64.tar.gz").as_deref(),
        Some(hash_a.as_str())
    );
}

#[test]
fn strips_windows_non_unc_verbatim_path_prefix_safely() {
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new(
            r"\\?\C:\Users\tester\AppData\Local\Temp\vdpi.exe"
        )),
        PathBuf::from(r"C:\Users\tester\AppData\Local\Temp\vdpi.exe")
    );
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new(r"\\?\d:\vdpi.exe")),
        PathBuf::from(r"d:\vdpi.exe")
    );

    // UNC verbatim paths, device paths, and regular paths must remain untouched.
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new(r"\\?\UNC\server\share\vdpi.exe")),
        PathBuf::from(r"\\?\UNC\server\share\vdpi.exe")
    );
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new(r"\\?\Volume{1234}\vdpi.exe")),
        PathBuf::from(r"\\?\Volume{1234}\vdpi.exe")
    );
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new(r"C:\Program Files\vdpi\bin\vdpi.exe")),
        PathBuf::from(r"C:\Program Files\vdpi\bin\vdpi.exe")
    );
    assert_eq!(
        strip_windows_verbatim_prefix(Path::new("/usr/local/bin/vdpi")),
        PathBuf::from("/usr/local/bin/vdpi")
    );
}
