use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn strip_windows_verbatim_prefix(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if let Some(rest) = raw.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = raw.strip_prefix(r"\\?\") {
        PathBuf::from(rest)
    } else {
        path.to_path_buf()
    }
}

#[cfg(windows)]
fn compile_windows_version_info() {
    let version = env!("CARGO_PKG_VERSION");
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "vdpi")
        .set("FileDescription", "vdpi Anti-DPI Engine")
        .set("CompanyName", "Vuln-Inc")
        .set(
            "LegalCopyright",
            "Copyright (c) 2026 Vuln-Inc (MIT License)",
        )
        .set("OriginalFilename", "vdpi.exe")
        .set("InternalName", "vdpi")
        .set("ProductVersion", version)
        .set("FileVersion", version);
    res.compile()
        .expect("failed to compile Windows PE version info resource");
}

fn configure_embedded_wintun(target_os: &str, target_arch: &str) {
    if target_os != "windows" || target_arch != "x86_64" {
        return;
    }

    let Some(raw_path) = env::var_os("VDPI_EMBED_WINTUN_DLL") else {
        return;
    };
    if raw_path.is_empty() {
        return;
    }

    let dll_path = PathBuf::from(&raw_path);
    let file = match fs::File::open(&dll_path) {
        Ok(file) => file,
        Err(err) => {
            println!(
                "cargo:warning=VDPI_EMBED_WINTUN_DLL ({}) is not readable: {err}; building without embedded wintun.dll",
                dll_path.display()
            );
            return;
        }
    };

    let Ok(meta) = file.metadata() else {
        println!(
            "cargo:warning=failed to inspect VDPI_EMBED_WINTUN_DLL ({}); building without embedded wintun.dll",
            dll_path.display()
        );
        return;
    };
    if !meta.is_file() || meta.len() == 0 {
        println!(
            "cargo:warning=VDPI_EMBED_WINTUN_DLL ({}) is empty or not a regular file; building without embedded wintun.dll",
            dll_path.display()
        );
        return;
    }
    drop(file);

    let canonical = fs::canonicalize(&dll_path).unwrap_or(dll_path);
    let clean = strip_windows_verbatim_prefix(&canonical);
    let Some(clean_str) = clean.to_str() else {
        println!(
            "cargo:warning=VDPI_EMBED_WINTUN_DLL path is not valid UTF-8 ({}); building without embedded wintun.dll",
            clean.display()
        );
        return;
    };

    println!("cargo:rerun-if-changed={clean_str}");
    println!("cargo:rustc-cfg=vdpi_embedded_wintun");
    println!("cargo:rustc-env=VDPI_EMBEDDED_WINTUN_PATH={clean_str}");
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(vdpi_embedded_wintun)");
    println!("cargo:rerun-if-env-changed=VDPI_EMBED_WINTUN_DLL");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    #[cfg(windows)]
    if target_os == "windows" {
        compile_windows_version_info();
    }

    configure_embedded_wintun(&target_os, &target_arch);
}
