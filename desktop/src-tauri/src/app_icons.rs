//! Native OS application icon extraction with bounded in-memory caching and zero
//! external dependencies.
//!
//! Resolves per-application icons as validated `data:image/png;base64,...` URIs across
//! Windows (`SHGetFileInfoW` + `GetIconInfo` + `GetDIBits`), macOS (`.app` bundle ->
//! `.icns` embedded PNG parser), and Linux (`.desktop` entry -> `Icon=` PNG resolver).

use std::collections::HashMap;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use crate::models::AppIconRequestDto;

/// Maximum number of applications processed per `get_app_icons` batch request.
const MAX_BATCH_APPS: usize = 256;

/// Maximum number of cached entries retained in the global in-memory icon cache.
const MAX_ICON_CACHE_ENTRIES: usize = 512;

/// Maximum raw PNG payload size accepted (128 KiB).
const MAX_RAW_PNG_BYTES: usize = 128 * 1024;

/// Maximum returned `data:image/png;base64,...` URI length (192 KiB).
const MAX_DATA_URI_BYTES: usize = 192 * 1024;

/// Standard 8-byte PNG signature (`\x89PNG\r\n\x1a\n`).
const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Data URI prefix for validated PNG icon payloads.
const DATA_URI_PREFIX: &str = "data:image/png;base64,";

/// Global bounded icon cache keyed by normalized `(path, exe_name)`.
static ICON_CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();

fn icon_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    ICON_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolves native OS application icons for a batch of applications (capped at 256 items).
///
/// Returns a map from `app.key` to a validated `"data:image/png;base64,..."` URI for each
/// application whose icon could be safely extracted. Results (including negative lookups)
/// are cached in a bounded global in-memory map so repeated tab opens are instant.
pub fn resolve_app_icons(apps: &[AppIconRequestDto]) -> HashMap<String, String> {
    let mut results = HashMap::new();

    for app in apps.iter().take(MAX_BATCH_APPS) {
        if app.key.trim().is_empty() || results.contains_key(&app.key) {
            continue;
        }

        let cache_key = cache_key_for(app);
        let cached = {
            let guard = icon_cache()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.get(&cache_key).cloned()
        };

        if let Some(cached_uri) = cached {
            if let Some(uri) = cached_uri {
                results.insert(app.key.clone(), uri);
            }
            continue;
        }

        let resolved = extract_icon_data_uri(app);

        {
            let mut guard = icon_cache()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if guard.len() >= MAX_ICON_CACHE_ENTRIES && !guard.contains_key(&cache_key) {
                guard.clear();
            }
            guard.insert(cache_key, resolved.clone());
        }

        if let Some(uri) = resolved {
            results.insert(app.key.clone(), uri);
        }
    }

    results
}

fn cache_key_for(app: &AppIconRequestDto) -> String {
    let norm_path = app
        .path
        .as_deref()
        .map(|p| p.trim().trim_matches('"').trim().to_ascii_lowercase())
        .unwrap_or_default();
    let exe_trimmed = app.exe_name.trim();
    let norm_exe = if exe_trimmed.is_empty() {
        app.key.trim().to_ascii_lowercase()
    } else {
        exe_trimmed.to_ascii_lowercase()
    };
    format!("{norm_path}\x1f{norm_exe}")
}

/// Returns `true` for empty, NUL-containing, UNC, network, URI, or Windows device paths
/// (`\\...`, `//...`, `\\?\`, `\\.\`, `\/...`, `/\...`, `*://*`) so icon lookups never
/// trigger SMB authentication or stall on offline network shares.
fn is_unsafe_or_network_path(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.is_empty()
        || trimmed.contains('\0')
        || trimmed.starts_with(r"\\")
        || trimmed.starts_with("//")
        || trimmed.starts_with(r"\/")
        || trimmed.starts_with(r"/\")
        || trimmed.contains("://")
}

fn sanitize_candidate_path(raw: &str) -> Option<&str> {
    let trimmed = raw.trim().trim_matches('"').trim();
    if is_unsafe_or_network_path(trimmed) {
        None
    } else {
        Some(trimmed)
    }
}

fn extract_icon_data_uri(app: &AppIconRequestDto) -> Option<String> {
    let clean_path = match app.path.as_deref() {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                // Reject UNC / network / device paths strictly instead of falling back.
                Some(sanitize_candidate_path(trimmed)?)
            }
        }
        None => None,
    };

    if !app.exe_name.trim().is_empty() && is_unsafe_or_network_path(&app.exe_name) {
        return None;
    }

    let png_bytes = extract_platform_icon_png(clean_path, &app.exe_name, &app.key)?;
    png_to_data_uri(&png_bytes)
}

fn extract_platform_icon_png(
    clean_path: Option<&str>,
    exe_name: &str,
    #[cfg_attr(target_os = "windows", allow(unused_variables))] key: &str,
) -> Option<Vec<u8>> {
    #[cfg(target_os = "windows")]
    {
        windows_icons::extract_icon_png(clean_path, exe_name)
    }
    #[cfg(target_os = "macos")]
    {
        macos_icons::extract_icon_png(clean_path, exe_name, key)
    }
    #[cfg(target_os = "linux")]
    {
        linux_icons::extract_icon_png(clean_path, exe_name, key)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = (clean_path, exe_name, key);
        None
    }
}

/// Validates PNG magic bytes and size caps, then encodes as `data:image/png;base64,...`.
fn png_to_data_uri(png: &[u8]) -> Option<String> {
    if png.is_empty() || png.len() > MAX_RAW_PNG_BYTES || !png.starts_with(&PNG_MAGIC) {
        return None;
    }

    let encoded = encode_base64(png);
    let total_len = DATA_URI_PREFIX.len() + encoded.len();
    if total_len > MAX_DATA_URI_BYTES {
        return None;
    }

    let mut uri = String::with_capacity(total_len);
    uri.push_str(DATA_URI_PREFIX);
    uri.push_str(&encoded);
    Some(uri)
}

/// Pure-Rust RFC 4648 standard Base64 encoder (with `=` padding).
fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        match chunk {
            [b0, b1, b2] => {
                out.push(TABLE[(b0 >> 2) as usize]);
                out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
                out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
                out.push(TABLE[(b2 & 0x3f) as usize]);
            }
            [b0, b1] => {
                out.push(TABLE[(b0 >> 2) as usize]);
                out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
                out.push(TABLE[((b1 & 0x0f) << 2) as usize]);
                out.push(b'=');
            }
            [b0] => {
                out.push(TABLE[(b0 >> 2) as usize]);
                out.push(TABLE[((b0 & 0x03) << 4) as usize]);
                out.push(b'=');
                out.push(b'=');
            }
            _ => {}
        }
    }

    String::from_utf8(out).expect("base64 table produces valid ASCII")
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_file_bounded(path: &Path, max_bytes: usize) -> Option<Vec<u8>> {
    use std::io::Read;

    let file = std::fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > max_bytes as u64 {
        return None;
    }

    let mut buf = Vec::with_capacity(meta.len() as usize);
    let mut limited = file.take((max_bytes as u64).saturating_add(1));
    limited.read_to_end(&mut buf).ok()?;
    if buf.len() > max_bytes {
        return None;
    }
    Some(buf)
}

#[cfg(any(target_os = "windows", test))]
fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

#[cfg(any(target_os = "windows", test))]
fn crc32_chunks(a: &[u8], b: &[u8]) -> u32 {
    let crc = crc32_update(0xffff_ffff, a);
    let crc = crc32_update(crc, b);
    !crc
}

#[cfg(any(target_os = "windows", test))]
fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut s1: u32 = 1;
    let mut s2: u32 = 0;
    for &b in data {
        s1 = (s1 + u32::from(b)) % MOD_ADLER;
        s2 = (s2 + s1) % MOD_ADLER;
    }
    (s2 << 16) | s1
}

#[cfg(any(target_os = "windows", test))]
fn zlib_store(raw: &[u8]) -> Vec<u8> {
    const MAX_STORED_BLOCK: usize = u16::MAX as usize;
    let block_count = raw.len().div_ceil(MAX_STORED_BLOCK).max(1);
    let mut out = Vec::with_capacity(2 + raw.len() + block_count * 5 + 4);

    // Zlib header: CMF=0x78 (deflate, 32K window), FLG=0x01 ((0x78*256 + 0x01) % 31 == 0).
    out.push(0x78);
    out.push(0x01);

    if raw.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    } else {
        let mut offset = 0usize;
        while offset < raw.len() {
            let remaining = raw.len() - offset;
            let chunk_len = remaining.min(MAX_STORED_BLOCK);
            let is_final = offset + chunk_len == raw.len();
            let len_u16 = chunk_len as u16;
            let nlen_u16 = !len_u16;

            out.push(u8::from(is_final));
            out.extend_from_slice(&len_u16.to_le_bytes());
            out.extend_from_slice(&nlen_u16.to_le_bytes());
            out.extend_from_slice(&raw[offset..offset + chunk_len]);
            offset += chunk_len;
        }
    }

    out.extend_from_slice(&adler32(raw).to_be_bytes());
    out
}

#[cfg(any(target_os = "windows", test))]
fn write_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) -> Option<()> {
    let len = u32::try_from(data.len()).ok()?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    let crc = crc32_chunks(chunk_type, data);
    out.extend_from_slice(&crc.to_be_bytes());
    Some(())
}

/// Pure-Rust stored-block 8-bit RGBA PNG encoder with valid CRC-32 and Adler-32 checksums.
#[cfg(any(target_os = "windows", test))]
fn encode_rgba_png(width: u32, height: u32, rgba: &[u8]) -> Option<Vec<u8>> {
    if !(1..=256).contains(&width) || !(1..=256).contains(&height) {
        return None;
    }

    let row_bytes = (width as usize).checked_mul(4)?;
    let expected_len = row_bytes.checked_mul(height as usize)?;
    if rgba.len() != expected_len {
        return None;
    }

    let raw_len = (height as usize).checked_mul(row_bytes.checked_add(1)?)?;
    let mut raw = Vec::with_capacity(raw_len);
    for row in rgba.chunks_exact(row_bytes) {
        raw.push(0); // Filter type 0 (None)
        raw.extend_from_slice(row);
    }

    let compressed = zlib_store(&raw);

    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8; // Bit depth: 8
    ihdr[9] = 6; // Color type: Truecolor with alpha (RGBA)
    ihdr[10] = 0; // Compression: deflate
    ihdr[11] = 0; // Filter: adaptive
    ihdr[12] = 0; // Interlace: none

    let mut png = Vec::with_capacity(8 + 25 + 12 + compressed.len() + 12);
    png.extend_from_slice(&PNG_MAGIC);
    write_png_chunk(&mut png, b"IHDR", &ihdr)?;
    write_png_chunk(&mut png, b"IDAT", &compressed)?;
    write_png_chunk(&mut png, b"IEND", &[])?;
    Some(png)
}

/// Downscales an RGBA image with a premultiplied-alpha box filter if either dimension
/// exceeds `max_dim`, keeping large high-DPI Windows icons crisp and well under 128 KiB.
#[cfg(any(target_os = "windows", test))]
fn downscale_rgba_if_needed(
    width: u32,
    height: u32,
    rgba: Vec<u8>,
    max_dim: u32,
) -> (u32, u32, Vec<u8>) {
    if width <= max_dim && height <= max_dim {
        return (width, height, rgba);
    }

    let (dst_w, dst_h) = if width >= height {
        let h = ((u64::from(height) * u64::from(max_dim)) / u64::from(width)).max(1) as u32;
        (max_dim, h)
    } else {
        let w = ((u64::from(width) * u64::from(max_dim)) / u64::from(height)).max(1) as u32;
        (w, max_dim)
    };

    let src_w = width as usize;
    let src_h = height as usize;
    let dst_w_usize = dst_w as usize;
    let dst_h_usize = dst_h as usize;
    let mut out = Vec::with_capacity(dst_w_usize * dst_h_usize * 4);

    for dy in 0..dst_h_usize {
        let y0 = (dy * src_h) / dst_h_usize;
        let y1 = (((dy + 1) * src_h) / dst_h_usize)
            .max(y0 + 1)
            .min(src_h);
        for dx in 0..dst_w_usize {
            let x0 = (dx * src_w) / dst_w_usize;
            let x1 = (((dx + 1) * src_w) / dst_w_usize)
                .max(x0 + 1)
                .min(src_w);

            let mut sum_a: u64 = 0;
            let mut sum_r: u64 = 0;
            let mut sum_g: u64 = 0;
            let mut sum_b: u64 = 0;
            let mut count: u64 = 0;

            for y in y0..y1 {
                let row_start = y * src_w * 4;
                let row_slice = &rgba[row_start + x0 * 4..row_start + x1 * 4];
                for px in row_slice.as_chunks::<4>().0 {
                    let a = u64::from(px[3]);
                    sum_a += a;
                    sum_r += u64::from(px[0]) * a;
                    sum_g += u64::from(px[1]) * a;
                    sum_b += u64::from(px[2]) * a;
                    count += 1;
                }
            }

            let out_a = ((sum_a + count / 2) / count.max(1)).min(255) as u8;
            let (out_r, out_g, out_b) = match std::num::NonZeroU64::new(sum_a) {
                Some(alpha) => {
                    let a = alpha.get();
                    (
                        ((sum_r + a / 2) / alpha).min(255) as u8,
                        ((sum_g + a / 2) / alpha).min(255) as u8,
                        ((sum_b + a / 2) / alpha).min(255) as u8,
                    )
                }
                None => (0, 0, 0),
            };

            out.extend_from_slice(&[out_r, out_g, out_b, out_a]);
        }
    }

    (dst_w, dst_h, out)
}

#[cfg(target_os = "windows")]
mod windows_icons {
    use core::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    use super::{downscale_rgba_if_needed, encode_rgba_png};

    type Handle = *mut c_void;
    type HIcon = Handle;
    type HBitmap = Handle;
    type HDc = Handle;
    type HGDIObj = Handle;

    const MAX_PATH: usize = 260;
    const SHGFI_ICON: u32 = 0x0000_0100;
    const SHGFI_LARGEICON: u32 = 0x0000_0000;
    const BI_RGB: u32 = 0;
    const DIB_RGB_COLORS: u32 = 0;
    const MAX_ICON_DIMENSION: u32 = 64;
    const MAX_SOURCE_DIMENSION: i32 = 512;

    #[repr(C)]
    #[allow(dead_code)]
    struct ShFileInfoW {
        h_icon: HIcon,
        i_icon: i32,
        dw_attributes: u32,
        sz_display_name: [u16; MAX_PATH],
        sz_type_name: [u16; 80],
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct IconInfo {
        f_icon: i32,
        x_hotspot: u32,
        y_hotspot: u32,
        hbm_mask: HBitmap,
        hbm_color: HBitmap,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct Bitmap {
        bm_type: i32,
        bm_width: i32,
        bm_height: i32,
        bm_width_bytes: i32,
        bm_planes: u16,
        bm_bits_pixel: u16,
        bm_bits: *mut c_void,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct BitmapInfoHeader {
        bi_size: u32,
        bi_width: i32,
        bi_height: i32,
        bi_planes: u16,
        bi_bit_count: u16,
        bi_compression: u32,
        bi_size_image: u32,
        bi_x_pels_per_meter: i32,
        bi_y_pels_per_meter: i32,
        bi_clr_used: u32,
        bi_clr_important: u32,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct RgbQuad {
        rgb_blue: u8,
        rgb_green: u8,
        rgb_red: u8,
        rgb_reserved: u8,
    }

    #[repr(C)]
    #[allow(dead_code)]
    struct BitmapInfo {
        bmi_header: BitmapInfoHeader,
        bmi_colors: [RgbQuad; 1],
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHGetFileInfoW(
            psz_path: *const u16,
            dw_file_attributes: u32,
            psfi: *mut ShFileInfoW,
            cb_file_info: u32,
            u_flags: u32,
        ) -> usize;
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetIconInfo(h_icon: HIcon, piconinfo: *mut IconInfo) -> i32;
        fn DestroyIcon(h_icon: HIcon) -> i32;
    }

    #[link(name = "gdi32")]
    extern "system" {
        fn GetObjectW(h: HGDIObj, c: i32, pv: *mut c_void) -> i32;
        fn CreateCompatibleDC(hdc: HDc) -> HDc;
        fn DeleteDC(hdc: HDc) -> i32;
        fn GetDIBits(
            hdc: HDc,
            hbm: HBitmap,
            start: u32,
            c_lines: u32,
            lpv_bits: *mut c_void,
            lpbmi: *mut BitmapInfo,
            usage: u32,
        ) -> i32;
        fn DeleteObject(ho: HGDIObj) -> i32;
    }

    struct OwnedHIcon(HIcon);

    impl Drop for OwnedHIcon {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an owned HICON returned by `SHGetFileInfoW`.
                unsafe {
                    DestroyIcon(self.0);
                }
            }
        }
    }

    struct OwnedHBitmap(HBitmap);

    impl Drop for OwnedHBitmap {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an owned HBITMAP returned by `GetIconInfo`.
                unsafe {
                    DeleteObject(self.0);
                }
            }
        }
    }

    struct OwnedHDc(HDc);

    impl Drop for OwnedHDc {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an owned memory DC returned by `CreateCompatibleDC`.
                unsafe {
                    DeleteDC(self.0);
                }
            }
        }
    }

    fn make_top_down_32bit_bmi(width: i32, height: i32) -> BitmapInfo {
        BitmapInfo {
            bmi_header: BitmapInfoHeader {
                bi_size: std::mem::size_of::<BitmapInfoHeader>() as u32,
                bi_width: width,
                bi_height: -height,
                bi_planes: 1,
                bi_bit_count: 32,
                bi_compression: BI_RGB,
                bi_size_image: 0,
                bi_x_pels_per_meter: 0,
                bi_y_pels_per_meter: 0,
                bi_clr_used: 0,
                bi_clr_important: 0,
            },
            bmi_colors: [RgbQuad {
                rgb_blue: 0,
                rgb_green: 0,
                rgb_red: 0,
                rgb_reserved: 0,
            }],
        }
    }

    fn query_bitmap_dims(bitmap: HBitmap) -> Option<(u32, u32)> {
        if bitmap.is_null() {
            return None;
        }
        // SAFETY: `Bitmap` is a plain C struct where zero-initialization is valid.
        let mut bmp: Bitmap = unsafe { std::mem::zeroed() };
        // SAFETY: `bitmap` is a valid HBITMAP handle and `bmp` matches `sizeof(BITMAP)`.
        let written = unsafe {
            GetObjectW(
                bitmap,
                std::mem::size_of::<Bitmap>() as i32,
                (&mut bmp as *mut Bitmap).cast::<c_void>(),
            )
        };
        if written == 0
            || !(1..=MAX_SOURCE_DIMENSION).contains(&bmp.bm_width)
            || !(1..=MAX_SOURCE_DIMENSION).contains(&bmp.bm_height)
        {
            return None;
        }
        Some((bmp.bm_width as u32, bmp.bm_height as u32))
    }

    fn read_bitmap_bgra(dc: HDc, bitmap: HBitmap, width: u32, height: u32) -> Option<Vec<u8>> {
        let byte_len = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
        let mut bmi = make_top_down_32bit_bmi(i32::try_from(width).ok()?, i32::try_from(height).ok()?);
        let mut bgra = vec![0u8; byte_len];
        // SAFETY: `dc` is a valid compatible DC, `bitmap` is an unselected HBITMAP, and `bgra`
        // holds exactly `width * height * 4` bytes matching the 32-bit `bmi` specification.
        let lines = unsafe {
            GetDIBits(
                dc,
                bitmap,
                0,
                height,
                bgra.as_mut_ptr().cast::<c_void>(),
                &mut bmi,
                DIB_RGB_COLORS,
            )
        };
        if lines == 0 {
            None
        } else {
            Some(bgra)
        }
    }

    fn resolve_target_path(clean_path: Option<&str>, exe_name: &str) -> Option<PathBuf> {
        if let Some(p) = clean_path {
            let candidate = PathBuf::from(p);
            if candidate.is_file() {
                return Some(candidate);
            }
        }

        let exe = exe_name.trim();
        if exe.is_empty() || exe.contains(['\\', '/', ':', '\0']) || exe.contains("..") {
            return None;
        }

        let sys_root = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("WINDIR"))?;
        let system32 = PathBuf::from(sys_root).join("System32");
        let direct = system32.join(exe);
        if direct.is_file() {
            return Some(direct);
        }
        if !exe.to_ascii_lowercase().ends_with(".exe") {
            let with_exe = system32.join(format!("{exe}.exe"));
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
        None
    }

    fn extract_icon_from_path(path: &Path) -> Option<Vec<u8>> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: `ShFileInfoW` is a plain C struct where zero-initialization is valid.
        let mut shfi: ShFileInfoW = unsafe { std::mem::zeroed() };
        // SAFETY: `wide` is NUL-terminated UTF-16 and `shfi` matches `sizeof(SHFILEINFOW)`.
        let ok = unsafe {
            SHGetFileInfoW(
                wide.as_ptr(),
                0,
                &mut shfi,
                std::mem::size_of::<ShFileInfoW>() as u32,
                SHGFI_ICON | SHGFI_LARGEICON,
            )
        };
        if ok == 0 || shfi.h_icon.is_null() {
            return None;
        }
        let icon = OwnedHIcon(shfi.h_icon);

        // SAFETY: `IconInfo` is a plain C struct where zero-initialization is valid.
        let mut info: IconInfo = unsafe { std::mem::zeroed() };
        // SAFETY: `icon.0` is a valid HICON obtained from `SHGetFileInfoW`.
        if unsafe { GetIconInfo(icon.0, &mut info) } == 0 {
            return None;
        }
        // Immediately bind both returned bitmaps to RAII Drop guards so early returns never leak.
        let color_bmp = OwnedHBitmap(info.hbm_color);
        let mask_bmp = OwnedHBitmap(info.hbm_mask);

        // SAFETY: `CreateCompatibleDC(NULL)` creates a screen-compatible memory DC.
        let raw_dc = unsafe { CreateCompatibleDC(std::ptr::null_mut()) };
        if raw_dc.is_null() {
            return None;
        }
        let dc = OwnedHDc(raw_dc);

        let (width, height, rgba) = if !color_bmp.0.is_null() {
            let (width, height) = query_bitmap_dims(color_bmp.0)?;
            let mut bgra = read_bitmap_bgra(dc.0, color_bmp.0, width, height)?;

            let has_alpha = bgra.as_chunks::<4>().0.iter().any(|px| px[3] != 0);
            if !has_alpha {
                let mask_bgra = query_bitmap_dims(mask_bmp.0)
                    .filter(|&(mask_w, mask_h)| {
                        mask_w == width
                            && (mask_h == height || mask_h == height.saturating_mul(2))
                    })
                    .and_then(|(mask_w, mask_h)| {
                        read_bitmap_bgra(dc.0, mask_bmp.0, mask_w, mask_h)
                    });
                if let Some(mask_bgra) = mask_bgra {
                    for (px, mask_px) in bgra
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(mask_bgra.as_chunks::<4>().0)
                    {
                        // In Win32 AND masks, black (0) is opaque and white (0xFF) is transparent.
                        px[3] = if mask_px[0] == 0 { 255 } else { 0 };
                    }
                } else {
                    for px in bgra.as_chunks_mut::<4>().0 {
                        px[3] = 255;
                    }
                }
            }

            // Convert BGRA -> RGBA in place.
            for px in bgra.as_chunks_mut::<4>().0 {
                px.swap(0, 2);
            }
            (width, height, bgra)
        } else {
            // Pure monochrome icon: `hbmMask` contains AND mask (top half) + XOR mask (bottom half).
            let (width, full_height) = query_bitmap_dims(mask_bmp.0)?;
            if full_height < 2 || (full_height & 1) != 0 {
                return None;
            }
            let height = full_height / 2;
            let mask_bgra = read_bitmap_bgra(dc.0, mask_bmp.0, width, full_height)?;
            let half_bytes = (width as usize).checked_mul(height as usize)?.checked_mul(4)?;
            let (and_half, xor_half) = mask_bgra.split_at(half_bytes);

            let mut rgba = Vec::with_capacity(half_bytes);
            for (and_px, xor_px) in and_half
                .as_chunks::<4>()
                .0
                .iter()
                .zip(xor_half.as_chunks::<4>().0)
            {
                let and_set = and_px[0] != 0;
                let xor_set = xor_px[0] != 0;
                match (and_set, xor_set) {
                    (false, false) => rgba.extend_from_slice(&[0, 0, 0, 255]),
                    (false, true) | (true, true) => rgba.extend_from_slice(&[255, 255, 255, 255]),
                    (true, false) => rgba.extend_from_slice(&[0, 0, 0, 0]),
                }
            }
            (width, height, rgba)
        };

        let (final_w, final_h, final_rgba) =
            downscale_rgba_if_needed(width, height, rgba, MAX_ICON_DIMENSION);
        encode_rgba_png(final_w, final_h, &final_rgba)
    }

    pub(super) fn extract_icon_png(clean_path: Option<&str>, exe_name: &str) -> Option<Vec<u8>> {
        let target = resolve_target_path(clean_path, exe_name)?;
        extract_icon_from_path(&target)
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_plist_string_value(plist_xml: &str, key_name: &str) -> Option<String> {
    let key_tag = format!("<key>{key_name}</key>");
    let key_pos = plist_xml.find(&key_tag)?;
    let after_key = &plist_xml[key_pos + key_tag.len()..];
    let open_start = after_key.find("<string>")?;
    if after_key[..open_start].contains("<key>") {
        return None;
    }
    let value_start = &after_key[open_start + "<string>".len()..];
    let close_pos = value_start.find("</string>")?;
    let value = value_start[..close_pos].trim();
    if value.is_empty() || value.contains(['/', '\\', '\0']) || value.contains("..") {
        return None;
    }
    Some(value.to_string())
}

#[cfg(any(target_os = "macos", test))]
fn parse_cf_bundle_icon_file(plist_xml: &str) -> Option<String> {
    parse_plist_string_value(plist_xml, "CFBundleIconFile")
        .or_else(|| parse_plist_string_value(plist_xml, "CFBundleIconName"))
}

#[cfg(any(target_os = "macos", test))]
fn icns_chunk_priority(chunk_type: &[u8; 4]) -> usize {
    match chunk_type {
        b"icp5" => 0, // 32x32
        b"icp6" => 1, // 64x64
        b"ic11" => 2, // 32x32@2x (64x64)
        b"ic07" => 3, // 128x128
        b"ic12" => 4, // 64x64@2x (128x128)
        b"ic08" => 5, // 256x256
        b"ic13" => 6, // 128x128@2x (256x256)
        _ => 7,
    }
}

/// Parses an Apple `.icns` container in pure Rust and returns the best embedded PNG chunk
/// within [`MAX_RAW_PNG_BYTES`], preferring `icp5`, `icp6`, `ic11`, `ic07`, `ic12`, `ic08`, `ic13`.
#[cfg(any(target_os = "macos", test))]
fn extract_png_from_icns(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 8 || &data[0..4] != b"icns" {
        return None;
    }

    let declared_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let limit = data.len().min(declared_len);
    let mut offset = 8usize;
    let mut best: Option<(usize, &[u8])> = None;

    while offset.saturating_add(8) <= limit {
        let chunk_type = [
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ];
        let chunk_len = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;
        if chunk_len < 8 || offset.saturating_add(chunk_len) > limit {
            break;
        }

        let payload = &data[offset + 8..offset + chunk_len];
        offset += chunk_len;

        if payload.starts_with(&PNG_MAGIC) && payload.len() <= MAX_RAW_PNG_BYTES {
            let prio = icns_chunk_priority(&chunk_type);
            if best.is_none_or(|(best_prio, _)| prio < best_prio) {
                best = Some((prio, payload));
                if prio == 0 {
                    break;
                }
            }
        }
    }

    best.map(|(_, bytes)| bytes.to_vec())
}

#[cfg(target_os = "macos")]
mod macos_icons {
    use std::path::{Path, PathBuf};

    use super::{extract_png_from_icns, parse_cf_bundle_icon_file, read_file_bounded};

    const MAX_PLIST_BYTES: usize = 512 * 1024;
    const MAX_ICNS_BYTES: usize = 8 * 1024 * 1024;

    fn is_app_bundle(path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("app"))
            && path.is_dir()
    }

    fn candidate_bundles(clean_path: Option<&str>, exe_name: &str, key: &str) -> Vec<PathBuf> {
        let mut bundles = Vec::new();

        if let Some(raw_path) = clean_path {
            for ancestor in Path::new(raw_path).ancestors() {
                if is_app_bundle(ancestor) {
                    bundles.push(ancestor.to_path_buf());
                }
            }
        }

        let name = if !exe_name.trim().is_empty() {
            exe_name.trim()
        } else {
            key.trim()
        };

        if !name.is_empty() && !name.contains(['/', '\\', '\0']) && !name.contains("..") {
            let stem = name
                .strip_suffix(".app")
                .or_else(|| name.strip_suffix(".APP"))
                .unwrap_or(name);
            let bundle_name = format!("{stem}.app");

            let mut roots = vec![
                PathBuf::from("/Applications"),
                PathBuf::from("/System/Applications"),
            ];
            if let Some(home) = std::env::var_os("HOME") {
                roots.push(PathBuf::from(home).join("Applications"));
            }

            for root in roots {
                let candidate = root.join(&bundle_name);
                if candidate.is_dir() && !bundles.contains(&candidate) {
                    bundles.push(candidate);
                }
            }
        }

        bundles
    }

    fn extract_png_from_bundle(bundle: &Path) -> Option<Vec<u8>> {
        let contents = bundle.join("Contents");
        let resources = contents.join("Resources");
        if !resources.is_dir() {
            return None;
        }

        // 1. Try Info.plist `CFBundleIconFile` (or `CFBundleIconName`).
        let plist_icon = read_file_bounded(&contents.join("Info.plist"), MAX_PLIST_BYTES)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|xml| parse_cf_bundle_icon_file(&xml));
        if let Some(icon_file) = plist_icon {
            let filename = if icon_file.to_ascii_lowercase().ends_with(".icns") {
                icon_file
            } else {
                format!("{icon_file}.icns")
            };
            if let Some(png) = read_file_bounded(&resources.join(filename), MAX_ICNS_BYTES)
                .as_deref()
                .and_then(extract_png_from_icns)
            {
                return Some(png);
            }
        }

        // 2. Fallback: scan Contents/Resources for `*.icns` files in deterministic order.
        let mut icns_files: Vec<PathBuf> = std::fs::read_dir(resources)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("icns"))
            })
            .collect();
        icns_files.sort();

        for icns_path in icns_files {
            if let Some(png) = read_file_bounded(&icns_path, MAX_ICNS_BYTES)
                .as_deref()
                .and_then(extract_png_from_icns)
            {
                return Some(png);
            }
        }

        None
    }

    pub(super) fn extract_icon_png(
        clean_path: Option<&str>,
        exe_name: &str,
        key: &str,
    ) -> Option<Vec<u8>> {
        for bundle in candidate_bundles(clean_path, exe_name, key) {
            if let Some(png) = extract_png_from_bundle(&bundle) {
                return Some(png);
            }
        }
        None
    }
}

#[cfg(any(target_os = "linux", test))]
fn tokenize_desktop_exec(exec_line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in exec_line.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' && !in_single {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch.is_ascii_whitespace() && !in_single && !in_double {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(any(target_os = "linux", test))]
fn extract_exec_candidates(exec_line: &str) -> Vec<String> {
    let tokens = tokenize_desktop_exec(exec_line);
    let mut idx = 0usize;

    // Skip `env` wrapper and leading `KEY=VALUE` assignments.
    while idx < tokens.len() {
        let tok = tokens[idx].as_str();
        let base = tok.rsplit('/').next().unwrap_or(tok);
        if base == "env" || tok.contains('=') {
            idx += 1;
        } else {
            break;
        }
    }

    let Some(cmd) = tokens.get(idx) else {
        return Vec::new();
    };
    let basename = cmd
        .rsplit('/')
        .next()
        .unwrap_or(cmd)
        .trim()
        .to_ascii_lowercase();
    if basename.is_empty() {
        return Vec::new();
    }

    if basename == "flatpak" && tokens.get(idx + 1).is_some_and(|arg| arg == "run") {
        return tokens
            .iter()
            .skip(idx + 2)
            .filter(|arg| !arg.starts_with('-') && !arg.starts_with('%'))
            .map(|arg| arg.trim().to_ascii_lowercase())
            .find(|app_id| !app_id.is_empty())
            .into_iter()
            .collect();
    }

    vec![basename]
}

#[cfg(any(target_os = "linux", test))]
fn parse_desktop_entry(content: &str) -> Option<(Vec<String>, String)> {
    let mut in_desktop_entry = false;
    let mut saw_desktop_entry = false;
    let mut icon: Option<String> = None;
    let mut exec_keys: Vec<String> = Vec::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if line == "[Desktop Entry]" {
                in_desktop_entry = true;
                saw_desktop_entry = true;
            } else if saw_desktop_entry {
                break;
            } else {
                in_desktop_entry = false;
            }
            continue;
        }
        if !in_desktop_entry {
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim();
        if k == "Icon" && !v.is_empty() {
            icon = Some(v.to_string());
        } else if k == "Exec" && !v.is_empty() {
            exec_keys = extract_exec_candidates(v);
        }
    }

    icon.map(|ic| (exec_keys, ic))
}

#[cfg(target_os = "linux")]
mod linux_icons {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use super::{
        is_unsafe_or_network_path, parse_desktop_entry, read_file_bounded, MAX_RAW_PNG_BYTES,
        PNG_MAGIC,
    };

    const MAX_DESKTOP_FILE_BYTES: usize = 64 * 1024;

    static DESKTOP_ICON_INDEX: OnceLock<HashMap<String, String>> = OnceLock::new();

    fn desktop_dirs() -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            let home_path = PathBuf::from(home);
            dirs.push(home_path.join(".local/share/applications"));
            dirs.push(home_path.join(".local/share/flatpak/exports/share/applications"));
        }
        dirs.push(PathBuf::from("/usr/local/share/applications"));
        dirs.push(PathBuf::from("/usr/share/applications"));
        dirs.push(PathBuf::from("/var/lib/flatpak/exports/share/applications"));
        dirs.push(PathBuf::from("/var/lib/snapd/desktop/applications"));
        dirs
    }

    fn build_desktop_icon_index() -> HashMap<String, String> {
        let mut index = HashMap::new();

        for dir in desktop_dirs() {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if !path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("desktop"))
                {
                    continue;
                }

                let Some(bytes) = read_file_bounded(&path, MAX_DESKTOP_FILE_BYTES) else {
                    continue;
                };
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    continue;
                };
                let Some((exec_keys, icon)) = parse_desktop_entry(text) else {
                    continue;
                };

                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    let norm_stem = stem.trim().to_ascii_lowercase();
                    if !norm_stem.is_empty() {
                        index.entry(norm_stem).or_insert_with(|| icon.clone());
                    }
                }
                for key in exec_keys {
                    index.entry(key).or_insert_with(|| icon.clone());
                }
            }
        }

        index
    }

    fn desktop_icon_index() -> &'static HashMap<String, String> {
        DESKTOP_ICON_INDEX.get_or_init(build_desktop_icon_index)
    }

    fn read_validated_png(path: &Path) -> Option<Vec<u8>> {
        if !path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("png"))
        {
            return None;
        }
        let bytes = read_file_bounded(path, MAX_RAW_PNG_BYTES)?;
        if bytes.starts_with(&PNG_MAGIC) {
            Some(bytes)
        } else {
            None
        }
    }

    fn resolve_icon_png(icon_value: &str) -> Option<Vec<u8>> {
        let trimmed = icon_value.trim();
        if is_unsafe_or_network_path(trimmed) {
            return None;
        }

        if trimmed.starts_with('/') {
            return read_validated_png(Path::new(trimmed));
        }

        if trimmed.contains(['/', '\\', '\0']) || trimmed.contains("..") {
            return None;
        }

        let stem = trimmed
            .strip_suffix(".png")
            .or_else(|| trimmed.strip_suffix(".PNG"))
            .unwrap_or(trimmed);
        if stem.is_empty() {
            return None;
        }
        let filename = format!("{stem}.png");

        let mut hicolor_roots = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            let home_path = PathBuf::from(home);
            hicolor_roots.push(home_path.join(".local/share/icons/hicolor"));
            hicolor_roots.push(home_path.join(".local/share/flatpak/exports/share/icons/hicolor"));
        }
        hicolor_roots.push(PathBuf::from("/usr/local/share/icons/hicolor"));
        hicolor_roots.push(PathBuf::from("/usr/share/icons/hicolor"));
        hicolor_roots.push(PathBuf::from("/var/lib/flatpak/exports/share/icons/hicolor"));

        for size in ["48x48", "64x64", "32x32", "128x128"] {
            for root in &hicolor_roots {
                let candidate = root.join(size).join("apps").join(&filename);
                if let Some(png) = read_validated_png(&candidate) {
                    return Some(png);
                }
            }
        }

        for pixmap_dir in ["/usr/local/share/pixmaps", "/usr/share/pixmaps"] {
            let candidate = Path::new(pixmap_dir).join(&filename);
            if let Some(png) = read_validated_png(&candidate) {
                return Some(png);
            }
        }

        None
    }

    pub(super) fn extract_icon_png(
        clean_path: Option<&str>,
        exe_name: &str,
        key: &str,
    ) -> Option<Vec<u8>> {
        let mut lookup_keys = Vec::new();
        for raw in [exe_name, key] {
            let norm = raw.trim().to_ascii_lowercase();
            if !norm.is_empty() && !lookup_keys.contains(&norm) {
                lookup_keys.push(norm);
            }
        }
        if let Some(name) = clean_path
            .and_then(|p| Path::new(p).file_name())
            .and_then(std::ffi::OsStr::to_str)
        {
            let norm = name.trim().to_ascii_lowercase();
            if !norm.is_empty() && !lookup_keys.contains(&norm) {
                lookup_keys.push(norm);
            }
        }

        let index = desktop_icon_index();
        for candidate_key in &lookup_keys {
            if let Some(png) = index
                .get(candidate_key)
                .map(String::as_str)
                .and_then(resolve_icon_png)
            {
                return Some(png);
            }
        }

        // Direct theme fallback when no `.desktop` entry matched.
        for candidate_key in &lookup_keys {
            if let Some(png) = resolve_icon_png(candidate_key) {
                return Some(png);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_synthetic_icns(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let body_len: usize = chunks.iter().map(|(_, payload)| 8 + payload.len()).sum();
        let total_len = (8 + body_len) as u32;
        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(b"icns");
        out.extend_from_slice(&total_len.to_be_bytes());
        for (chunk_type, payload) in chunks {
            let chunk_len = (8 + payload.len()) as u32;
            out.extend_from_slice(*chunk_type);
            out.extend_from_slice(&chunk_len.to_be_bytes());
            out.extend_from_slice(payload);
        }
        out
    }

    #[test]
    fn base64_encodes_rfc4648_vectors() {
        assert_eq!(encode_base64(b""), "");
        assert_eq!(encode_base64(b"f"), "Zg==");
        assert_eq!(encode_base64(b"fo"), "Zm8=");
        assert_eq!(encode_base64(b"foo"), "Zm9v");
        assert_eq!(encode_base64(b"foob"), "Zm9vYg==");
        assert_eq!(encode_base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(encode_base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode_base64(&[0x00, 0xff, 0x80, 0x7f]), "AP+Afw==");
    }

    #[test]
    fn encode_rgba_png_produces_valid_png_chunks_and_checksums() {
        let rgba: Vec<u8> = vec![
            255, 0, 0, 255, 0, 255, 0, 255, // row 0: red, green
            0, 0, 255, 128, 255, 255, 255, 0, // row 1: half-blue, transparent
        ];
        let png = encode_rgba_png(2, 2, &rgba).expect("encode 2x2 RGBA PNG");
        assert!(png.starts_with(&PNG_MAGIC));

        // Walk every PNG chunk and verify CRC-32 checksums and structure.
        let mut offset = 8usize;
        let mut chunk_types = Vec::new();
        while offset < png.len() {
            let len = u32::from_be_bytes([
                png[offset],
                png[offset + 1],
                png[offset + 2],
                png[offset + 3],
            ]) as usize;
            let ctype = &png[offset + 4..offset + 8];
            let data = &png[offset + 8..offset + 8 + len];
            let crc_offset = offset + 8 + len;
            let stored_crc = u32::from_be_bytes([
                png[crc_offset],
                png[crc_offset + 1],
                png[crc_offset + 2],
                png[crc_offset + 3],
            ]);
            assert_eq!(
                stored_crc,
                crc32_chunks(ctype, data),
                "CRC-32 mismatch for chunk {:?}",
                std::str::from_utf8(ctype)
            );

            if ctype == b"IHDR" {
                assert_eq!(len, 13);
                assert_eq!(u32::from_be_bytes([data[0], data[1], data[2], data[3]]), 2);
                assert_eq!(u32::from_be_bytes([data[4], data[5], data[6], data[7]]), 2);
                assert_eq!(data[8], 8);
                assert_eq!(data[9], 6);
            } else if ctype == b"IDAT" {
                assert_eq!(&data[0..2], &[0x78, 0x01]);
                assert_eq!(data[2], 0x01); // final stored block
                let blk_len = u16::from_le_bytes([data[3], data[4]]);
                let blk_nlen = u16::from_le_bytes([data[5], data[6]]);
                assert_eq!(blk_len, 18); // 2 rows * (1 filter byte + 8 RGBA bytes)
                assert_eq!(blk_nlen, !blk_len);
                let raw_scanlines = &data[7..7 + blk_len as usize];
                let stored_adler = u32::from_be_bytes([
                    data[data.len() - 4],
                    data[data.len() - 3],
                    data[data.len() - 2],
                    data[data.len() - 1],
                ]);
                assert_eq!(stored_adler, adler32(raw_scanlines));
            } else if ctype == b"IEND" {
                assert_eq!(len, 0);
                assert_eq!(stored_crc, 0xae42_6082);
            }

            chunk_types.push(ctype.to_vec());
            offset = crc_offset + 4;
        }

        assert_eq!(
            chunk_types,
            vec![b"IHDR".to_vec(), b"IDAT".to_vec(), b"IEND".to_vec()]
        );

        let uri = png_to_data_uri(&png).expect("valid PNG converts to data URI");
        assert!(uri.starts_with(DATA_URI_PREFIX));
        assert!(uri.len() <= MAX_DATA_URI_BYTES);

        // Non-PNG / SVG and oversized payloads must be rejected.
        assert!(png_to_data_uri(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>").is_none());
        let mut oversized = PNG_MAGIC.to_vec();
        oversized.resize(MAX_RAW_PNG_BYTES + 1, 0);
        assert!(png_to_data_uri(&oversized).is_none());

        // Downscaling reduces large RGBA images cleanly to <= 64px.
        let big = vec![200u8; 128 * 128 * 4];
        let (dw, dh, scaled) = downscale_rgba_if_needed(128, 128, big, 64);
        assert_eq!((dw, dh), (64, 64));
        assert_eq!(scaled.len(), 64 * 64 * 4);
        assert_eq!(&scaled[0..4], &[200, 200, 200, 200]);
    }

    #[test]
    fn icns_parser_extracts_preferred_embedded_png_and_skips_non_png() {
        let png_32 = encode_rgba_png(2, 2, &[10u8; 16]).expect("encode icp5 png");
        let png_128 = encode_rgba_png(3, 3, &[20u8; 36]).expect("encode ic07 png");
        let png_256 = encode_rgba_png(4, 4, &[30u8; 64]).expect("encode ic08 png");

        // Preferred icp5 beats ic07, ic08, and non-PNG ic09 chunks.
        let icns_with_icp5 = build_synthetic_icns(&[
            (b"ic09", b"\x00\x00\x00\x0cjP  not-a-png"),
            (b"ic08", &png_256),
            (b"ic07", &png_128),
            (b"icp5", &png_32),
        ]);
        assert_eq!(extract_png_from_icns(&icns_with_icp5), Some(png_32));

        // Without icp5/icp6/ic11, ic07 beats ic08.
        let icns_without_small = build_synthetic_icns(&[(b"ic08", &png_256), (b"ic07", &png_128)]);
        assert_eq!(extract_png_from_icns(&icns_without_small), Some(png_128));

        // Malformed, non-PNG, and zero-length chunks return None safely without looping.
        assert!(extract_png_from_icns(b"not-icns").is_none());
        let non_png_only = build_synthetic_icns(&[(b"ic08", b"<svg/>")]);
        assert!(extract_png_from_icns(&non_png_only).is_none());
        let zero_len_chunk = b"icns\x00\x00\x00\x10icp5\x00\x00\x00\x00";
        assert!(extract_png_from_icns(zero_len_chunk).is_none());

        // Info.plist parser extracts CFBundleIconFile and blocks traversal.
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Discord</string>
  <key>CFBundleIconFile</key><string>electron.icns</string>
</dict></plist>"#;
        assert_eq!(
            parse_cf_bundle_icon_file(plist).as_deref(),
            Some("electron.icns")
        );

        let evil_plist = "<key>CFBundleIconFile</key><string>../../etc/passwd</string>";
        assert!(parse_cf_bundle_icon_file(evil_plist).is_none());
    }

    #[test]
    fn linux_desktop_entry_parser_extracts_exec_and_icon() {
        let desktop = r#"[Desktop Entry]
Name=Discord
Exec=env XDG_SESSION_TYPE=x11 "/opt/Discord/Discord" --start-minimized %U
Icon=discord

[Desktop Action quit]
Name=Quit
Icon=wrong-action-icon
"#;
        let (execs, icon) = parse_desktop_entry(desktop).expect("parse desktop entry");
        assert_eq!(execs, vec!["discord"]);
        assert_eq!(icon, "discord");

        let flatpak_desktop = r#"[Desktop Entry]
Exec=/usr/bin/flatpak run --branch=stable --arch=x86_64 com.discordapp.Discord
Icon=com.discordapp.Discord
"#;
        let (fp_execs, fp_icon) = parse_desktop_entry(flatpak_desktop).expect("parse flatpak");
        assert_eq!(fp_execs, vec!["com.discordapp.discord"]);
        assert_eq!(fp_icon, "com.discordapp.Discord");
    }

    #[test]
    fn unc_network_and_device_paths_are_rejected() {
        for bad in [
            r"\\fileserver\share\app.exe",
            "//fileserver/share/app.exe",
            r"\\?\C:\Windows\System32\cmd.exe",
            r"\\.\PhysicalDrive0",
            r"\/server/share/app.exe",
            r"/\server\share\app.exe",
            "smb://server/share/app",
            "file:///etc/passwd",
            "C:\\app\0.exe",
            "",
            "   ",
        ] {
            assert!(
                is_unsafe_or_network_path(bad),
                "expected unsafe/network path to be rejected: {bad:?}"
            );
            assert!(
                sanitize_candidate_path(bad).is_none(),
                "expected sanitize_candidate_path to reject: {bad:?}"
            );
        }

        assert!(sanitize_candidate_path(r#""\\fileserver\share\app.exe""#).is_none());
        assert_eq!(
            sanitize_candidate_path(r#" "C:\Windows\System32\cmd.exe" "#),
            Some(r"C:\Windows\System32\cmd.exe")
        );
        assert_eq!(
            sanitize_candidate_path("/Applications/Discord.app"),
            Some("/Applications/Discord.app")
        );

        let rejected = resolve_app_icons(&[
            AppIconRequestDto {
                key: "unc-test".to_string(),
                path: Some(r"\\192.0.2.1\nonexistent\cmd.exe".to_string()),
                exe_name: "cmd.exe".to_string(),
            },
            AppIconRequestDto {
                key: "device-test".to_string(),
                path: Some(r"\\?\C:\Windows\System32\cmd.exe".to_string()),
                exe_name: "cmd.exe".to_string(),
            },
        ]);
        assert!(rejected.is_empty());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_extracts_real_system_executable_icon() {
        let sys_root = std::env::var("SystemRoot")
            .or_else(|_| std::env::var("WINDIR"))
            .unwrap_or_else(|_| r"C:\Windows".to_string());
        let system32 = std::path::PathBuf::from(sys_root).join("System32");
        let notepad = system32.join("notepad.exe");
        let cmd = system32.join("cmd.exe");
        let target = if notepad.is_file() { notepad } else { cmd };
        assert!(
            target.is_file(),
            "expected system executable to exist at {}",
            target.display()
        );

        let exe_name = target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("cmd.exe")
            .to_string();
        let req = vec![AppIconRequestDto {
            key: "sys-exe".to_string(),
            path: Some(target.to_string_lossy().into_owned()),
            exe_name,
        }];

        let first = resolve_app_icons(&req);
        let uri = first
            .get("sys-exe")
            .expect("expected Windows icon extraction to return a PNG data URI");
        assert!(uri.starts_with(DATA_URI_PREFIX));
        assert!(uri.len() <= MAX_DATA_URI_BYTES);

        // Second lookup must hit the in-memory cache and return the identical URI.
        let second = resolve_app_icons(&req);
        assert_eq!(second.get("sys-exe"), Some(uri));
    }
}
