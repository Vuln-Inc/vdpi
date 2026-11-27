//! Lightweight English (`en`) / Turkish (`tr`) localization for `vdpi` interactive TUIs
//! and console prompts.
//!
//! Resolution precedence:
//! 1. Explicit thread-local override ([`push_thread_lang`], used by unit tests for parallel safety)
//! 2. `VDPI_LANG` environment variable (`en`, `tr`, or `auto`)
//! 3. Persisted `language` preference in `config.toml` (loaded via [`init_from_config`] or set via [`set_language_pref`])
//! 4. OS UI locale detection (Windows `GetUserDefaultUILanguage`, Unix `LC_ALL`/`LC_MESSAGES`/`LANG`/`LANGUAGE`)
//! 5. Fallback [`Lang::En`] (and always [`Lang::En`] under `#[cfg(test)]` unless explicitly overridden)

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

/// Supported UI languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Tr,
}

impl Lang {
    /// Canonical lowercase ISO 639-1 code persisted in `config.toml`.
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Tr => "tr",
        }
    }

    /// Short uppercase badge shown in compact TUI headers.
    pub const fn badge(self) -> &'static str {
        match self {
            Self::En => "EN",
            Self::Tr => "TR",
        }
    }

    /// Returns the other supported language.
    pub const fn toggle(self) -> Self {
        match self {
            Self::En => Self::Tr,
            Self::Tr => Self::En,
        }
    }

    /// Parses a language code or locale tag (e.g. `"en"`, `"tr"`, `"tr_TR.UTF-8"`, `"en-US"`).
    pub fn parse(raw: &str) -> Option<Self> {
        parse_lang_tag(raw)
    }
}

const PREF_AUTO: u8 = 0;
const PREF_EN: u8 = 1;
const PREF_TR: u8 = 2;

const THREAD_NONE: u8 = 0;
const THREAD_AUTO: u8 = 1;
const THREAD_EN: u8 = 2;
const THREAD_TR: u8 = 3;

static GLOBAL_PREF: AtomicU8 = AtomicU8::new(PREF_AUTO);
static CONFIG_INITIALIZED: AtomicBool = AtomicBool::new(false);

thread_local! {
    static THREAD_OVERRIDE: Cell<u8> = const { Cell::new(THREAD_NONE) };
}

/// RAII guard restoring the previous thread-local language override on drop.
pub struct ThreadLangGuard {
    prev: u8,
}

impl Drop for ThreadLangGuard {
    fn drop(&mut self) {
        THREAD_OVERRIDE.with(|cell| cell.set(self.prev));
    }
}

/// Temporarily overrides [`active_lang`] on the current thread only.
///
/// Pass `Some(Lang::Tr)` or `Some(Lang::En)` to pin a language, or `None` to force
/// auto-resolution while ignoring any outer thread-local pin. Safe for parallel tests.
pub fn push_thread_lang(lang: Option<Lang>) -> ThreadLangGuard {
    let encoded = match lang {
        None => THREAD_AUTO,
        Some(Lang::En) => THREAD_EN,
        Some(Lang::Tr) => THREAD_TR,
    };
    let prev = THREAD_OVERRIDE.with(|cell| {
        let old = cell.get();
        cell.set(encoded);
        old
    });
    ThreadLangGuard { prev }
}

/// Validates and canonicalizes a `config.toml` `language` preference value.
///
/// Accepts `"auto"`, `"en"`, and `"tr"` (case-insensitive, surrounding whitespace ignored).
pub fn parse_config_language(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("auto") {
        Some("auto")
    } else if trimmed.eq_ignore_ascii_case("en") {
        Some("en")
    } else if trimmed.eq_ignore_ascii_case("tr") {
        Some("tr")
    } else {
        None
    }
}

/// Parses a language code or POSIX locale tag (e.g. `"tr"`, `"tr_TR.UTF-8"`, `"en-US"`)
/// into a supported [`Lang`].
pub fn parse_lang_tag(raw: &str) -> Option<Lang> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_mod = trimmed.split('@').next().unwrap_or(trimmed);
    let without_enc = without_mod.split('.').next().unwrap_or(without_mod);
    let primary = without_enc
        .split(['-', '_'])
        .next()
        .unwrap_or(without_enc)
        .trim();

    if primary.eq_ignore_ascii_case("tr")
        || primary.eq_ignore_ascii_case("turkish")
        || primary.eq_ignore_ascii_case("turkce")
        || (!primary.is_ascii() && primary.to_lowercase() == "türkçe")
    {
        Some(Lang::Tr)
    } else if primary.eq_ignore_ascii_case("en") || primary.eq_ignore_ascii_case("english") {
        Some(Lang::En)
    } else {
        None
    }
}

/// Sets the process-wide persisted language preference (`None` means `"auto"`).
pub fn set_language_pref(pref: Option<Lang>) {
    let encoded = match pref {
        None => PREF_AUTO,
        Some(Lang::En) => PREF_EN,
        Some(Lang::Tr) => PREF_TR,
    };
    GLOBAL_PREF.store(encoded, Ordering::Release);
    CONFIG_INITIALIZED.store(true, Ordering::Release);
}

/// Alias for [`set_language_pref`] for TUI startup initialization.
pub fn set_override(pref: Option<Lang>) {
    set_language_pref(pref);
}

/// Returns the currently stored process-wide language preference (`None` when `"auto"`).
pub fn language_pref() -> Option<Lang> {
    match GLOBAL_PREF.load(Ordering::Acquire) {
        PREF_EN => Some(Lang::En),
        PREF_TR => Some(Lang::Tr),
        _ => None,
    }
}

/// Loads the `language` setting from `config.toml` once at interactive TUI entry
/// if no preference has been set yet in this process.
///
/// Under `#[cfg(test)]` this is a no-op so unit tests never inherit a developer's
/// host `config.toml`.
pub fn init_from_config() {
    init_from_config_impl();
}

#[cfg(test)]
fn init_from_config_impl() {}

#[cfg(not(test))]
fn init_from_config_impl() {
    if CONFIG_INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let user_lang = crate::config_file::load_file_config(
        Some(&crate::config_file::user_config_path()),
        false,
    )
    .ok()
    .and_then(|(_, cfg)| cfg.language);

    let configured = user_lang.or_else(|| {
        crate::config_file::load_file_config(
            Some(&crate::config_file::system_config_path()),
            false,
        )
        .ok()
        .and_then(|(_, cfg)| cfg.language)
    });

    if let Some(raw) = configured {
        if raw.trim().eq_ignore_ascii_case("auto") {
            GLOBAL_PREF.store(PREF_AUTO, Ordering::Release);
        } else if let Some(lang) = parse_lang_tag(&raw) {
            let encoded = match lang {
                Lang::En => PREF_EN,
                Lang::Tr => PREF_TR,
            };
            GLOBAL_PREF.store(encoded, Ordering::Release);
        }
    }
}

/// Returns `true` when a Win32 `LANGID` has Turkish (`0x1F`) as its primary language ID.
pub const fn is_turkish_win_lang_id(lang_id: u16) -> bool {
    (lang_id & 0x03FF) == 0x1F
}

#[cfg(windows)]
fn detect_system_lang_impl() -> Lang {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY: `GetUserDefaultUILanguage` takes no arguments and returns the current user's Win32 LANGID.
    let lang_id = unsafe { GetUserDefaultUILanguage() };
    if is_turkish_win_lang_id(lang_id) {
        Lang::Tr
    } else {
        Lang::En
    }
}

#[cfg(not(windows))]
fn detect_system_lang_impl() -> Lang {
    detect_lang_from_locale_vars(|key| std::env::var(key).ok())
}

#[cfg(any(not(windows), test))]
fn detect_lang_from_locale_vars<F>(mut get_var: F) -> Lang
where
    F: FnMut(&str) -> Option<String>,
{
    for key in ["LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"] {
        let Some(raw) = get_var(key) else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if key == "LANGUAGE" {
            for entry in trimmed.split(':') {
                let item = entry.trim();
                if item.is_empty() {
                    continue;
                }
                if is_posix_c_locale(item) {
                    return Lang::En;
                }
                return parse_lang_tag(item).unwrap_or(Lang::En);
            }
            continue;
        }
        if is_posix_c_locale(trimmed) {
            return Lang::En;
        }
        return parse_lang_tag(trimmed).unwrap_or(Lang::En);
    }
    Lang::En
}

#[cfg(any(not(windows), test))]
fn is_posix_c_locale(raw: &str) -> bool {
    let base = raw
        .split('@')
        .next()
        .unwrap_or(raw)
        .split('.')
        .next()
        .unwrap_or(raw)
        .trim();
    base.eq_ignore_ascii_case("c") || base.eq_ignore_ascii_case("posix")
}

/// Detects the active OS UI language directly (Windows `GetUserDefaultUILanguage`
/// or Unix `LC_ALL` / `LC_MESSAGES` / `LANG` / `LANGUAGE`).
pub fn detect_system_lang() -> Lang {
    detect_system_lang_impl()
}

fn resolve_lang_with<F>(
    thread_override: u8,
    env_vdpi_lang: Option<&str>,
    global_pref: Option<Lang>,
    detect_auto: F,
) -> Lang
where
    F: FnOnce() -> Lang,
{
    match thread_override {
        THREAD_EN => return Lang::En,
        THREAD_TR => return Lang::Tr,
        _ => {}
    }

    if let Some(raw) = env_vdpi_lang.map(str::trim).filter(|s| !s.is_empty()) {
        if raw.eq_ignore_ascii_case("auto") {
            return detect_auto();
        }
        if let Some(lang) = parse_lang_tag(raw) {
            return lang;
        }
    }

    if let Some(pref) = global_pref {
        return pref;
    }

    detect_auto()
}

/// Resolves the active language using `auto_fallback` instead of querying the OS UI locale
/// when no explicit override or `VDPI_LANG` is active.
///
/// Useful for binary-crate unit tests running on non-English hosts (where library crate `vdpi`
/// is compiled without `#[cfg(test)]`).
pub fn active_lang_with_fallback(auto_fallback: Lang) -> Lang {
    let thread_override = THREAD_OVERRIDE.with(Cell::get);
    let env_val = std::env::var("VDPI_LANG").ok();
    resolve_lang_with(thread_override, env_val.as_deref(), language_pref(), || {
        auto_fallback
    })
}

/// Returns the active UI language.
///
/// Under `#[cfg(test)]`, defaults to [`Lang::En`] unless explicitly overridden via
/// [`push_thread_lang`], `VDPI_LANG`, or [`set_language_pref`].
pub fn active_lang() -> Lang {
    active_lang_impl()
}

#[cfg(test)]
fn active_lang_impl() -> Lang {
    active_lang_with_fallback(Lang::En)
}

#[cfg(not(test))]
fn active_lang_impl() -> Lang {
    let thread_override = THREAD_OVERRIDE.with(Cell::get);
    let env_val = std::env::var("VDPI_LANG").ok();
    resolve_lang_with(
        thread_override,
        env_val.as_deref(),
        language_pref(),
        detect_system_lang,
    )
}

/// Picks either `en` or `tr_text` according to `lang`.
#[inline]
pub const fn tr_for(lang: Lang, en: &'static str, tr_text: &'static str) -> &'static str {
    match lang {
        Lang::En => en,
        Lang::Tr => tr_text,
    }
}

/// Picks either `en` or `tr_text` according to [`active_lang`].
#[inline]
pub fn tr(en: &'static str, tr_text: &'static str) -> &'static str {
    tr_for(active_lang(), en, tr_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lang_tags_and_config_values() {
        assert_eq!(Lang::parse("en"), Some(Lang::En));
        assert_eq!(Lang::parse("EN"), Some(Lang::En));
        assert_eq!(Lang::parse("en-US"), Some(Lang::En));
        assert_eq!(Lang::parse("en_GB.UTF-8"), Some(Lang::En));
        assert_eq!(Lang::parse("English"), Some(Lang::En));

        assert_eq!(Lang::parse("tr"), Some(Lang::Tr));
        assert_eq!(Lang::parse("TR"), Some(Lang::Tr));
        assert_eq!(Lang::parse("tr-TR"), Some(Lang::Tr));
        assert_eq!(Lang::parse("tr_TR.UTF-8"), Some(Lang::Tr));
        assert_eq!(Lang::parse("tr_TR.UTF-8@euro"), Some(Lang::Tr));
        assert_eq!(Lang::parse("Turkish"), Some(Lang::Tr));
        assert_eq!(Lang::parse("Türkçe"), Some(Lang::Tr));
        assert_eq!(Lang::parse("turkce"), Some(Lang::Tr));

        assert_eq!(Lang::parse(""), None);
        assert_eq!(Lang::parse("   "), None);
        assert_eq!(Lang::parse("auto"), None);
        assert_eq!(Lang::parse("de-DE"), None);

        assert_eq!(parse_config_language("auto"), Some("auto"));
        assert_eq!(parse_config_language(" AUTO "), Some("auto"));
        assert_eq!(parse_config_language("en"), Some("en"));
        assert_eq!(parse_config_language("EN"), Some("en"));
        assert_eq!(parse_config_language("tr"), Some("tr"));
        assert_eq!(parse_config_language("Tr"), Some("tr"));
        assert_eq!(parse_config_language("fr"), None);
        assert_eq!(parse_config_language("tr-TR"), None);
    }

    #[test]
    fn lang_methods_and_toggle_work() {
        assert_eq!(Lang::En.code(), "en");
        assert_eq!(Lang::Tr.code(), "tr");
        assert_eq!(Lang::En.badge(), "EN");
        assert_eq!(Lang::Tr.badge(), "TR");
        assert_eq!(Lang::En.toggle(), Lang::Tr);
        assert_eq!(Lang::Tr.toggle(), Lang::En);
    }

    #[test]
    fn windows_lang_id_detection_matches_turkish_primary_lang() {
        // 0x041F = tr-TR (LANG_TURKISH = 0x1F, SUBLANG_TURKISH_TURKEY = 0x01)
        assert!(is_turkish_win_lang_id(0x041F));
        assert!(is_turkish_win_lang_id(0x001F));
        assert!(is_turkish_win_lang_id(0x081F));
        // 0x0409 = en-US, 0x0809 = en-GB, 0x041E = th-TH, 0x0407 = de-DE
        assert!(!is_turkish_win_lang_id(0x0409));
        assert!(!is_turkish_win_lang_id(0x0809));
        assert!(!is_turkish_win_lang_id(0x041E));
        assert!(!is_turkish_win_lang_id(0x0407));
    }

    #[test]
    fn unix_locale_var_detection_follows_posix_precedence() {
        let lookup = |pairs: &[(&str, &str)]| {
            detect_lang_from_locale_vars(|key| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_string())
            })
        };

        assert_eq!(lookup(&[]), Lang::En);
        assert_eq!(lookup(&[("LANG", "tr_TR.UTF-8")]), Lang::Tr);
        assert_eq!(lookup(&[("LC_MESSAGES", "tr_TR")]), Lang::Tr);
        assert_eq!(lookup(&[("LC_ALL", "tr_TR.UTF-8")]), Lang::Tr);
        assert_eq!(lookup(&[("LANGUAGE", "tr:en")]), Lang::Tr);
        assert_eq!(lookup(&[("LANGUAGE", "en:tr")]), Lang::En);
        // LC_ALL overrides LANG
        assert_eq!(
            lookup(&[("LC_ALL", "en_US.UTF-8"), ("LANG", "tr_TR.UTF-8")]),
            Lang::En
        );
        // LC_ALL=C / POSIX forces English even if LANG is Turkish
        assert_eq!(
            lookup(&[("LC_ALL", "C.UTF-8"), ("LANG", "tr_TR.UTF-8")]),
            Lang::En
        );
        assert_eq!(
            lookup(&[("LC_ALL", "POSIX"), ("LANG", "tr_TR.UTF-8")]),
            Lang::En
        );
        // Empty higher-priority vars are skipped cleanly
        assert_eq!(
            lookup(&[("LC_ALL", ""), ("LC_MESSAGES", "   "), ("LANG", "tr_TR")]),
            Lang::Tr
        );
        // Non-Turkish locales default to English
        assert_eq!(lookup(&[("LANG", "de_DE.UTF-8")]), Lang::En);
    }

    #[test]
    fn precedence_resolves_thread_env_pref_and_auto() {
        // Thread override beats everything
        assert_eq!(
            resolve_lang_with(THREAD_TR, Some("en"), Some(Lang::En), || Lang::En),
            Lang::Tr
        );
        assert_eq!(
            resolve_lang_with(THREAD_EN, Some("tr"), Some(Lang::Tr), || Lang::Tr),
            Lang::En
        );

        // VDPI_LANG beats persisted pref and OS locale
        assert_eq!(
            resolve_lang_with(THREAD_NONE, Some("tr"), Some(Lang::En), || Lang::En),
            Lang::Tr
        );
        assert_eq!(
            resolve_lang_with(THREAD_NONE, Some("en"), Some(Lang::Tr), || Lang::Tr),
            Lang::En
        );
        // VDPI_LANG=auto bypasses persisted pref and uses OS locale
        assert_eq!(
            resolve_lang_with(THREAD_NONE, Some("auto"), Some(Lang::En), || Lang::Tr),
            Lang::Tr
        );
        // Invalid VDPI_LANG falls through to persisted pref
        assert_eq!(
            resolve_lang_with(THREAD_NONE, Some("xx"), Some(Lang::Tr), || Lang::En),
            Lang::Tr
        );

        // Persisted pref beats OS locale when VDPI_LANG is unset
        assert_eq!(
            resolve_lang_with(THREAD_NONE, None, Some(Lang::Tr), || Lang::En),
            Lang::Tr
        );
        // Auto fallback uses OS locale
        assert_eq!(
            resolve_lang_with(THREAD_NONE, None, None, || Lang::Tr),
            Lang::Tr
        );
    }

    #[test]
    fn test_default_is_english_and_thread_guard_restores_cleanly() {
        assert_eq!(active_lang(), Lang::En);
        assert_eq!(tr("Quit", "Çıkış"), "Quit");

        {
            let _guard = push_thread_lang(Some(Lang::Tr));
            assert_eq!(active_lang(), Lang::Tr);
            assert_eq!(tr("Quit", "Çıkış"), "Çıkış");
            {
                let _nested = push_thread_lang(Some(Lang::En));
                assert_eq!(active_lang(), Lang::En);
                assert_eq!(tr("Quit", "Çıkış"), "Quit");
            }
            assert_eq!(active_lang(), Lang::Tr);
        }

        assert_eq!(active_lang(), Lang::En);
        assert_eq!(tr("Quit", "Çıkış"), "Quit");
    }
}
