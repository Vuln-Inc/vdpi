pub use vdpi_core::{binder, bypass, desync, dns, tls};

pub mod config;
pub mod config_file;
pub mod health;
pub mod i18n;
pub mod platform;
pub mod proxy;
pub mod server;
pub mod service;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod split_tunnel;
pub mod update;
