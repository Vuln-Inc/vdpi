pub mod http;
pub mod socks;

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
