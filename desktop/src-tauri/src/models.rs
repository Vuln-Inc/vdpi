use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineModeDto {
    Tun,
    Proxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStateDto {
    Running,
    Stopped,
    NotInstalled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitTunnelModeDto {
    All,
    Exclude,
    Include,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnCoexistenceDto {
    AutoYield,
    Warn,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemePreferenceDto {
    #[default]
    System,
    Dark,
    Light,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LanguagePreferenceDto {
    #[default]
    System,
    En,
    Tr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagStatusDto {
    Idle,
    Running,
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppCategoryDto {
    Popular,
    Running,
    Installed,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveTelemetryDto {
    pub running: bool,
    pub engine: EngineModeDto,
    pub addr: String,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub tun_interface: Option<String>,
    pub physical_nic: Option<String>,
    pub vpn_conflict: Option<String>,
    pub version: Option<String>,
    pub mode: Option<String>,
    pub doh_enabled: bool,
    pub dns_display: String,
    pub block_quic: bool,
    pub active_connections: usize,
    pub total_connections: u64,
    pub learned_hosts: usize,
    pub isp_stage: Option<String>,
    pub udp_flows_active: u64,
    pub quic_blocked: u64,
    pub dns_queries: u64,
    pub rss_kb: Option<u64>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub rx_rate_bps: u64,
    pub tx_rate_bps: u64,
    pub tls_handshakes: u64,
    pub auto_heal_escalations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WintunStatusDto {
    pub required: bool,
    pub ready: bool,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatusSnapshotDto {
    pub snapshot_seq: u64,
    pub app_version: String,
    pub platform: String,
    pub service_state: ServiceStateDto,
    pub installed_version: Option<String>,
    pub configured_engine: EngineModeDto,
    pub live: Option<LiveTelemetryDto>,
    pub vpn_conflict: Option<String>,
    pub wintun: WintunStatusDto,
    pub split_tunnel_mode: SplitTunnelModeDto,
    pub split_tunnel_count: usize,
    pub config_path: String,
    pub logs_dir: String,
    pub tray_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GuiPreferencesDto {
    pub theme: ThemePreferenceDto,
    #[serde(default)]
    pub language: LanguagePreferenceDto,
    pub keep_in_tray_on_close: bool,
    pub minimize_to_tray: bool,
    pub start_minimized_to_tray: bool,
    pub show_taskbar_icon_when_minimized: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopSettingsPayloadDto {
    pub engine: EngineModeDto,
    pub dns_addr: String,
    pub dns_display: String,
    pub dns_is_custom_url: bool,
    pub doh_enabled: bool,
    pub effective_doh: bool,
    pub block_quic: bool,
    pub tun_ipv6: bool,
    pub ipv4_only: bool,
    pub vpn_coexistence: VpnCoexistenceDto,
    pub bypass_domains: Vec<String>,
    pub include_domains: Vec<String>,
    pub split_tunnel_mode: SplitTunnelModeDto,
    pub split_tunnel_apps: Vec<String>,
    pub gui: GuiPreferencesDto,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsConfigUpdateDto {
    pub dns_addr: String,
    pub doh_enabled: bool,
    pub block_quic: bool,
    pub tun_ipv6: bool,
    pub ipv4_only: bool,
    pub vpn_coexistence: VpnCoexistenceDto,
    pub bypass_domains: Vec<String>,
    pub include_domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredAppItemDto {
    pub display_name: String,
    pub exe_name: String,
    pub normalized_key: String,
    pub path: Option<String>,
    pub is_running: bool,
    pub category: AppCategoryDto,
    pub companions: Vec<String>,
    pub group_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelPresetDto {
    pub id: String,
    pub label: String,
    pub description: String,
    pub apps: Vec<String>,
    pub group_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelPayloadDto {
    pub mode: SplitTunnelModeDto,
    pub selected_apps: Vec<String>,
    pub discovered_apps: Vec<DiscoveredAppItemDto>,
    pub presets: Vec<SplitTunnelPresetDto>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelSaveRequestDto {
    pub mode: SplitTunnelModeDto,
    pub apps: Vec<String>,
    pub apply_live: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticCheckItemDto {
    pub id: String,
    pub name: String,
    pub target: String,
    pub status: DiagStatusDto,
    pub latency_ms: Option<u64>,
    pub summary: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticsReportDto {
    pub ran_at_ms: u64,
    pub all_passed: bool,
    pub passed_count: usize,
    pub total_count: usize,
    pub checks: Vec<DiagnosticCheckItemDto>,
    pub redacted_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckPayloadDto {
    pub current_version: String,
    pub latest_version: String,
    pub has_update: bool,
    pub release_url: String,
    pub release_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionResultDto {
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_restart: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled: Option<bool>,
}
