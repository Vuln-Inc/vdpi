export type NavTab =
  | "overview"
  | "split"
  | "dns"
  | "diagnostics"
  | "installation"
  | "settings";

export type EngineMode = "tun" | "proxy";
export type ServiceState = "running" | "stopped" | "not_installed";
export type SplitTunnelMode = "all" | "exclude" | "include";
export type VpnCoexistence = "auto_yield" | "warn" | "off";
export type ThemePreference = "system" | "dark" | "light";
export type LanguagePreference = "system" | "en" | "tr";
export type DiagStatus = "idle" | "running" | "pass" | "warn" | "fail";
export type AppCategory = "popular" | "running" | "installed" | "custom";
export type CliVersionRelation =
  | "not_installed"
  | "up_to_date"
  | "upgrade_available"
  | "newer_installed"
  | "repair_needed"
  | "bundled_missing"
  | "unknown";
export type ServiceOperation =
  | "installing"
  | "upgrading"
  | "repairing"
  | "uninstalling"
  | "resuming"
  | "pausing"
  | "switching_engine"
  | "saving_config"
  | "resetting_network";
export type ActionErrorCode =
  | "busy"
  | "shutting_down"
  | "downgrade_blocked"
  | "version_unknown"
  | "bundled_cli_missing"
  | "wintun_missing"
  | "wintun_invalid"
  | "already_up_to_date";

export interface LiveTelemetry {
  running: boolean;
  engine: EngineMode;
  addr: string;
  port: number;
  socksPort: number | null;
  tunInterface: string | null;
  physicalNic: string | null;
  vpnConflict: string | null;
  version: string | null;
  mode: string | null;
  dohEnabled: boolean;
  dnsDisplay: string;
  blockQuic: boolean;
  activeConnections: number;
  totalConnections: number;
  learnedHosts: number;
  ispStage: string | null;
  udpFlowsActive: number;
  quicBlocked: number;
  dnsQueries: number;
  rssKb: number | null;
  bytesRx: number;
  bytesTx: number;
  rxRateBps: number;
  txRateBps: number;
  tlsHandshakes: number;
  autoHealEscalations: number;
}

export interface WintunStatus {
  required: boolean;
  ready: boolean;
  message: string | null;
}

export interface DesktopStatusSnapshot {
  snapshotSeq?: number;
  appVersion: string;
  platform: "windows" | "macos" | "linux";
  serviceState: ServiceState;
  installedVersion: string | null;
  configuredEngine: EngineMode;
  live: LiveTelemetry | null;
  vpnConflict: string | null;
  wintun: WintunStatus;
  splitTunnelMode: SplitTunnelMode;
  splitTunnelCount: number;
  configPath: string;
  logsDir: string;
  traySupported?: boolean;
  configWarning?: string | null;
  bundledEngineVersion?: string | null;
  cliVersionRelation?: CliVersionRelation;
  canInstallFromBundle?: boolean;
  liveVersionStale?: boolean;
  pendingOperation?: ServiceOperation | null;
  runningFromReadonlyDmg?: boolean;
}

export interface ThroughputPoint {
  tsMs: number;
  rxBps: number;
  txBps: number;
}

export interface ActivityEvent {
  id: string;
  tsMs: number;
  level: "info" | "warn" | "error";
  category: "engine" | "dns" | "vpn" | "split" | "system";
  message: string;
}

export interface GuiPreferences {
  theme: ThemePreference;
  language?: LanguagePreference;
  keepInTrayOnClose: boolean;
  minimizeToTray: boolean;
  startMinimizedToTray: boolean;
  showTaskbarIconWhenMinimized: boolean;
}

export interface DesktopSettingsPayload {
  engine: EngineMode;
  dnsAddr: string;
  dnsDisplay: string;
  dnsIsCustomUrl: boolean;
  dohEnabled: boolean;
  effectiveDoh: boolean;
  blockQuic: boolean;
  tunIpv6: boolean;
  ipv4Only: boolean;
  vpnCoexistence: VpnCoexistence;
  bypassDomains: string[];
  includeDomains: string[];
  splitTunnelMode: SplitTunnelMode;
  splitTunnelApps: string[];
  gui: GuiPreferences;
}

export interface DnsConfigUpdate {
  dnsAddr: string;
  dohEnabled: boolean;
  blockQuic: boolean;
  tunIpv6: boolean;
  ipv4Only: boolean;
  vpnCoexistence: VpnCoexistence;
  bypassDomains: string[];
  includeDomains: string[];
}

export interface DiscoveredAppItem {
  displayName: string;
  exeName: string;
  normalizedKey: string;
  path: string | null;
  isRunning: boolean;
  category: AppCategory;
  companions: string[];
  groupTag: "games" | "browsers" | "communication" | "media" | "other";
}

export interface SplitTunnelPreset {
  id: string;
  label: string;
  description: string;
  apps: string[];
  groupTag: "games" | "browsers" | "communication" | "media";
}

export interface SplitTunnelPayload {
  mode: SplitTunnelMode;
  selectedApps: string[];
  discoveredApps: DiscoveredAppItem[];
  presets: SplitTunnelPreset[];
}

export interface SplitTunnelSaveRequest {
  mode: SplitTunnelMode;
  apps: string[];
  applyLive: boolean;
}

export interface AppIconRequest {
  key: string;
  path: string | null;
  exeName: string;
}

export interface DiagnosticCheckItem {
  id: string;
  name: string;
  target: string;
  status: DiagStatus;
  latencyMs: number | null;
  summary: string;
  detail: string | null;
}

export interface DiagnosticsReport {
  ranAtMs: number;
  allPassed: boolean;
  passedCount: number;
  totalCount: number;
  checks: DiagnosticCheckItem[];
  redactedText: string;
}

export interface UpdateCheckPayload {
  currentVersion: string;
  latestVersion: string;
  hasUpdate: boolean;
  releaseUrl: string;
  releaseNotes: string[];
}

export interface ActionResult {
  ok: boolean;
  message: string;
  needsRestart?: boolean;
  cancelled?: boolean;
  code?: ActionErrorCode;
  snapshot?: DesktopStatusSnapshot;
}
