import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import type {
  ActionResult,
  AppIconRequest,
  CliVersionRelation,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  DiagnosticCheckItem,
  DiagnosticsReport,
  DiscoveredAppItem,
  DnsConfigUpdate,
  EngineMode,
  GuiPreferences,
  LiveTelemetry,
  ServiceOperation,
  ServiceState,
  SplitTunnelMode,
  SplitTunnelPayload,
  SplitTunnelPreset,
  SplitTunnelSaveRequest,
  UpdateCheckPayload,
  WintunStatus,
} from "../types";
import {
  compareSemver,
  extractExecutableName,
  isKnownPublicDohIp,
  redactDnsPreview,
  scrubUrlsInText,
  validateCustomDnsClient,
  validateDomainRule,
} from "./format";

export const STATUS_EVENT = "vdpi://status";

export type AppFolderTarget = "config" | "logs" | "app";

const APP_VERSION = "0.6.3";
const READ_IPC_TIMEOUT_MS = 15_000;
const APP_ICONS_TIMEOUT_MS = 10_000;
const UPDATE_IPC_TIMEOUT_MS = 25_000;
const DIAGNOSTICS_IPC_TIMEOUT_MS = 30_000;
const SERVICE_ACTION_TIMEOUT_MS = 180_000;
const MAX_DOMAIN_ENTRIES = 512;
const MAX_SPLIT_TUNNEL_APPS = 256;
const MOCK_CONFIG_DIR = "C:\\Users\\demo\\AppData\\Roaming\\vdpi";
const MOCK_CONFIG_PATH = `${MOCK_CONFIG_DIR}\\config.toml`;
const MOCK_LOGS_DIR = `${MOCK_CONFIG_DIR}\\logs`;
const MOCK_APP_DIR = "C:\\Program Files\\vdpi";
const EMPTY_INCLUDE_WARNING =
  "Warning: empty Include protects no apps until at least one application is added.";
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;

/**
 * Wraps a promise with a bounded timeout so a hung backend IPC command can
 * never permanently deadlock the desktop UI.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      reject(
        new Error(
          `IPC command "${label}" timed out after ${Math.round(timeoutMs / 1000)}s.`,
        ),
      );
    }, timeoutMs);

    promise.then(
      (value) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        resolve(value);
      },
      (err: unknown) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

function invokeWithTimeout<T>(
  command: string,
  timeoutMs: number,
  args?: Record<string, unknown>,
): Promise<T> {
  const call =
    args === undefined ? invoke<T>(command) : invoke<T>(command, args);
  return withTimeout(call, timeoutMs, command);
}

/**
 * Returns true when running inside the Tauri desktop webview, or false in
 * browser preview / Vitest / Playwright environments.
 */
export function isTauriRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  const win = window as unknown as Record<string, unknown>;
  return (
    typeof win.__TAURI_INTERNALS__ !== "undefined" &&
    win.__TAURI_INTERNALS__ !== null
  );
}

// ============================================================================
// Deterministic Stateful Browser-Preview Fallback
// ============================================================================

interface TelemetryStep {
  rxRateBps: number;
  txRateBps: number;
  activeConnections: number;
  udpFlowsActive: number;
  dnsDelta: number;
  quicDelta: number;
  tlsDelta: number;
}

const DETERMINISTIC_TELEMETRY_STEPS: readonly TelemetryStep[] = [
  { rxRateBps: 1_840_000, txRateBps: 312_000, activeConnections: 18, udpFlowsActive: 9, dnsDelta: 3, quicDelta: 1, tlsDelta: 2 },
  { rxRateBps: 2_310_000, txRateBps: 398_000, activeConnections: 21, udpFlowsActive: 11, dnsDelta: 4, quicDelta: 2, tlsDelta: 3 },
  { rxRateBps: 2_690_000, txRateBps: 445_000, activeConnections: 23, udpFlowsActive: 12, dnsDelta: 5, quicDelta: 1, tlsDelta: 3 },
  { rxRateBps: 1_960_000, txRateBps: 294_000, activeConnections: 19, udpFlowsActive: 10, dnsDelta: 2, quicDelta: 1, tlsDelta: 1 },
  { rxRateBps: 1_420_000, txRateBps: 218_000, activeConnections: 16, udpFlowsActive: 8, dnsDelta: 2, quicDelta: 0, tlsDelta: 2 },
  { rxRateBps: 2_150_000, txRateBps: 360_000, activeConnections: 20, udpFlowsActive: 10, dnsDelta: 3, quicDelta: 2, tlsDelta: 2 },
  { rxRateBps: 3_120_000, txRateBps: 512_000, activeConnections: 25, udpFlowsActive: 13, dnsDelta: 6, quicDelta: 2, tlsDelta: 4 },
  { rxRateBps: 2_840_000, txRateBps: 468_000, activeConnections: 24, udpFlowsActive: 12, dnsDelta: 4, quicDelta: 1, tlsDelta: 3 },
  { rxRateBps: 1_780_000, txRateBps: 276_000, activeConnections: 17, udpFlowsActive: 9, dnsDelta: 3, quicDelta: 1, tlsDelta: 2 },
  { rxRateBps: 1_290_000, txRateBps: 194_000, activeConnections: 15, udpFlowsActive: 7, dnsDelta: 2, quicDelta: 0, tlsDelta: 1 },
  { rxRateBps: 1_640_000, txRateBps: 258_000, activeConnections: 17, udpFlowsActive: 8, dnsDelta: 3, quicDelta: 1, tlsDelta: 2 },
  { rxRateBps: 2_480_000, txRateBps: 412_000, activeConnections: 22, udpFlowsActive: 11, dnsDelta: 4, quicDelta: 2, tlsDelta: 3 },
];

const MOCK_PICKER_CANDIDATES: readonly string[] = [
  "C:\\Program Files\\Telegram Desktop\\Telegram.exe",
  "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
  "C:\\Program Files (x86)\\Epic Games\\Launcher\\Portal\\Binaries\\Win64\\EpicGamesLauncher.exe",
  "C:\\Program Files\\qBittorrent\\qbittorrent.exe",
  "C:\\Program Files\\CustomApp\\CustomApp.exe",
];

function createDefaultPresets(): SplitTunnelPreset[] {
  return [
    {
      id: "discord",
      label: "Discord",
      description: "Discord stable, PTB, and Canary voice/chat clients",
      apps: ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"],
      groupTag: "communication",
    },
    {
      id: "roblox",
      label: "Roblox",
      description: "Roblox Player, launcher, and Bloxstrap",
      apps: [
        "RobloxPlayerBeta.exe",
        "RobloxPlayerLauncher.exe",
        "Bloxstrap.exe",
      ],
      groupTag: "games",
    },
    {
      id: "valorant-riot",
      label: "Valorant & Riot",
      description: "Valorant, Riot Client, Vanguard, and League of Legends",
      apps: [
        "VALORANT.exe",
        "VALORANT-Win64-Shipping.exe",
        "RiotClientServices.exe",
        "RiotClientUx.exe",
        "vgc.exe",
        "vgtray.exe",
        "LeagueClient.exe",
        "League of Legends.exe",
      ],
      groupTag: "games",
    },
    {
      id: "steam",
      label: "Steam",
      description: "Steam client, web helper, and in-game overlay",
      apps: ["steam.exe", "steamwebhelper.exe", "GameOverlayUI.exe"],
      groupTag: "games",
    },
    {
      id: "web-browsers",
      label: "Web Browsers",
      description: "Chrome, Edge, Firefox, Brave, Opera, and Vivaldi",
      apps: [
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
        "vivaldi.exe",
      ],
      groupTag: "browsers",
    },
    {
      id: "obs-studio",
      label: "OBS Studio",
      description: "OBS Studio 64-bit and 32-bit streaming and recording",
      apps: ["obs64.exe", "obs32.exe"],
      groupTag: "media",
    },
  ];
}

function createDefaultDiscoveredApps(): DiscoveredAppItem[] {
  return [
    {
      displayName: "Discord",
      exeName: "Discord.exe",
      normalizedKey: "discord",
      path: "C:\\Users\\demo\\AppData\\Local\\Discord\\app-1.0.9175\\Discord.exe",
      isRunning: true,
      category: "running",
      companions: ["discordptb", "discordcanary"],
      groupTag: "communication",
    },
    {
      displayName: "Google Chrome",
      exeName: "chrome.exe",
      normalizedKey: "chrome",
      path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      isRunning: true,
      category: "running",
      companions: ["chrome_proxy"],
      groupTag: "browsers",
    },
    {
      displayName: "Steam",
      exeName: "steam.exe",
      normalizedKey: "steam",
      path: "C:\\Program Files (x86)\\Steam\\steam.exe",
      isRunning: true,
      category: "running",
      companions: ["steamwebhelper", "gameoverlayui"],
      groupTag: "games",
    },
    {
      displayName: "Visual Studio Code",
      exeName: "Code.exe",
      normalizedKey: "code",
      path: "C:\\Users\\demo\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
      isRunning: true,
      category: "running",
      companions: [],
      groupTag: "other",
    },
    {
      displayName: "Spotify",
      exeName: "Spotify.exe",
      normalizedKey: "spotify",
      path: "C:\\Users\\demo\\AppData\\Roaming\\Spotify\\Spotify.exe",
      isRunning: true,
      category: "running",
      companions: [],
      groupTag: "media",
    },
    {
      displayName: "Roblox",
      exeName: "RobloxPlayerBeta.exe",
      normalizedKey: "robloxplayerbeta",
      path: "C:\\Users\\demo\\AppData\\Local\\Roblox\\Versions\\version-demo\\RobloxPlayerBeta.exe",
      isRunning: false,
      category: "popular",
      companions: ["robloxplayerlauncher", "bloxstrap"],
      groupTag: "games",
    },
    {
      displayName: "Valorant",
      exeName: "VALORANT-Win64-Shipping.exe",
      normalizedKey: "valorant-win64-shipping",
      path: "C:\\Riot Games\\VALORANT\\live\\ShooterGame\\Binaries\\Win64\\VALORANT-Win64-Shipping.exe",
      isRunning: false,
      category: "popular",
      companions: ["valorant", "riotclientservices", "riotclientux", "vgc", "vgtray"],
      groupTag: "games",
    },
    {
      displayName: "League of Legends",
      exeName: "LeagueClient.exe",
      normalizedKey: "leagueclient",
      path: "C:\\Riot Games\\League of Legends\\LeagueClient.exe",
      isRunning: false,
      category: "installed",
      companions: ["leagueclientux", "league of legends"],
      groupTag: "games",
    },
    {
      displayName: "Mozilla Firefox",
      exeName: "firefox.exe",
      normalizedKey: "firefox",
      path: "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
      isRunning: false,
      category: "installed",
      companions: [],
      groupTag: "browsers",
    },
    {
      displayName: "Microsoft Edge",
      exeName: "msedge.exe",
      normalizedKey: "msedge",
      path: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
      isRunning: false,
      category: "installed",
      companions: [],
      groupTag: "browsers",
    },
    {
      displayName: "Brave Browser",
      exeName: "brave.exe",
      normalizedKey: "brave",
      path: "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
      isRunning: false,
      category: "installed",
      companions: [],
      groupTag: "browsers",
    },
    {
      displayName: "OBS Studio",
      exeName: "obs64.exe",
      normalizedKey: "obs64",
      path: "C:\\Program Files\\obs-studio\\bin\\64bit\\obs64.exe",
      isRunning: false,
      category: "installed",
      companions: ["obs32"],
      groupTag: "media",
    },
  ];
}

function normalizeExeKey(raw: string): string {
  const unquoted = raw.trim().replace(/^["']+|["']+$/g, "").trim();
  const lastSep = Math.max(
    unquoted.lastIndexOf("/"),
    unquoted.lastIndexOf("\\"),
  );
  const fileName = (lastSep >= 0 ? unquoted.slice(lastSep + 1) : unquoted)
    .trim()
    .replace(/^["']+|["']+$/g, "")
    .trim();
  const lowered = fileName
    .replace(/\u0130/g, "i")
    .toLowerCase()
    .replace(/\u0307/g, "")
    .replace(/\u0131/g, "i");
  return lowered.replace(/\.exe$/, "").trim();
}

function classifyMockGroupTag(
  exeName: string,
): DiscoveredAppItem["groupTag"] {
  const key = normalizeExeKey(exeName);
  if (
    ["chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "arc"].includes(
      key,
    )
  ) {
    return "browsers";
  }
  if (
    [
      "discord",
      "discordptb",
      "discordcanary",
      "telegram",
      "slack",
      "zoom",
      "signal",
      "teams",
    ].includes(key)
  ) {
    return "communication";
  }
  if (
    [
      "steam",
      "steamwebhelper",
      "gameoverlayui",
      "robloxplayerbeta",
      "robloxplayerlauncher",
      "bloxstrap",
      "valorant",
      "valorant-win64-shipping",
      "vgc",
      "vgtray",
      "riotclientservices",
      "riotclientux",
      "leagueclient",
      "leagueclientux",
      "league of legends",
      "epicgameslauncher",
    ].includes(key) ||
    key.endsWith("-win64-shipping")
  ) {
    return "games";
  }
  if (["obs64", "obs32", "spotify", "vlc", "mpv"].includes(key)) {
    return "media";
  }
  return "other";
}

function displayNameFromExe(exeName: string): string {
  const stem = exeName.replace(/\.(exe|app|appimage|bat|cmd)$/i, "").trim();
  if (!stem) {
    return exeName;
  }
  return stem
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
}

interface MockStore {
  snapshotSeq: number;
  serviceState: ServiceState;
  installedVersion: string | null;
  bundledEngineVersion: string | null;
  canInstallFromBundle: boolean;
  liveVersionStale: boolean;
  pendingOperation: ServiceOperation | null;
  runningFromReadonlyDmg: boolean;
  vpnConflict: string | null;
  wintun: WintunStatus;
  traySupported: boolean;
  configWarning: string | null;
  settings: DesktopSettingsPayload;
  discoveredApps: DiscoveredAppItem[];
  presets: SplitTunnelPreset[];
  live: LiveTelemetry | null;
  tickIndex: number;
  pickerIndex: number;
}

function buildLiveTelemetry(
  settings: DesktopSettingsPayload,
  vpnConflict: string | null,
  previous?: LiveTelemetry | null,
  version?: string | null,
): LiveTelemetry {
  const step = DETERMINISTIC_TELEMETRY_STEPS[0];
  const isTun = settings.engine === "tun";
  return {
    running: true,
    engine: settings.engine,
    addr: "127.0.0.1",
    port: 18080,
    socksPort: isTun ? null : 11080,
    tunInterface: isTun ? "vdpi-tun0" : null,
    physicalNic: isTun ? "Ethernet" : null,
    vpnConflict,
    version: version ?? previous?.version ?? APP_VERSION,
    mode: isTun ? "tun-adaptive" : "proxy-adaptive",
    dohEnabled: settings.effectiveDoh,
    dnsDisplay: settings.dnsDisplay,
    blockQuic: settings.blockQuic,
    activeConnections: previous?.activeConnections ?? step.activeConnections,
    totalConnections: previous?.totalConnections ?? 412,
    learnedHosts: previous?.learnedHosts ?? 24,
    ispStage: previous?.ispStage ?? "ComboMultiRecord",
    udpFlowsActive: isTun
      ? (previous?.udpFlowsActive ?? step.udpFlowsActive)
      : 0,
    quicBlocked:
      isTun && settings.blockQuic ? (previous?.quicBlocked ?? 34) : 0,
    dnsQueries: previous?.dnsQueries ?? 286,
    rssKb: isTun ? 18432 : 12288,
    bytesRx: previous?.bytesRx ?? 48_234_496,
    bytesTx: previous?.bytesTx ?? 9_646_899,
    rxRateBps: step.rxRateBps,
    txRateBps: step.txRateBps,
    tlsHandshakes: previous?.tlsHandshakes ?? 194,
    autoHealEscalations: previous?.autoHealEscalations ?? 2,
  };
}

function createInitialMockStore(): MockStore {
  const settings: DesktopSettingsPayload = {
    engine: "tun",
    dnsAddr: "1.1.1.1",
    dnsDisplay: "1.1.1.1",
    dnsIsCustomUrl: false,
    dohEnabled: true,
    effectiveDoh: true,
    blockQuic: true,
    tunIpv6: false,
    ipv4Only: false,
    vpnCoexistence: "auto_yield",
    bypassDomains: ["localhost", "*.local"],
    includeDomains: [],
    splitTunnelMode: "exclude",
    splitTunnelApps: ["Discord.exe", "steam.exe"],
    gui: {
      theme: "system",
      language: "system",
      keepInTrayOnClose: false,
      minimizeToTray: false,
      startMinimizedToTray: false,
      showTaskbarIconWhenMinimized: false,
    },
  };

  return {
    snapshotSeq: 0,
    serviceState: "running",
    installedVersion: APP_VERSION,
    bundledEngineVersion: APP_VERSION,
    canInstallFromBundle: true,
    liveVersionStale: false,
    pendingOperation: null,
    runningFromReadonlyDmg: false,
    vpnConflict: null,
    wintun: {
      required: true,
      ready: true,
      message: null,
    },
    traySupported: true,
    configWarning: null,
    settings,
    discoveredApps: createDefaultDiscoveredApps(),
    presets: createDefaultPresets(),
    live: buildLiveTelemetry(settings, null, null, APP_VERSION),
    tickIndex: 0,
    pickerIndex: 0,
  };
}

let mockStore: MockStore = createInitialMockStore();
const mockSubscribers = new Set<(snapshot: DesktopStatusSnapshot) => void>();
let mockTickerId: ReturnType<typeof setInterval> | null = null;
let mockVisibilityListening = false;

function isDocumentHidden(): boolean {
  return typeof document !== "undefined" && Boolean(document.hidden);
}

function computeMockCliVersionRelation(store: MockStore): CliVersionRelation {
  if (!store.canInstallFromBundle || !store.bundledEngineVersion) {
    return "bundled_missing";
  }
  if (store.serviceState === "not_installed") {
    return "not_installed";
  }
  if (!store.installedVersion) {
    return "unknown";
  }
  const cmp = compareSemver(store.installedVersion, store.bundledEngineVersion);
  if (cmp === null) {
    return "unknown";
  }
  if (cmp < 0) {
    return "upgrade_available";
  }
  if (cmp > 0) {
    return "newer_installed";
  }
  return "up_to_date";
}

function cloneSnapshot(store: MockStore): DesktopStatusSnapshot {
  store.snapshotSeq += 1;
  const snapshot: DesktopStatusSnapshot = {
    snapshotSeq: store.snapshotSeq,
    appVersion: APP_VERSION,
    platform: "windows",
    serviceState: store.serviceState,
    installedVersion: store.installedVersion,
    configuredEngine: store.settings.engine,
    live: store.live ? { ...store.live } : null,
    vpnConflict: store.vpnConflict,
    wintun: {
      required: store.settings.engine === "tun",
      ready: store.wintun.ready,
      message: store.wintun.message,
    },
    splitTunnelMode: store.settings.splitTunnelMode,
    splitTunnelCount: store.settings.splitTunnelApps.length,
    configPath: MOCK_CONFIG_PATH,
    logsDir: MOCK_LOGS_DIR,
    traySupported: store.traySupported,
    bundledEngineVersion: store.bundledEngineVersion,
    cliVersionRelation: computeMockCliVersionRelation(store),
    canInstallFromBundle: store.canInstallFromBundle,
    liveVersionStale: store.liveVersionStale,
    runningFromReadonlyDmg: store.runningFromReadonlyDmg,
  };
  if (store.configWarning !== null) {
    snapshot.configWarning = store.configWarning;
  }
  if (store.pendingOperation !== null) {
    snapshot.pendingOperation = store.pendingOperation;
  }
  return snapshot;
}

function cloneSettings(store: MockStore): DesktopSettingsPayload {
  return {
    ...store.settings,
    bypassDomains: [...store.settings.bypassDomains],
    includeDomains: [...store.settings.includeDomains],
    splitTunnelApps: [...store.settings.splitTunnelApps],
    gui: { ...store.settings.gui },
  };
}

function cloneSplitTunnelPayload(store: MockStore): SplitTunnelPayload {
  return {
    mode: store.settings.splitTunnelMode,
    selectedApps: [...store.settings.splitTunnelApps],
    discoveredApps: store.discoveredApps.map((item) => ({
      ...item,
      companions: [...item.companions],
    })),
    presets: store.presets.map((preset) => ({
      ...preset,
      apps: [...preset.apps],
    })),
  };
}

function emitMockStatus(): void {
  if (mockSubscribers.size === 0) {
    return;
  }
  const snapshot = cloneSnapshot(mockStore);
  for (const subscriber of Array.from(mockSubscribers)) {
    try {
      subscriber({
        ...snapshot,
        live: snapshot.live ? { ...snapshot.live } : null,
        wintun: { ...snapshot.wintun },
      });
    } catch {
      // Isolate individual subscriber failures.
    }
  }
}

function advanceMockTelemetryTick(): void {
  if (mockStore.serviceState !== "running" || !mockStore.live) {
    return;
  }
  mockStore.tickIndex =
    (mockStore.tickIndex + 1) % DETERMINISTIC_TELEMETRY_STEPS.length;
  const step = DETERMINISTIC_TELEMETRY_STEPS[mockStore.tickIndex];
  const isTun = mockStore.settings.engine === "tun";

  mockStore.live = {
    ...mockStore.live,
    rxRateBps: step.rxRateBps,
    txRateBps: step.txRateBps,
    bytesRx: mockStore.live.bytesRx + step.rxRateBps,
    bytesTx: mockStore.live.bytesTx + step.txRateBps,
    activeConnections: step.activeConnections,
    totalConnections: mockStore.live.totalConnections + step.tlsDelta,
    udpFlowsActive: isTun ? step.udpFlowsActive : 0,
    dnsQueries: mockStore.live.dnsQueries + step.dnsDelta,
    quicBlocked:
      isTun && mockStore.settings.blockQuic
        ? mockStore.live.quicBlocked + step.quicDelta
        : mockStore.live.quicBlocked,
    tlsHandshakes: mockStore.live.tlsHandshakes + step.tlsDelta,
  };
}

function stopMockTicker(): void {
  if (mockTickerId !== null) {
    clearInterval(mockTickerId);
    mockTickerId = null;
  }
}

function ensureMockTickerRunning(): void {
  if (
    mockTickerId !== null ||
    mockSubscribers.size === 0 ||
    isDocumentHidden()
  ) {
    return;
  }
  mockTickerId = setInterval(() => {
    if (isDocumentHidden()) {
      return;
    }
    advanceMockTelemetryTick();
    emitMockStatus();
  }, 1000);
}

function handleMockVisibilityChange(): void {
  if (isDocumentHidden()) {
    stopMockTicker();
    return;
  }
  if (mockSubscribers.size > 0) {
    ensureMockTickerRunning();
  }
}

function ensureMockVisibilityListener(): void {
  if (mockVisibilityListening || typeof document === "undefined") {
    return;
  }
  document.addEventListener("visibilitychange", handleMockVisibilityChange);
  mockVisibilityListening = true;
}

function removeMockVisibilityListener(): void {
  if (!mockVisibilityListening || typeof document === "undefined") {
    return;
  }
  document.removeEventListener("visibilitychange", handleMockVisibilityChange);
  mockVisibilityListening = false;
}

function stopMockTickerIfIdle(): void {
  if (mockSubscribers.size === 0) {
    stopMockTicker();
    removeMockVisibilityListener();
  }
}

function sanitizeDomainList(
  domains: readonly string[],
  label: string,
): { ok: true; values: string[] } | { ok: false; message: string } {
  const seen = new Set<string>();
  const values: string[] = [];

  for (const raw of domains) {
    if (CONTROL_CHAR_RE.test(raw)) {
      return {
        ok: false,
        message: `Invalid ${label} domain entry: Domain rule cannot contain control characters or newlines.`,
      };
    }
    const trimmed = raw.trim();
    if (!trimmed) {
      continue;
    }
    const err = validateDomainRule(trimmed);
    if (err) {
      return {
        ok: false,
        message: `Invalid ${label} domain entry: ${err}`,
      };
    }
    const lower = trimmed.toLowerCase();
    if (!seen.has(lower)) {
      if (values.length >= MAX_DOMAIN_ENTRIES) {
        return {
          ok: false,
          message: `Invalid ${label} domain list: exceeds maximum of ${MAX_DOMAIN_ENTRIES} entries.`,
        };
      }
      seen.add(lower);
      values.push(lower);
    }
  }

  return { ok: true, values };
}

function formatSplitSummaryLabel(mode: SplitTunnelMode, count: number): string {
  const noun = count === 1 ? "app" : "apps";
  switch (mode) {
    case "all":
      return "All apps";
    case "exclude":
      return `Exclude (${count} ${noun})`;
    case "include":
      return `Include (${count} ${noun})`;
  }
}

function buildMockDiagnosticsReport(store: MockStore): DiagnosticsReport {
  const ranAtMs = Date.now();
  const isRunning = store.serviceState === "running" && store.live !== null;
  const isNotInstalled = store.serviceState === "not_installed";
  const engineLabel = store.settings.engine === "tun" ? "TUN" : "Proxy";

  const splitSummary = formatSplitSummaryLabel(
    store.settings.splitTunnelMode,
    store.settings.splitTunnelApps.length,
  );
  const emptyInclude =
    store.settings.splitTunnelMode === "include" &&
    store.settings.splitTunnelApps.length === 0;

  const vpnCheck: DiagnosticCheckItem = store.vpnConflict
    ? {
        id: "vpn_coexistence",
        name: "VPN coexistence",
        target: store.vpnConflict,
        status: "warn",
        latencyMs: 3,
        summary: `Active VPN detected (${store.vpnConflict}) · ${splitSummary}`,
        detail: `VPN coexistence policy: ${store.settings.vpnCoexistence}`,
      }
    : emptyInclude
      ? {
          id: "vpn_coexistence",
          name: "VPN coexistence",
          target: "Routing & split rules",
          status: "warn",
          latencyMs: 2,
          summary: `No VPN conflict · ${splitSummary}`,
          detail: EMPTY_INCLUDE_WARNING,
        }
      : {
          id: "vpn_coexistence",
          name: "VPN coexistence",
          target: "Routing & split rules",
          status: "pass",
          latencyMs: 2,
          summary: `No VPN conflict · ${splitSummary}`,
          detail: `VPN coexistence: ${store.settings.vpnCoexistence} · ${store.settings.bypassDomains.length} bypass / ${store.settings.includeDomains.length} include domains`,
        };

  const wintunCheck: DiagnosticCheckItem = store.wintun.ready
    ? {
        id: "wintun_driver",
        name: "Wintun driver",
        target: "wintun.dll",
        status: "pass",
        latencyMs: 1,
        summary:
          store.settings.engine === "tun"
            ? "wintun.dll verified and ready for TUN adapter"
            : "wintun.dll available (not required in Proxy mode)",
        detail: null,
      }
    : {
        id: "wintun_driver",
        name: "Wintun driver",
        target: "wintun.dll",
        status: store.settings.engine === "tun" ? "fail" : "warn",
        latencyMs: null,
        summary: "wintun.dll missing",
        detail:
          store.wintun.message ??
          "Extract all files from the zip (keep wintun.dll beside vdpi.exe).",
      };

  const dnsCheck: DiagnosticCheckItem = {
    id: "dns_resolution",
    name: store.settings.effectiveDoh
      ? "Encrypted DNS (DoH)"
      : "DNS Resolution (UDP)",
    target: store.settings.dnsDisplay,
    status: isNotInstalled ? "warn" : "pass",
    latencyMs: store.settings.effectiveDoh ? 14 : 9,
    summary: store.settings.effectiveDoh
      ? `Resolved via DoH (${store.settings.dnsDisplay})`
      : `Resolved via UDP (${store.settings.dnsDisplay})`,
    detail: `QUIC blocking: ${store.settings.blockQuic ? "enabled" : "disabled"} · IPv4-only: ${store.settings.ipv4Only ? "on" : "off"}`,
  };

  const discordCheck: DiagnosticCheckItem = isRunning
    ? {
        id: "discord_gateway",
        name: "Discord Web & Gateway",
        target: "discord.com:443",
        status: "pass",
        latencyMs: 31,
        summary: "TLS 1.3 handshake succeeded via adaptive bypass",
        detail: `Engine: ${engineLabel} · stage ComboMultiRecord`,
      }
    : {
        id: "discord_gateway",
        name: "Discord Web & Gateway",
        target: "discord.com:443",
        status: isNotInstalled ? "fail" : "warn",
        latencyMs: isNotInstalled ? null : 58,
        summary: isNotInstalled
          ? "Protection service not installed; bypass check skipped"
          : "Protection paused; direct probe without DPI bypass",
        detail: "Start protection to verify live anti-DPI handshake behavior.",
      };

  const robloxCheck: DiagnosticCheckItem = isRunning
    ? {
        id: "roblox_clientsettings",
        name: "Roblox ClientSettings",
        target: "roblox.com:443",
        status: "pass",
        latencyMs: 42,
        summary: "TLS 1.3 handshake succeeded via adaptive bypass",
        detail: `Engine: ${engineLabel} · stage ComboMultiRecord`,
      }
    : {
        id: "roblox_clientsettings",
        name: "Roblox ClientSettings",
        target: "roblox.com:443",
        status: isNotInstalled ? "fail" : "warn",
        latencyMs: isNotInstalled ? null : 64,
        summary: isNotInstalled
          ? "Protection service not installed; bypass check skipped"
          : "Protection paused; direct probe without DPI bypass",
        detail: "Start protection to verify live anti-DPI handshake behavior.",
      };

  const runtimeCheck: DiagnosticCheckItem = isNotInstalled
    ? {
        id: "service_hygiene",
        name: "Service & Runtime Hygiene",
        target: `${engineLabel} service`,
        status: "fail",
        latencyMs: null,
        summary: "Background service is not installed",
        detail:
          "Install the background service from Settings to enable protection.",
      }
    : isRunning && store.live
      ? {
          id: "service_hygiene",
          name: "Service & Runtime Hygiene",
          target:
            store.settings.engine === "tun"
              ? (store.live.tunInterface ?? "vdpi-tun0")
              : `${store.live.addr}:${store.live.port}`,
          status: "pass",
          latencyMs: 2,
          summary: `${engineLabel} active (v${APP_VERSION}) · ${store.live.activeConnections} TCP flows`,
          detail:
            store.settings.engine === "tun"
              ? `Adapter ${store.live.tunInterface ?? "vdpi-tun0"} via ${store.live.physicalNic ?? "Ethernet"} · adaptive stage ${store.live.ispStage ?? "ComboMultiRecord"}`
              : `HTTP ${store.live.addr}:${store.live.port} · SOCKS5 :${store.live.socksPort ?? 11080}`,
        }
      : {
          id: "service_hygiene",
          name: "Service & Runtime Hygiene",
          target: `${engineLabel} service`,
          status: "warn",
          latencyMs: 1,
          summary: `Service installed (${engineLabel}) but protection is paused`,
          detail: "Click Connect on Overview to resume live anti-DPI protection.",
        };

  const checks: DiagnosticCheckItem[] = [
    vpnCheck,
    wintunCheck,
    dnsCheck,
    discordCheck,
    robloxCheck,
    runtimeCheck,
  ];

  const passedCount = checks.filter((item) => item.status === "pass").length;
  const totalCount = checks.length;
  const allPassed = passedCount === totalCount;

  const redactedLines = [
    `vdpi Diagnostics Report (v${APP_VERSION}, windows)`,
    `Generated: ${new Date(ranAtMs).toISOString()}`,
    `Engine: ${engineLabel} | Service: ${store.serviceState} | DNS: ${store.settings.dnsDisplay} (${store.settings.effectiveDoh ? "DoH" : "UDP"})`,
    `Split Tunnel: ${splitSummary} | VPN Coexistence: ${store.settings.vpnCoexistence}`,
    `Result: ${passedCount}/${totalCount} checks passed`,
    "",
    ...checks.map((item) => {
      const tag = item.status.toUpperCase().padEnd(4, " ");
      const lat = item.latencyMs !== null ? ` (${item.latencyMs} ms)` : "";
      return `[${tag}] ${item.name}${lat} - ${item.summary}`;
    }),
  ];

  return {
    ranAtMs,
    allPassed,
    passedCount,
    totalCount,
    checks,
    redactedText: redactedLines.join("\n"),
  };
}

/**
 * Resets the browser-preview in-memory mock store and stops any active mock
 * telemetry interval. Intended for deterministic unit and visual QA tests.
 */
export function resetMockIpcState(): void {
  stopMockTicker();
  removeMockVisibilityListener();
  mockSubscribers.clear();
  mockStore = createInitialMockStore();
}

// ============================================================================
// Typed IPC Commands (19 Backend Commands + File Picker + Status Subscription)
// ============================================================================

export async function getStatus(
  force?: boolean,
): Promise<DesktopStatusSnapshot> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<DesktopStatusSnapshot>(
      "get_status",
      READ_IPC_TIMEOUT_MS,
      force !== undefined ? { force: Boolean(force) } : undefined,
    );
  }
  return cloneSnapshot(mockStore);
}

export async function getSettings(): Promise<DesktopSettingsPayload> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<DesktopSettingsPayload>(
      "get_settings",
      READ_IPC_TIMEOUT_MS,
    );
  }
  return cloneSettings(mockStore);
}

export async function saveGuiPreferences(
  prefs: GuiPreferences,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "save_gui_preferences",
      READ_IPC_TIMEOUT_MS,
      { prefs },
    );
  }
  const nextLanguage =
    prefs.language === "system" ||
    prefs.language === "en" ||
    prefs.language === "tr"
      ? prefs.language
      : (mockStore.settings.gui.language ?? "system");

  mockStore.settings = {
    ...mockStore.settings,
    gui: {
      theme: prefs.theme,
      language: nextLanguage,
      keepInTrayOnClose: Boolean(prefs.keepInTrayOnClose),
      minimizeToTray: Boolean(prefs.minimizeToTray),
      startMinimizedToTray: Boolean(prefs.startMinimizedToTray),
      showTaskbarIconWhenMinimized: Boolean(prefs.showTaskbarIconWhenMinimized),
    },
  };
  return {
    ok: true,
    message: "GUI preferences saved.",
  };
}

export async function toggleProtection(
  connect?: boolean,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "toggle_protection",
      SERVICE_ACTION_TIMEOUT_MS,
      connect !== undefined ? { connect } : {},
    );
  }

  if (mockStore.serviceState === "not_installed") {
    return {
      ok: false,
      message:
        "Background service is not installed. Install the service from Settings first.",
    };
  }

  const isActive =
    mockStore.serviceState === "running" || Boolean(mockStore.live?.running);
  const shouldConnect = connect !== undefined ? Boolean(connect) : !isActive;

  if (!shouldConnect) {
    if (mockStore.serviceState === "stopped" && mockStore.live === null) {
      return {
        ok: true,
        message: "Protection is already paused.",
      };
    }
    mockStore.serviceState = "stopped";
    mockStore.live = null;
    emitMockStatus();
    return {
      ok: true,
      message: "Protection paused.",
    };
  }

  if (isActive) {
    return {
      ok: true,
      message: `Protection is already active (${mockStore.settings.engine === "tun" ? "TUN" : "Proxy"}).`,
    };
  }

  mockStore.serviceState = "running";
  mockStore.live = buildLiveTelemetry(
    mockStore.settings,
    mockStore.vpnConflict,
    null,
    mockStore.installedVersion,
  );
  emitMockStatus();
  return {
    ok: true,
    message: `Protection active (${mockStore.settings.engine === "tun" ? "TUN" : "Proxy"}).`,
  };
}

export async function switchEngine(engine: EngineMode): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "switch_engine",
      SERVICE_ACTION_TIMEOUT_MS,
      { engine },
    );
  }

  const label = engine === "tun" ? "TUN" : "Proxy";
  if (mockStore.settings.engine === engine) {
    return {
      ok: true,
      message: `Already using ${label} engine.`,
      needsRestart: false,
    };
  }

  mockStore.settings = {
    ...mockStore.settings,
    engine,
  };
  mockStore.wintun = {
    ...mockStore.wintun,
    required: engine === "tun",
  };

  if (mockStore.serviceState === "running") {
    mockStore.live = buildLiveTelemetry(
      mockStore.settings,
      mockStore.vpnConflict,
      mockStore.live,
      mockStore.installedVersion,
    );
  }

  emitMockStatus();
  return {
    ok: true,
    message: `Switched engine to ${label}.`,
    needsRestart: false,
  };
}

export async function saveDnsRules(
  update: DnsConfigUpdate,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "save_dns_rules",
      SERVICE_ACTION_TIMEOUT_MS,
      { update },
    );
  }

  const dnsValidation = validateCustomDnsClient(update.dnsAddr);
  if (!dnsValidation.valid) {
    return {
      ok: false,
      message: scrubUrlsInText(
        dnsValidation.error ??
          "DNS address must be a valid IPv4/IPv6 address or https:// DoH URL.",
      ),
    };
  }
  const dnsAddr = dnsValidation.normalized;

  const bypassRes = sanitizeDomainList(update.bypassDomains, "bypass");
  if (!bypassRes.ok) {
    return { ok: false, message: bypassRes.message };
  }

  const includeRes = sanitizeDomainList(update.includeDomains, "include");
  if (!includeRes.ok) {
    return { ok: false, message: includeRes.message };
  }

  const dnsIsCustomUrl = dnsValidation.kind === "doh_url";
  const dnsDisplay = redactDnsPreview(dnsAddr) || dnsAddr;
  const effectiveDoh = dnsIsCustomUrl
    ? true
    : Boolean(update.dohEnabled) && isKnownPublicDohIp(dnsAddr);

  mockStore.settings = {
    ...mockStore.settings,
    dnsAddr,
    dnsDisplay,
    dnsIsCustomUrl,
    dohEnabled: Boolean(update.dohEnabled),
    effectiveDoh,
    blockQuic: Boolean(update.blockQuic),
    tunIpv6: Boolean(update.tunIpv6),
    ipv4Only: Boolean(update.ipv4Only),
    vpnCoexistence: update.vpnCoexistence,
    bypassDomains: bypassRes.values,
    includeDomains: includeRes.values,
  };

  if (mockStore.live) {
    mockStore.live = {
      ...mockStore.live,
      dnsDisplay,
      dohEnabled: effectiveDoh,
      blockQuic: mockStore.settings.blockQuic,
    };
  }

  emitMockStatus();
  return {
    ok: true,
    message: "DNS and routing rules saved.",
    needsRestart: false,
  };
}

export async function getSplitTunnel(): Promise<SplitTunnelPayload> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<SplitTunnelPayload>(
      "get_split_tunnel",
      READ_IPC_TIMEOUT_MS,
    );
  }
  return cloneSplitTunnelPayload(mockStore);
}

function svgToDataUri(svg: string): string {
  const compact = svg.trim();
  if (typeof btoa === "function") {
    return `data:image/svg+xml;base64,${btoa(compact)}`;
  }
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(compact)}`;
}

const MOCK_ICON_SVGS = {
  discord: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#5865F2"/><path d="M20.3 9.2a13 13 0 0 0-3.2-1c-.1.2-.3.6-.4.8a12 12 0 0 0-3.4 0c-.1-.2-.3-.6-.4-.8a13 13 0 0 0-3.2 1C7.7 12.2 7.1 15.1 7.4 18a13 13 0 0 0 3.9 2c.3-.4.6-.9.8-1.4-.5-.2-.9-.4-1.3-.7.1-.1.2-.2.3-.3 2.5 1.1 5.3 1.1 7.8 0 .1.1.2.2.3.3-.4.3-.8.5-1.3.7.2.5.5 1 .8 1.4a13 13 0 0 0 3.9-2c.3-3.3-.5-6.2-2.3-8.8z" fill="#FFFFFF"/><circle cx="11.5" cy="14.7" r="1.45" fill="#5865F2"/><circle cx="16.5" cy="14.7" r="1.45" fill="#5865F2"/></svg>',
  ),
  chrome: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><defs><clipPath id="c"><circle cx="14" cy="14" r="13"/></clipPath></defs><g clip-path="url(#c)"><path d="M0 0h28v8.4H14L9.15 16.8 2.15 4.7 0 0z" fill="#EA4335"/><path d="M14 8.4H28V28H11.85l7-11.2L14 8.4z" fill="#FBBC05"/><path d="M0 0l2.15 4.7 7 12.1h9.7l-7 11.2H0V0z" fill="#34A853"/></g><circle cx="14" cy="14" r="6.2" fill="#FFFFFF"/><circle cx="14" cy="14" r="4.8" fill="#4285F4"/></svg>',
  ),
  firefox: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#FF7139"/><path d="M14 1a13 13 0 0 1 11.4 6.7c-2.3-2.1-5.4-2.8-8.1-1.9 2.2 1.2 3.7 3.6 3.7 6.4 0 4-3.2 7.2-7.2 7.2-3.5 0-6.5-2.5-7.1-5.9-.5-2.6.5-5.3 2.5-6.9-1.5.5-2.8 1.5-3.6 2.8A13 13 0 0 1 14 1z" fill="#FFAD00"/><circle cx="14.2" cy="14.6" r="5.6" fill="#4338CA"/></svg>',
  ),
  msedge: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#0078D4"/><path d="M26 17.5a13 13 0 0 1-22.4 4.2 9.5 9.5 0 0 0 7.9 2.6c4.2 0 7.7-2.2 9.9-4.5 1.8-1.8 3.2-2.3 4.6-2.3z" fill="#30C5B0"/><path d="M14.2 2.2c5.9 0 10.8 4.1 12 9.6-1.4-2.1-4.1-3.3-7.1-3.3-4.6 0-8.1 3.2-8.1 7.3 0 2.6 1.5 4.9 3.9 6.1-5.4-.2-9.8-4.4-9.8-9.8 0-5.5 4.1-9.9 9.1-9.9z" fill="#38BDF8"/><circle cx="15.2" cy="15.4" r="4" fill="#FFFFFF"/></svg>',
  ),
  brave: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#FB542B"/><path d="M14 5.2l7 2.8-1.4 9.5L14 22.8l-5.6-5.3L7 8l7-2.8z" fill="#FFFFFF"/><path d="M14 7.8l4.4 1.8-.9 6.6L14 19.6l-3.5-3.4-.9-6.6L14 7.8z" fill="#FB542B"/><path d="M11.6 11.4h4.8l-1.1 2.2h-2.6l-1.1-2.2zm1.3 3.4h2.2l-1.1 2-1.1-2z" fill="#FFFFFF"/></svg>',
  ),
  steam: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#1B2838"/><circle cx="18.2" cy="10.8" r="3.9" fill="none" stroke="#FFFFFF" stroke-width="2"/><circle cx="18.2" cy="10.8" r="1.5" fill="#FFFFFF"/><circle cx="10.6" cy="17.8" r="2.7" fill="none" stroke="#FFFFFF" stroke-width="1.8"/><path d="M12.7 16.1l3.6-3.1M1.8 14.3l7.3 3" stroke="#FFFFFF" stroke-width="2.4" stroke-linecap="round"/></svg>',
  ),
  spotify: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#1DB954"/><path d="M8 11.2c3.8-1.1 8.6-.9 12.1 1.1M8.8 14.9c3.1-.9 7-.7 9.9.9M9.6 18.4c2.4-.7 5.4-.5 7.7.8" fill="none" stroke="#121212" stroke-width="2.1" stroke-linecap="round"/></svg>',
  ),
  valorant: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#FF4655"/><path d="M6.5 8.5v5.1l5.6 7h4.2l-9.8-12.1zm15 0l-6.1 7.6h4.2l1.9-2.4V8.5z" fill="#FFFFFF"/></svg>',
  ),
  league: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#091428"/><rect x="2" y="2" width="24" height="24" rx="4.5" fill="none" stroke="#C89B3C" stroke-width="1.4"/><path d="M10.2 7.2h3.4v10.6h5.6v3H10.2V7.2z" fill="#C89B3C"/></svg>',
  ),
  roblox: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#1F2227"/><g transform="rotate(16 14 14)"><rect x="7" y="7" width="14" height="14" rx="2" fill="#FFFFFF"/><rect x="12" y="12" width="4" height="4" rx="0.5" fill="#1F2227"/></g></svg>',
  ),
  telegram: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#229ED9"/><path d="M20.8 8.8L18.4 20c-.2.8-.7 1-1.3.6l-3.7-2.7-1.8 1.7c-.2.2-.4.4-.8.4l.3-3.8 6.9-6.2c.3-.3-.1-.4-.5-.2l-8.5 5.4-3.7-1.1c-.8-.3-.8-.8.2-1.2l14.4-5.5c.7-.2 1.2.2 1 1.4z" fill="#FFFFFF"/></svg>',
  ),
  obs: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#1E222A"/><circle cx="14" cy="10.4" r="3.6" fill="none" stroke="#FFFFFF" stroke-width="2.2"/><circle cx="17.2" cy="15.9" r="3.6" fill="none" stroke="#FFFFFF" stroke-width="2.2"/><circle cx="10.8" cy="15.9" r="3.6" fill="none" stroke="#FFFFFF" stroke-width="2.2"/><circle cx="14" cy="14" r="2.2" fill="#1E222A"/></svg>',
  ),
  vscode: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#007ACC"/><path d="M18.6 6.2l3.4 1.6v12.4l-3.4 1.6-7.8-6.4-3.3 2.5-1.5-.8v-6.2l1.5-.8 3.3 2.5 7.8-6.4zm0 4.2L13.7 14l4.9 3.6v-7.2z" fill="#FFFFFF"/></svg>',
  ),
  vlc: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#25282E"/><path d="M12.4 6h3.2l4.4 14.5H8L12.4 6z" fill="#FF8800"/><path d="M11.1 10.4h5.8l.8 2.6h-7.4l.8-2.6zm-1.6 5.2h9l.8 2.6H8.7l.8-2.6z" fill="#FFFFFF"/><rect x="6.5" y="20" width="15" height="2.4" rx="1" fill="#FF8800"/></svg>',
  ),
  epic: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect width="28" height="28" rx="6" fill="#202226"/><path d="M8.2 5.8h11.6v12.8L14 22.4l-5.8-3.8V5.8z" fill="none" stroke="#FFFFFF" stroke-width="1.6"/><path d="M11 9.5h6v1.8h-4v1.8h3.4v1.8H13v1.9h4v1.8h-6V9.5z" fill="#FFFFFF"/></svg>',
  ),
  qbittorrent: svgToDataUri(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><circle cx="14" cy="14" r="13" fill="#2F67BA"/><circle cx="10.8" cy="14.5" r="2.9" fill="none" stroke="#FFFFFF" stroke-width="1.9"/><path d="M13.7 11.6v8.2" stroke="#FFFFFF" stroke-width="1.9" stroke-linecap="round"/><circle cx="18.3" cy="14.5" r="2.9" fill="none" stroke="#FFFFFF" stroke-width="1.9"/><path d="M15.4 8.2v9.2" stroke="#FFFFFF" stroke-width="1.9" stroke-linecap="round"/></svg>',
  ),
} as const;

const MOCK_APP_ICON_BY_KEY: Record<string, string> = {
  discord: MOCK_ICON_SVGS.discord,
  discordptb: MOCK_ICON_SVGS.discord,
  discordcanary: MOCK_ICON_SVGS.discord,
  chrome: MOCK_ICON_SVGS.chrome,
  chrome_proxy: MOCK_ICON_SVGS.chrome,
  firefox: MOCK_ICON_SVGS.firefox,
  msedge: MOCK_ICON_SVGS.msedge,
  brave: MOCK_ICON_SVGS.brave,
  steam: MOCK_ICON_SVGS.steam,
  steamwebhelper: MOCK_ICON_SVGS.steam,
  gameoverlayui: MOCK_ICON_SVGS.steam,
  spotify: MOCK_ICON_SVGS.spotify,
  valorant: MOCK_ICON_SVGS.valorant,
  "valorant-win64-shipping": MOCK_ICON_SVGS.valorant,
  riotclientservices: MOCK_ICON_SVGS.valorant,
  riotclientux: MOCK_ICON_SVGS.valorant,
  vgc: MOCK_ICON_SVGS.valorant,
  vgtray: MOCK_ICON_SVGS.valorant,
  leagueclient: MOCK_ICON_SVGS.league,
  leagueclientux: MOCK_ICON_SVGS.league,
  "league of legends": MOCK_ICON_SVGS.league,
  robloxplayerbeta: MOCK_ICON_SVGS.roblox,
  robloxplayerlauncher: MOCK_ICON_SVGS.roblox,
  bloxstrap: MOCK_ICON_SVGS.roblox,
  telegram: MOCK_ICON_SVGS.telegram,
  obs64: MOCK_ICON_SVGS.obs,
  obs32: MOCK_ICON_SVGS.obs,
  code: MOCK_ICON_SVGS.vscode,
  vlc: MOCK_ICON_SVGS.vlc,
  epicgameslauncher: MOCK_ICON_SVGS.epic,
  qbittorrent: MOCK_ICON_SVGS.qbittorrent,
};

export async function getAppIcons(
  apps: AppIconRequest[],
): Promise<Record<string, string>> {
  if (!Array.isArray(apps) || apps.length === 0) {
    return {};
  }

  if (isTauriRuntime()) {
    const raw = await invokeWithTimeout<Record<string, string>>(
      "get_app_icons",
      APP_ICONS_TIMEOUT_MS,
      { apps },
    );
    if (!raw || typeof raw !== "object") {
      return {};
    }
    const sanitized: Record<string, string> = {};
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string" && value.length > 0) {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }

  const icons: Record<string, string> = {};
  for (const app of apps) {
    if (!app || typeof app.key !== "string" || !app.key) {
      continue;
    }
    const normalizedKey = normalizeExeKey(app.key);
    const exeKey = normalizeExeKey(app.exeName || "");
    const uri =
      MOCK_APP_ICON_BY_KEY[normalizedKey] ?? MOCK_APP_ICON_BY_KEY[exeKey];
    if (uri) {
      icons[app.key] = uri;
    }
  }
  return icons;
}

export async function saveSplitTunnel(
  request: SplitTunnelSaveRequest,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "save_split_tunnel",
      SERVICE_ACTION_TIMEOUT_MS,
      { request },
    );
  }

  for (const raw of request.apps) {
    if (CONTROL_CHAR_RE.test(raw)) {
      return {
        ok: false,
        message: "Application names cannot contain control characters or newlines.",
      };
    }
  }

  const seenKeys = new Set<string>();
  const sanitizedApps: string[] = [];
  let truncatedCount = 0;

  for (const raw of request.apps) {
    const exeName = extractExecutableName(raw);
    if (!exeName) {
      continue;
    }
    const key = normalizeExeKey(exeName);
    if (!key || seenKeys.has(key)) {
      continue;
    }
    seenKeys.add(key);
    if (sanitizedApps.length < MAX_SPLIT_TUNNEL_APPS) {
      sanitizedApps.push(exeName);
    } else {
      truncatedCount += 1;
    }
  }

  mockStore.settings = {
    ...mockStore.settings,
    splitTunnelMode: request.mode,
    splitTunnelApps: sanitizedApps,
  };

  const savedKeys = new Set(
    sanitizedApps.map((exeName) => normalizeExeKey(exeName)),
  );
  mockStore.discoveredApps = mockStore.discoveredApps.filter(
    (item) =>
      item.category !== "custom" ||
      item.isRunning ||
      savedKeys.has(item.normalizedKey),
  );

  const knownKeys = new Set(
    mockStore.discoveredApps.map((item) => item.normalizedKey),
  );
  for (const exeName of sanitizedApps) {
    const key = normalizeExeKey(exeName);
    if (!knownKeys.has(key)) {
      knownKeys.add(key);
      mockStore.discoveredApps.push({
        displayName: displayNameFromExe(exeName),
        exeName,
        normalizedKey: key,
        path: null,
        isRunning: false,
        category: "custom",
        companions: [],
        groupTag: classifyMockGroupTag(exeName),
      });
    }
  }

  const summary = formatSplitSummaryLabel(request.mode, sanitizedApps.length);
  const serviceRunning = mockStore.serviceState === "running";
  const appliedLive = Boolean(request.applyLive && serviceRunning);

  let message = appliedLive
    ? `Split tunneling saved: ${summary} (applied live)`
    : serviceRunning
      ? `Split tunneling saved: ${summary}. Restart protection to apply changes.`
      : `Split tunneling saved: ${summary}`;
  if (request.mode === "include" && sanitizedApps.length === 0) {
    message = message.endsWith(".")
      ? `${message} ${EMPTY_INCLUDE_WARNING}`
      : `${message}. ${EMPTY_INCLUDE_WARNING}`;
  }
  if (truncatedCount > 0) {
    const noun = truncatedCount === 1 ? "app" : "apps";
    const notice = `Notice: split tunnel app list exceeded the maximum of ${MAX_SPLIT_TUNNEL_APPS} apps; truncated ${truncatedCount} extra ${noun}.`;
    message = message.endsWith(".")
      ? `${message} ${notice}`
      : `${message}. ${notice}`;
  }

  emitMockStatus();
  return {
    ok: true,
    message,
    needsRestart: appliedLive ? false : serviceRunning ? true : undefined,
  };
}

export async function runDiagnostics(): Promise<DiagnosticsReport> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<DiagnosticsReport>(
      "run_diagnostics",
      DIAGNOSTICS_IPC_TIMEOUT_MS,
    );
  }
  return buildMockDiagnosticsReport(mockStore);
}

export async function installService(
  engine?: EngineMode,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "install_service",
      SERVICE_ACTION_TIMEOUT_MS,
      engine !== undefined ? { engine } : undefined,
    );
  }

  if (!mockStore.canInstallFromBundle || !mockStore.bundledEngineVersion) {
    return {
      ok: false,
      code: "bundled_cli_missing",
      message:
        "Bundled vdpi engine binary was not found in the application folder.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  if (mockStore.serviceState !== "not_installed") {
    return {
      ok: true,
      message: "Background service is already installed.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  const targetEngine = engine ?? mockStore.settings.engine;
  if (targetEngine === "tun" && !mockStore.wintun.ready) {
    return {
      ok: false,
      code: "wintun_missing",
      message:
        mockStore.wintun.message ??
        "wintun.dll is missing beside vdpi.exe. Extract all files or use Proxy mode.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  mockStore.settings = {
    ...mockStore.settings,
    engine: targetEngine,
  };
  mockStore.wintun = {
    ...mockStore.wintun,
    required: targetEngine === "tun",
  };
  mockStore.serviceState = "running";
  mockStore.installedVersion = mockStore.bundledEngineVersion;
  mockStore.liveVersionStale = false;
  mockStore.live = buildLiveTelemetry(
    mockStore.settings,
    mockStore.vpnConflict,
    null,
    mockStore.installedVersion,
  );
  emitMockStatus();

  return {
    ok: true,
    message: "Background service installed and started.",
    snapshot: cloneSnapshot(mockStore),
  };
}

export async function upgradeService(): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "upgrade_service",
      SERVICE_ACTION_TIMEOUT_MS,
    );
  }

  if (!mockStore.canInstallFromBundle || !mockStore.bundledEngineVersion) {
    return {
      ok: false,
      code: "bundled_cli_missing",
      message:
        "Bundled vdpi engine binary was not found in the application folder.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  if (mockStore.serviceState === "not_installed") {
    return {
      ok: false,
      message: "Background service is not installed. Install the service first.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  const cmp = compareSemver(
    mockStore.installedVersion,
    mockStore.bundledEngineVersion,
  );
  if (cmp === null) {
    return {
      ok: false,
      code: "version_unknown",
      message:
        "Installed engine version could not be determined. Use Repair / Reinstall instead.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  if (cmp > 0) {
    return {
      ok: false,
      code: "downgrade_blocked",
      message: `Installed engine v${mockStore.installedVersion} is newer than bundled v${mockStore.bundledEngineVersion}. Downgrade blocked.`,
      snapshot: cloneSnapshot(mockStore),
    };
  }

  if (cmp === 0) {
    return {
      ok: true,
      code: "already_up_to_date",
      message: `Engine is already up to date (v${mockStore.installedVersion}).`,
      snapshot: cloneSnapshot(mockStore),
    };
  }

  mockStore.installedVersion = mockStore.bundledEngineVersion;
  mockStore.liveVersionStale = false;
  if (mockStore.serviceState === "running") {
    mockStore.live = buildLiveTelemetry(
      mockStore.settings,
      mockStore.vpnConflict,
      mockStore.live,
      mockStore.installedVersion,
    );
  }
  emitMockStatus();

  return {
    ok: true,
    message: `Engine updated to v${mockStore.bundledEngineVersion}.`,
    snapshot: cloneSnapshot(mockStore),
  };
}

export async function repairService(
  engine?: EngineMode,
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "repair_service",
      SERVICE_ACTION_TIMEOUT_MS,
      engine !== undefined ? { engine } : undefined,
    );
  }

  if (!mockStore.canInstallFromBundle || !mockStore.bundledEngineVersion) {
    return {
      ok: false,
      code: "bundled_cli_missing",
      message:
        "Bundled vdpi engine binary was not found in the application folder.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  if (
    mockStore.serviceState !== "not_installed" &&
    mockStore.installedVersion !== null
  ) {
    const cmp = compareSemver(
      mockStore.installedVersion,
      mockStore.bundledEngineVersion,
    );
    if (cmp !== null && cmp > 0) {
      return {
        ok: false,
        code: "downgrade_blocked",
        message: `Installed engine v${mockStore.installedVersion} is newer than bundled v${mockStore.bundledEngineVersion}. Downgrade blocked.`,
        snapshot: cloneSnapshot(mockStore),
      };
    }
  }

  const targetEngine = engine ?? mockStore.settings.engine;
  if (targetEngine === "tun" && !mockStore.wintun.ready) {
    return {
      ok: false,
      code: "wintun_missing",
      message:
        mockStore.wintun.message ??
        "wintun.dll is missing beside vdpi.exe. Extract all files or use Proxy mode.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  mockStore.settings = {
    ...mockStore.settings,
    engine: targetEngine,
  };
  mockStore.wintun = {
    ...mockStore.wintun,
    required: targetEngine === "tun",
  };
  mockStore.serviceState = "running";
  mockStore.installedVersion = mockStore.bundledEngineVersion;
  mockStore.liveVersionStale = false;
  mockStore.live = buildLiveTelemetry(
    mockStore.settings,
    mockStore.vpnConflict,
    mockStore.live,
    mockStore.installedVersion,
  );
  emitMockStatus();

  return {
    ok: true,
    message: `Background service repaired (v${mockStore.bundledEngineVersion}).`,
    snapshot: cloneSnapshot(mockStore),
  };
}

export async function uninstallService(): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "uninstall_service",
      SERVICE_ACTION_TIMEOUT_MS,
    );
  }

  if (mockStore.serviceState === "not_installed") {
    return {
      ok: true,
      message: "Background service is already uninstalled.",
      snapshot: cloneSnapshot(mockStore),
    };
  }

  mockStore.serviceState = "not_installed";
  mockStore.installedVersion = null;
  mockStore.liveVersionStale = false;
  mockStore.live = null;
  emitMockStatus();

  return {
    ok: true,
    message: "Background service uninstalled.",
    snapshot: cloneSnapshot(mockStore),
  };
}

export async function resetNetworkSettings(): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "reset_network_settings",
      SERVICE_ACTION_TIMEOUT_MS,
    );
  }

  if (mockStore.serviceState === "running") {
    mockStore.serviceState = "stopped";
  }
  mockStore.live = null;
  emitMockStatus();

  return {
    ok: true,
    message: "Network settings reset to defaults.",
    code: undefined,
    snapshot: cloneSnapshot(mockStore),
  };
}

export async function checkUpdates(
  force?: boolean,
): Promise<UpdateCheckPayload> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<UpdateCheckPayload>(
      "check_updates",
      UPDATE_IPC_TIMEOUT_MS,
      force !== undefined ? { force: Boolean(force) } : undefined,
    );
  }

  return {
    currentVersion: APP_VERSION,
    latestVersion: APP_VERSION,
    hasUpdate: false,
    releaseUrl: `https://github.com/Vuln-Inc/vdpi/releases/tag/v${APP_VERSION}`,
    releaseNotes: [
      "Native desktop control center with live throughput telemetry.",
      "Visual split tunneling with curated one-click app presets.",
      "Encrypted DNS (DoH) editor with VPN coexistence controls.",
    ],
  };
}

export async function openAppFolder(
  kind: AppFolderTarget = "config",
): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "open_app_folder",
      READ_IPC_TIMEOUT_MS,
      { kind, target: kind },
    );
  }

  const folderPath =
    kind === "logs"
      ? MOCK_LOGS_DIR
      : kind === "app"
        ? MOCK_APP_DIR
        : MOCK_CONFIG_DIR;
  return {
    ok: true,
    message: `Preview mode: would open ${folderPath}`,
  };
}

export async function openExternalUrl(url: string): Promise<ActionResult> {
  const trimmed = url.trim();
  if (!trimmed || CONTROL_CHAR_RE.test(trimmed)) {
    return {
      ok: false,
      message: "Only valid http:// or https:// URLs can be opened externally.",
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      ok: false,
      message: "Only valid http:// or https:// URLs can be opened externally.",
    };
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return {
      ok: false,
      message: "Only http:// and https:// URLs can be opened externally.",
    };
  }

  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "open_external_url",
      READ_IPC_TIMEOUT_MS,
      { url: trimmed },
    );
  }

  if (typeof window !== "undefined" && typeof window.open === "function") {
    try {
      const opened = window.open(trimmed, "_blank", "noopener,noreferrer");
      if (opened) {
        opened.opener = null;
      }
    } catch {
      // Ignore popup or headless environment errors (e.g. jsdom).
    }
  }

  return {
    ok: true,
    message: `Preview mode: opened ${parsed.origin}`,
  };
}

function isLinuxPlatform(): boolean {
  if (typeof navigator === "undefined") {
    return false;
  }
  const platform = navigator.platform ?? "";
  const userAgent = navigator.userAgent ?? "";
  const combined = `${platform} ${userAgent}`;
  return /linux/i.test(combined) && !/android/i.test(combined);
}

export async function pickExecutableFile(): Promise<string | null> {
  if (isTauriRuntime()) {
    const applicationsFilter = {
      name: "Applications",
      extensions: ["exe", "app", "AppImage", "bat", "cmd"],
    };
    const allFilesFilter = {
      name: "All Files",
      extensions: ["*"],
    };
    const filters = isLinuxPlatform()
      ? [allFilesFilter, applicationsFilter]
      : [applicationsFilter, allFilesFilter];

    const selected = await open({
      title: "Select Application Executable",
      multiple: false,
      directory: false,
      filters,
    });
    if (typeof selected === "string" && selected.trim().length > 0) {
      return selected.trim();
    }
    if (
      Array.isArray(selected) &&
      typeof selected[0] === "string" &&
      selected[0].trim().length > 0
    ) {
      return selected[0].trim();
    }
    return null;
  }

  // Deterministic, non-blocking picker fallback for browser preview & Playwright.
  const selectedKeys = new Set(
    mockStore.settings.splitTunnelApps.map((app) =>
      normalizeExeKey(extractExecutableName(app) || app),
    ),
  );

  for (let offset = 0; offset < MOCK_PICKER_CANDIDATES.length; offset += 1) {
    const idx =
      (mockStore.pickerIndex + offset) % MOCK_PICKER_CANDIDATES.length;
    const candidate = MOCK_PICKER_CANDIDATES[idx];
    const key = normalizeExeKey(extractExecutableName(candidate));
    if (!selectedKeys.has(key)) {
      mockStore.pickerIndex = (idx + 1) % MOCK_PICKER_CANDIDATES.length;
      return candidate;
    }
  }

  const fallback =
    MOCK_PICKER_CANDIDATES[
      mockStore.pickerIndex % MOCK_PICKER_CANDIDATES.length
    ];
  mockStore.pickerIndex =
    (mockStore.pickerIndex + 1) % MOCK_PICKER_CANDIDATES.length;
  return fallback;
}

export async function quitApp(): Promise<ActionResult> {
  if (isTauriRuntime()) {
    const result = await invokeWithTimeout<ActionResult | void>(
      "quit_app",
      READ_IPC_TIMEOUT_MS,
    );
    if (
      result &&
      typeof result === "object" &&
      "ok" in result &&
      typeof result.ok === "boolean"
    ) {
      return result;
    }
    return {
      ok: true,
      message: "Exiting desktop GUI.",
    };
  }

  return {
    ok: false,
    message:
      "Preview mode: Quit GUI is only available in the native desktop app.",
  };
}

export async function subscribeStatus(
  cb: (snapshot: DesktopStatusSnapshot) => void,
): Promise<() => void> {
  if (isTauriRuntime()) {
    const unlisten: UnlistenFn = await listen<DesktopStatusSnapshot>(
      STATUS_EVENT,
      (event) => {
        cb(event.payload);
      },
    );
    return () => {
      unlisten();
    };
  }

  mockSubscribers.add(cb);
  ensureMockVisibilityListener();
  ensureMockTickerRunning();

  return () => {
    mockSubscribers.delete(cb);
    stopMockTickerIfIdle();
  };
}
