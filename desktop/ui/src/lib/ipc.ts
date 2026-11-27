import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import type {
  ActionResult,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  DiagnosticCheckItem,
  DiagnosticsReport,
  DiscoveredAppItem,
  DnsConfigUpdate,
  EngineMode,
  GuiPreferences,
  LiveTelemetry,
  ServiceState,
  SplitTunnelMode,
  SplitTunnelPayload,
  SplitTunnelPreset,
  SplitTunnelSaveRequest,
  UpdateCheckPayload,
  WintunStatus,
} from "../types";
import {
  extractExecutableName,
  isKnownPublicDohIp,
  redactDnsPreview,
  scrubUrlsInText,
  validateCustomDnsClient,
  validateDomainRule,
} from "./format";

export const STATUS_EVENT = "vdpi://status";

export type AppFolderTarget = "config" | "logs" | "app";

const APP_VERSION = "0.6.0";
const READ_IPC_TIMEOUT_MS = 15_000;
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
    version: APP_VERSION,
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
    live: buildLiveTelemetry(settings, null),
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

function cloneSnapshot(store: MockStore): DesktopStatusSnapshot {
  store.snapshotSeq += 1;
  return {
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
    configWarning: store.configWarning,
  };
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
        id: "vpn",
        name: "VPN coexistence",
        target: store.vpnConflict,
        status: "warn",
        latencyMs: 3,
        summary: `Active VPN detected (${store.vpnConflict}) · ${splitSummary}`,
        detail: `VPN coexistence policy: ${store.settings.vpnCoexistence}`,
      }
    : emptyInclude
      ? {
          id: "vpn",
          name: "VPN coexistence",
          target: "Routing & split rules",
          status: "warn",
          latencyMs: 2,
          summary: `No VPN conflict · ${splitSummary}`,
          detail: EMPTY_INCLUDE_WARNING,
        }
      : {
          id: "vpn",
          name: "VPN coexistence",
          target: "Routing & split rules",
          status: "pass",
          latencyMs: 2,
          summary: `No VPN conflict · ${splitSummary}`,
          detail: `VPN coexistence: ${store.settings.vpnCoexistence} · ${store.settings.bypassDomains.length} bypass / ${store.settings.includeDomains.length} include domains`,
        };

  const wintunCheck: DiagnosticCheckItem = store.wintun.ready
    ? {
        id: "wintun",
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
        id: "wintun",
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
    id: "dns",
    name: store.settings.effectiveDoh
      ? "Encrypted DNS (DoH)"
      : "Upstream DNS (UDP)",
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
        id: "discord",
        name: "Discord",
        target: "discord.com:443",
        status: "pass",
        latencyMs: 31,
        summary: "TLS 1.3 handshake succeeded via adaptive bypass",
        detail: `Engine: ${engineLabel} · stage ComboMultiRecord`,
      }
    : {
        id: "discord",
        name: "Discord",
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
        id: "roblox",
        name: "Roblox",
        target: "roblox.com:443",
        status: "pass",
        latencyMs: 42,
        summary: "TLS 1.3 handshake succeeded via adaptive bypass",
        detail: `Engine: ${engineLabel} · stage ComboMultiRecord`,
      }
    : {
        id: "roblox",
        name: "Roblox",
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
        id: "runtime",
        name: "Runtime hygiene",
        target: `${engineLabel} service`,
        status: "fail",
        latencyMs: null,
        summary: "Background service is not installed",
        detail:
          "Install the background service from Settings to enable protection.",
      }
    : isRunning && store.live
      ? {
          id: "runtime",
          name: "Runtime hygiene",
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
          id: "runtime",
          name: "Runtime hygiene",
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
// Typed IPC Commands (15 Backend Commands + File Picker + Status Subscription)
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
  mockStore.settings = {
    ...mockStore.settings,
    gui: {
      theme: prefs.theme,
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
  mockStore.live = buildLiveTelemetry(mockStore.settings, mockStore.vpnConflict);
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
      READ_IPC_TIMEOUT_MS,
    );
  }
  return buildMockDiagnosticsReport(mockStore);
}

export async function installService(): Promise<ActionResult> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<ActionResult>(
      "install_service",
      SERVICE_ACTION_TIMEOUT_MS,
    );
  }

  if (mockStore.serviceState !== "not_installed") {
    return {
      ok: true,
      message: "Background service is already installed.",
    };
  }

  mockStore.serviceState = "running";
  mockStore.installedVersion = APP_VERSION;
  mockStore.live = buildLiveTelemetry(mockStore.settings, mockStore.vpnConflict);
  emitMockStatus();

  return {
    ok: true,
    message: "Background service installed and started.",
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
    };
  }

  mockStore.serviceState = "not_installed";
  mockStore.installedVersion = null;
  mockStore.live = null;
  emitMockStatus();

  return {
    ok: true,
    message: "Background service uninstalled.",
  };
}

export async function checkUpdates(): Promise<UpdateCheckPayload> {
  if (isTauriRuntime()) {
    return invokeWithTimeout<UpdateCheckPayload>(
      "check_updates",
      READ_IPC_TIMEOUT_MS,
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
