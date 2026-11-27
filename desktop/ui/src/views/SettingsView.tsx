import { memo, useEffect, useId, useRef, useState } from "react";
import { ConfirmDialog } from "../components/ConfirmDialog";
import {
  IconAlert,
  IconCheck,
  IconExternal,
  IconEye,
  IconFolder,
  IconPower,
  IconRefresh,
  IconShield,
  IconTray,
} from "../components/Icons";
import {
  SegmentedControl,
  type SegmentedOption,
} from "../components/SegmentedControl";
import { Switch } from "../components/Switch";
import type { ToastTone } from "../components/ToastStack";
import { scrubUrlsInText } from "../lib/format";
import {
  checkUpdates,
  installService,
  isTauriRuntime,
  openAppFolder,
  openExternalUrl,
  quitApp,
  saveGuiPreferences,
  uninstallService,
} from "../lib/ipc";
import type {
  ActionResult,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  GuiPreferences,
  ServiceState,
  ThemePreference,
  UpdateCheckPayload,
} from "../types";

export interface SettingsViewProps {
  status: DesktopStatusSnapshot | null;
  settings: DesktopSettingsPayload | null;
  onPreferencesChanged: (prefs: GuiPreferences) => void | Promise<void>;
  onRefreshSettings?: () => void | Promise<unknown>;
  onServiceChanged: () => void | Promise<void>;
  onPushToast: (tone: ToastTone, message: string) => void;
}

const DEFAULT_GUI_PREFERENCES: GuiPreferences = {
  theme: "system",
  keepInTrayOnClose: false,
  minimizeToTray: false,
  startMinimizedToTray: false,
  showTaskbarIconWhenMinimized: false,
};

const THEME_OPTIONS: readonly SegmentedOption<ThemePreference>[] = [
  { value: "system", label: "System" },
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
];

const STYLE_ID = "vdpi-settings-view-styles";

const FALLBACK_STYLES = `
@keyframes vdpi-settings-spin {
  to {
    transform: rotate(360deg);
  }
}

:where(.view-settings) {
  display: flex;
  flex-direction: column;
  gap: var(--space-4, 16px);
  width: 100%;
  box-sizing: border-box;
}

:where(.settings-card) {
  display: flex;
  flex-direction: column;
  background: var(--bg-surface, var(--surface, #131518));
  border: 1px solid var(--border-subtle, var(--border, rgba(255, 255, 255, 0.1)));
  border-radius: var(--radius-lg, 10px);
  overflow: hidden;
  box-sizing: border-box;
}

:where(.settings-card__header) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3, 12px);
  padding: 14px 16px;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
}

:where(.settings-card__heading) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

:where(.settings-card__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--ink-secondary, #A1A6B0);
  flex-shrink: 0;
}

:where(.settings-card__title) {
  margin: 0;
  font-size: var(--text-md, 14px);
  font-weight: var(--weight-semibold, 600);
  line-height: var(--leading-md, 20px);
  letter-spacing: -0.01em;
  color: var(--ink-primary, #F3F4F6);
}

:where(.settings-list) {
  display: flex;
  flex-direction: column;
}

:where(.settings-row) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4, 16px);
  padding: 13px 16px;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  box-sizing: border-box;
}

:where(.settings-row:last-child) {
  border-bottom: none;
}

:where(.settings-row--nested) {
  padding-left: 28px;
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.02));
}

:where(.settings-row__copy) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.settings-row__label) {
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-medium, 500);
  line-height: var(--leading-base, 20px);
  color: var(--ink-primary, #F3F4F6);
}

:where(.settings-row__desc) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  font-weight: var(--weight-regular, 400);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

:where(.settings-row__path) {
  margin: 2px 0 0;
  font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  font-size: var(--text-xs, 11px);
  line-height: var(--leading-xs, 16px);
  color: var(--ink-tertiary, #7C828E);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:where(.settings-row__control) {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2, 8px);
  flex-shrink: 0;
}

:where(.settings-note) {
  margin: 0;
  padding: 11px 16px;
  border-top: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.02));
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

:where(.settings-info-notice) {
  margin: 0;
  padding: 10px 16px;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  background: var(--accent-subtle, rgba(59, 130, 246, 0.08));
  color: var(--ink-secondary, #A1A6B0);
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
}

:where(.settings-badge) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 22px;
  padding: 0 9px;
  border-radius: var(--radius-pill, 9999px);
  border: 1px solid var(--status-neutral-border, rgba(255, 255, 255, 0.12));
  background: var(--status-neutral-bg, rgba(255, 255, 255, 0.06));
  color: var(--status-neutral-fg, #A1A6B0);
  font-size: var(--text-xs, 11px);
  font-weight: var(--weight-medium, 500);
  line-height: 1;
  white-space: nowrap;
  box-sizing: border-box;
}

:where(.settings-badge--active) {
  border-color: var(--status-green-border, rgba(48, 209, 88, 0.28));
  background: var(--status-green-bg, rgba(48, 209, 88, 0.12));
  color: var(--status-green-fg, #30D158);
}

:where(.settings-badge--accent) {
  border-color: var(--accent-border, rgba(59, 130, 246, 0.32));
  background: var(--accent-subtle, rgba(59, 130, 246, 0.14));
  color: var(--accent-fg, #60A5FA);
}

:where(.settings-badge__dot) {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex-shrink: 0;
}

:where(.settings-service-meta) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px 14px;
  margin-top: 2px;
}

:where(.settings-mono-value) {
  font-family: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  font-size: var(--text-sm, 12px);
  color: var(--ink-secondary, #A1A6B0);
  font-variant-numeric: tabular-nums;
}

:where(.settings-spinner) {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  border: 1.75px solid currentColor;
  border-right-color: transparent;
  animation: vdpi-settings-spin 0.7s linear infinite;
  flex-shrink: 0;
}

:where(.settings-update-panel) {
  margin: 0 16px 14px;
  padding: 12px 14px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--border-subtle, rgba(255, 255, 255, 0.1));
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.03));
  box-sizing: border-box;
}

:where(.settings-update-panel--available) {
  border-color: var(--accent-border, rgba(59, 130, 246, 0.32));
  background: var(--accent-subtle, rgba(59, 130, 246, 0.08));
}

:where(.settings-update-panel--uptodate) {
  border-color: var(--status-green-border, rgba(48, 209, 88, 0.28));
  background: var(--status-green-bg, rgba(48, 209, 88, 0.08));
}

:where(.settings-update-panel--error) {
  border-color: var(--status-crimson-border, rgba(255, 69, 58, 0.28));
  background: var(--status-crimson-bg, rgba(255, 69, 58, 0.08));
}

:where(.settings-update-panel__top) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3, 12px);
  flex-wrap: wrap;
}

:where(.settings-update-panel__status) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-medium, 500);
  color: var(--ink-primary, #F3F4F6);
}

:where(.settings-update-panel--uptodate .settings-update-panel__icon) {
  color: var(--status-green-fg, #30D158);
}

:where(.settings-update-panel--available .settings-update-panel__icon) {
  color: var(--accent-fg, #60A5FA);
}

:where(.settings-update-panel--error .settings-update-panel__icon) {
  color: var(--status-crimson-fg, #FF453A);
}

:where(.settings-update-panel__meta) {
  margin: 4px 0 0;
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

:where(.settings-update-notes) {
  margin: 8px 0 0;
  padding: 0 0 0 18px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

:where(.settings-update-link) {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 0;
  border: 0;
  background: transparent;
  font: inherit;
  font-size: var(--text-sm, 12px);
  font-weight: var(--weight-medium, 500);
  color: var(--accent-fg, #60A5FA);
  text-decoration: none;
  white-space: nowrap;
  cursor: pointer;
}

:where(.settings-update-link:hover:not(:disabled)) {
  text-decoration: underline;
}

:where(.settings-update-link:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.settings-update-link:focus-visible) {
  outline: var(--focus-ring-width, 2px) solid var(--focus-ring-color, #3B82F6);
  outline-offset: 2px;
  border-radius: 4px;
}

:where(.settings-actions-group) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--space-2, 8px);
}

@media (prefers-reduced-motion: reduce) {
  :where(.settings-spinner) {
    animation: none;
  }
}
`;

function ensureStyles(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = FALLBACK_STYLES;
  document.head.appendChild(style);
}

function formatVersion(version: string | null | undefined): string {
  if (!version) return "—";
  const trimmed = version.trim();
  if (!trimmed) return "—";
  return trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
}

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message.trim()) {
    return scrubUrlsInText(err.message.trim());
  }
  if (typeof err === "string" && err.trim()) {
    return scrubUrlsInText(err.trim());
  }
  if (
    typeof err === "object" &&
    err !== null &&
    "message" in err &&
    typeof (err as { message?: unknown }).message === "string"
  ) {
    const msg = (err as { message: string }).message.trim();
    if (msg) return scrubUrlsInText(msg);
  }
  return fallback;
}

function asActionResult(value: unknown): ActionResult | null {
  if (
    typeof value === "object" &&
    value !== null &&
    "ok" in value &&
    typeof (value as { ok?: unknown }).ok === "boolean"
  ) {
    return value as ActionResult;
  }
  return null;
}

function isGuiPreferences(value: unknown): value is GuiPreferences {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<GuiPreferences>;
  return (
    (candidate.theme === "system" ||
      candidate.theme === "dark" ||
      candidate.theme === "light") &&
    typeof candidate.keepInTrayOnClose === "boolean" &&
    typeof candidate.minimizeToTray === "boolean" &&
    typeof candidate.startMinimizedToTray === "boolean" &&
    typeof candidate.showTaskbarIconWhenMinimized === "boolean"
  );
}

function sanitizeExternalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const parsed = new URL(raw);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

function formatServiceState(state: ServiceState | undefined): {
  label: string;
  badgeClass: string;
} {
  switch (state) {
    case "running":
      return {
        label: "Running",
        badgeClass: "settings-badge settings-badge--active",
      };
    case "stopped":
      return {
        label: "Stopped",
        badgeClass: "settings-badge",
      };
    case "not_installed":
      return {
        label: "Not Installed",
        badgeClass: "settings-badge",
      };
    default:
      return {
        label: "Checking...",
        badgeClass: "settings-badge",
      };
  }
}

function SettingsViewComponent({
  status,
  settings,
  onPreferencesChanged,
  onRefreshSettings,
  onServiceChanged,
  onPushToast,
}: SettingsViewProps) {
  const mountedRef = useRef(true);
  const savingPrefsRef = useRef(false);
  const serviceBusyRef = useRef(false);
  const checkingUpdatesRef = useRef(false);
  const openingFolderRef = useRef(false);
  const openingExternalRef = useRef(false);
  const quittingRef = useRef(false);

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const idPrefix = useId();
  const [prefs, setPrefs] = useState<GuiPreferences>(
    () => settings?.gui ?? DEFAULT_GUI_PREFERENCES,
  );
  const confirmedPrefsRef = useRef<GuiPreferences>(
    settings?.gui ?? DEFAULT_GUI_PREFERENCES,
  );
  const [savingPrefs, setSavingPrefs] = useState(false);

  const [serviceBusy, setServiceBusy] = useState<
    "install" | "uninstall" | null
  >(null);
  const [confirmUninstallOpen, setConfirmUninstallOpen] = useState(false);

  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updateResult, setUpdateResult] = useState<UpdateCheckPayload | null>(
    null,
  );
  const [updateError, setUpdateError] = useState<string | null>(null);

  const [openingFolder, setOpeningFolder] = useState<"config" | "logs" | null>(
    null,
  );
  const [openingExternal, setOpeningExternal] = useState(false);
  const [quitting, setQuitting] = useState(false);

  useEffect(() => {
    if (settings?.gui) {
      setPrefs(settings.gui);
      confirmedPrefsRef.current = settings.gui;
    }
  }, [settings?.gui]);

  const prefsDisabled = !settings || savingPrefs;
  const isMac = status?.platform === "macos";
  const isLinux = status?.platform === "linux";
  const traySupported = status?.traySupported !== false;
  const showLinuxTrayNotice = isLinux && !traySupported;
  const traySurfaceLabel = isMac ? "menu bar" : "system tray";
  const trayPresenceEnabled =
    prefs.keepInTrayOnClose ||
    prefs.minimizeToTray ||
    prefs.startMinimizedToTray;
  const trayEffectivelyActive = trayPresenceEnabled && traySupported;
  const trayUnavailable = trayPresenceEnabled && !traySupported;
  const showMinimizedIconToggle =
    prefs.minimizeToTray || prefs.startMinimizedToTray;

  const serviceState = status?.serviceState;
  const serviceInfo = formatServiceState(serviceState);
  const isUnixSystemServiceConfig =
    (isMac || isLinux) &&
    (serviceState === "running" ||
      serviceState === "stopped" ||
      Boolean(
        status?.configPath &&
          (status.configPath.startsWith("/etc/") ||
            status.configPath.startsWith("/Library/")),
      ));
  const installedVersionRaw =
    status?.installedVersion ??
    (serviceState === "running" ? status?.live?.version : null);
  const installedVersionDisplay =
    serviceState === "not_installed"
      ? "Not installed"
      : installedVersionRaw
        ? formatVersion(installedVersionRaw)
        : status
          ? "Unknown"
          : "—";

  const appVersionDisplay = status?.appVersion
    ? formatVersion(status.appVersion)
    : "v—";

  const commitPreferences = async (patch: Partial<GuiPreferences>) => {
    if (savingPrefsRef.current) return;
    savingPrefsRef.current = true;
    const previous = confirmedPrefsRef.current;
    const next: GuiPreferences = { ...previous, ...patch };

    setPrefs(next);
    setSavingPrefs(true);
    try {
      const response: unknown = await saveGuiPreferences(next);
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        let refreshed: unknown = null;
        if (onRefreshSettings) {
          try {
            refreshed = await onRefreshSettings();
          } catch {
            refreshed = null;
          }
        }
        if (!mountedRef.current) return;
        if (
          refreshed &&
          typeof refreshed === "object" &&
          "gui" in refreshed &&
          isGuiPreferences((refreshed as { gui?: unknown }).gui)
        ) {
          const persistedGui = (refreshed as { gui: GuiPreferences }).gui;
          confirmedPrefsRef.current = persistedGui;
          setPrefs(persistedGui);
        } else if (!refreshed) {
          setPrefs(previous);
        }
        onPushToast(
          "error",
          scrubUrlsInText(
            action.message?.trim() || "Failed to save GUI preferences.",
          ),
        );
        return;
      }
      const resolved = isGuiPreferences(response) ? response : next;
      confirmedPrefsRef.current = resolved;
      setPrefs(resolved);
      await onPreferencesChanged(resolved);
    } catch (err) {
      if (mountedRef.current) {
        setPrefs(previous);
        onPushToast(
          "error",
          getErrorMessage(err, "Failed to save GUI preferences."),
        );
      }
    } finally {
      savingPrefsRef.current = false;
      if (mountedRef.current) {
        setSavingPrefs(false);
      }
    }
  };

  const handleInstallService = async () => {
    if (serviceBusyRef.current) return;
    serviceBusyRef.current = true;
    setServiceBusy("install");
    try {
      const response: unknown = await installService();
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action?.cancelled) {
        onPushToast(
          "info",
          action.message?.trim() || "Service installation cancelled.",
        );
        return;
      }
      if (action && !action.ok) {
        throw new Error(
          action.message || "Failed to install background service.",
        );
      }
      await onServiceChanged();
      if (!mountedRef.current) return;
      onPushToast(
        "success",
        action?.message?.trim() || "Background service installed.",
      );
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          getErrorMessage(err, "Failed to install background service."),
        );
      }
    } finally {
      serviceBusyRef.current = false;
      if (mountedRef.current) {
        setServiceBusy(null);
      }
    }
  };

  const handleConfirmUninstall = async () => {
    if (serviceBusyRef.current) return;
    serviceBusyRef.current = true;
    setServiceBusy("uninstall");
    try {
      const response: unknown = await uninstallService();
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action?.cancelled) {
        setConfirmUninstallOpen(false);
        onPushToast(
          "info",
          action.message?.trim() || "Service uninstall cancelled.",
        );
        return;
      }
      if (action && !action.ok) {
        throw new Error(
          action.message || "Failed to uninstall background service.",
        );
      }
      setConfirmUninstallOpen(false);
      await onServiceChanged();
      if (!mountedRef.current) return;
      onPushToast(
        "success",
        action?.message?.trim() || "Background service uninstalled.",
      );
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          getErrorMessage(err, "Failed to uninstall background service."),
        );
      }
    } finally {
      serviceBusyRef.current = false;
      if (mountedRef.current) {
        setServiceBusy(null);
      }
    }
  };

  const handleCheckUpdates = async () => {
    if (checkingUpdatesRef.current) return;
    checkingUpdatesRef.current = true;
    setCheckingUpdates(true);
    setUpdateError(null);
    try {
      const result = await checkUpdates();
      if (!mountedRef.current) return;
      setUpdateResult(result);
    } catch (err) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(err, "Could not check for updates.");
      setUpdateResult(null);
      setUpdateError(message);
      onPushToast("error", message);
    } finally {
      checkingUpdatesRef.current = false;
      if (mountedRef.current) {
        setCheckingUpdates(false);
      }
    }
  };

  const handleOpenReleaseUrl = async (url: string) => {
    if (openingExternalRef.current) return;
    openingExternalRef.current = true;
    setOpeningExternal(true);
    try {
      const response: unknown = await openExternalUrl(url);
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        throw new Error(action.message || "Failed to open release page.");
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          getErrorMessage(err, "Failed to open release page."),
        );
      }
    } finally {
      openingExternalRef.current = false;
      if (mountedRef.current) {
        setOpeningExternal(false);
      }
    }
  };

  const handleOpenFolder = async (kind: "config" | "logs") => {
    if (openingFolderRef.current) return;
    openingFolderRef.current = true;
    setOpeningFolder(kind);
    try {
      const response: unknown = await openAppFolder(kind);
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        throw new Error(
          action.message ||
            `Failed to open ${kind === "config" ? "config" : "logs"} folder.`,
        );
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          getErrorMessage(
            err,
            `Failed to open ${kind === "config" ? "config" : "logs"} folder.`,
          ),
        );
      }
    } finally {
      openingFolderRef.current = false;
      if (mountedRef.current) {
        setOpeningFolder(null);
      }
    }
  };

  const handleQuitGui = async () => {
    if (quittingRef.current) return;
    quittingRef.current = true;
    setQuitting(true);
    try {
      const response: unknown = await quitApp();
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        onPushToast(
          isTauriRuntime() ? "error" : "info",
          action.message?.trim() || "Failed to quit GUI.",
        );
        setQuitting(false);
        quittingRef.current = false;
        return;
      }
      if (!isTauriRuntime()) {
        if (action?.message?.trim()) {
          onPushToast("info", action.message.trim());
        }
        setQuitting(false);
        quittingRef.current = false;
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast("error", getErrorMessage(err, "Failed to quit GUI."));
        setQuitting(false);
      }
      quittingRef.current = false;
    }
  };

  const safeReleaseUrl = sanitizeExternalUrl(updateResult?.releaseUrl);

  const keepInTrayLabelId = `${idPrefix}-keep-in-tray-label`;
  const keepInTrayDescId = `${idPrefix}-keep-in-tray-desc`;
  const minimizeToTrayLabelId = `${idPrefix}-minimize-to-tray-label`;
  const minimizeToTrayDescId = `${idPrefix}-minimize-to-tray-desc`;
  const showTaskbarLabelId = `${idPrefix}-show-taskbar-label`;
  const showTaskbarDescId = `${idPrefix}-show-taskbar-desc`;
  const startMinimizedLabelId = `${idPrefix}-start-minimized-label`;
  const startMinimizedDescId = `${idPrefix}-start-minimized-desc`;
  const themeLabelId = `${idPrefix}-theme-label`;

  return (
    <div className="view-stack view-settings">
      <header className="view-header">
        <div className="view-header-text">
          <h1 className="view-title">Settings</h1>
          <p className="view-subtitle">
            {isMac
              ? "Control menu bar presence, background service installation, appearance, and updates."
              : "Control tray presence, background service installation, appearance, and updates."}
          </p>
        </div>
      </header>

      {/* 1. Window & System Tray / Menu Bar */}
      <section
        className="card card-flush settings-card"
        aria-labelledby={`${idPrefix}-tray-heading`}
      >
        <div className="settings-card__header">
          <div className="settings-card__heading">
            <span className="settings-card__icon" aria-hidden="true">
              <IconTray size={16} />
            </span>
            <h2 id={`${idPrefix}-tray-heading`} className="settings-card__title">
              {isMac ? "Window & Menu Bar" : "Window & System Tray"}
            </h2>
          </div>
          <span
            className={
              trayEffectivelyActive
                ? "settings-badge settings-badge--accent"
                : "settings-badge"
            }
          >
            <span className="settings-badge__dot" aria-hidden="true" />
            {trayUnavailable
              ? "Tray unavailable"
              : isMac
                ? trayEffectivelyActive
                  ? "Menu bar active"
                  : "No menu bar icon"
                : trayEffectivelyActive
                  ? "Tray active"
                  : "No tray icon"}
          </span>
        </div>

        {showLinuxTrayNotice ? (
          <p className="settings-info-notice" role="status">
            System tray support was not detected in this Linux desktop
            environment (StatusNotifier / AppIndicator required). Tray options
            may not display an icon.
          </p>
        ) : null}

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={keepInTrayLabelId} className="settings-row__label">
                {isMac
                  ? "Keep in menu bar when closed"
                  : "Keep in system tray when closed"}
              </span>
              <p id={keepInTrayDescId} className="settings-row__desc">
                {prefs.keepInTrayOnClose
                  ? `Closing the window hides it to the ${traySurfaceLabel} with a live status dot and quick menu.`
                  : isMac
                    ? "Closing the window completely exits the GUI app with zero Dock or menu bar icon."
                    : "Closing the window completely exits the GUI app with zero taskbar or tray icon."}
              </p>
            </div>
            <div className="settings-row__control">
              <Switch
                id={`${idPrefix}-keep-in-tray`}
                checked={prefs.keepInTrayOnClose}
                disabled={prefsDisabled}
                ariaLabelledBy={keepInTrayLabelId}
                ariaDescribedBy={keepInTrayDescId}
                onChange={(checked) => {
                  void commitPreferences({ keepInTrayOnClose: checked });
                }}
              />
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={minimizeToTrayLabelId} className="settings-row__label">
                {isMac ? "Minimize to menu bar" : "Minimize to system tray"}
              </span>
              <p id={minimizeToTrayDescId} className="settings-row__desc">
                {isMac
                  ? "Minimizing hides the window to the menu bar and automatically enables menu bar presence."
                  : "Minimizing hides the window to the system tray and automatically enables tray presence."}
              </p>
            </div>
            <div className="settings-row__control">
              <Switch
                id={`${idPrefix}-minimize-to-tray`}
                checked={prefs.minimizeToTray}
                disabled={prefsDisabled}
                ariaLabelledBy={minimizeToTrayLabelId}
                ariaDescribedBy={minimizeToTrayDescId}
                onChange={(checked) => {
                  void commitPreferences({ minimizeToTray: checked });
                }}
              />
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={startMinimizedLabelId} className="settings-row__label">
                {isMac
                  ? "Start minimized to menu bar"
                  : "Start minimized to tray"}
              </span>
              <p id={startMinimizedDescId} className="settings-row__desc">
                Launch the GUI hidden in the {traySurfaceLabel} instead of
                opening the main window.
              </p>
            </div>
            <div className="settings-row__control">
              <Switch
                id={`${idPrefix}-start-minimized`}
                checked={prefs.startMinimizedToTray}
                disabled={prefsDisabled}
                ariaLabelledBy={startMinimizedLabelId}
                ariaDescribedBy={startMinimizedDescId}
                onChange={(checked) => {
                  void commitPreferences({ startMinimizedToTray: checked });
                }}
              />
            </div>
          </div>

          {showMinimizedIconToggle ? (
            <div className="settings-row settings-row--nested">
              <div className="settings-row__copy">
                <span id={showTaskbarLabelId} className="settings-row__label">
                  {isMac
                    ? "Show Dock icon when minimized"
                    : "Show taskbar icon when minimized"}
                </span>
                <p id={showTaskbarDescId} className="settings-row__desc">
                  {isMac
                    ? "Keep the app icon visible in the Dock while minimized to the menu bar."
                    : "Keep the window button visible in the taskbar while minimized to the system tray."}
                </p>
              </div>
              <div className="settings-row__control">
                <Switch
                  id={`${idPrefix}-show-taskbar`}
                  checked={prefs.showTaskbarIconWhenMinimized}
                  disabled={prefsDisabled}
                  ariaLabelledBy={showTaskbarLabelId}
                  ariaDescribedBy={showTaskbarDescId}
                  onChange={(checked) => {
                    void commitPreferences({
                      showTaskbarIconWhenMinimized: checked,
                    });
                  }}
                />
              </div>
            </div>
          ) : null}
        </div>

        <p className="settings-note">
          Closing or quitting the GUI does not stop the background vdpi service
          if installed.
        </p>
      </section>

      {/* 2. Background Service */}
      <section
        className="card card-flush settings-card"
        aria-labelledby={`${idPrefix}-service-heading`}
      >
        <div className="settings-card__header">
          <div className="settings-card__heading">
            <span className="settings-card__icon" aria-hidden="true">
              <IconShield size={16} />
            </span>
            <h2
              id={`${idPrefix}-service-heading`}
              className="settings-card__title"
            >
              Background Service
            </h2>
          </div>
          <span className={serviceInfo.badgeClass} data-service-state={serviceState ?? "loading"}>
            <span className="settings-badge__dot" aria-hidden="true" />
            {serviceInfo.label}
          </span>
        </div>

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">vdpi system service</span>
              <p className="settings-row__desc">
                Binary:{" "}
                <span className="mono tabular-nums">
                  {installedVersionDisplay}
                </span>
              </p>
            </div>

            <div className="settings-row__control">
              {serviceState === "not_installed" ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!status || serviceBusy !== null}
                  aria-busy={serviceBusy === "install"}
                  onClick={() => {
                    void handleInstallService();
                  }}
                >
                  {serviceBusy === "install" ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : null}
                  <span>
                    {serviceBusy === "install"
                      ? "Installing..."
                      : "Install Background Service"}
                  </span>
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-danger"
                  disabled={!status || serviceBusy !== null}
                  aria-busy={serviceBusy === "uninstall"}
                  onClick={() => setConfirmUninstallOpen(true)}
                >
                  {serviceBusy === "uninstall" ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : null}
                  <span>
                    {serviceBusy === "uninstall"
                      ? "Uninstalling..."
                      : "Uninstall Service"}
                  </span>
                </button>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* 3. Appearance */}
      <section
        className="card card-flush settings-card"
        aria-labelledby={`${idPrefix}-appearance-heading`}
      >
        <div className="settings-card__header">
          <div className="settings-card__heading">
            <span className="settings-card__icon" aria-hidden="true">
              <IconEye size={16} />
            </span>
            <h2
              id={`${idPrefix}-appearance-heading`}
              className="settings-card__title"
            >
              Appearance
            </h2>
          </div>
        </div>

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={themeLabelId} className="settings-row__label">
                Theme
              </span>
              <p className="settings-row__desc">
                Match your operating system theme or lock to dark or light mode.
              </p>
            </div>
            <div className="settings-row__control">
              <SegmentedControl<ThemePreference>
                id={`${idPrefix}-theme-control`}
                options={THEME_OPTIONS}
                value={prefs.theme}
                disabled={prefsDisabled}
                ariaLabelledBy={themeLabelId}
                onChange={(nextTheme) => {
                  void commitPreferences({ theme: nextTheme });
                }}
              />
            </div>
          </div>
        </div>
      </section>

      {/* 4. Updates & Local Data */}
      <section
        className="card card-flush settings-card"
        aria-labelledby={`${idPrefix}-updates-heading`}
      >
        <div className="settings-card__header">
          <div className="settings-card__heading">
            <span className="settings-card__icon" aria-hidden="true">
              <IconRefresh size={16} />
            </span>
            <h2
              id={`${idPrefix}-updates-heading`}
              className="settings-card__title"
            >
              Updates &amp; Local Data
            </h2>
          </div>
          <span className="settings-mono-value mono tabular-nums">
            {appVersionDisplay}
          </span>
        </div>

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">Desktop application</span>
              <p className="settings-row__desc">
                Current version{" "}
                <span className="mono tabular-nums">{appVersionDisplay}</span>
              </p>
            </div>
            <div className="settings-row__control">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={checkingUpdates}
                aria-busy={checkingUpdates}
                onClick={() => {
                  void handleCheckUpdates();
                }}
              >
                {checkingUpdates ? (
                  <span className="settings-spinner" aria-hidden="true" />
                ) : (
                  <IconRefresh size={14} />
                )}
                <span>
                  {checkingUpdates ? "Checking..." : "Check for Updates"}
                </span>
              </button>
            </div>
          </div>

          {updateResult ? (
            <div
              className={`settings-update-panel ${
                updateResult.hasUpdate
                  ? "settings-update-panel--available"
                  : "settings-update-panel--uptodate"
              }`}
              role="status"
              aria-live="polite"
            >
              <div className="settings-update-panel__top">
                <div className="settings-update-panel__status">
                  <span className="settings-update-panel__icon" aria-hidden="true">
                    {updateResult.hasUpdate ? (
                      <IconRefresh size={15} />
                    ) : (
                      <IconCheck size={15} />
                    )}
                  </span>
                  {updateResult.hasUpdate ? (
                    <span className="tabular-nums">
                      Update available:{" "}
                      <span className="mono">
                        {formatVersion(updateResult.latestVersion)}
                      </span>
                    </span>
                  ) : (
                    <span>Up to date</span>
                  )}
                </div>

                {updateResult.hasUpdate && safeReleaseUrl ? (
                  <button
                    type="button"
                    className="settings-update-link"
                    disabled={openingExternal}
                    aria-busy={openingExternal}
                    onClick={() => {
                      void handleOpenReleaseUrl(safeReleaseUrl);
                    }}
                  >
                    <span>View release</span>
                    <IconExternal size={13} />
                  </button>
                ) : null}
              </div>

              <p className="settings-update-panel__meta tabular-nums">
                {updateResult.hasUpdate ? (
                  <>
                    Installed{" "}
                    <span className="mono">
                      {formatVersion(updateResult.currentVersion)}
                    </span>{" "}
                    -&gt; latest{" "}
                    <span className="mono">
                      {formatVersion(updateResult.latestVersion)}
                    </span>
                  </>
                ) : (
                  <>
                    You are running the latest version (
                    <span className="mono">
                      {formatVersion(updateResult.currentVersion)}
                    </span>
                    ).
                  </>
                )}
              </p>

              {updateResult.hasUpdate && updateResult.releaseNotes.length > 0 ? (
                <ul className="settings-update-notes">
                  {updateResult.releaseNotes.map((note, idx) => (
                    <li key={`${idx}-${note}`}>{note}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}

          {updateError ? (
            <div
              className="settings-update-panel settings-update-panel--error"
              role="alert"
            >
              <div className="settings-update-panel__status">
                <span className="settings-update-panel__icon" aria-hidden="true">
                  <IconAlert size={15} />
                </span>
                <span>Update check failed</span>
              </div>
              <p className="settings-update-panel__meta">{updateError}</p>
            </div>
          ) : null}

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">Configuration folder</span>
              <p className="settings-row__desc">
                {isUnixSystemServiceConfig
                  ? "Contains config.toml for the background service (gui-prefs.json is stored separately in your user config folder)."
                  : "Contains config.toml and gui-prefs.json."}
              </p>
              {status?.configPath ? (
                <p
                  className="settings-row__path"
                  title={status.configPath}
                >
                  {status.configPath}
                </p>
              ) : null}
            </div>
            <div className="settings-row__control">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={openingFolder !== null}
                aria-busy={openingFolder === "config"}
                onClick={() => {
                  void handleOpenFolder("config");
                }}
              >
                <IconFolder size={14} />
                <span>Open Config Folder</span>
              </button>
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">Logs folder</span>
              <p className="settings-row__desc">
                Diagnostic logs written by the vdpi service and desktop app.
              </p>
              {status?.logsDir ? (
                <p className="settings-row__path" title={status.logsDir}>
                  {status.logsDir}
                </p>
              ) : null}
            </div>
            <div className="settings-row__control">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={openingFolder !== null}
                aria-busy={openingFolder === "logs"}
                onClick={() => {
                  void handleOpenFolder("logs");
                }}
              >
                <IconFolder size={14} />
                <span>Open Logs Folder</span>
              </button>
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">Desktop GUI</span>
              <p className="settings-row__desc">
                {isMac
                  ? "Exit the desktop window and remove any menu bar icon immediately."
                  : "Exit the desktop window and remove any tray icon immediately."}
              </p>
            </div>
            <div className="settings-row__control">
              <button
                type="button"
                className="btn btn-secondary"
                disabled={quitting}
                aria-busy={quitting}
                onClick={() => {
                  void handleQuitGui();
                }}
              >
                {quitting ? (
                  <span className="settings-spinner" aria-hidden="true" />
                ) : (
                  <IconPower size={14} />
                )}
                <span>{quitting ? "Quitting..." : "Quit GUI"}</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <ConfirmDialog
        open={confirmUninstallOpen}
        title="Uninstall background service?"
        description="This removes the vdpi system service and stops background protection. Your configuration and GUI preferences will remain on disk."
        confirmLabel={
          serviceBusy === "uninstall" ? "Uninstalling..." : "Uninstall Service"
        }
        cancelLabel="Cancel"
        danger
        busy={serviceBusy === "uninstall"}
        onConfirm={() => {
          void handleConfirmUninstall();
        }}
        onCancel={() => {
          if (serviceBusy !== "uninstall") {
            setConfirmUninstallOpen(false);
          }
        }}
      />
    </div>
  );
}

function areSettingsPropsEqual(
  prev: SettingsViewProps,
  next: SettingsViewProps,
): boolean {
  if (
    prev.settings !== next.settings ||
    prev.onPreferencesChanged !== next.onPreferencesChanged ||
    prev.onRefreshSettings !== next.onRefreshSettings ||
    prev.onServiceChanged !== next.onServiceChanged ||
    prev.onPushToast !== next.onPushToast
  ) {
    return false;
  }

  const prevStatus = prev.status;
  const nextStatus = next.status;
  if (prevStatus === nextStatus) {
    return true;
  }
  if (!prevStatus || !nextStatus) {
    return false;
  }

  return (
    prevStatus.platform === nextStatus.platform &&
    prevStatus.traySupported === nextStatus.traySupported &&
    prevStatus.serviceState === nextStatus.serviceState &&
    prevStatus.appVersion === nextStatus.appVersion &&
    prevStatus.installedVersion === nextStatus.installedVersion &&
    prevStatus.live?.version === nextStatus.live?.version &&
    prevStatus.configPath === nextStatus.configPath &&
    prevStatus.logsDir === nextStatus.logsDir
  );
}

export const SettingsView = memo(SettingsViewComponent, areSettingsPropsEqual);
SettingsView.displayName = "SettingsView";

export default SettingsView;
