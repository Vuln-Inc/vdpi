import { memo, useEffect, useId, useMemo, useRef, useState } from "react";
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
import { useLang, type ResolvedLanguage } from "../i18n/context";
import { tSettings } from "../i18n/settings";
import {
  LANGUAGE_STORAGE_KEY,
  localizeActionMessage,
  tShell,
} from "../i18n/shell";
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
  EngineMode,
  GuiPreferences,
  LanguagePreference,
  NavTab,
  ServiceState,
  ThemePreference,
  UpdateCheckPayload,
} from "../types";

export interface SettingsViewProps {
  status: DesktopStatusSnapshot | null;
  settings: DesktopSettingsPayload | null;
  busyAction?: string | null;
  updateInfo?: UpdateCheckPayload | null;
  checkingUpdates?: boolean;
  onCheckUpdates?: (manual?: boolean) => void | Promise<void>;
  onOpenReleaseUrl?: (url: string) => void | Promise<void>;
  onPreferencesPreview?: (prefs: GuiPreferences) => void;
  onPreferencesChanged: (prefs: GuiPreferences) => void | Promise<void>;
  onRefreshSettings?: () => void | Promise<unknown>;
  onServiceChanged: () => void | Promise<void>;
  onInstallService?: (engine?: EngineMode) => void | Promise<void>;
  onUpgradeService?: () => void | Promise<void>;
  onUninstallService?: () => void | Promise<void>;
  onResetNetwork?: () => void | Promise<void>;
  onNavigate?: (tab: NavTab) => void;
  onPushToast: (tone: ToastTone, message: string) => void;
  onModalOpenChange?: (open: boolean) => void;
}

const DEFAULT_GUI_PREFERENCES: GuiPreferences = {
  theme: "system",
  language: "system",
  keepInTrayOnClose: false,
  minimizeToTray: false,
  startMinimizedToTray: false,
  showTaskbarIconWhenMinimized: false,
};

function readStoredLanguage(): LanguagePreference | undefined {
  if (typeof window === "undefined") return undefined;
  try {
    const raw = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (raw === "system" || raw === "en" || raw === "tr") {
      return raw;
    }
  } catch {
    // Ignore storage access errors in restricted webviews.
  }
  return undefined;
}

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

:where(.settings-row-group) {
  display: flex;
  flex-direction: column;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
}

:where(.settings-row-group:last-child) {
  border-bottom: none;
}

:where(.settings-row-group > .settings-row) {
  border-bottom: none;
}

:where(.settings-row-group--expanded > .settings-row) {
  padding-bottom: 10px;
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

:where(.settings-badge--warn) {
  border-color: var(--status-amber-border, rgba(255, 159, 10, 0.28));
  background: var(--status-amber-bg, rgba(255, 159, 10, 0.12));
  color: var(--status-amber-fg, #FF9F0A);
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
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin: 0 16px 14px;
  padding: 11px 14px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--border-subtle, rgba(255, 255, 255, 0.1));
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.03));
  box-sizing: border-box;
}

:where(.settings-update-panel__body) {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.settings-update-panel__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px;
  height: 18px;
  margin-top: 1px;
  flex-shrink: 0;
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
  gap: 6px;
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-semibold, 600);
  line-height: 1.35;
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
  margin: 0;
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
  if (!version) return "-";
  const trimmed = version.trim();
  if (!trimmed) return "-";
  const bare = trimmed.replace(/^[vV]/, "");
  return bare ? `v${bare}` : "-";
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
  const validLang =
    candidate.language === undefined ||
    candidate.language === "system" ||
    candidate.language === "en" ||
    candidate.language === "tr";
  return (
    (candidate.theme === "system" ||
      candidate.theme === "dark" ||
      candidate.theme === "light") &&
    validLang &&
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

function formatServiceState(
  state: ServiceState | undefined,
  lang: ResolvedLanguage,
): {
  label: string;
  badgeClass: string;
} {
  switch (state) {
    case "running":
      return {
        label: tSettings(lang, "serviceStateRunning"),
        badgeClass: "settings-badge settings-badge--active",
      };
    case "stopped":
      return {
        label: tSettings(lang, "serviceStateStopped"),
        badgeClass: "settings-badge",
      };
    case "not_installed":
      return {
        label: tSettings(lang, "serviceStateNotInstalled"),
        badgeClass: "settings-badge",
      };
    default:
      return {
        label: tSettings(lang, "serviceStateChecking"),
        badgeClass: "settings-badge",
      };
  }
}

function SettingsViewComponent({
  status,
  settings,
  busyAction = null,
  updateInfo,
  checkingUpdates: checkingUpdatesProp,
  onCheckUpdates,
  onOpenReleaseUrl,
  onPreferencesPreview,
  onPreferencesChanged,
  onRefreshSettings,
  onServiceChanged,
  onInstallService,
  onUpgradeService,
  onUninstallService,
  onResetNetwork,
  onNavigate,
  onPushToast,
  onModalOpenChange,
}: SettingsViewProps) {
  const { lang } = useLang();
  const mountedRef = useRef(true);
  const savingPrefsRef = useRef(false);
  const serviceBusyRef = useRef(false);
  const checkingUpdatesRef = useRef(false);
  const openingFolderRef = useRef(false);
  const openingExternalRef = useRef(false);
  const quittingRef = useRef(false);

  const themeOptions = useMemo<readonly SegmentedOption<ThemePreference>[]>(
    () => [
      { value: "system", label: tSettings(lang, "themeSystem") },
      { value: "dark", label: tSettings(lang, "themeDark") },
      { value: "light", label: tSettings(lang, "themeLight") },
    ],
    [lang],
  );

  const languageOptions = useMemo<
    readonly SegmentedOption<LanguagePreference>[]
  >(
    () => [
      { value: "system", label: tSettings(lang, "languageSystem") },
      { value: "en", label: tSettings(lang, "languageEn") },
      { value: "tr", label: tSettings(lang, "languageTr") },
    ],
    [lang],
  );

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const idPrefix = useId();
  const [prefs, setPrefs] = useState<GuiPreferences>(() => ({
    ...DEFAULT_GUI_PREFERENCES,
    ...(settings?.gui ?? {}),
    language: settings?.gui?.language ?? readStoredLanguage() ?? "system",
  }));
  const confirmedPrefsRef = useRef<GuiPreferences>(prefs);
  const [savingPrefs, setSavingPrefs] = useState(false);

  const [serviceBusy, setServiceBusy] = useState<
    "install" | "upgrade" | "uninstall" | null
  >(null);
  const [confirmUninstallOpen, setConfirmUninstallOpen] = useState(false);

  const [localCheckingUpdates, setLocalCheckingUpdates] = useState(false);
  const [localUpdateResult, setLocalUpdateResult] =
    useState<UpdateCheckPayload | null>(null);
  const [updateError, setUpdateError] = useState<string | null>(null);

  const [openingFolder, setOpeningFolder] = useState<"config" | "logs" | null>(
    null,
  );
  const [openingExternal, setOpeningExternal] = useState(false);
  const [quitting, setQuitting] = useState(false);

  const checkingUpdates =
    checkingUpdatesProp !== undefined
      ? checkingUpdatesProp
      : localCheckingUpdates;
  const updateResult =
    updateInfo !== undefined ? updateInfo : localUpdateResult;

  useEffect(() => {
    if (!settings?.gui || savingPrefsRef.current) {
      return;
    }
    const merged: GuiPreferences = {
      ...settings.gui,
      language:
        settings.gui.language ??
        confirmedPrefsRef.current.language ??
        readStoredLanguage() ??
        "system",
    };
    setPrefs(merged);
    confirmedPrefsRef.current = merged;
  }, [settings?.gui]);

  const modalOpenRef = useRef(false);
  useEffect(() => {
    if (modalOpenRef.current !== confirmUninstallOpen) {
      modalOpenRef.current = confirmUninstallOpen;
      onModalOpenChange?.(confirmUninstallOpen);
    }
  }, [confirmUninstallOpen, onModalOpenChange]);

  useEffect(() => {
    return () => {
      if (modalOpenRef.current) {
        modalOpenRef.current = false;
        onModalOpenChange?.(false);
      }
    };
  }, [onModalOpenChange]);

  const prefsDisabled = !settings || savingPrefs;
  const isMac = status?.platform === "macos";
  const isLinux = status?.platform === "linux";
  const traySupported = status?.traySupported !== false;
  const showLinuxTrayNotice = isLinux && !traySupported;
  const trayPresenceEnabled =
    prefs.keepInTrayOnClose ||
    prefs.minimizeToTray ||
    prefs.startMinimizedToTray;
  const trayEffectivelyActive = trayPresenceEnabled && traySupported;
  const trayUnavailable = trayPresenceEnabled && !traySupported;
  const showMinimizedIconToggle =
    prefs.minimizeToTray || prefs.startMinimizedToTray;

  const serviceState = status?.serviceState;
  const serviceInfo = formatServiceState(serviceState, lang);

  useEffect(() => {
    if (serviceState === "not_installed" && confirmUninstallOpen) {
      setConfirmUninstallOpen(false);
    }
  }, [confirmUninstallOpen, serviceState]);

  const configuredEngine: EngineMode =
    status?.configuredEngine ?? settings?.engine ?? "tun";
  const wintunMissing = Boolean(
    status?.platform === "windows" &&
      status.wintun.required &&
      !status.wintun.ready,
  );
  const installBlockedByWintun = wintunMissing && configuredEngine === "tun";
  const bundleMissing = status?.canInstallFromBundle === false;
  const isRepairNeeded = Boolean(
    status &&
      serviceState !== "not_installed" &&
      status.cliVersionRelation === "repair_needed",
  );
  const normalizedBusy = busyAction?.trim().toLowerCase() ?? null;
  const isCentralBusy = normalizedBusy !== null;
  const isInstalling =
    serviceBusy === "install" ||
    normalizedBusy === "install-service" ||
    status?.pendingOperation === "installing";
  const isUpgrading =
    serviceBusy === "upgrade" ||
    normalizedBusy === "upgrade-service" ||
    status?.pendingOperation === "upgrading";
  const isUninstalling =
    serviceBusy === "uninstall" ||
    normalizedBusy === "uninstall-service" ||
    status?.pendingOperation === "uninstalling";
  const isResettingNetwork =
    normalizedBusy === "reset-network" ||
    normalizedBusy === "resetting_network" ||
    status?.pendingOperation === "resetting_network";
  const anyServiceBusy =
    serviceBusy !== null ||
    isCentralBusy ||
    isResettingNetwork ||
    Boolean(status?.pendingOperation);
  const showUpgradeAction = Boolean(
    onUpgradeService &&
      status &&
      serviceState !== "not_installed" &&
      status.cliVersionRelation === "upgrade_available",
  );
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
      ? tSettings(lang, "serviceVersionNotInstalled")
      : installedVersionRaw
        ? formatVersion(installedVersionRaw)
        : status
          ? tSettings(lang, "serviceVersionUnknown")
          : "-";

  const appVersionDisplay = status?.appVersion
    ? formatVersion(status.appVersion)
    : "v-";

  const commitPreferences = async (patch: Partial<GuiPreferences>) => {
    if (savingPrefsRef.current) return;
    savingPrefsRef.current = true;
    const previous = confirmedPrefsRef.current;
    const next: GuiPreferences = { ...previous, ...patch };

    setPrefs(next);
    onPreferencesPreview?.(next);
    setSavingPrefs(true);
    try {
      const response: unknown = await saveGuiPreferences(next);
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
        const refreshedGui =
          refreshed && typeof refreshed === "object" && "gui" in refreshed
            ? (refreshed as { gui?: unknown }).gui
            : undefined;
        if (isGuiPreferences(refreshedGui)) {
          const mergedPersisted: GuiPreferences = {
            ...refreshedGui,
            language: refreshedGui.language ?? previous.language ?? "system",
          };
          confirmedPrefsRef.current = mergedPersisted;
          if (mountedRef.current) {
            setPrefs(mergedPersisted);
          }
          onPreferencesPreview?.(mergedPersisted);
        } else {
          confirmedPrefsRef.current = previous;
          if (mountedRef.current) {
            setPrefs(previous);
          }
          onPreferencesPreview?.(previous);
        }
        if (action.code === "shutting_down" || action.code === "busy") {
          onPushToast(
            "info",
            tShell(
              lang,
              action.code === "shutting_down"
                ? "actionShuttingDown"
                : "actionBusy",
            ),
          );
        } else {
          onPushToast(
            "error",
            localizeActionMessage(
              lang,
              scrubUrlsInText(
                action.message?.trim() || tSettings(lang, "savePrefsFailed"),
              ),
            ),
          );
        }
        return;
      }
      const resolved: GuiPreferences = isGuiPreferences(response)
        ? { ...response, language: response.language ?? next.language }
        : next;
      confirmedPrefsRef.current = resolved;
      if (mountedRef.current) {
        setPrefs(resolved);
      }
      await onPreferencesChanged(resolved);
    } catch (err) {
      confirmedPrefsRef.current = previous;
      if (mountedRef.current) {
        setPrefs(previous);
      }
      onPreferencesPreview?.(previous);
      onPushToast(
        "error",
        localizeActionMessage(
          lang,
          getErrorMessage(err, tSettings(lang, "savePrefsFailed")),
        ),
      );
    } finally {
      savingPrefsRef.current = false;
      if (mountedRef.current) {
        setSavingPrefs(false);
      }
    }
  };

  const handleInstallService = async () => {
    if (serviceBusyRef.current || anyServiceBusy || installBlockedByWintun) {
      return;
    }
    serviceBusyRef.current = true;
    setServiceBusy("install");
    if (onInstallService) {
      try {
        await onInstallService(configuredEngine);
      } finally {
        serviceBusyRef.current = false;
        if (mountedRef.current) {
          setServiceBusy(null);
        }
      }
      return;
    }
    try {
      const response: unknown = await installService();
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action?.cancelled) {
        onPushToast(
          "info",
          localizeActionMessage(
            lang,
            action.message?.trim() || tSettings(lang, "installCancelled"),
          ),
        );
        return;
      }
      if (action && !action.ok) {
        throw new Error(action.message || tSettings(lang, "installFailed"));
      }
      await onServiceChanged();
      if (!mountedRef.current) return;
      onPushToast(
        "success",
        localizeActionMessage(
          lang,
          action?.message?.trim() || tSettings(lang, "installSuccess"),
        ),
      );
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          localizeActionMessage(
            lang,
            getErrorMessage(err, tSettings(lang, "installFailed")),
          ),
        );
      }
    } finally {
      serviceBusyRef.current = false;
      if (mountedRef.current) {
        setServiceBusy(null);
      }
    }
  };

  const handleUpgradeService = async () => {
    if (serviceBusyRef.current || anyServiceBusy || !onUpgradeService) return;
    serviceBusyRef.current = true;
    setServiceBusy("upgrade");
    try {
      await onUpgradeService();
    } finally {
      serviceBusyRef.current = false;
      if (mountedRef.current) {
        setServiceBusy(null);
      }
    }
  };

  const handleConfirmUninstall = async () => {
    if (serviceBusyRef.current || anyServiceBusy) return;
    serviceBusyRef.current = true;
    setServiceBusy("uninstall");
    if (onUninstallService) {
      try {
        await onUninstallService();
        if (mountedRef.current) {
          setConfirmUninstallOpen(false);
        }
      } finally {
        serviceBusyRef.current = false;
        if (mountedRef.current) {
          setServiceBusy(null);
        }
      }
      return;
    }
    try {
      const response: unknown = await uninstallService();
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action?.cancelled) {
        setConfirmUninstallOpen(false);
        onPushToast(
          "info",
          localizeActionMessage(
            lang,
            action.message?.trim() || tSettings(lang, "uninstallCancelled"),
          ),
        );
        return;
      }
      if (action && !action.ok) {
        throw new Error(action.message || tSettings(lang, "uninstallFailed"));
      }
      setConfirmUninstallOpen(false);
      await onServiceChanged();
      if (!mountedRef.current) return;
      onPushToast(
        "success",
        localizeActionMessage(
          lang,
          action?.message?.trim() || tSettings(lang, "uninstallSuccess"),
        ),
      );
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          localizeActionMessage(
            lang,
            getErrorMessage(err, tSettings(lang, "uninstallFailed")),
          ),
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
    if (checkingUpdatesRef.current || checkingUpdates) return;
    checkingUpdatesRef.current = true;
    setUpdateError(null);
    if (onCheckUpdates) {
      if (checkingUpdatesProp === undefined) {
        setLocalCheckingUpdates(true);
      }
      try {
        await onCheckUpdates(true);
      } catch (err) {
        if (!mountedRef.current) return;
        const message = getErrorMessage(
          err,
          tSettings(lang, "checkUpdatesFailed"),
        );
        setUpdateError(message);
        onPushToast("error", message);
      } finally {
        checkingUpdatesRef.current = false;
        if (mountedRef.current && checkingUpdatesProp === undefined) {
          setLocalCheckingUpdates(false);
        }
      }
      return;
    }

    setLocalCheckingUpdates(true);
    try {
      const result = await checkUpdates(true);
      if (!mountedRef.current) return;
      setLocalUpdateResult(result);
    } catch (err) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(
        err,
        tSettings(lang, "checkUpdatesFailed"),
      );
      setLocalUpdateResult(null);
      setUpdateError(message);
      onPushToast("error", message);
    } finally {
      checkingUpdatesRef.current = false;
      if (mountedRef.current) {
        setLocalCheckingUpdates(false);
      }
    }
  };

  const handleOpenReleaseUrl = async (url: string) => {
    if (openingExternalRef.current) return;
    openingExternalRef.current = true;
    setOpeningExternal(true);
    if (onOpenReleaseUrl) {
      try {
        await onOpenReleaseUrl(url);
      } catch (err) {
        if (mountedRef.current) {
          onPushToast(
            "error",
            localizeActionMessage(
              lang,
              getErrorMessage(err, tSettings(lang, "openReleaseFailed")),
            ),
          );
        }
      } finally {
        openingExternalRef.current = false;
        if (mountedRef.current) {
          setOpeningExternal(false);
        }
      }
      return;
    }

    try {
      const response: unknown = await openExternalUrl(url);
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        throw new Error(action.message || tSettings(lang, "openReleaseFailed"));
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          localizeActionMessage(
            lang,
            getErrorMessage(err, tSettings(lang, "openReleaseFailed")),
          ),
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
    const folderFailMsg =
      kind === "config"
        ? tSettings(lang, "openConfigFolderFailed")
        : tSettings(lang, "openLogsFolderFailed");
    try {
      const response: unknown = await openAppFolder(kind);
      if (!mountedRef.current) return;
      const action = asActionResult(response);
      if (action && !action.ok) {
        throw new Error(action.message || folderFailMsg);
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          localizeActionMessage(lang, getErrorMessage(err, folderFailMsg)),
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
          localizeActionMessage(
            lang,
            action.message?.trim() || tSettings(lang, "quitGuiFailed"),
          ),
        );
        setQuitting(false);
        quittingRef.current = false;
        return;
      }
      if (!isTauriRuntime()) {
        if (action?.message?.trim()) {
          onPushToast(
            "info",
            localizeActionMessage(lang, action.message.trim()),
          );
        }
        setQuitting(false);
        quittingRef.current = false;
      }
    } catch (err) {
      if (mountedRef.current) {
        onPushToast(
          "error",
          localizeActionMessage(
            lang,
            getErrorMessage(err, tSettings(lang, "quitGuiFailed")),
          ),
        );
        setQuitting(false);
      }
      quittingRef.current = false;
    }
  };

  const safeReleaseUrl = sanitizeExternalUrl(updateResult?.releaseUrl);
  const cleanedReleaseNotes = useMemo(
    () =>
      (updateResult?.releaseNotes ?? [])
        .map((note) =>
          scrubUrlsInText(note.trim().replace(/^[-*•]\s+/, "").trim()),
        )
        .filter((note) => note.length > 0),
    [updateResult?.releaseNotes],
  );

  const keepInTrayLabelId = `${idPrefix}-keep-in-tray-label`;
  const keepInTrayDescId = `${idPrefix}-keep-in-tray-desc`;
  const minimizeToTrayLabelId = `${idPrefix}-minimize-to-tray-label`;
  const minimizeToTrayDescId = `${idPrefix}-minimize-to-tray-desc`;
  const showTaskbarLabelId = `${idPrefix}-show-taskbar-label`;
  const showTaskbarDescId = `${idPrefix}-show-taskbar-desc`;
  const startMinimizedLabelId = `${idPrefix}-start-minimized-label`;
  const startMinimizedDescId = `${idPrefix}-start-minimized-desc`;
  const themeLabelId = `${idPrefix}-theme-label`;
  const languageLabelId = `${idPrefix}-language-label`;

  return (
    <div className="view-stack view-settings">
      <header className="view-header">
        <div className="view-header-text">
          <h1 className="view-title">{tSettings(lang, "title")}</h1>
          <p className="view-subtitle">
            {isMac
              ? tSettings(lang, "subtitleMac")
              : tSettings(lang, "subtitleDefault")}
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
              {isMac
                ? tSettings(lang, "trayHeadingMac")
                : tSettings(lang, "trayHeadingDefault")}
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
              ? tSettings(lang, "trayBadgeUnavailable")
              : isMac
                ? trayEffectivelyActive
                  ? tSettings(lang, "trayBadgeMenuBarActive")
                  : tSettings(lang, "trayBadgeNoMenuBarIcon")
                : trayEffectivelyActive
                  ? tSettings(lang, "trayBadgeActive")
                  : tSettings(lang, "trayBadgeNoIcon")}
          </span>
        </div>

        {showLinuxTrayNotice ? (
          <p className="settings-info-notice" role="status">
            {tSettings(lang, "linuxTrayNotice")}
          </p>
        ) : null}

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={keepInTrayLabelId} className="settings-row__label">
                {isMac
                  ? tSettings(lang, "keepInTrayLabelMac")
                  : tSettings(lang, "keepInTrayLabelDefault")}
              </span>
              <p id={keepInTrayDescId} className="settings-row__desc">
                {prefs.keepInTrayOnClose
                  ? isMac
                    ? tSettings(lang, "keepInTrayDescOnMac")
                    : tSettings(lang, "keepInTrayDescOnDefault")
                  : isMac
                    ? tSettings(lang, "keepInTrayDescOffMac")
                    : tSettings(lang, "keepInTrayDescOffDefault")}
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
                {isMac
                  ? tSettings(lang, "minimizeToTrayLabelMac")
                  : tSettings(lang, "minimizeToTrayLabelDefault")}
              </span>
              <p id={minimizeToTrayDescId} className="settings-row__desc">
                {isMac
                  ? tSettings(lang, "minimizeToTrayDescMac")
                  : tSettings(lang, "minimizeToTrayDescDefault")}
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
                  ? tSettings(lang, "startMinimizedLabelMac")
                  : tSettings(lang, "startMinimizedLabelDefault")}
              </span>
              <p id={startMinimizedDescId} className="settings-row__desc">
                {isMac
                  ? tSettings(lang, "startMinimizedDescMac")
                  : tSettings(lang, "startMinimizedDescDefault")}
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
                    ? tSettings(lang, "showTaskbarLabelMac")
                    : tSettings(lang, "showTaskbarLabelDefault")}
                </span>
                <p id={showTaskbarDescId} className="settings-row__desc">
                  {isMac
                    ? tSettings(lang, "showTaskbarDescMac")
                    : tSettings(lang, "showTaskbarDescDefault")}
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

        <p className="settings-note">{tSettings(lang, "trayFooterNote")}</p>
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
              {tSettings(lang, "serviceHeading")}
            </h2>
          </div>
          <div className="settings-actions-group">
            {isRepairNeeded ? (
              <span
                className="settings-badge settings-badge--warn"
                data-cli-relation="repair_needed"
              >
                <span className="settings-badge__dot" aria-hidden="true" />
                {tSettings(lang, "badgeRepairNeeded")}
              </span>
            ) : null}
            <span
              className={serviceInfo.badgeClass}
              data-service-state={serviceState ?? "loading"}
            >
              <span className="settings-badge__dot" aria-hidden="true" />
              {serviceInfo.label}
            </span>
          </div>
        </div>

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">
                {tSettings(lang, "serviceRowLabel")}
              </span>
              <p className="settings-row__desc">
                {tSettings(lang, "serviceBinaryPrefix")}{" "}
                <span className="mono tabular-nums">
                  {installedVersionDisplay}
                </span>
              </p>
            </div>

            <div className="settings-row__control settings-actions-group">
              {onNavigate ? (
                <button
                  type="button"
                  className={isRepairNeeded ? "btn btn-primary" : "btn btn-secondary"}
                  disabled={anyServiceBusy}
                  onClick={() => onNavigate("installation")}
                >
                  <span>
                    {tSettings(
                      lang,
                      isRepairNeeded
                        ? "btnRepairInInstallation"
                        : "btnOpenInstallation",
                    )}
                  </span>
                </button>
              ) : null}
              {showUpgradeAction ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={
                    !status ||
                    anyServiceBusy ||
                    bundleMissing
                  }
                  aria-busy={isUpgrading}
                  onClick={() => {
                    void handleUpgradeService();
                  }}
                >
                  {isUpgrading ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : null}
                  <span>
                    {isUpgrading
                      ? tSettings(lang, "btnUpdatingEngine")
                      : tSettings(lang, "btnUpdateEngine")}
                  </span>
                </button>
              ) : null}
              {serviceState === "not_installed" ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={
                    !status ||
                    anyServiceBusy ||
                    installBlockedByWintun ||
                    bundleMissing
                  }
                  aria-busy={isInstalling}
                  onClick={() => {
                    void handleInstallService();
                  }}
                >
                  {isInstalling ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : null}
                  <span>
                    {isInstalling
                      ? tSettings(lang, "btnInstalling")
                      : tSettings(lang, "btnInstallService")}
                  </span>
                </button>
              ) : (
                <button
                  type="button"
                  className="btn btn-danger"
                  disabled={!status || anyServiceBusy}
                  aria-busy={isUninstalling}
                  onClick={() => setConfirmUninstallOpen(true)}
                >
                  {isUninstalling ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : null}
                  <span>
                    {isUninstalling
                      ? tSettings(lang, "btnUninstalling")
                      : tSettings(lang, "btnUninstallService")}
                  </span>
                </button>
              )}
            </div>
          </div>
        </div>
        {isRepairNeeded ? (
          <p className="settings-note">
            {tSettings(lang, "serviceRepairNeededNote")}
          </p>
        ) : null}
        {bundleMissing ? (
          <p className="settings-note">
            {tSettings(lang, "serviceBundleMissingNote")}
          </p>
        ) : null}
        {serviceState === "not_installed" && installBlockedByWintun ? (
          <p className="settings-note">
            {tSettings(lang, "serviceWintunMissingNote")}
          </p>
        ) : null}
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
              {tSettings(lang, "appearanceHeading")}
            </h2>
          </div>
        </div>

        <div className="settings-list">
          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={themeLabelId} className="settings-row__label">
                {tSettings(lang, "themeLabel")}
              </span>
              <p className="settings-row__desc">
                {tSettings(lang, "themeDesc")}
              </p>
            </div>
            <div className="settings-row__control">
              <SegmentedControl<ThemePreference>
                id={`${idPrefix}-theme-control`}
                options={themeOptions}
                value={prefs.theme}
                disabled={prefsDisabled}
                ariaLabelledBy={themeLabelId}
                onChange={(nextTheme) => {
                  void commitPreferences({ theme: nextTheme });
                }}
              />
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span id={languageLabelId} className="settings-row__label">
                {tSettings(lang, "languageLabel")}
              </span>
              <p className="settings-row__desc">
                {tSettings(lang, "languageDesc")}
              </p>
            </div>
            <div className="settings-row__control">
              <SegmentedControl<LanguagePreference>
                id={`${idPrefix}-language-control`}
                options={languageOptions}
                value={prefs.language ?? "system"}
                disabled={prefsDisabled}
                ariaLabelledBy={languageLabelId}
                onChange={(nextLanguage) => {
                  void commitPreferences({ language: nextLanguage });
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
              {tSettings(lang, "updatesHeading")}
            </h2>
          </div>
          <span className="settings-mono-value mono tabular-nums">
            {appVersionDisplay}
          </span>
        </div>

        <div className="settings-list">
          <div
            className={`settings-row-group${
              updateResult || updateError ? " settings-row-group--expanded" : ""
            }`}
          >
            <div className="settings-row">
              <div className="settings-row__copy">
                <span className="settings-row__label">
                  {tSettings(lang, "desktopAppLabel")}
                </span>
                <p className="settings-row__desc">
                  {tSettings(lang, "currentVersionPrefix")}{" "}
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
                    {checkingUpdates
                      ? tSettings(lang, "btnCheckingUpdates")
                      : tSettings(lang, "btnCheckUpdates")}
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
                <span
                  className="settings-update-panel__icon"
                  aria-hidden="true"
                >
                  {updateResult.hasUpdate ? (
                    <IconRefresh size={15} />
                  ) : (
                    <IconCheck size={15} />
                  )}
                </span>
                <div className="settings-update-panel__body">
                  <div className="settings-update-panel__top">
                    <div className="settings-update-panel__status">
                      {updateResult.hasUpdate ? (
                        <span className="tabular-nums">
                          {tSettings(lang, "updateAvailablePrefix")}{" "}
                          <span className="mono">
                            {formatVersion(updateResult.latestVersion)}
                          </span>
                        </span>
                      ) : (
                        <span>{tSettings(lang, "upToDate")}</span>
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
                        <span>{tSettings(lang, "viewRelease")}</span>
                        <IconExternal size={13} />
                      </button>
                    ) : null}
                  </div>

                  <p className="settings-update-panel__meta tabular-nums">
                    {updateResult.hasUpdate ? (
                      <>
                        {tSettings(lang, "installedPrefix")}{" "}
                        <span className="mono">
                          {formatVersion(updateResult.currentVersion)}
                        </span>{" "}
                        -&gt; {tSettings(lang, "latestPrefix")}{" "}
                        <span className="mono">
                          {formatVersion(updateResult.latestVersion)}
                        </span>
                      </>
                    ) : (
                      <>
                        {tSettings(lang, "runningLatestBefore")}
                        <span className="mono">
                          {formatVersion(updateResult.currentVersion)}
                        </span>
                        {tSettings(lang, "runningLatestAfter")}
                      </>
                    )}
                  </p>

                  {updateResult.hasUpdate && cleanedReleaseNotes.length > 0 ? (
                    <ul className="settings-update-notes">
                      {cleanedReleaseNotes.map((note, idx) => (
                        <li key={`${idx}-${note}`}>{note}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              </div>
            ) : null}

            {updateError ? (
              <div
                className="settings-update-panel settings-update-panel--error"
                role="alert"
              >
                <span className="settings-update-panel__icon" aria-hidden="true">
                  <IconAlert size={15} />
                </span>
                <div className="settings-update-panel__body">
                  <div className="settings-update-panel__status">
                    <span>{tSettings(lang, "updateCheckFailed")}</span>
                  </div>
                  <p className="settings-update-panel__meta">{updateError}</p>
                </div>
              </div>
            ) : null}
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">
                {tSettings(lang, "configFolderLabel")}
              </span>
              <p className="settings-row__desc">
                {isUnixSystemServiceConfig
                  ? tSettings(lang, "configFolderDescUnix")
                  : tSettings(lang, "configFolderDescDefault")}
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
                <span>{tSettings(lang, "btnOpenConfigFolder")}</span>
              </button>
            </div>
          </div>

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">
                {tSettings(lang, "logsFolderLabel")}
              </span>
              <p className="settings-row__desc">
                {tSettings(lang, "logsFolderDesc")}
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
                <span>{tSettings(lang, "btnOpenLogsFolder")}</span>
              </button>
            </div>
          </div>

          {onResetNetwork ? (
            <div className="settings-row">
              <div className="settings-row__copy">
                <span className="settings-row__label">
                  {tSettings(lang, "resetNetworkLabel")}
                </span>
                <p className="settings-row__desc">
                  {tSettings(lang, "resetNetworkDesc")}
                </p>
              </div>
              <div className="settings-row__control">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={anyServiceBusy}
                  aria-busy={isResettingNetwork}
                  onClick={() => {
                    void onResetNetwork();
                  }}
                >
                  {isResettingNetwork ? (
                    <span className="settings-spinner" aria-hidden="true" />
                  ) : (
                    <IconRefresh size={14} />
                  )}
                  <span>
                    {isResettingNetwork
                      ? tSettings(lang, "btnResettingNetwork")
                      : tSettings(lang, "btnResetNetwork")}
                  </span>
                </button>
              </div>
            </div>
          ) : null}

          <div className="settings-row">
            <div className="settings-row__copy">
              <span className="settings-row__label">
                {tSettings(lang, "desktopGuiLabel")}
              </span>
              <p className="settings-row__desc">
                {isMac
                  ? tSettings(lang, "desktopGuiDescMac")
                  : tSettings(lang, "desktopGuiDescDefault")}
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
                <span>
                  {quitting
                    ? tSettings(lang, "btnQuitting")
                    : tSettings(lang, "btnQuitGui")}
                </span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <ConfirmDialog
        open={confirmUninstallOpen}
        title={tSettings(lang, "uninstallTitle")}
        description={tSettings(lang, "uninstallDesc")}
        confirmLabel={
          isUninstalling
            ? tSettings(lang, "btnUninstalling")
            : tSettings(lang, "btnUninstallService")
        }
        cancelLabel={tSettings(lang, "cancel")}
        danger
        busy={isUninstalling}
        onConfirm={() => {
          void handleConfirmUninstall();
        }}
        onCancel={() => {
          if (!isUninstalling) {
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
    prev.busyAction !== next.busyAction ||
    prev.updateInfo !== next.updateInfo ||
    prev.checkingUpdates !== next.checkingUpdates ||
    prev.onCheckUpdates !== next.onCheckUpdates ||
    prev.onOpenReleaseUrl !== next.onOpenReleaseUrl ||
    prev.onPreferencesPreview !== next.onPreferencesPreview ||
    prev.onPreferencesChanged !== next.onPreferencesChanged ||
    prev.onRefreshSettings !== next.onRefreshSettings ||
    prev.onServiceChanged !== next.onServiceChanged ||
    prev.onInstallService !== next.onInstallService ||
    prev.onUpgradeService !== next.onUpgradeService ||
    prev.onUninstallService !== next.onUninstallService ||
    prev.onResetNetwork !== next.onResetNetwork ||
    prev.onNavigate !== next.onNavigate ||
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
    prevStatus.configuredEngine === nextStatus.configuredEngine &&
    prevStatus.appVersion === nextStatus.appVersion &&
    prevStatus.installedVersion === nextStatus.installedVersion &&
    prevStatus.bundledEngineVersion === nextStatus.bundledEngineVersion &&
    prevStatus.cliVersionRelation === nextStatus.cliVersionRelation &&
    prevStatus.canInstallFromBundle === nextStatus.canInstallFromBundle &&
    prevStatus.pendingOperation === nextStatus.pendingOperation &&
    prevStatus.wintun.required === nextStatus.wintun.required &&
    prevStatus.wintun.ready === nextStatus.wintun.ready &&
    prevStatus.live?.version === nextStatus.live?.version &&
    prevStatus.configPath === nextStatus.configPath &&
    prevStatus.logsDir === nextStatus.logsDir
  );
}

export const SettingsView = memo(SettingsViewComponent, areSettingsPropsEqual);
SettingsView.displayName = "SettingsView";

export default SettingsView;
