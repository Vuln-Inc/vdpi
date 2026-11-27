import {
  memo,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { ConfirmDialog } from "../components/ConfirmDialog";
import {
  IconAlert,
  IconCheck,
  IconChevron,
  IconClose,
  IconDiagnostics,
  IconExternal,
  IconFolder,
  IconRefresh,
  IconShield,
  IconTrash,
} from "../components/Icons";
import { InlineBanner } from "../components/InlineBanner";
import { useLang } from "../i18n/context";
import { tInstallation } from "../i18n/installation";
import { compareSemver, scrubUrlsInText } from "../lib/format";
import type {
  CliVersionRelation,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  EngineMode,
  NavTab,
  UpdateCheckPayload,
} from "../types";

export interface InstallationViewProps {
  status: DesktopStatusSnapshot | null;
  settings: DesktopSettingsPayload | null;
  updateInfo: UpdateCheckPayload | null;
  checkingUpdates: boolean;
  busyAction: string | null;
  installError: {
    message: string;
    kind: "cancelled" | "wintun" | "antivirus" | "generic";
    attemptedEngine?: EngineMode;
  } | null;
  onInstallService: (engine: EngineMode) => void | Promise<void>;
  onSwitchEngine?: (engine: EngineMode) => void | Promise<void>;
  onUpgradeService: () => void | Promise<void>;
  onRepairService: (engine?: EngineMode) => void | Promise<void>;
  onUninstallService: () => void | Promise<void>;
  onCheckUpdates: (manual?: boolean) => void | Promise<void>;
  onOpenReleaseUrl: (url: string) => void | Promise<void>;
  onOpenAppFolder: (target: "config" | "logs" | "app") => void | Promise<void>;
  onRefreshStatus: () => void | Promise<void>;
  onClearInstallError: () => void;
  onNavigate: (tab: NavTab) => void;
}

const STYLE_ID = "vdpi-installation-view-styles";

const SCOPED_STYLES = `
@keyframes vdpi-install-indeterminate {
  0% {
    transform: translateX(-100%);
  }
  100% {
    transform: translateX(260%);
  }
}

:where(.view-installation) {
  display: flex;
  flex-direction: column;
  gap: var(--space-4, 16px);
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

:where(.install-card) {
  display: flex;
  flex-direction: column;
  background: var(--bg-surface, #131518);
  border: 1px solid var(--border-subtle, rgba(255, 255, 255, 0.1));
  border-radius: var(--radius-lg, 10px);
  overflow: hidden;
  min-width: 0;
  box-sizing: border-box;
}

:where([data-theme="light"] .install-card) {
  box-shadow: var(--shadow-sm, 0 1px 2px rgba(11, 12, 14, 0.05));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .install-card) {
    box-shadow: var(--shadow-sm, 0 1px 2px rgba(11, 12, 14, 0.05));
  }
}

:where(.install-card__header) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3, 12px);
  padding: 13px 16px;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  min-width: 0;
  flex-wrap: wrap;
}

:where(.install-card__heading) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

:where(.install-card__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--ink-secondary, #A1A6B0);
  flex-shrink: 0;
}

:where(.install-card__title) {
  margin: 0;
  font-size: var(--text-md, 14px);
  font-weight: var(--weight-semibold, 600);
  line-height: var(--leading-md, 20px);
  letter-spacing: -0.01em;
  color: var(--ink-primary, #F3F4F6);
}

:where(.install-card__body) {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 14px 16px;
  min-width: 0;
}

:where(.install-card__subtitle) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

:where(.install-card__footer) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
  padding: 12px 16px;
  border-top: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.02));
}

:where(.install-actions-group) {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  min-width: 0;
}

/* Release update card internals */
:where(.install-release-version) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-family: var(--font-mono, ui-monospace, monospace);
  font-size: var(--text-sm, 12px);
  font-weight: var(--weight-medium, 500);
  color: var(--ink-primary, #F3F4F6);
  font-variant-numeric: tabular-nums;
}

:where(.install-release-notes) {
  margin: 0;
  padding-left: 18px;
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: var(--text-sm, 12px);
  line-height: var(--leading-sm, 18px);
  color: var(--ink-secondary, #A1A6B0);
}

/* Engine mode 2-column radiogroup */
:where(.install-mode-grid) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  width: 100%;
  min-width: 0;
}

:where(.install-mode-card) {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  padding: 12px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--border-subtle, rgba(255, 255, 255, 0.1));
  background: var(--bg-surface, #131518);
  color: var(--ink-primary, #F3F4F6);
  text-align: left;
  cursor: pointer;
  min-width: 0;
  box-sizing: border-box;
  font: inherit;
  transition: var(--transition-colors, color 120ms ease, background-color 120ms ease, border-color 120ms ease);
}

:where(.install-mode-card:hover:not(:disabled)) {
  background: var(--bg-surface-hover, #21252D);
  border-color: var(--border-strong, rgba(255, 255, 255, 0.22));
}

:where(.install-mode-card[aria-checked="true"]) {
  background: var(--accent-subtle, rgba(59, 130, 246, 0.14));
  border-color: var(--accent-border, rgba(59, 130, 246, 0.32));
}

:where(.install-mode-card[aria-checked="true"]:hover:not(:disabled)) {
  background: var(--accent-subtle-hover, rgba(59, 130, 246, 0.2));
  border-color: var(--accent-border, rgba(59, 130, 246, 0.32));
}

:where(.install-mode-card:focus-visible) {
  outline: var(--focus-ring-width, 2px) solid var(--focus-ring-color, #60A5FA);
  outline-offset: var(--focus-ring-offset, 2px);
}

:where(.install-mode-card:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.install-mode-card__top) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  width: 100%;
  min-width: 0;
}

:where(.install-mode-card__title-wrap) {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}

:where(.install-mode-card__radio) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 14px;
  height: 14px;
  border-radius: 9999px;
  border: 1.5px solid var(--border-control, #5E687B);
  flex-shrink: 0;
  box-sizing: border-box;
}

:where(.install-mode-card[aria-checked="true"] .install-mode-card__radio) {
  border-color: var(--accent, #2563EB);
}

:where(.install-mode-card[aria-checked="true"] .install-mode-card__radio::after) {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 9999px;
  background: var(--accent, #2563EB);
}

:where(.install-mode-card__title) {
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-semibold, 600);
  line-height: 1.3;
  color: var(--ink-primary, #F3F4F6);
  white-space: nowrap;
}

:where(.install-mode-card__desc) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: 1.45;
  color: var(--ink-secondary, #A1A6B0);
}

:where(.install-elevation-note) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: 1.45;
  color: var(--ink-tertiary, #949BA8);
}

/* Wintun missing strip */
:where(.install-callout) {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 11px 13px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--border-subtle, rgba(255, 255, 255, 0.1));
  background: var(--bg-surface-subtle, #171A1F);
  min-width: 0;
  box-sizing: border-box;
}

:where(.install-callout--accent) {
  border-color: var(--accent-border, rgba(59, 130, 246, 0.32));
  background: var(--accent-subtle, rgba(59, 130, 246, 0.14));
}

:where(.install-callout--warn) {
  border-color: var(--status-warning-border, rgba(255, 159, 10, 0.28));
  border-left: 3px solid var(--status-amber, #FF9F0A);
  background: var(--status-warning-bg, rgba(255, 159, 10, 0.12));
}

:where(.install-callout--info) {
  border-color: var(--border-default, rgba(255, 255, 255, 0.14));
  border-left: 3px solid var(--accent, #2563EB);
  background: var(--bg-surface-subtle, #171A1F);
}

:where(.install-callout__head) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}

:where(.install-callout__copy) {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  flex: 1 1 220px;
}

:where(.install-callout__title) {
  margin: 0;
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-semibold, 600);
  line-height: 1.35;
  color: var(--ink-primary, #F3F4F6);
}

:where(.install-callout__desc) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: 1.45;
  color: var(--ink-secondary, #A1A6B0);
}

/* Indeterminate progress track */
:where(.install-progress) {
  display: flex;
  flex-direction: column;
  gap: 6px;
  min-width: 0;
}

:where(.install-progress__track) {
  position: relative;
  width: 100%;
  height: 3px;
  border-radius: 9999px;
  background: var(--border-subtle, rgba(255, 255, 255, 0.1));
  overflow: hidden;
}

:where(.install-progress__bar) {
  position: absolute;
  top: 0;
  left: 0;
  width: 38%;
  height: 100%;
  border-radius: 9999px;
  background: var(--accent, #2563EB);
  animation: vdpi-install-indeterminate 1.25s cubic-bezier(0.4, 0, 0.2, 1) infinite;
}

:where(.install-progress__label) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: 1.4;
  color: var(--ink-secondary, #A1A6B0);
}

/* Inline error recovery banner */
:where(.install-error) {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 12px 14px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--status-danger-border, rgba(255, 69, 58, 0.28));
  border-left: 3px solid var(--status-crimson, #FF453A);
  background: var(--status-danger-bg, rgba(255, 69, 58, 0.12));
  color: var(--ink-primary, #F3F4F6);
  min-width: 0;
  box-sizing: border-box;
}

:where(.install-error__top) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}

:where(.install-error__head) {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.install-error__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  color: var(--status-danger-fg, #FF6961);
  margin-top: 2px;
  flex-shrink: 0;
}

:where(.install-error__copy) {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

:where(.install-error__title) {
  margin: 0;
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-semibold, 600);
  line-height: 1.35;
  color: var(--ink-primary, #F3F4F6);
}

:where(.install-error__msg) {
  margin: 0;
  font-size: var(--text-sm, 12px);
  line-height: 1.45;
  color: var(--ink-secondary, #A1A6B0);
  word-break: break-word;
}

:where(.install-error__dismiss) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border: 0;
  border-radius: var(--radius-sm, 6px);
  background: transparent;
  color: var(--ink-secondary, #A1A6B0);
  cursor: pointer;
  flex-shrink: 0;
}

:where(.install-error__dismiss:hover) {
  background: var(--bg-surface-hover, rgba(255, 255, 255, 0.08));
  color: var(--ink-primary, #F3F4F6);
}

:where(.install-error__dismiss:focus-visible) {
  outline: var(--focus-ring-width, 2px) solid var(--focus-ring-color, #60A5FA);
  outline-offset: 1px;
}

/* Collapsible "What gets installed" details */
:where(.install-details) {
  border-top: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  background: var(--bg-surface-subtle, rgba(255, 255, 255, 0.02));
}

:where(.install-details__trigger) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
  padding: 10px 16px;
  border: 0;
  background: transparent;
  color: var(--ink-secondary, #A1A6B0);
  font: inherit;
  font-size: var(--text-sm, 12px);
  font-weight: var(--weight-medium, 500);
  cursor: pointer;
  text-align: left;
  transition: var(--transition-colors, color 120ms ease, background-color 120ms ease);
}

:where(.install-details__trigger:hover) {
  color: var(--ink-primary, #F3F4F6);
  background: var(--bg-surface-hover, rgba(255, 255, 255, 0.04));
}

:where(.install-details__trigger:focus-visible) {
  outline: var(--focus-ring-width, 2px) solid var(--focus-ring-color, #60A5FA);
  outline-offset: -2px;
}

:where(.install-details__list) {
  margin: 0;
  padding: 0 16px 12px 32px;
  display: flex;
  flex-direction: column;
  gap: 5px;
  font-size: var(--text-sm, 12px);
  line-height: 1.45;
  color: var(--ink-secondary, #A1A6B0);
}

/* Installed status key-value grid */
:where(.install-meta-grid) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 14px;
  min-width: 0;
}

:where(.install-meta-item) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

:where(.install-meta-item--full) {
  grid-column: 1 / -1;
}

:where(.install-meta-label) {
  font-size: var(--text-xs, 11px);
  font-weight: var(--weight-medium, 500);
  color: var(--ink-tertiary, #949BA8);
  letter-spacing: 0.02em;
}

:where(.install-meta-value) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-medium, 500);
  color: var(--ink-primary, #F3F4F6);
  min-width: 0;
}

:where(.install-meta-path) {
  font-family: var(--font-mono, ui-monospace, monospace);
  font-size: var(--text-xs, 11px);
  line-height: 1.45;
  color: var(--ink-secondary, #A1A6B0);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  min-width: 0;
}

/* Paths list rows */
:where(.install-path-list) {
  display: flex;
  flex-direction: column;
}

:where(.install-path-row) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 11px 16px;
  border-bottom: 1px solid var(--border-hairline, rgba(255, 255, 255, 0.07));
  min-width: 0;
}

:where(.install-path-row:last-child) {
  border-bottom: none;
}

:where(.install-path-row__copy) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.install-path-row__label) {
  font-size: var(--text-base, 13px);
  font-weight: var(--weight-medium, 500);
  color: var(--ink-primary, #F3F4F6);
}

:where(.install-loading) {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 18px 16px;
  font-size: var(--text-sm, 12px);
  color: var(--ink-secondary, #A1A6B0);
}

:where([data-theme="light"] .install-mode-card) {
  background: var(--bg-surface, #FFFFFF);
}

:where([data-theme="light"] .install-mode-card[aria-checked="true"]) {
  background: var(--accent-subtle, rgba(0, 102, 204, 0.1));
  border-color: var(--accent-border, rgba(0, 102, 204, 0.28));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .install-mode-card) {
    background: var(--bg-surface, #FFFFFF);
  }
  :where(:root:not([data-theme="dark"]) .install-mode-card[aria-checked="true"]) {
    background: var(--accent-subtle, rgba(0, 102, 204, 0.1));
    border-color: var(--accent-border, rgba(0, 102, 204, 0.28));
  }
}

@media (prefers-reduced-motion: reduce) {
  :where(.install-progress__bar) {
    animation: none;
    width: 100%;
    opacity: 0.5;
  }
}
`;

function ensureStyles(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = SCOPED_STYLES;
  document.head.appendChild(style);
}

function formatVersionLabel(version: string | null | undefined): string | null {
  if (!version) return null;
  const trimmed = version.trim();
  if (!trimmed) return null;
  return /^[vV]/.test(trimmed) ? `v${trimmed.slice(1)}` : `v${trimmed}`;
}

function sanitizeExternalUrl(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    const parsed = new URL(raw.trim());
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      return parsed.toString();
    }
    return null;
  } catch {
    return null;
  }
}

function resolveCliVersionRelation(
  status: DesktopStatusSnapshot | null,
  installedVersion: string | null,
  bundledVersion: string | null,
  bundledMissing: boolean,
): CliVersionRelation {
  if (status?.cliVersionRelation) {
    return status.cliVersionRelation;
  }
  if (bundledMissing) {
    return "bundled_missing";
  }
  if (!status || status.serviceState === "not_installed") {
    return "not_installed";
  }
  const cmp = compareSemver(installedVersion, bundledVersion);
  if (cmp === null) return "unknown";
  if (cmp < 0) return "upgrade_available";
  if (cmp > 0) return "newer_installed";
  return "up_to_date";
}

function InstallationViewComponent({
  status,
  settings,
  updateInfo,
  checkingUpdates,
  busyAction,
  installError,
  onInstallService,
  onSwitchEngine,
  onUpgradeService,
  onRepairService,
  onUninstallService,
  onCheckUpdates,
  onOpenReleaseUrl,
  onOpenAppFolder,
  onRefreshStatus,
  onClearInstallError,
  onNavigate,
}: InstallationViewProps) {
  const { lang } = useLang();
  const idPrefix = useId();
  const mountedRef = useRef(true);
  const proxyRadioRef = useRef<HTMLButtonElement>(null);
  const tunRadioRef = useRef<HTMLButtonElement>(null);

  const [selectedEngine, setSelectedEngine] = useState<EngineMode>("proxy");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [confirmRepairOpen, setConfirmRepairOpen] = useState(false);
  const [confirmUninstallOpen, setConfirmUninstallOpen] = useState(false);
  const [recheckingWintun, setRecheckingWintun] = useState(false);

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const platform = status?.platform ?? "windows";
  const serviceState = status?.serviceState;
  const isNotInstalled = serviceState === "not_installed";
  const isInstalled = serviceState === "running" || serviceState === "stopped";

  const bundledRaw = status?.bundledEngineVersion?.trim() || null;
  const installedRaw =
    status?.installedVersion?.trim() ||
    (serviceState === "running" ? status?.live?.version?.trim() || null : null);
  const liveRaw = status?.live?.version?.trim() || null;

  const bundledDisplay = formatVersionLabel(bundledRaw);
  const installedDisplay = formatVersionLabel(installedRaw);
  const liveDisplay = formatVersionLabel(liveRaw);

  const bundledMissing =
    status?.canInstallFromBundle === false ||
    status?.cliVersionRelation === "bundled_missing";

  const relation = resolveCliVersionRelation(
    status,
    installedRaw,
    bundledRaw,
    bundledMissing,
  );

  const isUpgradeAvailable =
    isInstalled && relation === "upgrade_available" && !bundledMissing;
  const isNewerInstalled = isInstalled && relation === "newer_installed";
  const isRepairNeeded = isInstalled && relation === "repair_needed";
  const liveVersionStale = Boolean(
    isInstalled && status?.liveVersionStale && installedDisplay && liveDisplay,
  );
  const runningFromReadonlyDmg = Boolean(status?.runningFromReadonlyDmg);

  const activeEngine: EngineMode =
    status?.live?.engine ??
    settings?.engine ??
    status?.configuredEngine ??
    "proxy";

  const normalizedBusy = busyAction?.trim().toLowerCase() ?? null;
  const pendingOp = status?.pendingOperation ?? null;

  const isInstalling =
    pendingOp === "installing" ||
    normalizedBusy === "install" ||
    normalizedBusy === "install-service" ||
    normalizedBusy === "installing";
  const isUpgrading =
    pendingOp === "upgrading" ||
    normalizedBusy === "upgrade" ||
    normalizedBusy === "upgrade-service" ||
    normalizedBusy === "upgrading";
  const isRepairing =
    pendingOp === "repairing" ||
    normalizedBusy === "repair" ||
    normalizedBusy === "repair-service" ||
    normalizedBusy === "repairing";
  const isUninstalling =
    pendingOp === "uninstalling" ||
    normalizedBusy === "uninstall" ||
    normalizedBusy === "uninstall-service" ||
    normalizedBusy === "uninstalling";

  const isAnyServiceBusy = Boolean(normalizedBusy || pendingOp);

  const showWintunMissing = Boolean(
    isNotInstalled &&
      platform === "windows" &&
      selectedEngine === "tun" &&
      status &&
      !status.wintun.ready,
  );

  const installDisabled =
    !status || isAnyServiceBusy || bundledMissing || showWintunMissing;

  const repairDisabled =
    !status || isAnyServiceBusy || isNewerInstalled || bundledMissing;

  const repairDisabledTitle = isNewerInstalled
    ? tInstallation(lang, "repairDisabledNewerHint")
    : bundledMissing
      ? tInstallation(lang, "repairDisabledBundleHint")
      : undefined;

  const safeReleaseUrl = sanitizeExternalUrl(updateInfo?.releaseUrl);
  const showReleaseCard = Boolean(updateInfo?.hasUpdate);

  const elevationNote =
    platform === "windows"
      ? tInstallation(lang, "elevationWindows")
      : selectedEngine === "proxy"
        ? tInstallation(lang, "elevationUnixProxy")
        : platform === "macos"
          ? tInstallation(lang, "elevationMacTun")
          : tInstallation(lang, "elevationLinuxTun");

  const activeProgressText = isInstalling
    ? tInstallation(lang, "progressInstalling")
    : isUpgrading
      ? tInstallation(lang, "progressUpgrading")
      : isRepairing
        ? tInstallation(lang, "progressRepairing")
        : isUninstalling
          ? tInstallation(lang, "progressUninstalling")
          : null;

  const handleStartInstall = (engineToUse: EngineMode = selectedEngine) => {
    if (isAnyServiceBusy || bundledMissing) return;
    if (
      engineToUse === "tun" &&
      platform === "windows" &&
      status &&
      !status.wintun.ready
    ) {
      return;
    }
    onClearInstallError();
    void onInstallService(engineToUse);
  };

  const handleRadioKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    current: EngineMode,
  ) => {
    if (
      event.key === "ArrowRight" ||
      event.key === "ArrowDown" ||
      event.key === "ArrowLeft" ||
      event.key === "ArrowUp"
    ) {
      event.preventDefault();
      const next: EngineMode = current === "proxy" ? "tun" : "proxy";
      setSelectedEngine(next);
      if (next === "proxy") {
        proxyRadioRef.current?.focus();
      } else {
        tunRadioRef.current?.focus();
      }
      return;
    }

    if (event.key === "Enter") {
      event.preventDefault();
      if (!installDisabled) {
        handleStartInstall(current);
      }
    }
  };

  const handleRecheckWintun = async () => {
    if (recheckingWintun) return;
    setRecheckingWintun(true);
    try {
      await onRefreshStatus();
    } finally {
      if (mountedRef.current) {
        setRecheckingWintun(false);
      }
    }
  };

  const handleConfirmRepair = async () => {
    if (isAnyServiceBusy) return;
    try {
      await onRepairService();
    } finally {
      if (mountedRef.current) {
        setConfirmRepairOpen(false);
      }
    }
  };

  const handleConfirmUninstall = async () => {
    if (isAnyServiceBusy) return;
    try {
      await onUninstallService();
    } finally {
      if (mountedRef.current) {
        setConfirmUninstallOpen(false);
      }
    }
  };

  const handleRetryFromError = () => {
    if (isAnyServiceBusy) return;
    const attempted = installError?.attemptedEngine ?? selectedEngine;
    onClearInstallError();
    if (isNotInstalled) {
      void onInstallService(attempted);
    } else if (isUpgradeAvailable) {
      void onUpgradeService();
    } else if (!isNewerInstalled && !bundledMissing) {
      void onRepairService();
    }
  };

  const handleTryProxyInstead = () => {
    if (isAnyServiceBusy || bundledMissing) return;
    setSelectedEngine("proxy");
    onClearInstallError();
    void onInstallService("proxy");
  };

  const renderErrorBanner = () => {
    if (!installError) return null;

    const errorTitle =
      installError.kind === "cancelled"
        ? tInstallation(lang, "errorTitleCancelled")
        : installError.kind === "wintun"
          ? tInstallation(lang, "errorTitleWintun")
          : installError.kind === "antivirus"
            ? tInstallation(lang, "errorTitleAntivirus")
            : tInstallation(lang, "errorTitleGeneric");

    const errorHint =
      installError.kind === "cancelled"
        ? tInstallation(lang, "errorHintCancelled")
        : installError.kind === "wintun"
          ? tInstallation(lang, "errorHintWintun")
          : installError.kind === "antivirus"
            ? tInstallation(lang, "errorHintAntivirus")
            : null;

    const scrubbedMessage = scrubUrlsInText(installError.message.trim());
    const showTryProxy =
      isNotInstalled &&
      !bundledMissing &&
      (installError.attemptedEngine === "tun" ||
        installError.kind === "wintun" ||
        selectedEngine === "tun");

    return (
      <div className="install-error" role="alert">
        <div className="install-error__top">
          <div className="install-error__head">
            <span className="install-error__icon" aria-hidden="true">
              <IconAlert size={16} />
            </span>
            <div className="install-error__copy">
              <p className="install-error__title">{errorTitle}</p>
              {scrubbedMessage ? (
                <p className="install-error__msg">{scrubbedMessage}</p>
              ) : null}
              {errorHint ? (
                <p className="install-error__msg">{errorHint}</p>
              ) : null}
            </div>
          </div>

          <button
            type="button"
            className="install-error__dismiss"
            aria-label={tInstallation(lang, "btnDismissError")}
            onClick={onClearInstallError}
          >
            <IconClose size={14} />
          </button>
        </div>

        <div className="install-actions-group">
          {showTryProxy ? (
            <button
              type="button"
              className="btn btn-primary btn-sm"
              disabled={isAnyServiceBusy}
              onClick={handleTryProxyInstead}
            >
              <span>{tInstallation(lang, "btnTryProxyInstead")}</span>
            </button>
          ) : null}

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            disabled={isAnyServiceBusy || bundledMissing}
            onClick={handleRetryFromError}
          >
            <IconRefresh size={13} />
            <span>{tInstallation(lang, "btnRetry")}</span>
          </button>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => {
              void onOpenAppFolder("app");
            }}
          >
            <IconFolder size={13} />
            <span>{tInstallation(lang, "btnOpenAppFolder")}</span>
          </button>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => onNavigate("diagnostics")}
          >
            <IconDiagnostics size={13} />
            <span>{tInstallation(lang, "btnOpenDiagnostics")}</span>
          </button>
        </div>
      </div>
    );
  };

  const renderProgressTrack = () => {
    if (!activeProgressText) return null;
    return (
      <div className="install-progress" aria-live="polite" role="status">
        <div className="install-progress__track" aria-hidden="true">
          <div className="install-progress__bar" />
        </div>
        <p className="install-progress__label">{activeProgressText}</p>
      </div>
    );
  };

  const installedBadge = isUpgradeAvailable
    ? {
        className: "pill pill-accent",
        label: tInstallation(lang, "badgeUpgradeAvailable"),
      }
    : isRepairNeeded
      ? {
          className: "pill pill-warn",
          label: tInstallation(lang, "badgeRepairNeeded"),
        }
      : isNewerInstalled
        ? {
            className: "pill pill-neutral",
            label: tInstallation(lang, "badgeNewerInstalled"),
          }
        : {
            className: "pill pill-success",
            label: tInstallation(lang, "badgeUpToDate"),
          };

  const detailsPanelId = `${idPrefix}-what-gets-installed`;
  const engineGroupLabelId = `${idPrefix}-engine-group-label`;

  const whatGetsInstalledItems = [
    platform === "windows"
      ? tInstallation(lang, "detailsItemBinaryWin")
      : tInstallation(lang, "detailsItemBinaryUnix"),
    platform === "windows"
      ? tInstallation(lang, "detailsItemServiceWin")
      : platform === "macos"
        ? tInstallation(lang, "detailsItemServiceMac")
        : tInstallation(lang, "detailsItemServiceLinux"),
    tInstallation(lang, "detailsItemConfig"),
    tInstallation(lang, "detailsItemUninstall"),
  ];

  return (
    <div className="view-stack view-installation">
      <header className="view-header">
        <div className="view-header-text">
          <h1 className="view-title">{tInstallation(lang, "title")}</h1>
          <p className="view-subtitle">{tInstallation(lang, "subtitle")}</p>
        </div>
      </header>

      {/* 1. App Release Update Card */}
      {showReleaseCard && updateInfo ? (
        <section
          className="install-card"
          aria-labelledby={`${idPrefix}-release-heading`}
        >
          <div className="install-card__header">
            <div className="install-card__heading">
              <span className="install-card__icon" aria-hidden="true">
                <IconRefresh size={16} />
              </span>
              <h2
                id={`${idPrefix}-release-heading`}
                className="install-card__title"
              >
                {tInstallation(lang, "releaseCardTitle")}
              </h2>
            </div>
            <span className="pill pill-accent">
              {tInstallation(lang, "releaseCardBadge")}
            </span>
          </div>

          <div className="install-card__body">
            <div className="install-release-version">
              <span>
                {tInstallation(lang, "releaseVersionSummary", {
                  current:
                    formatVersionLabel(updateInfo.currentVersion) ??
                    updateInfo.currentVersion,
                  latest:
                    formatVersionLabel(updateInfo.latestVersion) ??
                    updateInfo.latestVersion,
                })}
              </span>
            </div>

            {updateInfo.releaseNotes.length > 0 ? (
              <ul className="install-release-notes">
                {updateInfo.releaseNotes.map((note, idx) => (
                  <li key={`${idx}-${note}`}>{note}</li>
                ))}
              </ul>
            ) : null}
          </div>

          <div className="install-card__footer">
            <div className="install-actions-group">
              {safeReleaseUrl ? (
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    void onOpenReleaseUrl(safeReleaseUrl);
                  }}
                >
                  <span>{tInstallation(lang, "btnDownloadRelease")}</span>
                  <IconExternal size={13} />
                </button>
              ) : null}

              <button
                type="button"
                className="btn btn-secondary"
                disabled={checkingUpdates}
                aria-busy={checkingUpdates}
                onClick={() => {
                  void onCheckUpdates(true);
                }}
              >
                {checkingUpdates ? (
                  <span className="spinner" aria-hidden="true" />
                ) : (
                  <IconRefresh size={14} />
                )}
                <span>
                  {checkingUpdates
                    ? tInstallation(lang, "btnChecking")
                    : tInstallation(lang, "btnCheckAgain")}
                </span>
              </button>
            </div>
          </div>
        </section>
      ) : null}

      {/* 2. macOS Read-only DMG Notice */}
      {runningFromReadonlyDmg ? (
        <InlineBanner
          tone="info"
          title={tInstallation(lang, "dmgNoticeTitle")}
          description={tInstallation(lang, "dmgNoticeDesc")}
        />
      ) : null}

      {/* 3. Missing Bundled Engine Warning */}
      {bundledMissing ? (
        <InlineBanner
          tone="warn"
          title={tInstallation(lang, "bundledMissingTitle")}
          description={tInstallation(lang, "bundledMissingDesc")}
          actionLabel={tInstallation(lang, "btnOpenAppFolder")}
          onAction={() => {
            void onOpenAppFolder("app");
          }}
        />
      ) : null}

      {/* 4. Engine Installation & Management Card */}
      <section
        className="install-card"
        aria-labelledby={`${idPrefix}-engine-heading`}
      >
        {status === null ? (
          <div className="install-loading" role="status" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            <span>{tInstallation(lang, "loadingStatus")}</span>
          </div>
        ) : isNotInstalled ? (
          <>
            <div className="install-card__header">
              <div className="install-card__heading">
                <span className="install-card__icon" aria-hidden="true">
                  <IconShield size={16} />
                </span>
                <h2
                  id={`${idPrefix}-engine-heading`}
                  className="install-card__title"
                >
                  {tInstallation(lang, "setupCardTitle")}
                </h2>
              </div>
              <span className="pill pill-neutral">
                {tInstallation(lang, "statusNotInstalled")}
              </span>
            </div>

            <div className="install-card__body">
              <p className="install-card__subtitle" id={engineGroupLabelId}>
                {tInstallation(lang, "setupCardSubtitle")}
              </p>

              <div
                className="install-mode-grid"
                role="radiogroup"
                aria-label={tInstallation(lang, "engineGroupAria")}
                aria-describedby={engineGroupLabelId}
              >
                <button
                  ref={proxyRadioRef}
                  type="button"
                  role="radio"
                  aria-checked={selectedEngine === "proxy"}
                  tabIndex={selectedEngine === "proxy" ? 0 : -1}
                  className="install-mode-card"
                  disabled={isAnyServiceBusy}
                  onClick={() => setSelectedEngine("proxy")}
                  onKeyDown={(e) => handleRadioKeyDown(e, "proxy")}
                >
                  <div className="install-mode-card__top">
                    <span className="install-mode-card__title-wrap">
                      <span
                        className="install-mode-card__radio"
                        aria-hidden="true"
                      />
                      <span className="install-mode-card__title">
                        {tInstallation(lang, "engineProxyTitle")}
                      </span>
                    </span>
                    <span className="pill pill-accent">
                      {tInstallation(lang, "engineProxyBadge")}
                    </span>
                  </div>
                  <p className="install-mode-card__desc">
                    {tInstallation(lang, "engineProxyDesc")}
                  </p>
                </button>

                <button
                  ref={tunRadioRef}
                  type="button"
                  role="radio"
                  aria-checked={selectedEngine === "tun"}
                  tabIndex={selectedEngine === "tun" ? 0 : -1}
                  className="install-mode-card"
                  disabled={isAnyServiceBusy}
                  onClick={() => setSelectedEngine("tun")}
                  onKeyDown={(e) => handleRadioKeyDown(e, "tun")}
                >
                  <div className="install-mode-card__top">
                    <span className="install-mode-card__title-wrap">
                      <span
                        className="install-mode-card__radio"
                        aria-hidden="true"
                      />
                      <span className="install-mode-card__title">
                        {tInstallation(lang, "engineTunTitle")}
                      </span>
                    </span>
                    <span className="pill pill-neutral">
                      {tInstallation(lang, "engineTunBadge")}
                    </span>
                  </div>
                  <p className="install-mode-card__desc">
                    {tInstallation(lang, "engineTunDesc")}
                  </p>
                </button>
              </div>

              {showWintunMissing ? (
                <div
                  className="install-callout install-callout--warn"
                  role="status"
                >
                  <div className="install-callout__head">
                    <div className="install-callout__copy">
                      <p className="install-callout__title">
                        {tInstallation(lang, "wintunMissingTitle")}
                      </p>
                      <p className="install-callout__desc">
                        {status.wintun.message?.trim()
                          ? scrubUrlsInText(status.wintun.message.trim())
                          : tInstallation(lang, "wintunMissingDesc")}
                      </p>
                    </div>
                  </div>
                  <div className="install-actions-group">
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => {
                        void onOpenAppFolder("app");
                      }}
                    >
                      <IconFolder size={13} />
                      <span>{tInstallation(lang, "btnOpenAppFolder")}</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      disabled={recheckingWintun}
                      aria-busy={recheckingWintun}
                      onClick={() => {
                        void handleRecheckWintun();
                      }}
                    >
                      {recheckingWintun ? (
                        <span className="spinner" aria-hidden="true" />
                      ) : (
                        <IconRefresh size={13} />
                      )}
                      <span>
                        {recheckingWintun
                          ? tInstallation(lang, "btnRechecking")
                          : tInstallation(lang, "btnRecheckWintun")}
                      </span>
                    </button>
                  </div>
                </div>
              ) : null}

              <p className="install-elevation-note">{elevationNote}</p>

              <div className="install-actions-group">
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={installDisabled}
                  aria-busy={isInstalling}
                  onClick={() => handleStartInstall(selectedEngine)}
                >
                  {isInstalling ? (
                    <span className="spinner" aria-hidden="true" />
                  ) : (
                    <IconShield size={14} />
                  )}
                  <span>
                    {isInstalling
                      ? tInstallation(lang, "btnInstalling")
                      : tInstallation(lang, "btnInstallAndProtect")}
                  </span>
                </button>

                {!showReleaseCard ? (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={checkingUpdates || isAnyServiceBusy}
                    aria-busy={checkingUpdates}
                    onClick={() => {
                      void onCheckUpdates(true);
                    }}
                  >
                    {checkingUpdates ? (
                      <span className="spinner" aria-hidden="true" />
                    ) : (
                      <IconRefresh size={14} />
                    )}
                    <span>
                      {checkingUpdates
                        ? tInstallation(lang, "btnChecking")
                        : tInstallation(lang, "btnCheckUpdates")}
                    </span>
                  </button>
                ) : null}
              </div>

              {renderProgressTrack()}
              {renderErrorBanner()}
            </div>

            <div className="install-details">
              <button
                type="button"
                className="install-details__trigger"
                aria-expanded={detailsOpen}
                aria-controls={detailsPanelId}
                onClick={() => setDetailsOpen((prev) => !prev)}
              >
                <span>{tInstallation(lang, "detailsToggleLabel")}</span>
                <IconChevron
                  size={14}
                  direction={detailsOpen ? "down" : "right"}
                />
              </button>
              {detailsOpen ? (
                <ul id={detailsPanelId} className="install-details__list">
                  {whatGetsInstalledItems.map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          </>
        ) : (
          <>
            <div className="install-card__header">
              <div className="install-card__heading">
                <span className="install-card__icon" aria-hidden="true">
                  <IconShield size={16} />
                </span>
                <h2
                  id={`${idPrefix}-engine-heading`}
                  className="install-card__title"
                >
                  {tInstallation(lang, "engineCardTitle")}
                </h2>
              </div>
              <span className={installedBadge.className}>
                {relation === "up_to_date" ? (
                  <IconCheck size={11} />
                ) : null}
                <span>{installedBadge.label}</span>
              </span>
            </div>

            <div className="install-card__body">
              {/* Bundled Engine Upgrade Callout */}
              {isUpgradeAvailable && bundledDisplay ? (
                <div className="install-callout install-callout--accent">
                  <div className="install-callout__head">
                    <div className="install-callout__copy">
                      <p className="install-callout__title">
                        {tInstallation(lang, "upgradeBannerTitle", {
                          version: bundledDisplay,
                        })}
                      </p>
                      <p className="install-callout__desc">
                        {tInstallation(lang, "upgradeBannerDesc", {
                          installed:
                            installedDisplay ??
                            tInstallation(lang, "valueUnknown"),
                          bundled: bundledDisplay,
                        })}
                      </p>
                    </div>
                  </div>
                  <div className="install-actions-group">
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={isAnyServiceBusy}
                      aria-busy={isUpgrading}
                      onClick={() => {
                        onClearInstallError();
                        void onUpgradeService();
                      }}
                    >
                      {isUpgrading ? (
                        <span className="spinner" aria-hidden="true" />
                      ) : (
                        <IconRefresh size={14} />
                      )}
                      <span>
                        {isUpgrading
                          ? tInstallation(lang, "btnUpdatingEngine")
                          : tInstallation(lang, "btnUpdateEngine", {
                              version: bundledDisplay,
                            })}
                      </span>
                    </button>
                  </div>
                </div>
              ) : null}

              {/* Repair Needed Callout */}
              {isRepairNeeded && !bundledMissing ? (
                <div
                  className="install-callout install-callout--warn"
                  role="status"
                >
                  <div className="install-callout__copy">
                    <p className="install-callout__title">
                      {tInstallation(lang, "repairNeededTitle")}
                    </p>
                    <p className="install-callout__desc">
                      {tInstallation(lang, "repairNeededDesc")}
                    </p>
                  </div>
                </div>
              ) : null}

              {/* Live Version Stale Notice */}
              {liveVersionStale && installedDisplay && liveDisplay ? (
                <div
                  className="install-callout install-callout--warn"
                  role="status"
                >
                  <div className="install-callout__copy">
                    <p className="install-callout__title">
                      {tInstallation(lang, "liveStaleTitle")}
                    </p>
                    <p className="install-callout__desc">
                      {tInstallation(lang, "liveStaleDesc", {
                        installed: installedDisplay,
                        live: liveDisplay,
                      })}
                    </p>
                  </div>
                </div>
              ) : null}

              {/* Newer Installed Downgrade Protection Notice */}
              {isNewerInstalled ? (
                <div
                  className="install-callout install-callout--info"
                  role="status"
                >
                  <div className="install-callout__copy">
                    <p className="install-callout__title">
                      {tInstallation(lang, "newerInstalledTitle")}
                    </p>
                    <p className="install-callout__desc">
                      {tInstallation(lang, "newerInstalledDesc", {
                        installed:
                          installedDisplay ??
                          tInstallation(lang, "valueUnknown"),
                        bundled:
                          bundledDisplay ??
                          tInstallation(lang, "valueUnavailable"),
                      })}
                    </p>
                  </div>
                </div>
              ) : null}

              {renderProgressTrack()}
              {renderErrorBanner()}

              {/* Installed Status Grid */}
              <div className="install-meta-grid">
                <div className="install-meta-item">
                  <span className="install-meta-label">
                    {tInstallation(lang, "metaInstalledEngine")}
                  </span>
                  <span className="install-meta-value mono tabular-nums">
                    {installedDisplay ?? tInstallation(lang, "valueUnknown")}
                  </span>
                </div>

                <div className="install-meta-item">
                  <span className="install-meta-label">
                    {tInstallation(lang, "metaBundledEngine")}
                  </span>
                  <span className="install-meta-value mono tabular-nums">
                    {bundledDisplay ?? tInstallation(lang, "valueUnavailable")}
                  </span>
                </div>

                <div className="install-meta-item">
                  <span className="install-meta-label">
                    {tInstallation(lang, "metaEngineMode")}
                  </span>
                  {onSwitchEngine ? (
                    <div
                      className="segmented"
                      role="group"
                      aria-label={tInstallation(lang, "switchEngineGroupAria")}
                      style={{ alignSelf: "flex-start", marginTop: 2 }}
                    >
                      <button
                        type="button"
                        className={
                          activeEngine === "proxy"
                            ? "segmented-item active"
                            : "segmented-item"
                        }
                        aria-pressed={activeEngine === "proxy"}
                        disabled={isAnyServiceBusy}
                        onClick={() => {
                          if (activeEngine !== "proxy") {
                            onClearInstallError();
                            void onSwitchEngine("proxy");
                          }
                        }}
                      >
                        {tInstallation(lang, "switchEngineProxy")}
                      </button>
                      <button
                        type="button"
                        className={
                          activeEngine === "tun"
                            ? "segmented-item active"
                            : "segmented-item"
                        }
                        aria-pressed={activeEngine === "tun"}
                        disabled={
                          isAnyServiceBusy ||
                          (platform === "windows" && !status.wintun.ready && activeEngine !== "tun")
                        }
                        title={
                          platform === "windows" && !status.wintun.ready && activeEngine !== "tun"
                            ? tInstallation(lang, "switchEngineWintunMissing")
                            : undefined
                        }
                        onClick={() => {
                          if (activeEngine !== "tun") {
                            onClearInstallError();
                            void onSwitchEngine("tun");
                          }
                        }}
                      >
                        {tInstallation(lang, "switchEngineTun")}
                      </button>
                    </div>
                  ) : (
                    <span className="install-meta-value">
                      {activeEngine === "tun"
                        ? tInstallation(lang, "engineLabelTun")
                        : tInstallation(lang, "engineLabelProxy")}
                    </span>
                  )}
                </div>

                <div className="install-meta-item">
                  <span className="install-meta-label">
                    {tInstallation(lang, "metaServiceState")}
                  </span>
                  <span className="install-meta-value">
                    <span
                      className={`status-dot status-dot-sm ${
                        serviceState === "running"
                          ? "status-dot-active"
                          : "status-dot-idle"
                      }`}
                      aria-hidden="true"
                    />
                    <span>
                      {serviceState === "running"
                        ? tInstallation(lang, "serviceLabelRunning")
                        : tInstallation(lang, "serviceLabelStopped")}
                    </span>
                  </span>
                </div>

                {status.configPath ? (
                  <div className="install-meta-item install-meta-item--full">
                    <span className="install-meta-label">
                      {tInstallation(lang, "metaConfigPath")}
                    </span>
                    <span
                      className="install-meta-path"
                      title={status.configPath}
                    >
                      {status.configPath}
                    </span>
                  </div>
                ) : null}
              </div>
            </div>

            <div className="install-card__footer">
              <div className="install-actions-group">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={repairDisabled}
                  aria-busy={isRepairing}
                  title={repairDisabledTitle}
                  onClick={() => setConfirmRepairOpen(true)}
                >
                  {isRepairing ? (
                    <span className="spinner" aria-hidden="true" />
                  ) : (
                    <IconRefresh size={14} />
                  )}
                  <span>
                    {isRepairing
                      ? tInstallation(lang, "btnRepairing")
                      : tInstallation(lang, "btnRepairReinstall")}
                  </span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={checkingUpdates || isAnyServiceBusy}
                  aria-busy={checkingUpdates}
                  onClick={() => {
                    void onCheckUpdates(true);
                  }}
                >
                  {checkingUpdates ? (
                    <span className="spinner" aria-hidden="true" />
                  ) : (
                    <IconRefresh size={14} />
                  )}
                  <span>
                    {checkingUpdates
                      ? tInstallation(lang, "btnChecking")
                      : tInstallation(lang, "btnCheckUpdates")}
                  </span>
                </button>
              </div>

              <button
                type="button"
                className="btn btn-danger"
                disabled={isAnyServiceBusy}
                aria-busy={isUninstalling}
                onClick={() => setConfirmUninstallOpen(true)}
              >
                {isUninstalling ? (
                  <span className="spinner" aria-hidden="true" />
                ) : (
                  <IconTrash size={14} />
                )}
                <span>
                  {isUninstalling
                    ? tInstallation(lang, "btnUninstalling")
                    : tInstallation(lang, "btnUninstallService")}
                </span>
              </button>
            </div>
          </>
        )}
      </section>

      {/* 5. Paths & Local Data Card */}
      <section
        className="install-card"
        aria-labelledby={`${idPrefix}-paths-heading`}
      >
        <div className="install-card__header">
          <div className="install-card__heading">
            <span className="install-card__icon" aria-hidden="true">
              <IconFolder size={16} />
            </span>
            <h2
              id={`${idPrefix}-paths-heading`}
              className="install-card__title"
            >
              {tInstallation(lang, "pathsCardTitle")}
            </h2>
          </div>

          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => {
              void onOpenAppFolder("app");
            }}
          >
            <IconFolder size={13} />
            <span>{tInstallation(lang, "btnAppFolder")}</span>
          </button>
        </div>

        <div className="install-path-list">
          <div className="install-path-row">
            <div className="install-path-row__copy">
              <span className="install-path-row__label">
                {tInstallation(lang, "pathConfigLabel")}
              </span>
              <span
                className="install-meta-path"
                title={status?.configPath ?? undefined}
              >
                {status?.configPath ?? "-"}
              </span>
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                void onOpenAppFolder("config");
              }}
            >
              <IconFolder size={13} />
              <span>{tInstallation(lang, "btnOpenFolder")}</span>
            </button>
          </div>

          <div className="install-path-row">
            <div className="install-path-row__copy">
              <span className="install-path-row__label">
                {tInstallation(lang, "pathLogsLabel")}
              </span>
              <span
                className="install-meta-path"
                title={status?.logsDir ?? undefined}
              >
                {status?.logsDir ?? "-"}
              </span>
            </div>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => {
                void onOpenAppFolder("logs");
              }}
            >
              <IconFolder size={13} />
              <span>{tInstallation(lang, "btnOpenFolder")}</span>
            </button>
          </div>
        </div>
      </section>

      {/* Repair / Reinstall Confirm Dialog */}
      <ConfirmDialog
        open={confirmRepairOpen}
        title={tInstallation(lang, "repairDialogTitle")}
        description={
          bundledDisplay
            ? tInstallation(lang, "repairDialogDesc", {
                version: bundledDisplay,
              })
            : tInstallation(lang, "repairDialogDescNoVersion")
        }
        confirmLabel={
          isRepairing
            ? tInstallation(lang, "btnRepairing")
            : tInstallation(lang, "repairDialogConfirm")
        }
        cancelLabel={tInstallation(lang, "cancel")}
        busy={isRepairing}
        onConfirm={() => {
          void handleConfirmRepair();
        }}
        onCancel={() => {
          if (!isRepairing) {
            setConfirmRepairOpen(false);
          }
        }}
      />

      {/* Uninstall Service Confirm Dialog */}
      <ConfirmDialog
        open={confirmUninstallOpen}
        title={tInstallation(lang, "uninstallDialogTitle")}
        description={tInstallation(lang, "uninstallDialogDesc")}
        confirmLabel={
          isUninstalling
            ? tInstallation(lang, "btnUninstalling")
            : tInstallation(lang, "uninstallDialogConfirm")
        }
        cancelLabel={tInstallation(lang, "cancel")}
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

export const InstallationView = memo(InstallationViewComponent);
InstallationView.displayName = "InstallationView";

export default InstallationView;
