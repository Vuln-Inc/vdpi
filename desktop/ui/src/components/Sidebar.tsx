import { memo, useEffect } from "react";
import type { ComponentType } from "react";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import { localizeActionMessage, tShell } from "../i18n/shell";
import type {
  DesktopStatusSnapshot,
  NavTab,
  VpnCoexistence,
} from "../types";
import {
  BrandMark,
  IconDiagnostics,
  IconDns,
  IconInstall,
  IconOverview,
  IconSettings,
  IconSplitTunnel,
  IconTray,
  IconUpdateBadge,
} from "./Icons";

export interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  status: DesktopStatusSnapshot | null;
  hasAppUpdate?: boolean;
  latestReleaseVersion?: string | null;
  keepInTrayOnClose?: boolean;
  trayActive?: boolean;
  vpnCoexistence?: VpnCoexistence;
  className?: string;
}

type FooterStatusTone = "active" | "warn" | "paused";

interface NavItemConfig {
  id: NavTab;
  labelKey:
    | "navOverview"
    | "navSplit"
    | "navDns"
    | "navDiagnostics"
    | "navSettings";
  shortcut: string;
  Icon: ComponentType<{ size?: number; className?: string }>;
}

const NAV_ITEMS: ReadonlyArray<NavItemConfig> = [
  { id: "overview", labelKey: "navOverview", shortcut: "Control+1", Icon: IconOverview },
  { id: "split", labelKey: "navSplit", shortcut: "Control+2", Icon: IconSplitTunnel },
  { id: "dns", labelKey: "navDns", shortcut: "Control+3", Icon: IconDns },
  { id: "diagnostics", labelKey: "navDiagnostics", shortcut: "Control+4", Icon: IconDiagnostics },
  { id: "settings", labelKey: "navSettings", shortcut: "Control+5", Icon: IconSettings },
];

const STYLE_ID = "vdpi-sidebar-styles";

const FALLBACK_STYLES = `
:where(.sidebar) {
  --_sb-bg: var(--surface, #141416);
  --_sb-border: var(--border, rgba(255, 255, 255, 0.08));
  --_sb-ink: var(--ink-primary, var(--text-primary, #f5f5f7));
  --_sb-secondary: var(--ink-secondary, var(--text-secondary, #a1a1a6));
  --_sb-tertiary: var(--ink-tertiary, #7c828e);
  --_sb-muted: var(--ink-muted, #7c7c82);
  --_sb-hover: var(--surface-hover, rgba(255, 255, 255, 0.045));
  --_sb-active-bg: var(--surface-raised, rgba(255, 255, 255, 0.085));
  --_sb-pill-bg: var(--surface-raised, rgba(255, 255, 255, 0.06));
  --_sb-pill-border: var(--border, rgba(255, 255, 255, 0.09));
  --_sb-warn-fg: var(--status-warning-fg, var(--status-amber-fg, #ff9f0a));
  --_sb-warn-bg: var(--status-warning-bg, var(--status-amber-bg, rgba(255, 159, 10, 0.12)));
  --_sb-warn-border: var(--status-warning-border, var(--status-amber-border, rgba(255, 159, 10, 0.28)));
  --_sb-dot-active: var(--signal, var(--success, #30d158));
  --_sb-dot-warn: var(--warning, #ff9f0a);
  --_sb-dot-paused: var(--ink-muted, #6e6e73);
  --_sb-focus: var(--accent, #409cff);
  --_sb-mono: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-direction: column;
  width: 208px;
  min-width: 208px;
  flex: 0 0 208px;
  height: 100%;
  overflow: hidden;
  background: var(--_sb-bg);
  border-right: 1px solid var(--_sb-border);
  color: var(--_sb-ink);
  box-sizing: border-box;
  user-select: none;
}

:where([data-theme="light"] .sidebar) {
  --_sb-bg: var(--surface, #f6f6f8);
  --_sb-border: var(--border, rgba(0, 0, 0, 0.08));
  --_sb-ink: var(--ink-primary, var(--text-primary, #111113));
  --_sb-secondary: var(--ink-secondary, var(--text-secondary, #55555b));
  --_sb-tertiary: var(--ink-tertiary, #6b7280);
  --_sb-muted: var(--ink-muted, #727278);
  --_sb-hover: var(--surface-hover, rgba(0, 0, 0, 0.04));
  --_sb-active-bg: var(--surface-raised, rgba(0, 0, 0, 0.075));
  --_sb-pill-bg: var(--surface-raised, rgba(0, 0, 0, 0.045));
  --_sb-pill-border: var(--border, rgba(0, 0, 0, 0.09));
  --_sb-warn-fg: var(--status-warning-fg, var(--status-amber-fg, #a15c00));
  --_sb-warn-bg: var(--status-warning-bg, var(--status-amber-bg, rgba(255, 159, 10, 0.14)));
  --_sb-warn-border: var(--status-warning-border, var(--status-amber-border, rgba(161, 92, 0, 0.24)));
  --_sb-dot-active: var(--signal, var(--success, #1f8a3c));
  --_sb-dot-warn: var(--warning, #c96a00);
  --_sb-dot-paused: var(--ink-muted, #8e8e93);
  --_sb-focus: var(--accent, #0066cc);
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .sidebar) {
    --_sb-bg: var(--surface, #f6f6f8);
    --_sb-border: var(--border, rgba(0, 0, 0, 0.08));
    --_sb-ink: var(--ink-primary, var(--text-primary, #111113));
    --_sb-secondary: var(--ink-secondary, var(--text-secondary, #55555b));
    --_sb-tertiary: var(--ink-tertiary, #6b7280);
    --_sb-muted: var(--ink-muted, #727278);
    --_sb-hover: var(--surface-hover, rgba(0, 0, 0, 0.04));
    --_sb-active-bg: var(--surface-raised, rgba(0, 0, 0, 0.075));
    --_sb-pill-bg: var(--surface-raised, rgba(0, 0, 0, 0.045));
    --_sb-pill-border: var(--border, rgba(0, 0, 0, 0.09));
    --_sb-warn-fg: var(--status-warning-fg, var(--status-amber-fg, #a15c00));
    --_sb-warn-bg: var(--status-warning-bg, var(--status-amber-bg, rgba(255, 159, 10, 0.14)));
    --_sb-warn-border: var(--status-warning-border, var(--status-amber-border, rgba(161, 92, 0, 0.24)));
    --_sb-dot-active: var(--signal, var(--success, #1f8a3c));
    --_sb-dot-warn: var(--warning, #c96a00);
    --_sb-dot-paused: var(--ink-muted, #8e8e93);
    --_sb-focus: var(--accent, #0066cc);
  }
}

:where(.sidebar-header) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 16px 14px 14px;
  box-sizing: border-box;
}

:where(.sidebar-brand) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

:where(.sidebar-brand-icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 20px;
  height: 20px;
  color: var(--_sb-ink);
}

:where(.sidebar-brand-mark) {
  width: 20px;
  height: 20px;
  display: block;
}

:where(.sidebar-wordmark) {
  font-size: 14.5px;
  font-weight: 600;
  line-height: 1;
  letter-spacing: -0.02em;
  color: var(--_sb-ink);
}

:where(.sidebar-version-pill) {
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  padding: 2px 6px;
  border-radius: 9999px;
  border: 1px solid var(--_sb-pill-border);
  background: var(--_sb-pill-bg);
  color: var(--_sb-muted);
  font-family: var(--_sb-mono);
  font-size: 10.5px;
  font-weight: 500;
  line-height: 1.25;
  font-variant-numeric: tabular-nums;
}

:where(.sidebar-nav) {
  display: flex;
  flex-direction: column;
  gap: 0;
  flex: 1 1 auto;
  min-height: 0;
  padding: 0;
  overflow: hidden;
  box-sizing: border-box;
}

:where(.sidebar-nav-primary) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex: 1 1 auto;
  min-height: 0;
  padding: 4px 10px 10px;
  overflow-y: auto;
  box-sizing: border-box;
}

:where(.sidebar-nav-bottom) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  flex-shrink: 0;
  padding: 8px 10px;
  border-top: 1px solid var(--_sb-border);
  box-sizing: border-box;
}

:where(.sidebar-nav-update-badge) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-left: auto;
  width: 16px;
  height: 16px;
  box-shadow: none;
  filter: none;
}

:where(.sidebar-nav-update-badge--update) {
  color: var(--accent-fg, var(--_sb-focus));
}

:where(.sidebar-nav-update-badge--setup) {
  color: var(--_sb-warn-fg);
}

:where(.sidebar-nav-update-icon) {
  width: 15px;
  height: 15px;
  display: block;
}

:where(.sidebar-install-dot) {
  display: block;
  width: 7px;
  height: 7px;
  border-radius: 9999px;
  background: var(--status-warning, var(--status-amber, #c96a00));
  box-shadow: none;
  filter: none;
}

:where(.sidebar-nav-item) {
  display: flex;
  align-items: center;
  gap: 9px;
  width: 100%;
  min-height: 34px;
  padding: 0 10px;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--_sb-secondary);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  line-height: 1;
  text-align: left;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 110ms ease, color 110ms ease;
}

:where(.sidebar-nav-item:hover) {
  background: var(--_sb-hover);
  color: var(--_sb-ink);
}

:where(.sidebar-nav-item.is-active) {
  background: var(--_sb-active-bg);
  color: var(--_sb-ink);
}

:where(.sidebar-nav-item:focus-visible) {
  outline: 2px solid var(--_sb-focus);
  outline-offset: -2px;
}

:where(.sidebar-nav-icon-wrap) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 16px;
  height: 16px;
  opacity: 0.82;
}

:where(.sidebar-nav-item.is-active .sidebar-nav-icon-wrap),
:where(.sidebar-nav-item:hover .sidebar-nav-icon-wrap) {
  opacity: 1;
}

:where(.sidebar-nav-icon) {
  width: 16px;
  height: 16px;
  display: block;
}

:where(.sidebar-nav-label) {
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.sidebar-nav-pill) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  min-width: 18px;
  height: 18px;
  padding: 0 5px;
  border-radius: 9999px;
  border: 1px solid var(--_sb-pill-border);
  background: var(--_sb-pill-bg);
  color: var(--_sb-secondary);
  font-family: var(--_sb-mono);
  font-size: 10.5px;
  font-weight: 500;
  line-height: 1;
  font-variant-numeric: tabular-nums;
  box-sizing: border-box;
}

:where(.sidebar-nav-item.is-active .sidebar-nav-pill) {
  color: var(--_sb-ink);
}

:where(.sidebar-nav-pill.sidebar-nav-pill--warn),
:where(.sidebar-nav-item.is-active .sidebar-nav-pill.sidebar-nav-pill--warn) {
  border-color: var(--_sb-warn-border);
  background: var(--_sb-warn-bg);
  color: var(--_sb-warn-fg);
}

:where(.sidebar-footer) {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 12px 14px 14px;
  border-top: 1px solid var(--_sb-border);
  box-sizing: border-box;
}

:where(.sidebar-status-row) {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

:where(.sidebar-status-dot-wrap) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 14px;
  height: 14px;
}

:where(.sidebar-status-dot) {
  width: 7px;
  height: 7px;
  border-radius: 9999px;
  flex-shrink: 0;
  background: var(--_sb-dot-paused);
  box-shadow: none;
}

:where(.sidebar-status-dot.sidebar-status-dot--active) {
  background: var(--_sb-dot-active);
}

:where(.sidebar-status-dot.sidebar-status-dot--warn) {
  background: var(--status-warning, var(--status-amber, #c96a00));
}

:where(.sidebar-status-dot.sidebar-status-dot--paused) {
  background: var(--_sb-dot-paused);
}

:where(.sidebar-status-label) {
  font-size: 12px;
  font-weight: 500;
  line-height: 1.3;
  color: var(--_sb-ink);
  font-variant-numeric: tabular-nums;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.sidebar-tray-row) {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--ink-tertiary, var(--_sb-tertiary));
  font-size: 11px;
  font-weight: 400;
  line-height: 1.25;
}

:where(.sidebar-tray-icon-wrap) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 14px;
  height: 14px;
  color: var(--ink-tertiary, var(--_sb-tertiary));
  opacity: 1;
}

:where(.sidebar-tray-icon) {
  width: 14px;
  height: 14px;
  display: block;
}

:where(.sidebar-tray-label) {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.sidebar .sr-only) {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
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

function formatVersionPill(version: string | undefined | null): string {
  const trimmed = version?.trim();
  const normalized = trimmed ? trimmed.replace(/^[vV]/, "") : "";
  const base = normalized.length > 0 ? normalized : "0.6.1";
  return `v${base}`;
}

interface FooterStatusPresentation {
  tone: FooterStatusTone;
  label: string;
  title: string;
}

function deriveFooterStatus(
  status: DesktopStatusSnapshot | null,
  vpnCoexistence: VpnCoexistence | undefined,
  lang: ResolvedLanguage,
): FooterStatusPresentation {
  if (!status) {
    return {
      tone: "paused",
      label: tShell(lang, "statusPaused"),
      title: tShell(lang, "statusPausedTitle"),
    };
  }

  const live = status.live;
  const engine = live?.engine ?? status.configuredEngine;
  const vpnConflict =
    (live?.vpnConflict ?? status.vpnConflict)?.trim() || null;
  const isLiveRunning = Boolean(live?.running);
  const wintunMissing =
    engine === "tun" &&
    (status.platform === "windows" || status.wintun.required) &&
    !status.wintun.ready;

  if (status.serviceState === "not_installed") {
    return {
      tone: "warn",
      label: tShell(lang, "statusSetupNeeded"),
      title: tShell(lang, "statusServiceNotInstalledTitle"),
    };
  }

  if (wintunMissing && !isLiveRunning) {
    return {
      tone: "warn",
      label: tShell(lang, "statusDriverMissing"),
      title: status.wintun.message
        ? localizeActionMessage(lang, status.wintun.message)
        : tShell(lang, "statusWintunMissingTitle"),
    };
  }

  const activeEngineLabel =
    engine === "proxy"
      ? tShell(lang, "statusProxyActive", { port: live?.port ?? 8080 })
      : tShell(lang, "statusTunActive");

  const isYielded = Boolean(
    status.serviceState === "running" &&
      vpnConflict &&
      !live?.running &&
      vpnCoexistence === "auto_yield",
  );

  if (isYielded && vpnConflict) {
    return {
      tone: "warn",
      label: tShell(lang, "statusPausedVpn"),
      title: tShell(lang, "statusYieldedVpnTitle", { vpn: vpnConflict }),
    };
  }

  if (isLiveRunning) {
    if (vpnConflict && vpnCoexistence !== "off") {
      return {
        tone: "warn",
        label: activeEngineLabel,
        title: tShell(lang, "statusVpnConflictTitle", { vpn: vpnConflict }),
      };
    }
    return {
      tone: "active",
      label: activeEngineLabel,
      title:
        engine === "proxy"
          ? tShell(lang, "statusProtectedProxyTitle", {
              port: live?.port ?? 8080,
            })
          : tShell(lang, "statusProtectedTunTitle"),
    };
  }

  if (status.serviceState === "running") {
    return {
      tone: "warn",
      label: tShell(lang, "statusStarting"),
      title: tShell(lang, "statusStartingTitle"),
    };
  }

  return {
    tone: "paused",
    label: tShell(lang, "statusPaused"),
    title: tShell(lang, "statusPausedTitle"),
  };
}

function SidebarComponent({
  activeTab,
  onSelectTab,
  status,
  hasAppUpdate = false,
  latestReleaseVersion = null,
  keepInTrayOnClose = false,
  trayActive,
  vpnCoexistence,
  className,
}: SidebarProps) {
  const { lang } = useLang();

  useEffect(() => {
    ensureStyles();
  }, []);

  const versionText = formatVersionPill(status?.appVersion);
  const showSplitCount = Boolean(status && status.splitTunnelMode !== "all");
  const splitCount = status?.splitTunnelCount ?? 0;
  const isSplitIncludeEmpty = Boolean(
    status && status.splitTunnelMode === "include" && splitCount === 0,
  );
  const splitCountTitle = isSplitIncludeEmpty
    ? tShell(lang, "splitIncludeEmpty")
    : status?.splitTunnelMode === "include"
      ? splitCount === 1
        ? tShell(lang, "splitIncludeOne")
        : tShell(lang, "splitIncludeMany", { count: splitCount })
      : splitCount === 1
        ? tShell(lang, "splitExcludeOne")
        : tShell(lang, "splitExcludeMany", { count: splitCount });

  const hasEngineUpgrade =
    status?.cliVersionRelation === "upgrade_available";
  const hasUpdateAvailable = Boolean(hasAppUpdate || hasEngineUpgrade);
  const needsSetup = status?.serviceState === "not_installed";
  const needsRepair = status?.cliVersionRelation === "repair_needed";
  const showInstallBadge = hasUpdateAvailable || needsSetup || needsRepair;
  const installBadgeTone: "update" | "setup" | null = hasUpdateAvailable
    ? "update"
    : needsSetup || needsRepair
      ? "setup"
      : null;
  const installBadgeTitle = hasAppUpdate
    ? latestReleaseVersion?.trim()
      ? tShell(lang, "updateBadgeAppAvailable", {
          version: formatVersionPill(latestReleaseVersion),
        })
      : tShell(lang, "updateBadgeAvailable")
    : hasEngineUpgrade
      ? status?.bundledEngineVersion?.trim()
        ? tShell(lang, "updateBadgeEngineUpgrade", {
            version: formatVersionPill(status.bundledEngineVersion),
          })
        : tShell(lang, "updateBadgeAvailable")
      : needsSetup
        ? tShell(lang, "updateBadgeSetupNeeded")
        : needsRepair
          ? tShell(lang, "updateBadgeRepairNeeded")
          : null;

  const isInstallActive = activeTab === "installation";
  const installLabel = tShell(lang, "navInstallation");
  const installItemClasses = [
    "sidebar-nav-item",
    isInstallActive ? "is-active" : null,
  ]
    .filter(Boolean)
    .join(" ");

  const footerStatus = deriveFooterStatus(status, vpnCoexistence, lang);
  const wantsTray = Boolean(trayActive ?? keepInTrayOnClose);
  const traySupported = status?.traySupported !== false;
  const isTrayActive = wantsTray && traySupported;
  const isTrayUnavailable = wantsTray && !traySupported;
  const isMac = status?.platform === "macos";
  const trayLabel = isTrayUnavailable
    ? tShell(lang, "trayUnavailable")
    : isTrayActive
      ? isMac
        ? tShell(lang, "trayMenuBar")
        : tShell(lang, "trayOn")
      : tShell(lang, "trayWindowOnly");
  const trayTitle = isTrayUnavailable
    ? tShell(lang, "trayUnavailableTitle")
    : isTrayActive
      ? isMac
        ? tShell(lang, "trayMenuBarTitle")
        : tShell(lang, "trayOnTitle")
      : tShell(lang, "trayWindowOnlyTitle");

  const sidebarClasses = ["sidebar", className].filter(Boolean).join(" ");
  const splitPillClasses = [
    "sidebar-nav-pill",
    "tabular-nums",
    isSplitIncludeEmpty ? "sidebar-nav-pill--warn" : null,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <aside className={sidebarClasses} aria-label={tShell(lang, "navAsideAria")}>
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <span className="sidebar-brand-icon" aria-hidden="true">
            <BrandMark size={20} className="sidebar-brand-mark" />
          </span>
          <span className="sidebar-wordmark">vdpi</span>
        </div>
        <span className="sidebar-version-pill tabular-nums">{versionText}</span>
      </div>

      <nav
        className="sidebar-nav"
        aria-label={tShell(lang, "navPrimaryAria")}
      >
        <div className="sidebar-nav-primary">
          {NAV_ITEMS.map(({ id, labelKey, shortcut, Icon }) => {
            const isActive = activeTab === id;
            const isSplit = id === "split";
            const label = tShell(lang, labelKey);
            const itemClasses = [
              "sidebar-nav-item",
              isActive ? "is-active" : null,
            ]
              .filter(Boolean)
              .join(" ");

            return (
              <button
                key={id}
                type="button"
                className={itemClasses}
                aria-current={isActive ? "page" : undefined}
                aria-keyshortcuts={shortcut}
                data-tab={id}
                data-active={isActive ? "true" : undefined}
                onClick={() => onSelectTab(id)}
              >
                <span className="sidebar-nav-icon-wrap" aria-hidden="true">
                  <Icon size={16} className="sidebar-nav-icon" />
                </span>
                <span className="sidebar-nav-label">{label}</span>
                {isSplit && showSplitCount ? (
                  <>
                    <span
                      className={splitPillClasses}
                      data-tone={isSplitIncludeEmpty ? "warn" : undefined}
                      title={splitCountTitle}
                      aria-hidden="true"
                    >
                      {splitCount}
                    </span>
                    <span className="sr-only"> ({splitCountTitle})</span>
                  </>
                ) : null}
              </button>
            );
          })}
        </div>

        <div className="sidebar-nav-bottom">
          <button
            type="button"
            className={installItemClasses}
            aria-current={isInstallActive ? "page" : undefined}
            aria-keyshortcuts="Control+6"
            data-tab="installation"
            data-active={isInstallActive ? "true" : undefined}
            title={installBadgeTitle ?? undefined}
            onClick={() => onSelectTab("installation")}
          >
            <span className="sidebar-nav-icon-wrap" aria-hidden="true">
              <IconInstall size={16} className="sidebar-nav-icon" />
            </span>
            <span className="sidebar-nav-label">{installLabel}</span>
            {showInstallBadge && installBadgeTone && installBadgeTitle ? (
              <>
                <span
                  className={`sidebar-nav-update-badge sidebar-nav-update-badge--${installBadgeTone}`}
                  aria-hidden="true"
                  data-testid="sidebar-install-badge"
                  data-tone={installBadgeTone}
                >
                  {hasUpdateAvailable ? (
                    <IconUpdateBadge
                      size={15}
                      className="sidebar-nav-update-icon"
                    />
                  ) : (
                    <span className="sidebar-install-dot" />
                  )}
                </span>
                <span className="sr-only"> ({installBadgeTitle})</span>
              </>
            ) : null}
          </button>
        </div>
      </nav>

      <footer className="sidebar-footer">
        <div
          className="sidebar-status-row"
          data-status-tone={footerStatus.tone}
          title={footerStatus.title}
        >
          <span className="sidebar-status-dot-wrap" aria-hidden="true">
            <span
              className={`sidebar-status-dot sidebar-status-dot--${footerStatus.tone}`}
            />
          </span>
          <span className="sidebar-status-label tabular-nums">
            {footerStatus.label}
          </span>
          {footerStatus.tone === "warn" &&
          footerStatus.title &&
          footerStatus.title !== footerStatus.label ? (
            <span className="sr-only"> ({footerStatus.title})</span>
          ) : null}
        </div>

        <div
          className="sidebar-tray-row"
          data-tray={
            isTrayUnavailable ? "unavailable" : isTrayActive ? "on" : "off"
          }
          title={trayTitle}
        >
          <span className="sidebar-tray-icon-wrap" aria-hidden="true">
            <IconTray size={14} className="sidebar-tray-icon" />
          </span>
          <span className="sidebar-tray-label">{trayLabel}</span>
        </div>
      </footer>
    </aside>
  );
}

function areSidebarPropsEqual(
  prev: SidebarProps,
  next: SidebarProps,
): boolean {
  if (
    prev.activeTab !== next.activeTab ||
    prev.onSelectTab !== next.onSelectTab ||
    prev.className !== next.className ||
    prev.hasAppUpdate !== next.hasAppUpdate ||
    prev.latestReleaseVersion !== next.latestReleaseVersion ||
    prev.trayActive !== next.trayActive ||
    prev.keepInTrayOnClose !== next.keepInTrayOnClose ||
    prev.vpnCoexistence !== next.vpnCoexistence
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
    prevStatus.serviceState === nextStatus.serviceState &&
    prevStatus.configuredEngine === nextStatus.configuredEngine &&
    prevStatus.vpnConflict === nextStatus.vpnConflict &&
    prevStatus.wintun.ready === nextStatus.wintun.ready &&
    prevStatus.wintun.required === nextStatus.wintun.required &&
    prevStatus.wintun.message === nextStatus.wintun.message &&
    Boolean(prevStatus.live) === Boolean(nextStatus.live) &&
    prevStatus.live?.running === nextStatus.live?.running &&
    prevStatus.live?.engine === nextStatus.live?.engine &&
    prevStatus.live?.port === nextStatus.live?.port &&
    prevStatus.live?.vpnConflict === nextStatus.live?.vpnConflict &&
    prevStatus.splitTunnelMode === nextStatus.splitTunnelMode &&
    prevStatus.splitTunnelCount === nextStatus.splitTunnelCount &&
    prevStatus.appVersion === nextStatus.appVersion &&
    prevStatus.traySupported === nextStatus.traySupported &&
    prevStatus.cliVersionRelation === nextStatus.cliVersionRelation &&
    prevStatus.bundledEngineVersion === nextStatus.bundledEngineVersion &&
    prevStatus.pendingOperation === nextStatus.pendingOperation
  );
}

export const Sidebar = memo(SidebarComponent, areSidebarPropsEqual);
Sidebar.displayName = "Sidebar";

export default Sidebar;
