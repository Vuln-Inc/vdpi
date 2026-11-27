import { memo, useEffect } from "react";
import type { ComponentType } from "react";
import type {
  DesktopStatusSnapshot,
  NavTab,
  VpnCoexistence,
} from "../types";
import {
  BrandMark,
  IconDiagnostics,
  IconDns,
  IconOverview,
  IconSettings,
  IconSplitTunnel,
  IconTray,
} from "./Icons";

export interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  status: DesktopStatusSnapshot | null;
  keepInTrayOnClose?: boolean;
  trayActive?: boolean;
  vpnCoexistence?: VpnCoexistence;
  className?: string;
}

type FooterStatusTone = "active" | "warn" | "paused";

interface NavItemConfig {
  id: NavTab;
  label: string;
  Icon: ComponentType<{ size?: number; className?: string }>;
}

const NAV_ITEMS: ReadonlyArray<NavItemConfig> = [
  { id: "overview", label: "Overview", Icon: IconOverview },
  { id: "split", label: "Split Tunnel", Icon: IconSplitTunnel },
  { id: "dns", label: "DNS & Rules", Icon: IconDns },
  { id: "diagnostics", label: "Diagnostics", Icon: IconDiagnostics },
  { id: "settings", label: "Settings", Icon: IconSettings },
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
  gap: 2px;
  flex: 1 1 auto;
  padding: 4px 10px 12px;
  overflow-y: auto;
  box-sizing: border-box;
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
  background: var(--_sb-dot-warn);
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
  gap: 6px;
  padding-left: 1px;
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
  const base = trimmed && trimmed.length > 0 ? trimmed : "0.6.0";
  return base.startsWith("v") ? base : `v${base}`;
}

interface FooterStatusPresentation {
  tone: FooterStatusTone;
  label: string;
  title: string;
}

function deriveFooterStatus(
  status: DesktopStatusSnapshot | null,
  vpnCoexistence?: VpnCoexistence,
): FooterStatusPresentation {
  if (!status) {
    return {
      tone: "paused",
      label: "Paused",
      title: "Protection paused",
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
      label: "Setup needed",
      title: "Service not installed",
    };
  }

  if (wintunMissing && !isLiveRunning) {
    return {
      tone: "warn",
      label: "Driver missing",
      title: status.wintun.message ?? "wintun.dll missing",
    };
  }

  const activeEngineLabel =
    engine === "proxy"
      ? `Proxy · :${live?.port ?? 8080}`
      : "TUN · Active";

  const isYielded = Boolean(
    status.serviceState === "running" &&
      vpnConflict &&
      !live?.running &&
      vpnCoexistence === "auto_yield",
  );

  if (isYielded && vpnConflict) {
    return {
      tone: "warn",
      label: "Paused (VPN)",
      title: `Yielded to VPN (${vpnConflict})`,
    };
  }

  if (isLiveRunning) {
    if (vpnConflict && vpnCoexistence !== "off") {
      return {
        tone: "warn",
        label: activeEngineLabel,
        title: `VPN conflict detected (${vpnConflict})`,
      };
    }
    return {
      tone: "active",
      label: activeEngineLabel,
      title:
        engine === "proxy"
          ? `Protected via local proxy on port ${live?.port ?? 8080}`
          : "Protected via TUN adapter",
    };
  }

  if (status.serviceState === "running") {
    return {
      tone: "warn",
      label: "Starting...",
      title: "Starting protection service",
    };
  }

  return {
    tone: "paused",
    label: "Paused",
    title: "Protection paused",
  };
}

function SidebarComponent({
  activeTab,
  onSelectTab,
  status,
  keepInTrayOnClose = false,
  trayActive,
  vpnCoexistence,
  className,
}: SidebarProps) {
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
    ? "0 included apps (no apps protected)"
    : status?.splitTunnelMode === "include"
      ? `${splitCount} included ${splitCount === 1 ? "app" : "apps"}`
      : `${splitCount} excluded ${splitCount === 1 ? "app" : "apps"}`;

  const footerStatus = deriveFooterStatus(status, vpnCoexistence);
  const wantsTray = Boolean(trayActive ?? keepInTrayOnClose);
  const traySupported = status?.traySupported !== false;
  const isTrayActive = wantsTray && traySupported;
  const isTrayUnavailable = wantsTray && !traySupported;
  const isMac = status?.platform === "macos";
  const trayLabel = isTrayUnavailable
    ? "Tray unavailable"
    : isTrayActive
      ? isMac
        ? "Menu bar"
        : "Tray on"
      : "Window only";
  const trayTitle = isTrayUnavailable
    ? "System tray is unavailable in this desktop environment"
    : isTrayActive
      ? isMac
        ? "vdpi stays available in the menu bar"
        : "vdpi stays available in the system tray"
      : "Closing the window exits the UI window";

  const sidebarClasses = ["sidebar", className].filter(Boolean).join(" ");
  const splitPillClasses = [
    "sidebar-nav-pill",
    "tabular-nums",
    isSplitIncludeEmpty ? "sidebar-nav-pill--warn" : null,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <aside className={sidebarClasses} aria-label="Application navigation">
      <div className="sidebar-header">
        <div className="sidebar-brand">
          <span className="sidebar-brand-icon" aria-hidden="true">
            <BrandMark size={20} className="sidebar-brand-mark" />
          </span>
          <span className="sidebar-wordmark">vdpi</span>
        </div>
        <span className="sidebar-version-pill tabular-nums">{versionText}</span>
      </div>

      <nav className="sidebar-nav" role="navigation" aria-label="Primary">
        {NAV_ITEMS.map(({ id, label, Icon }) => {
          const isActive = activeTab === id;
          const isSplit = id === "split";
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
      </nav>

      <footer className="sidebar-footer">
        <div
          className="sidebar-status-row"
          data-status-tone={footerStatus.tone}
          title={footerStatus.title}
        >
          <span
            className={`sidebar-status-dot sidebar-status-dot--${footerStatus.tone}`}
            aria-hidden="true"
          />
          <span className="sidebar-status-label tabular-nums">
            {footerStatus.label}
          </span>
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
    prevStatus.traySupported === nextStatus.traySupported
  );
}

export const Sidebar = memo(SidebarComponent, areSidebarPropsEqual);
Sidebar.displayName = "Sidebar";

export default Sidebar;
