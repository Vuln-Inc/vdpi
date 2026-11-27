import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import {
  IconCheck,
  IconChevron,
  IconCopy,
  IconDiagnostics,
  IconFolder,
  IconOverview,
  IconSettings,
  IconShield,
} from "../components/Icons";
import { InlineBanner } from "../components/InlineBanner";
import type { ToastTone } from "../components/ToastStack";
import { formatClockTime, formatLatency, scrubUrlsInText } from "../lib/format";
import { runDiagnostics, type AppFolderTarget } from "../lib/ipc";
import type {
  DesktopStatusSnapshot,
  DiagnosticCheckItem,
  DiagnosticsReport,
  DiagStatus,
  EngineMode,
  NavTab,
} from "../types";

export interface DiagnosticsViewProps {
  status: DesktopStatusSnapshot | null;
  busyAction?: string | null;
  onPushToast?: (tone: ToastTone, message: string) => void;
  onNavigate?: (tab: NavTab) => void;
  onSwitchEngine?: (engine: EngineMode) => void | Promise<void>;
  onStartProtection?: () => void | Promise<void>;
  onOpenAppFolder?: (kind: AppFolderTarget) => void | Promise<void>;
}

interface ProbeCatalogItem {
  id: string;
  label: string;
  description: string;
}

const PROBE_CATALOG: readonly ProbeCatalogItem[] = [
  {
    id: "vpn",
    label: "VPN coexistence",
    description: "Detects active full-tunnel VPN adapters and routing conflicts.",
  },
  {
    id: "wintun",
    label: "Wintun driver",
    description: "Verifies wintun.dll presence and SHA-256 integrity on disk.",
  },
  {
    id: "dns",
    label: "DNS / DoH",
    description: "Probes configured resolver reachability and encrypted DNS responses.",
  },
  {
    id: "discord",
    label: "Discord",
    description: "Checks Discord HTTPS gateway reachability and TLS latency.",
  },
  {
    id: "roblox",
    label: "Roblox",
    description: "Tests Roblox client endpoints and connection latency.",
  },
  {
    id: "runtime",
    label: "Runtime hygiene",
    description: "Inspects background service health, config state, and runtime files.",
  },
];

const STATUS_LABELS: Record<DiagStatus, string> = {
  idle: "Idle",
  running: "Running",
  pass: "Pass",
  warn: "Warn",
  fail: "Fail",
};

const STYLE_ID = "vdpi-diagnostics-view-styles";

const FALLBACK_STYLES = `
@keyframes vdpi-diag-spin {
  to {
    transform: rotate(360deg);
  }
}

:where(.diag-view) {
  --_dv-surface: var(--bg-surface, var(--surface, #131518));
  --_dv-surface-subtle: var(--bg-surface-subtle, var(--surface-subtle, #171a1f));
  --_dv-surface-hover: var(--bg-surface-hover, var(--surface-raised, #21252d));
  --_dv-border: var(--border-subtle, var(--border, rgba(255, 255, 255, 0.1)));
  --_dv-border-hairline: var(--border-hairline, rgba(255, 255, 255, 0.07));
  --_dv-border-strong: var(--border-strong, rgba(255, 255, 255, 0.22));
  --_dv-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_dv-secondary: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_dv-tertiary: var(--ink-tertiary, #7c828e);
  --_dv-muted: var(--ink-muted, #5c616c);
  --_dv-accent: var(--accent, #3b82f6);
  --_dv-accent-hover: var(--accent-hover, #4b8df8);
  --_dv-on-accent: var(--ink-on-accent, #ffffff);
  --_dv-green: var(--status-green, #30d158);
  --_dv-green-fg: var(--status-green-fg, #30d158);
  --_dv-green-bg: var(--status-green-bg, rgba(48, 209, 88, 0.12));
  --_dv-green-border: var(--status-green-border, rgba(48, 209, 88, 0.28));
  --_dv-amber: var(--status-amber, #ff9f0a);
  --_dv-crimson: var(--status-crimson, #ff453a);
  --_dv-neutral: var(--status-neutral, #7c828e);
  --_dv-neutral-bg: var(--status-neutral-bg, rgba(255, 255, 255, 0.06));
  --_dv-neutral-border: var(--status-neutral-border, rgba(255, 255, 255, 0.12));
  --_dv-mono: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-direction: column;
  gap: 16px;
  color: var(--_dv-ink);
  box-sizing: border-box;
  min-height: 100%;
}

:where([data-theme="light"] .diag-view) {
  --_dv-surface: var(--bg-surface, var(--surface, #ffffff));
  --_dv-surface-subtle: var(--bg-surface-subtle, var(--surface-subtle, #f1f3f6));
  --_dv-surface-hover: var(--bg-surface-hover, var(--surface-raised, #e9ecf1));
  --_dv-border: var(--border-subtle, var(--border, rgba(11, 12, 14, 0.1)));
  --_dv-border-hairline: var(--border-hairline, rgba(11, 12, 14, 0.07));
  --_dv-border-strong: var(--border-strong, rgba(11, 12, 14, 0.24));
  --_dv-ink: var(--ink-primary, var(--text-primary, #111317));
  --_dv-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_dv-tertiary: var(--ink-tertiary, #4E5563);
  --_dv-muted: var(--ink-muted, #5A6270);
  --_dv-accent: var(--accent, #0066cc);
  --_dv-accent-hover: var(--accent-hover, #0055b3);
  --_dv-green: var(--status-green, #18793A);
  --_dv-green-fg: var(--status-green-fg, #18793a);
  --_dv-green-bg: var(--status-green-bg, rgba(48, 209, 88, 0.12));
  --_dv-green-border: var(--status-green-border, rgba(24, 121, 58, 0.24));
  --_dv-amber: var(--status-amber, #C96A00);
  --_dv-crimson: var(--status-crimson, #C82320);
  --_dv-neutral: var(--status-neutral, #6b7280);
  --_dv-neutral-bg: var(--status-neutral-bg, rgba(11, 12, 14, 0.05));
  --_dv-neutral-border: var(--status-neutral-border, rgba(11, 12, 14, 0.12));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .diag-view) {
    --_dv-surface: var(--bg-surface, var(--surface, #ffffff));
    --_dv-surface-subtle: var(--bg-surface-subtle, var(--surface-subtle, #f1f3f6));
    --_dv-surface-hover: var(--bg-surface-hover, var(--surface-raised, #e9ecf1));
    --_dv-border: var(--border-subtle, var(--border, rgba(11, 12, 14, 0.1)));
    --_dv-border-hairline: var(--border-hairline, rgba(11, 12, 14, 0.07));
    --_dv-border-strong: var(--border-strong, rgba(11, 12, 14, 0.24));
    --_dv-ink: var(--ink-primary, var(--text-primary, #111317));
    --_dv-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_dv-tertiary: var(--ink-tertiary, #4E5563);
    --_dv-muted: var(--ink-muted, #5A6270);
    --_dv-accent: var(--accent, #0066cc);
    --_dv-accent-hover: var(--accent-hover, #0055b3);
    --_dv-green: var(--status-green, #18793A);
    --_dv-green-fg: var(--status-green-fg, #18793a);
    --_dv-green-bg: var(--status-green-bg, rgba(48, 209, 88, 0.12));
    --_dv-green-border: var(--status-green-border, rgba(24, 121, 58, 0.24));
    --_dv-amber: var(--status-amber, #C96A00);
    --_dv-crimson: var(--status-crimson, #C82320);
    --_dv-neutral: var(--status-neutral, #6b7280);
    --_dv-neutral-bg: var(--status-neutral-bg, rgba(11, 12, 14, 0.05));
    --_dv-neutral-border: var(--status-neutral-border, rgba(11, 12, 14, 0.12));
  }
}

:where(.diag-header) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}

:where(.diag-header__text) {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
  flex: 1 1 260px;
}

:where(.diag-header__title) {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  line-height: 1.25;
  letter-spacing: -0.015em;
  color: var(--_dv-ink);
}

:where(.diag-header__subtitle) {
  margin: 0;
  font-size: 13px;
  line-height: 1.45;
  color: var(--_dv-secondary);
}

:where(.diag-header__actions) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  flex-shrink: 0;
}

:where(.diag-btn) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  min-height: 34px;
  padding: 0 13px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid transparent;
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease, opacity 120ms ease;
}

:where(.diag-btn:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_dv-accent));
  outline-offset: 2px;
}

:where(.diag-btn:disabled) {
  opacity: 0.5;
  cursor: not-allowed;
}

:where(.diag-btn--primary) {
  background: var(--_dv-accent);
  color: var(--_dv-on-accent);
}

:where(.diag-btn--primary:hover:not(:disabled)) {
  background: var(--_dv-accent-hover);
}

:where(.diag-btn--secondary) {
  background: var(--_dv-surface);
  border-color: var(--_dv-border);
  color: var(--_dv-ink);
}

:where(.diag-btn--secondary:hover:not(:disabled)) {
  background: var(--_dv-surface-hover);
  border-color: var(--_dv-border-strong);
}

:where(.diag-btn--copied) {
  border-color: var(--_dv-green-border);
  color: var(--_dv-green-fg);
}

:where(.diag-spinner) {
  display: inline-block;
  width: 13px;
  height: 13px;
  border-radius: 9999px;
  border: 1.75px solid currentColor;
  border-right-color: transparent;
  flex-shrink: 0;
  animation: vdpi-diag-spin 0.72s linear infinite;
}

:where(.diag-summary-banner--pass) {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  border-radius: var(--radius-lg, 10px);
  border: 1px solid var(--_dv-green-border);
  border-left: 3px solid var(--_dv-green);
  background: var(--_dv-green-bg);
  color: var(--_dv-ink);
  box-sizing: border-box;
}

:where(.diag-summary-banner__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 18px;
  height: 18px;
  margin-top: 1px;
  color: var(--_dv-green-fg);
}

:where(.diag-summary-banner__content) {
  flex: 1 1 auto;
  min-width: 0;
}

:where(.diag-summary-banner__title) {
  margin: 0;
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_dv-ink);
}

:where(.diag-summary-banner__description) {
  margin: 3px 0 0;
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--_dv-secondary);
}

:where(.diag-recovery-bar) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  padding: 10px 14px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_dv-border);
  background: var(--_dv-surface-subtle);
  box-sizing: border-box;
}

:where(.diag-recovery-bar__label) {
  font-size: 12px;
  font-weight: 500;
  color: var(--_dv-secondary);
}

:where(.diag-recovery-bar__actions) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.diag-card) {
  background: var(--_dv-surface);
  border: 1px solid var(--_dv-border);
  border-radius: var(--radius-lg, 10px);
  overflow: hidden;
  box-sizing: border-box;
}

:where(.diag-results-card[data-running="true"]) {
  opacity: 0.72;
  transition: opacity 140ms ease;
}

:where(.diag-results-card .diag-table-wrap) {
  border: 0;
  border-radius: 0;
}

:where(.diag-results-head) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--_dv-border-hairline);
  background: var(--_dv-surface-subtle);
  flex-wrap: wrap;
}

:where(.diag-results-title) {
  margin: 0;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--_dv-secondary);
}

:where(.diag-results-head__meta) {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.diag-stale-note) {
  display: inline-flex;
  align-items: center;
  height: 20px;
  padding: 0 7px;
  border-radius: var(--radius-pill, 9999px);
  border: 1px solid var(--status-amber-border, rgba(255, 159, 10, 0.28));
  background: var(--status-amber-bg, rgba(255, 159, 10, 0.12));
  color: var(--status-amber-fg, var(--_dv-amber));
  font-size: 11px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
}

:where(.diag-results-meta) {
  font-family: var(--_dv-mono);
  font-size: 11.5px;
  color: var(--_dv-tertiary);
  font-variant-numeric: tabular-nums;
}

:where(.diag-table-wrap) {
  width: 100%;
  overflow-x: auto;
}

:where(.diag-table) {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  font-size: 13px;
}

:where(.diag-table th) {
  padding: 9px 16px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--_dv-tertiary);
  border-bottom: 1px solid var(--_dv-border-hairline);
  background: var(--_dv-surface);
  white-space: nowrap;
}

:where(.diag-table td) {
  padding: 11px 16px;
  vertical-align: top;
  border-bottom: 1px solid var(--_dv-border-hairline);
  color: var(--_dv-ink);
}

:where(.diag-table tbody tr:last-child td) {
  border-bottom: none;
}

:where(.diag-table tbody tr:hover) {
  background: var(--_dv-surface-subtle);
}

:where(.diag-col-check) {
  width: 44%;
}

:where(.diag-col-target) {
  width: 28%;
}

:where(.diag-col-latency) {
  width: 14%;
  text-align: right;
  white-space: nowrap;
}

:where(.diag-col-status) {
  width: 14%;
  text-align: right;
  white-space: nowrap;
}

:where(.diag-check-cell) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

:where(.diag-check-name) {
  font-size: 13px;
  font-weight: 500;
  line-height: 1.35;
  color: var(--_dv-ink);
}

:where(.diag-check-summary) {
  margin: 0;
  font-size: 12px;
  line-height: 1.4;
  color: var(--_dv-secondary);
  word-break: break-word;
}

:where(.diag-check-detail) {
  margin: 2px 0 0;
  font-family: var(--_dv-mono);
  font-size: 11px;
  line-height: 1.4;
  color: var(--_dv-tertiary);
  word-break: break-word;
}

:where(.diag-target) {
  display: block;
  font-family: var(--_dv-mono);
  font-size: 12px;
  line-height: 1.4;
  color: var(--_dv-secondary);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.diag-latency) {
  font-family: var(--_dv-mono);
  font-size: 12px;
  line-height: 1.4;
  color: var(--_dv-secondary);
  font-variant-numeric: tabular-nums;
}

:where(.diag-status-pill) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 22px;
  padding: 0 8px;
  border-radius: var(--radius-pill, 9999px);
  border: 1px solid var(--_dv-neutral-border);
  background: var(--_dv-neutral-bg);
  color: var(--_dv-ink);
  font-size: 11.5px;
  font-weight: 500;
  line-height: 1;
  box-sizing: border-box;
}

:where(.diag-status-dot) {
  width: 6px;
  height: 6px;
  border-radius: 9999px;
  flex-shrink: 0;
  background: var(--_dv-neutral);
  box-shadow: none;
}

:where(.diag-status-dot--pass) {
  background: var(--_dv-green);
}

:where(.diag-status-dot--warn) {
  background: var(--_dv-amber);
}

:where(.diag-status-dot--fail) {
  background: var(--_dv-crimson);
}

:where(.diag-status-dot--running) {
  background: var(--_dv-accent);
}

:where(.diag-preview) {
  border-top: 1px solid var(--_dv-border-hairline);
  background: var(--_dv-surface);
}

:where(.diag-preview__toggle) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  padding: 10px 16px;
  border: 0;
  background: transparent;
  color: var(--_dv-secondary);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  text-align: left;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 120ms ease, color 120ms ease;
}

:where(.diag-preview__toggle:hover) {
  background: var(--_dv-surface-subtle);
  color: var(--_dv-ink);
}

:where(.diag-preview__toggle:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_dv-accent));
  outline-offset: -2px;
}

:where(.diag-preview__label) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

:where(.diag-preview__chevron) {
  color: var(--_dv-tertiary);
  transition: transform 120ms ease;
}

:where(.diag-preview__chevron--open) {
  transform: rotate(90deg);
}

:where(.diag-preview__body) {
  padding: 0 16px 14px;
}

:where(.diag-preview__pre) {
  margin: 0;
  padding: 10px 12px;
  max-height: 220px;
  overflow: auto;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_dv-border-hairline);
  background: var(--bg-input, var(--_dv-surface-subtle));
  color: var(--_dv-secondary);
  font-family: var(--_dv-mono);
  font-size: 11.5px;
  line-height: 1.5;
  white-space: pre-wrap;
  word-break: break-word;
  user-select: text;
}

:where(.diag-results-foot) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 10px 16px;
  border-top: 1px solid var(--_dv-border-hairline);
  background: var(--_dv-surface-subtle);
  font-size: 11.5px;
  color: var(--_dv-tertiary);
  flex-wrap: wrap;
}

:where(.diag-results-foot__privacy) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

:where(.diag-empty) {
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 22px;
}

:where(.diag-empty__head) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

:where(.diag-empty__intro) {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  min-width: 0;
  flex: 1 1 280px;
}

:where(.diag-empty__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_dv-border);
  background: var(--_dv-surface-subtle);
  color: var(--_dv-secondary);
  flex-shrink: 0;
}

:where(.diag-empty__title) {
  margin: 0;
  font-size: 14.5px;
  font-weight: 600;
  line-height: 1.3;
  color: var(--_dv-ink);
}

:where(.diag-empty__description) {
  margin: 4px 0 0;
  font-size: 12.5px;
  line-height: 1.5;
  color: var(--_dv-secondary);
}

:where(.diag-readonly-badge) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 24px;
  padding: 0 9px;
  border-radius: var(--radius-pill, 9999px);
  border: 1px solid var(--_dv-neutral-border);
  background: var(--_dv-neutral-bg);
  color: var(--_dv-secondary);
  font-size: 11.5px;
  font-weight: 500;
  white-space: nowrap;
  flex-shrink: 0;
}

:where(.diag-probe-grid) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin: 0;
  padding: 0;
  list-style: none;
}

:where(.diag-probe-item) {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 11px 12px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_dv-border-hairline);
  background: var(--_dv-surface-subtle);
  box-sizing: border-box;
}

:where(.diag-probe-item__name) {
  font-size: 12.5px;
  font-weight: 600;
  line-height: 1.3;
  color: var(--_dv-ink);
}

:where(.diag-probe-item__desc) {
  font-size: 12px;
  line-height: 1.4;
  color: var(--_dv-secondary);
}

:where(.diag-running-state) {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 20px 18px;
}

:where(.diag-running-state__title) {
  margin: 0;
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_dv-ink);
}

:where(.diag-running-state__desc) {
  margin: 2px 0 0;
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--_dv-secondary);
}

@media (max-width: 680px) {
  :where(.diag-probe-grid) {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (prefers-reduced-motion: reduce) {
  :where(.diag-spinner) {
    animation: none;
  }
  :where(.diag-preview__chevron) {
    transition: none;
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

async function copyTextToClipboard(text: string): Promise<void> {
  if (
    typeof navigator !== "undefined" &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === "function"
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall back to execCommand("copy") when Clipboard API rejects
      // (e.g. unfocused WKWebView/WebKitGTK or denied permission).
    }
  }

  if (typeof document === "undefined") {
    throw new Error("Clipboard API unavailable.");
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-9999px";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  try {
    textarea.focus();
    textarea.select();
    const ok =
      typeof document.execCommand === "function" &&
      document.execCommand("copy");
    if (!ok) {
      throw new Error("Copy command failed.");
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return scrubUrlsInText(error.message.trim());
  }
  if (typeof error === "string" && error.trim().length > 0) {
    return scrubUrlsInText(error.trim());
  }
  return "Unable to complete diagnostics. Try again in a moment.";
}

function formatContextSubtitle(status: DesktopStatusSnapshot | null): string {
  if (!status) {
    return "Read-only network, DNS, and runtime health checks.";
  }

  const engineLabel =
    (status.live?.engine ?? status.configuredEngine) === "tun"
      ? "TUN engine"
      : "Proxy engine";

  const stateLabel =
    status.serviceState === "not_installed"
      ? "Service not installed"
      : status.live?.running || status.serviceState === "running"
        ? "Service running"
        : "Service stopped";

  const parts = [engineLabel, stateLabel];
  const vpnConflict = (status.live?.vpnConflict ?? status.vpnConflict)?.trim();
  if (vpnConflict) {
    parts.push(`VPN detected (${vpnConflict})`);
  }
  parts.push("100% read-only");
  return parts.join(" · ");
}

interface ReportSummaryMetrics {
  allPassed: boolean;
  passedCount: number;
  totalCount: number;
  warnCount: number;
  failCount: number;
  issueBreakdown: string;
}

function summarizeReport(report: DiagnosticsReport): ReportSummaryMetrics {
  const totalCount =
    report.totalCount > 0 ? report.totalCount : report.checks.length;
  const passedCount = report.passedCount;
  let warnCount = 0;
  let failCount = 0;

  for (const check of report.checks) {
    if (check.status === "warn") {
      warnCount += 1;
    } else if (check.status === "fail") {
      failCount += 1;
    }
  }

  // Match vdpi TUI truthfulness: only claim allPassed when the backend flag,
  // counts, and individual check statuses all agree with zero warns/fails.
  const allPassed =
    report.allPassed &&
    warnCount === 0 &&
    failCount === 0 &&
    passedCount === totalCount;

  const issueParts: string[] = [];
  if (failCount > 0) {
    issueParts.push(`${failCount} failed`);
  }
  if (warnCount > 0) {
    issueParts.push(
      warnCount === 1 ? "1 warning" : `${warnCount} warnings`,
    );
  }

  const issueBreakdown =
    issueParts.length > 0
      ? issueParts.join(", ")
      : "one or more checks need attention";

  return {
    allPassed,
    passedCount,
    totalCount,
    warnCount,
    failCount,
    issueBreakdown,
  };
}

function renderCheckRow(check: DiagnosticCheckItem) {
  const summaryText = check.summary.trim();
  const detailText = check.detail?.trim() ?? "";
  const showDetail = detailText.length > 0 && detailText !== summaryText;
  const targetText = check.target.trim() || "--";

  return (
    <tr key={check.id} data-check-id={check.id} data-status={check.status}>
      <td className="diag-col-check">
        <div className="diag-check-cell">
          <span className="diag-check-name">{check.name}</span>
          {summaryText.length > 0 ? (
            <p className="diag-check-summary">{summaryText}</p>
          ) : null}
          {showDetail ? (
            <p className="diag-check-detail">{detailText}</p>
          ) : null}
        </div>
      </td>

      <td className="diag-col-target">
        <span className="diag-target" title={targetText}>
          {targetText}
        </span>
      </td>

      <td className="diag-col-latency">
        <span className="diag-latency tabular-nums">
          {formatLatency(check.latencyMs)}
        </span>
      </td>

      <td className="diag-col-status">
        <span
          className={`diag-status-pill diag-status-pill--${check.status}`}
          data-status={check.status}
        >
          <span
            className={`diag-status-dot diag-status-dot--${check.status}`}
            aria-hidden="true"
          />
          <span>{STATUS_LABELS[check.status]}</span>
        </span>
      </td>
    </tr>
  );
}

interface RecoveryAction {
  id: string;
  label: string;
  icon: "settings" | "proxy" | "folder" | "logs" | "shield" | "overview";
  busy?: boolean;
  disabled?: boolean;
  onClick: () => void;
}

function DiagnosticsViewComponent({
  status,
  busyAction = null,
  onPushToast,
  onNavigate,
  onSwitchEngine,
  onStartProtection,
  onOpenAppFolder,
}: DiagnosticsViewProps) {
  const [report, setReport] = useState<DiagnosticsReport | null>(null);
  const [reportStatusSnap, setReportStatusSnap] = useState<{
    ranAtMs: number;
    serviceState: DesktopStatusSnapshot["serviceState"] | null;
    liveEngine: EngineMode | null;
  } | null>(null);
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [previewOpen, setPreviewOpen] = useState(false);

  const previewPanelId = useId();
  const mountedRef = useRef(true);
  const inFlightRef = useRef(false);
  const copyTimerRef = useRef<number | null>(null);
  const statusRef = useRef(status);
  statusRef.current = status;

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
        copyTimerRef.current = null;
      }
    };
  }, []);

  const isWindows = status?.platform === "windows";
  const visibleCatalog = useMemo(
    () =>
      isWindows
        ? PROBE_CATALOG
        : PROBE_CATALOG.filter((item) => item.id !== "wintun"),
    [isWindows],
  );

  const subtitle = useMemo(() => formatContextSubtitle(status), [status]);

  const summary = useMemo(
    () => (report ? summarizeReport(report) : null),
    [report],
  );

  const activeEngine: EngineMode =
    status?.live?.engine ?? status?.configuredEngine ?? "tun";

  const isBusy = busyAction !== null;
  const isSwitchingProxy = busyAction === "switch-engine:proxy";
  const isStartingProtection = busyAction === "connecting";

  const recoveryActions = useMemo<RecoveryAction[]>(() => {
    if (!report || !summary || summary.allPassed) {
      return [];
    }

    const problemChecks = report.checks.filter(
      (check) => check.status === "warn" || check.status === "fail",
    );
    if (problemChecks.length === 0) {
      return [];
    }

    const hasWintunIssue = problemChecks.some((check) =>
      check.id.toLowerCase().includes("wintun"),
    );
    const hasServiceIssue = problemChecks.some((check) => {
      const id = check.id.toLowerCase();
      return id.includes("service") || id.includes("runtime");
    });
    const hasNetworkIssue = problemChecks.some((check) => {
      const id = check.id.toLowerCase();
      return (
        id.includes("discord") ||
        id.includes("roblox") ||
        id.includes("dns") ||
        id.includes("vpn")
      );
    });

    const wintunBlocked = Boolean(
      status?.platform === "windows" &&
        activeEngine === "tun" &&
        status.wintun.required &&
        !status.wintun.ready,
    );

    const actions: RecoveryAction[] = [];

    if (
      status?.serviceState === "stopped" &&
      !status.live?.running &&
      !wintunBlocked
    ) {
      if (onStartProtection) {
        actions.push({
          id: "start-protection",
          label: isStartingProtection ? "Starting..." : "Start Protection",
          icon: "shield",
          busy: isStartingProtection,
          disabled: running || isBusy,
          onClick: () => {
            void onStartProtection();
          },
        });
      } else if (onNavigate) {
        actions.push({
          id: "go-overview",
          label: "Go to Overview",
          icon: "overview",
          onClick: () => {
            onNavigate("overview");
          },
        });
      }
    } else if (status?.serviceState === "not_installed" && onNavigate) {
      actions.push({
        id: "go-overview",
        label: "Go to Overview",
        icon: "overview",
        onClick: () => {
          onNavigate("overview");
        },
      });
    }

    if (
      onSwitchEngine &&
      activeEngine !== "proxy" &&
      (hasWintunIssue || (hasNetworkIssue && summary.failCount > 0))
    ) {
      actions.push({
        id: "switch-proxy",
        label: isSwitchingProxy ? "Switching to Proxy..." : "Switch to Proxy",
        icon: "proxy",
        busy: isSwitchingProxy,
        disabled: running || isBusy,
        onClick: () => {
          void onSwitchEngine("proxy");
        },
      });
    }

    if (
      onNavigate &&
      (hasServiceIssue ||
        status?.serviceState === "not_installed" ||
        hasNetworkIssue)
    ) {
      actions.push({
        id: "open-settings",
        label: "Open Settings",
        icon: "settings",
        onClick: () => {
          onNavigate("settings");
        },
      });
    }

    if (onOpenAppFolder && hasWintunIssue) {
      actions.push({
        id: "open-app-folder",
        label: "Open App Folder",
        icon: "folder",
        onClick: () => {
          void onOpenAppFolder("app");
        },
      });
    }

    if (onOpenAppFolder) {
      actions.push({
        id: "open-logs",
        label: "Open Logs",
        icon: "logs",
        onClick: () => {
          void onOpenAppFolder("logs");
        },
      });
    }

    return actions;
  }, [
    activeEngine,
    isBusy,
    isStartingProtection,
    isSwitchingProxy,
    onNavigate,
    onOpenAppFolder,
    onStartProtection,
    onSwitchEngine,
    report,
    running,
    status?.live?.running,
    status?.platform,
    status?.serviceState,
    status?.wintun.ready,
    status?.wintun.required,
    summary,
  ]);

  const handleRunDiagnostics = useCallback(async () => {
    if (inFlightRef.current) return;
    inFlightRef.current = true;
    setRunning(true);
    setRunError(null);

    try {
      const nextReport = await runDiagnostics();
      if (!mountedRef.current) return;
      const latestStatus = statusRef.current;
      setReport(nextReport);
      setReportStatusSnap({
        ranAtMs: nextReport.ranAtMs,
        serviceState: latestStatus?.serviceState ?? null,
        liveEngine: latestStatus?.live?.engine ?? null,
      });
      setCopied(false);
    } catch (error) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(error);
      // Clear stale report so an older summary cannot contradict the run error.
      setReport(null);
      setReportStatusSnap(null);
      setCopied(false);
      setPreviewOpen(false);
      setRunError(message);
      onPushToast?.("error", message);
    } finally {
      inFlightRef.current = false;
      if (mountedRef.current) {
        setRunning(false);
      }
    }
  }, [onPushToast]);

  const hasRedactedText = Boolean(
    report && report.redactedText.trim().length > 0,
  );
  const canCopy = Boolean(!running && hasRedactedText);

  const handleCopyReport = useCallback(async () => {
    if (!report || !report.redactedText.trim()) return;

    try {
      await copyTextToClipboard(report.redactedText);
      if (!mountedRef.current) return;
      setCopied(true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        if (mountedRef.current) {
          setCopied(false);
        }
        copyTimerRef.current = null;
      }, 1800);
      onPushToast?.("success", "Redacted diagnostics report copied to clipboard.");
    } catch (error) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(error);
      onPushToast?.("error", `Failed to copy report: ${message}`);
    }
  }, [onPushToast, report]);

  const ranAtClock = report ? formatClockTime(report.ranAtMs) : null;
  const currentServiceState = status?.serviceState ?? null;
  const currentLiveEngine = status?.live?.engine ?? null;
  const statusChangedSinceRun = Boolean(
    report &&
      !running &&
      reportStatusSnap &&
      reportStatusSnap.ranAtMs === report.ranAtMs &&
      (reportStatusSnap.serviceState !== currentServiceState ||
        reportStatusSnap.liveEngine !== currentLiveEngine),
  );

  return (
    <div className="view-stack diag-view" data-view="diagnostics">
      <header className="diag-header">
        <div className="diag-header__text">
          <h1 className="diag-header__title">Diagnostics</h1>
          <p className="diag-header__subtitle tabular-nums">{subtitle}</p>
        </div>

        <div className="diag-header__actions">
          <button
            type="button"
            className={`btn btn-secondary diag-btn diag-btn--secondary${
              copied ? " diag-btn--copied" : ""
            }`}
            disabled={!canCopy}
            onClick={() => {
              void handleCopyReport();
            }}
          >
            {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
            <span>{copied ? "Copied" : "Copy Redacted Report"}</span>
          </button>

          <button
            type="button"
            className="btn btn-primary diag-btn diag-btn--primary"
            disabled={running}
            aria-busy={running}
            onClick={() => {
              void handleRunDiagnostics();
            }}
          >
            {running ? (
              <span className="spinner diag-spinner" aria-hidden="true" />
            ) : null}
            <span>{running ? "Running..." : "Run Diagnostics"}</span>
          </button>
        </div>
      </header>

      {runError ? (
        <InlineBanner
          tone="error"
          title="Diagnostics failed to run"
          description={runError}
          actionLabel="Retry"
          onAction={() => {
            void handleRunDiagnostics();
          }}
        />
      ) : null}

      {report && summary ? (
        summary.allPassed ? (
          <div
            className="inline-banner diag-summary-banner diag-summary-banner--pass"
            data-tone="success"
            role="status"
            aria-live="polite"
          >
            <span className="diag-summary-banner__icon" aria-hidden="true">
              <IconCheck size={16} />
            </span>
            <div className="diag-summary-banner__content">
              <p className="diag-summary-banner__title tabular-nums">
                {`All checks passed (${summary.passedCount}/${summary.totalCount})`}
              </p>
              <p className="diag-summary-banner__description tabular-nums">
                {isWindows
                  ? `Completed at ${ranAtClock} · All connectivity, driver, DNS, and runtime probes succeeded.`
                  : `Completed at ${ranAtClock} · All connectivity, DNS, and runtime probes succeeded.`}
              </p>
            </div>
          </div>
        ) : (
          <InlineBanner
            tone={summary.failCount > 0 ? "error" : "warn"}
            className={`diag-summary-banner ${
              summary.failCount > 0
                ? "diag-summary-banner--error"
                : "diag-summary-banner--warn"
            }`}
            title={
              summary.failCount > 0
                ? `Diagnostics failed (${summary.passedCount}/${summary.totalCount})`
                : `Diagnostics finished with warnings (${summary.passedCount}/${summary.totalCount})`
            }
            description={`Completed at ${ranAtClock} · ${summary.issueBreakdown}. Review details below or copy the redacted report.`}
          />
        )
      ) : null}

      {recoveryActions.length > 0 ? (
        <div
          className="diag-recovery-bar"
          role="group"
          aria-label="Recovery actions"
        >
          <span className="diag-recovery-bar__label">Suggested actions</span>
          <div className="diag-recovery-bar__actions">
            {recoveryActions.map((action) => (
              <button
                key={action.id}
                type="button"
                className="btn btn-secondary btn-sm"
                disabled={action.disabled ?? running}
                aria-busy={action.busy ? true : undefined}
                onClick={action.onClick}
              >
                {action.busy ? (
                  <span className="spinner diag-spinner" aria-hidden="true" />
                ) : action.icon === "settings" ? (
                  <IconSettings size={13} />
                ) : action.icon === "overview" ? (
                  <IconOverview size={13} />
                ) : action.icon === "folder" || action.icon === "logs" ? (
                  <IconFolder size={13} />
                ) : (
                  <IconShield size={13} />
                )}
                <span>{action.label}</span>
              </button>
            ))}
          </div>
        </div>
      ) : null}

      {running && !report ? (
        <section
          className="card card-flush diag-card diag-running-state"
          aria-live="polite"
          aria-busy="true"
        >
          <span className="spinner diag-spinner" aria-hidden="true" />
          <div>
            <p className="diag-running-state__title">Running diagnostics...</p>
            <p className="diag-running-state__desc">
              {isWindows
                ? "Probing VPN coexistence, Wintun driver, DNS/DoH, Discord, Roblox, and runtime hygiene. This is read-only and will not interrupt active connections."
                : "Probing VPN coexistence, DNS/DoH, Discord, Roblox, and runtime hygiene. This is read-only and will not interrupt active connections."}
            </p>
          </div>
        </section>
      ) : null}

      {report ? (
        <section
          className="card card-flush diag-card diag-results-card"
          data-running={running ? "true" : "false"}
          aria-label="Diagnostic check results"
        >
          <div className="diag-results-head">
            <h2 className="diag-results-title">Check Results</h2>
            <div className="diag-results-head__meta">
              {statusChangedSinceRun ? (
                <span className="diag-stale-note" role="status">
                  Status changed since last run
                </span>
              ) : null}
              <span className="diag-results-meta tabular-nums">
                {running
                  ? "Refreshing probes..."
                  : `Ran at ${ranAtClock} · ${report.checks.length} ${
                      report.checks.length === 1 ? "check" : "checks"
                    }`}
              </span>
            </div>
          </div>

          <div className="diag-table-wrap">
            <table className="diag-table">
              <thead>
                <tr>
                  <th scope="col" className="diag-col-check">
                    Check
                  </th>
                  <th scope="col" className="diag-col-target">
                    Target
                  </th>
                  <th scope="col" className="diag-col-latency">
                    Latency
                  </th>
                  <th scope="col" className="diag-col-status">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody>{report.checks.map(renderCheckRow)}</tbody>
            </table>
          </div>

          {hasRedactedText ? (
            <div className="diag-preview">
              <button
                type="button"
                className="diag-preview__toggle"
                aria-expanded={previewOpen}
                aria-controls={previewPanelId}
                onClick={() => setPreviewOpen((open) => !open)}
              >
                <span className="diag-preview__label">
                  <IconChevron
                    size={13}
                    direction="right"
                    className={`diag-preview__chevron${
                      previewOpen ? " diag-preview__chevron--open" : ""
                    }`}
                  />
                  <span>Preview redacted report</span>
                </span>
                <span className="tabular-nums">
                  {previewOpen ? "Hide" : "Show"}
                </span>
              </button>
              {previewOpen ? (
                <div id={previewPanelId} className="diag-preview__body">
                  <pre className="diag-preview__pre">
                    <code>{report.redactedText}</code>
                  </pre>
                </div>
              ) : null}
            </div>
          ) : null}

          <footer className="diag-results-foot">
            <span className="diag-results-foot__privacy">
              <IconShield size={13} />
              <span>
                Redacted report strips custom DoH tokens, credentials, private
                LAN IPs, and user home paths.
              </span>
            </span>
            <span className="tabular-nums">100% read-only</span>
          </footer>
        </section>
      ) : !running ? (
        <section
          className="card card-flush diag-card diag-empty"
          aria-label="Diagnostics overview"
        >
          <div className="diag-empty__head">
            <div className="diag-empty__intro">
              <span className="diag-empty__icon" aria-hidden="true">
                <IconDiagnostics size={18} />
              </span>
              <div>
                <h2 className="diag-empty__title">Ready to run diagnostics</h2>
                <p className="diag-empty__description">
                  Run a quick end-to-end health check to verify your network
                  environment and vdpi setup. Probes are strictly read-only and
                  never alter configuration, routes, or running services.
                </p>
              </div>
            </div>

            <span className="diag-readonly-badge">
              <IconShield size={13} />
              <span>100% read-only &amp; non-destructive</span>
            </span>
          </div>

          <ul className="diag-probe-grid" aria-label="Checks included">
            {visibleCatalog.map((item) => (
              <li key={item.id} className="diag-probe-item">
                <span className="diag-probe-item__name">{item.label}</span>
                <span className="diag-probe-item__desc">
                  {item.description}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ) : null}
    </div>
  );
}

function areDiagnosticsPropsEqual(
  prev: DiagnosticsViewProps,
  next: DiagnosticsViewProps,
): boolean {
  if (
    prev.busyAction !== next.busyAction ||
    prev.onPushToast !== next.onPushToast ||
    prev.onNavigate !== next.onNavigate ||
    prev.onSwitchEngine !== next.onSwitchEngine ||
    prev.onStartProtection !== next.onStartProtection ||
    prev.onOpenAppFolder !== next.onOpenAppFolder
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

  const prevLive = prevStatus.live;
  const nextLive = nextStatus.live;
  return (
    prevStatus.platform === nextStatus.platform &&
    prevStatus.serviceState === nextStatus.serviceState &&
    prevStatus.configuredEngine === nextStatus.configuredEngine &&
    prevStatus.vpnConflict === nextStatus.vpnConflict &&
    prevStatus.wintun.required === nextStatus.wintun.required &&
    prevStatus.wintun.ready === nextStatus.wintun.ready &&
    (prevLive?.running ?? false) === (nextLive?.running ?? false) &&
    prevLive?.engine === nextLive?.engine &&
    prevLive?.vpnConflict === nextLive?.vpnConflict
  );
}

export const DiagnosticsView = memo(
  DiagnosticsViewComponent,
  areDiagnosticsPropsEqual,
);
DiagnosticsView.displayName = "DiagnosticsView";

export default DiagnosticsView;
