import { memo, useEffect, useId, useMemo, useRef, useState } from "react";
import type { KeyboardEvent } from "react";
import {
  IconDns,
  IconEye,
  IconEyeOff,
  IconShield,
} from "../components/Icons";
import { InlineBanner } from "../components/InlineBanner";
import { SegmentedControl } from "../components/SegmentedControl";
import type { SegmentedOption } from "../components/SegmentedControl";
import { Switch } from "../components/Switch";
import type { ToastTone } from "../components/ToastStack";
import {
  isKnownPublicDohIp,
  redactDnsPreview,
  scrubUrlsInText,
  validateCustomDnsClient,
  type CustomDnsValidation,
} from "../lib/format";
import { saveDnsRules } from "../lib/ipc";
import type {
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  DnsConfigUpdate,
  VpnCoexistence,
} from "../types";
import { DomainListEditor } from "./DomainListEditor";

export interface DnsRulesViewProps {
  settings: DesktopSettingsPayload | null;
  status: DesktopStatusSnapshot | null;
  busyAction?: string | null;
  onSaved?: () => void | Promise<void>;
  onPushToast?: (tone: ToastTone, message: string) => void;
  onDirtyChange?: (dirty: boolean) => void;
}

type ResolverPresetId =
  | "cloudflare"
  | "quad9"
  | "google"
  | "adguard"
  | "adguard_unfiltered"
  | "custom";

interface ResolverPresetOption {
  id: Exclude<ResolverPresetId, "custom">;
  name: string;
  address: string;
  summary: string;
  badge: string;
}

interface SavedDnsBaseline {
  dnsAddr: string;
  dohEnabled: boolean;
  blockQuic: boolean;
  tunIpv6: boolean;
  ipv4Only: boolean;
  vpnCoexistence: VpnCoexistence;
  bypassDomains: string[];
  includeDomains: string[];
}

const RESOLVER_PRESETS: readonly ResolverPresetOption[] = [
  {
    id: "cloudflare",
    name: "Cloudflare",
    address: "1.1.1.1",
    summary: "Low-latency public DNS with IP-SAN DoH support.",
    badge: "Fast",
  },
  {
    id: "quad9",
    name: "Quad9",
    address: "9.9.9.9",
    summary: "Security-focused DNS with malicious domain blocking.",
    badge: "Security",
  },
  {
    id: "google",
    name: "Google",
    address: "8.8.8.8",
    summary: "Global anycast public resolver with IP-SAN DoH.",
    badge: "Global",
  },
  {
    id: "adguard",
    name: "AdGuard",
    address: "94.140.14.14",
    summary: "Blocks ads, trackers, and phishing domains.",
    badge: "Ad-block",
  },
  {
    id: "adguard_unfiltered",
    name: "AdGuard",
    address: "94.140.14.140",
    summary: "AdGuard infrastructure without content filtering.",
    badge: "Unfiltered",
  },
];

const RESOLVER_ORDER: readonly ResolverPresetId[] = [
  "cloudflare",
  "quad9",
  "google",
  "adguard",
  "adguard_unfiltered",
  "custom",
];

const VPN_COEXISTENCE_OPTIONS: readonly SegmentedOption<VpnCoexistence>[] = [
  { value: "auto_yield", label: "Auto-yield" },
  { value: "warn", label: "Warn" },
  { value: "off", label: "Off" },
];

const VPN_COEXISTENCE_DESCRIPTIONS: Record<VpnCoexistence, string> = {
  auto_yield:
    "Automatically pauses vdpi when a full-tunnel VPN is detected and resumes once the VPN disconnects.",
  warn: "Keeps vdpi running alongside full-tunnel VPNs and shows a conflict warning banner.",
  off: "Disables VPN interface conflict checks. Use only if you manage routing tables manually.",
};

const MAX_DOMAIN_ENTRIES = 512;

const STYLE_ID = "vdpi-dns-rules-view-styles";

const FALLBACK_STYLES = `
:where(.dns-view) {
  --_dns-surface: var(--bg-surface, var(--surface, #131518));
  --_dns-surface-subtle: var(--bg-surface-subtle, rgba(255, 255, 255, 0.035));
  --_dns-surface-raised: var(--bg-surface-elevated, var(--surface-raised, #1b1e24));
  --_dns-surface-hover: var(--bg-surface-hover, rgba(255, 255, 255, 0.055));
  --_dns-input-bg: var(--bg-input, #0e1013);
  --_dns-border: var(--border-subtle, var(--border, rgba(255, 255, 255, 0.1)));
  --_dns-border-strong: var(--border-strong, rgba(255, 255, 255, 0.2));
  --_dns-hairline: var(--border-hairline, rgba(255, 255, 255, 0.07));
  --_dns-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_dns-secondary: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_dns-muted: var(--ink-tertiary, var(--ink-muted, #7c828e));
  --_dns-accent: var(--accent, #3b82f6);
  --_dns-accent-hover: var(--accent-hover, #4b8df8);
  --_dns-accent-fg: var(--accent-fg, #60a5fa);
  --_dns-accent-subtle: var(--accent-subtle, rgba(59, 130, 246, 0.14));
  --_dns-accent-border: var(--accent-border, rgba(59, 130, 246, 0.36));
  --_dns-on-accent: var(--ink-on-accent, #ffffff);
  --_dns-ok-fg: var(--status-success-fg, #30d158);
  --_dns-ok-bg: var(--status-success-bg, rgba(48, 209, 88, 0.12));
  --_dns-ok-border: var(--status-success-border, rgba(48, 209, 88, 0.28));
  --_dns-warn-fg: var(--status-warning-fg, #ff9f0a);
  --_dns-warn-bg: var(--status-warning-bg, rgba(255, 159, 10, 0.12));
  --_dns-warn-border: var(--status-warning-border, rgba(255, 159, 10, 0.28));
  --_dns-danger-fg: var(--status-danger-fg, #ff453a);
  --_dns-danger-bg: var(--status-danger-bg, rgba(255, 69, 58, 0.12));
  --_dns-danger-border: var(--status-danger-border, rgba(255, 69, 58, 0.32));
  --_dns-mono: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  --_dns-shadow-sticky: var(--shadow-md, 0 8px 24px rgba(0, 0, 0, 0.4));
  display: flex;
  flex-direction: column;
  gap: 16px;
  color: var(--_dns-ink);
  box-sizing: border-box;
  padding-bottom: 8px;
}

:where([data-theme="light"] .dns-view) {
  --_dns-surface: var(--bg-surface, #ffffff);
  --_dns-surface-subtle: var(--bg-surface-subtle, #f1f3f6);
  --_dns-surface-raised: var(--bg-surface-elevated, #ffffff);
  --_dns-surface-hover: var(--bg-surface-hover, #e9ecf1);
  --_dns-input-bg: var(--bg-input, #ffffff);
  --_dns-border: var(--border-subtle, rgba(11, 12, 14, 0.1));
  --_dns-border-strong: var(--border-strong, rgba(11, 12, 14, 0.22));
  --_dns-hairline: var(--border-hairline, rgba(11, 12, 14, 0.07));
  --_dns-ink: var(--ink-primary, #111317);
  --_dns-secondary: var(--ink-secondary, #4e5460);
  --_dns-muted: var(--ink-tertiary, #6b7280);
  --_dns-accent: var(--accent, #0066cc);
  --_dns-accent-hover: var(--accent-hover, #0055b3);
  --_dns-accent-fg: var(--accent-fg, #0066cc);
  --_dns-accent-subtle: var(--accent-subtle, rgba(0, 102, 204, 0.1));
  --_dns-accent-border: var(--accent-border, rgba(0, 102, 204, 0.32));
  --_dns-ok-fg: var(--status-success-fg, #18793a);
  --_dns-ok-bg: var(--status-success-bg, rgba(48, 209, 88, 0.12));
  --_dns-ok-border: var(--status-success-border, rgba(24, 121, 58, 0.24));
  --_dns-warn-fg: var(--status-warning-fg, #a15c00);
  --_dns-warn-bg: var(--status-warning-bg, rgba(255, 159, 10, 0.14));
  --_dns-warn-border: var(--status-warning-border, rgba(161, 92, 0, 0.24));
  --_dns-danger-fg: var(--status-danger-fg, #c82320);
  --_dns-danger-bg: var(--status-danger-bg, rgba(255, 69, 58, 0.11));
  --_dns-danger-border: var(--status-danger-border, rgba(200, 35, 32, 0.28));
  --_dns-shadow-sticky: var(--shadow-md, 0 8px 24px rgba(11, 12, 14, 0.1));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .dns-view) {
    --_dns-surface: var(--bg-surface, #ffffff);
    --_dns-surface-subtle: var(--bg-surface-subtle, #f1f3f6);
    --_dns-surface-raised: var(--bg-surface-elevated, #ffffff);
    --_dns-surface-hover: var(--bg-surface-hover, #e9ecf1);
    --_dns-input-bg: var(--bg-input, #ffffff);
    --_dns-border: var(--border-subtle, rgba(11, 12, 14, 0.1));
    --_dns-border-strong: var(--border-strong, rgba(11, 12, 14, 0.22));
    --_dns-hairline: var(--border-hairline, rgba(11, 12, 14, 0.07));
    --_dns-ink: var(--ink-primary, #111317);
    --_dns-secondary: var(--ink-secondary, #4e5460);
    --_dns-muted: var(--ink-tertiary, #6b7280);
    --_dns-accent: var(--accent, #0066cc);
    --_dns-accent-hover: var(--accent-hover, #0055b3);
    --_dns-accent-fg: var(--accent-fg, #0066cc);
    --_dns-accent-subtle: var(--accent-subtle, rgba(0, 102, 204, 0.1));
    --_dns-accent-border: var(--accent-border, rgba(0, 102, 204, 0.32));
    --_dns-ok-fg: var(--status-success-fg, #18793a);
    --_dns-ok-bg: var(--status-success-bg, rgba(48, 209, 88, 0.12));
    --_dns-ok-border: var(--status-success-border, rgba(24, 121, 58, 0.24));
    --_dns-warn-fg: var(--status-warning-fg, #a15c00);
    --_dns-warn-bg: var(--status-warning-bg, rgba(255, 159, 10, 0.14));
    --_dns-warn-border: var(--status-warning-border, rgba(161, 92, 0, 0.24));
    --_dns-danger-fg: var(--status-danger-fg, #c82320);
    --_dns-danger-bg: var(--status-danger-bg, rgba(255, 69, 58, 0.11));
    --_dns-danger-border: var(--status-danger-border, rgba(200, 35, 32, 0.28));
    --_dns-shadow-sticky: var(--shadow-md, 0 8px 24px rgba(11, 12, 14, 0.1));
  }
}

@keyframes vdpi-dns-spin {
  to {
    transform: rotate(360deg);
  }
}

:where(.dns-view__header) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

:where(.dns-view__heading) {
  flex: 1 1 260px;
  min-width: 0;
}

:where(.dns-view__title) {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  line-height: 1.3;
  letter-spacing: -0.02em;
  color: var(--_dns-ink);
}

:where(.dns-view__subtitle) {
  margin: 4px 0 0;
  font-size: 13px;
  line-height: 1.45;
  color: var(--_dns-secondary);
}

:where(.dns-view__live-pill) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 28px;
  padding: 0 11px;
  border-radius: 999px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  font-size: 12px;
  line-height: 1;
  color: var(--_dns-secondary);
  white-space: nowrap;
  flex-shrink: 0;
  max-width: 100%;
  box-sizing: border-box;
}

:where(.dns-view__live-dot) {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--_dns-muted);
  flex-shrink: 0;
}

:where(.dns-view__live-dot--active) {
  background: var(--_dns-ok-fg);
}

:where(.dns-view__live-label) {
  font-weight: 500;
  color: var(--_dns-secondary);
}

:where(.dns-view__live-sep) {
  color: var(--_dns-muted);
  opacity: 0.7;
}

:where(.dns-view__live-addr) {
  font-family: var(--_dns-mono);
  font-size: 11.5px;
  color: var(--_dns-ink);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.dns-view__live-proto) {
  font-size: 11px;
  font-weight: 600;
  color: var(--_dns-secondary);
}

:where(.dns-view__live-proto--doh) {
  color: var(--_dns-accent-fg);
}

:where(.dns-section) {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 18px;
  border-radius: 10px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  box-sizing: border-box;
}

:where([data-theme="light"] .dns-section) {
  box-shadow: var(--shadow-sm, 0 1px 2px rgba(11, 12, 14, 0.05));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .dns-section) {
    box-shadow: var(--shadow-sm, 0 1px 2px rgba(11, 12, 14, 0.05));
  }
}

:where(.dns-section__head) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--_dns-hairline);
}

:where(.dns-section__title-row) {
  display: flex;
  align-items: center;
  gap: 8px;
}

:where(.dns-section__icon) {
  color: var(--_dns-secondary);
  flex-shrink: 0;
}

:where(.dns-section__title) {
  margin: 0;
  font-size: 14.5px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_dns-ink);
}

:where(.dns-section__desc) {
  margin: 3px 0 0;
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--_dns-secondary);
}

:where(.dns-resolver-grid) {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}

@media (max-width: 780px) {
  :where(.dns-resolver-grid) {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 520px) {
  :where(.dns-resolver-grid) {
    grid-template-columns: 1fr;
  }
}

:where(.dns-radio-card) {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  width: 100%;
  padding: 12px 13px;
  border-radius: 9px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface-subtle);
  color: var(--_dns-ink);
  text-align: left;
  font: inherit;
  cursor: pointer;
  box-sizing: border-box;
  transition:
    background-color 120ms ease,
    border-color 120ms ease,
    opacity 120ms ease;
}

:where(.dns-radio-card:hover:not(:disabled)) {
  background: var(--_dns-surface-hover);
  border-color: var(--_dns-border-strong);
}

:where(.dns-radio-card[aria-checked="true"]) {
  background: var(--_dns-accent-subtle);
  border-color: var(--_dns-accent-border);
}

:where(.dns-radio-card:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_dns-accent));
  outline-offset: 2px;
}

:where(.dns-radio-card:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.dns-radio-card__top) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
}

:where(.dns-radio-card__name-wrap) {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

:where(.dns-radio-dot) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 1.5px solid var(--_dns-border-strong);
  background: transparent;
  box-sizing: border-box;
  transition: border-color 120ms ease;
}

:where(.dns-radio-card[aria-checked="true"] .dns-radio-dot) {
  border-color: var(--accent-fg, var(--_dns-accent-fg));
}

:where(.dns-radio-dot__inner) {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent-fg, var(--_dns-accent-fg));
}

:where(.dns-radio-card__name) {
  font-size: 13px;
  font-weight: 600;
  line-height: 1.3;
  color: var(--_dns-ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:where(.dns-radio-card__addr) {
  font-family: var(--_dns-mono);
  font-size: 12px;
  line-height: 1.3;
  color: var(--_dns-secondary);
  padding-left: 24px;
  transition: color 120ms ease;
}

:where(.dns-radio-card[aria-checked="true"] .dns-radio-card__addr) {
  color: var(--_dns-accent-fg);
}

:where(.dns-radio-card__summary) {
  margin: 0;
  padding-left: 24px;
  font-size: 11.5px;
  line-height: 1.4;
  color: var(--_dns-secondary);
}

:where(.dns-badge) {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 7px;
  border-radius: 999px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface-raised);
  color: var(--_dns-secondary);
  font-size: 11px;
  font-weight: 500;
  line-height: 1.25;
  white-space: nowrap;
  flex-shrink: 0;
}

:where(.dns-badge--accent) {
  border-color: var(--_dns-accent-border);
  background: var(--_dns-accent-subtle);
  color: var(--_dns-accent-fg);
}

:where(.dns-badge--ok) {
  border-color: var(--_dns-ok-border);
  background: var(--_dns-ok-bg);
  color: var(--_dns-ok-fg);
}

:where(.dns-badge--warn) {
  border-color: var(--_dns-warn-border);
  background: var(--_dns-warn-bg);
  color: var(--_dns-warn-fg);
}

:where(.dns-custom-panel) {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px;
  border-radius: 9px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface-subtle);
}

:where(.dns-custom-panel__label-row) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}

:where(.dns-custom-panel__label) {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--_dns-ink);
}

:where(.dns-preview-pill) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
  padding: 3px 9px;
  border-radius: 999px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  font-size: 11.5px;
  color: var(--_dns-secondary);
}

:where(.dns-preview-pill__addr) {
  font-family: var(--_dns-mono);
  font-size: 11.5px;
  color: var(--_dns-ink);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

:where(.dns-custom-input-wrap) {
  display: flex;
  align-items: stretch;
  gap: 8px;
}

:where(.dns-custom-input) {
  flex: 1 1 auto;
  min-width: 0;
  height: 32px;
  padding: 0 12px;
  border-radius: 8px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-input-bg);
  color: var(--_dns-ink);
  font-family: var(--_dns-mono);
  font-size: 12.5px;
  line-height: 1.3;
  box-sizing: border-box;
  transition: border-color 120ms ease;
}

:where(.dns-custom-input::placeholder) {
  color: var(--_dns-muted);
}

:where(.dns-custom-input:hover:not(:disabled):not(:focus)) {
  border-color: var(--_dns-border-strong);
}

:where(.dns-custom-input:focus) {
  outline: 2px solid var(--focus-ring-color, var(--_dns-accent));
  outline-offset: -1px;
  border-color: var(--_dns-accent);
}

:where(.dns-custom-input[aria-invalid="true"]) {
  border-color: var(--_dns-danger-fg);
}

:where(.dns-custom-input[aria-invalid="true"]:focus) {
  outline-color: var(--_dns-danger-fg);
}

:where(.dns-custom-input:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.dns-reveal-btn) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  flex-shrink: 0;
  height: 32px;
  padding: 0 11px;
  border-radius: 8px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  color: var(--_dns-secondary);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease;
}

:where(.dns-reveal-btn:hover:not(:disabled)) {
  background: var(--_dns-surface-hover);
  border-color: var(--_dns-border-strong);
  color: var(--_dns-ink);
}

:where(.dns-reveal-btn:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_dns-accent));
  outline-offset: 2px;
}

:where(.dns-reveal-btn:disabled) {
  opacity: 0.5;
  cursor: not-allowed;
}

:where(.dns-hint) {
  margin: 0;
  font-size: 12px;
  line-height: 1.45;
  color: var(--_dns-secondary);
}

:where(.dns-hint--error) {
  color: var(--_dns-danger-fg);
}

:where(.dns-hint--ok) {
  color: var(--_dns-ok-fg);
}

:where(.dns-hint--warn) {
  color: var(--_dns-warn-fg);
}

:where(.dns-hint code) {
  font-family: var(--_dns-mono);
  font-size: 11.5px;
}

:where(.dns-rows) {
  display: flex;
  flex-direction: column;
}

:where(.dns-row) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  padding: 13px 0;
  border-top: 1px solid var(--_dns-hairline);
}

:where(.dns-row:first-child) {
  padding-top: 2px;
  border-top: none;
}

:where(.dns-row:last-child) {
  padding-bottom: 0;
}

:where(.dns-row__info) {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.dns-row__title-line) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.dns-row__label) {
  font-size: 13.5px;
  font-weight: 500;
  line-height: 1.35;
  color: var(--_dns-ink);
}

:where(.dns-row__desc) {
  margin: 0;
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--_dns-secondary);
}

:where(.dns-row__desc code) {
  font-family: var(--_dns-mono);
  font-size: 11.5px;
}

:where(.dns-row__control) {
  display: flex;
  align-items: center;
  flex-shrink: 0;
  padding-top: 1px;
}

:where(.dns-row--stacked) {
  flex-direction: column;
  gap: 10px;
}

:where(.dns-row--stacked .dns-row__control) {
  width: 100%;
}

:where(.dns-domains-grid) {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
}

@media (max-width: 820px) {
  :where(.dns-domains-grid) {
    grid-template-columns: 1fr;
  }
}

:where(.dns-domain-card) {
  padding: 14px;
  border-radius: 9px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface-subtle);
  box-sizing: border-box;
}

:where(.dns-loading) {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 10px;
  padding: 40px 20px;
  border-radius: 10px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  color: var(--_dns-secondary);
  font-size: 13px;
}

:where(.dns-sticky-bar) {
  position: sticky;
  bottom: 0;
  z-index: var(--z-sticky, 10);
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
  padding: 12px 16px;
  border-radius: 10px;
  border: 1px solid var(--_dns-accent-border);
  background: var(--_dns-surface-raised);
  box-shadow: var(--_dns-shadow-sticky);
  box-sizing: border-box;
}

:where(.dns-sticky-bar__info) {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}

:where(.dns-sticky-bar__title) {
  margin: 0;
  font-size: 13px;
  font-weight: 600;
  line-height: 1.3;
  color: var(--_dns-ink);
}

:where(.dns-sticky-bar__tags) {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

:where(.dns-sticky-bar__actions) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

:where(.dns-btn) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 7px;
  height: 32px;
  padding: 0 13px;
  border-radius: 8px;
  border: 1px solid var(--_dns-border);
  background: var(--_dns-surface);
  color: var(--_dns-ink);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 120ms ease, border-color 120ms ease, opacity 120ms ease;
}

:where(.dns-btn:hover:not(:disabled)) {
  background: var(--_dns-surface-hover);
  border-color: var(--_dns-border-strong);
}

:where(.dns-btn:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_dns-accent));
  outline-offset: 2px;
}

:where(.dns-btn:disabled) {
  opacity: 0.5;
  cursor: not-allowed;
}

:where(.dns-btn--primary) {
  border-color: transparent;
  background: var(--_dns-accent);
  color: var(--_dns-on-accent);
}

:where(.dns-btn--primary:hover:not(:disabled)) {
  background: var(--_dns-accent-hover);
  border-color: transparent;
}

:where(.dns-spinner) {
  display: inline-block;
  width: 13px;
  height: 13px;
  border-radius: 999px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  animation: vdpi-dns-spin 700ms linear infinite;
}

@media (prefers-reduced-motion: reduce) {
  :where(.dns-radio-card),
  :where(.dns-radio-dot),
  :where(.dns-custom-input),
  :where(.dns-reveal-btn),
  :where(.dns-btn) {
    transition: none;
  }

  :where(.dns-spinner) {
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

function looksLikeSecretDnsUrl(value: string): boolean {
  const trimmed = value.trim();
  return (
    trimmed.includes("://") ||
    trimmed.includes("/") ||
    trimmed.includes("@") ||
    trimmed.includes("?") ||
    trimmed.includes("#") ||
    trimmed.includes("\\") ||
    /^(?:https?|doh|dot|dns):/i.test(trimmed)
  );
}

function formatDohUrlHost(ip: string, ipVersion?: 4 | 6): string {
  const bare =
    ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
  if (ipVersion === 6 || bare.includes(":")) {
    return `[${bare}]`;
  }
  return bare;
}

function normalizeDomainRuleBase(rule: string): string {
  const lower = rule.trim().toLowerCase().replace(/\.+$/, "");
  if (lower.startsWith("*.")) {
    return lower.slice(2);
  }
  if (lower.startsWith(".")) {
    return lower.slice(1);
  }
  return lower;
}

function findDomainOverlaps(
  bypassList: readonly string[],
  includeList: readonly string[],
): string[] {
  const bypassEntries = bypassList
    .map((raw) => ({
      rule: raw.trim().toLowerCase(),
      base: normalizeDomainRuleBase(raw),
    }))
    .filter((entry) => entry.rule.length > 0 && entry.base.length > 0);

  const includeEntries = includeList
    .map((raw) => ({
      rule: raw.trim().toLowerCase(),
      base: normalizeDomainRuleBase(raw),
    }))
    .filter((entry) => entry.rule.length > 0 && entry.base.length > 0);

  if (bypassEntries.length === 0 || includeEntries.length === 0) {
    return [];
  }

  const seen = new Set<string>();
  const overlaps: string[] = [];

  for (const inc of includeEntries) {
    for (const byp of bypassEntries) {
      const overlapsRule =
        inc.base === byp.base ||
        inc.base.endsWith(`.${byp.base}`) ||
        byp.base.endsWith(`.${inc.base}`);
      if (!overlapsRule) continue;

      const label =
        byp.rule === inc.rule
          ? inc.rule
          : `${byp.rule} / ${inc.rule}`;
      if (!seen.has(label)) {
        seen.add(label);
        overlaps.push(label);
      }
    }
  }

  return overlaps;
}

function findPresetByAddress(dnsAddr: string): ResolverPresetOption | null {
  const trimmed = dnsAddr.trim();
  return (
    RESOLVER_PRESETS.find((preset) => preset.address === trimmed) ?? null
  );
}

function normalizeDomainList(list: readonly string[]): string[] {
  return list.map((d) => d.trim().toLowerCase()).filter(Boolean);
}

function areDomainListsEqual(
  a: readonly string[],
  b: readonly string[],
): boolean {
  const na = normalizeDomainList(a);
  const nb = normalizeDomainList(b);
  if (na.length !== nb.length) return false;
  for (let i = 0; i < na.length; i += 1) {
    if (na[i] !== nb[i]) return false;
  }
  return true;
}

function buildBaseline(settings: DesktopSettingsPayload): SavedDnsBaseline {
  return {
    dnsAddr: settings.dnsAddr.trim() || "1.1.1.1",
    dohEnabled: settings.dohEnabled,
    blockQuic: settings.blockQuic,
    tunIpv6: settings.tunIpv6,
    ipv4Only: settings.ipv4Only,
    vpnCoexistence: settings.vpnCoexistence,
    bypassDomains: [...settings.bypassDomains],
    includeDomains: [...settings.includeDomains],
  };
}

function serializeBaseline(b: SavedDnsBaseline): string {
  return JSON.stringify(b);
}

function getErrorMessage(error: unknown, fallback: string): string {
  if (error instanceof Error && error.message.trim()) {
    return error.message.trim();
  }
  if (typeof error === "string" && error.trim()) {
    return error.trim();
  }
  return fallback;
}

function DnsRulesViewComponent({
  settings,
  status,
  onSaved,
  onPushToast,
  onDirtyChange,
}: DnsRulesViewProps) {
  const customInputId = useId();
  const customHintId = useId();
  const dohLabelId = useId();
  const dohDescId = useId();
  const quicLabelId = useId();
  const quicDescId = useId();
  const ipv6LabelId = useId();
  const ipv6DescId = useId();
  const ipv4LabelId = useId();
  const ipv4DescId = useId();
  const vpnLabelId = useId();

  const mountedRef = useRef(true);
  const savingRef = useRef(false);
  const keepErrorBannerOnNextSyncRef = useRef(false);
  const resolverCardRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const lastSettingsSigRef = useRef<string | null>(null);
  const onDirtyChangeRef = useRef(onDirtyChange);
  onDirtyChangeRef.current = onDirtyChange;

  const [saved, setSaved] = useState<SavedDnsBaseline | null>(() =>
    settings ? buildBaseline(settings) : null,
  );
  const [selectedResolver, setSelectedResolver] = useState<ResolverPresetId>(
    () => {
      if (!settings) return "cloudflare";
      const match = findPresetByAddress(settings.dnsAddr);
      return match ? match.id : "custom";
    },
  );
  const [customDns, setCustomDns] = useState<string>(() => {
    if (!settings) return "";
    return findPresetByAddress(settings.dnsAddr) ? "" : settings.dnsAddr.trim();
  });
  const [revealCustom, setRevealCustom] = useState(false);

  const [dohEnabled, setDohEnabled] = useState<boolean>(
    () => settings?.dohEnabled ?? true,
  );
  const [blockQuic, setBlockQuic] = useState<boolean>(
    () => settings?.blockQuic ?? true,
  );
  const [tunIpv6, setTunIpv6] = useState<boolean>(
    () => settings?.tunIpv6 ?? false,
  );
  const [ipv4Only, setIpv4Only] = useState<boolean>(
    () => settings?.ipv4Only ?? false,
  );
  const [vpnCoexistence, setVpnCoexistence] = useState<VpnCoexistence>(
    () => settings?.vpnCoexistence ?? "auto_yield",
  );
  const [bypassDomains, setBypassDomains] = useState<string[]>(() =>
    settings ? [...settings.bypassDomains] : [],
  );
  const [includeDomains, setIncludeDomains] = useState<string[]>(() =>
    settings ? [...settings.includeDomains] : [],
  );

  const [saving, setSaving] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [resetNonce, setResetNonce] = useState(0);

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      onDirtyChangeRef.current?.(false);
    };
  }, []);

  const applyBaselineToDraft = (baseline: SavedDnsBaseline) => {
    const preset = findPresetByAddress(baseline.dnsAddr);
    setSelectedResolver(preset ? preset.id : "custom");
    setCustomDns(preset ? "" : baseline.dnsAddr);
    setRevealCustom(false);
    setDohEnabled(baseline.dohEnabled);
    setBlockQuic(baseline.blockQuic);
    setTunIpv6(baseline.tunIpv6);
    setIpv4Only(baseline.ipv4Only);
    setVpnCoexistence(baseline.vpnCoexistence);
    setBypassDomains([...baseline.bypassDomains]);
    setIncludeDomains([...baseline.includeDomains]);
    setResetNonce((prev) => prev + 1);
  };

  useEffect(() => {
    if (!settings) return;
    const nextBaseline = buildBaseline(settings);
    const sig = serializeBaseline(nextBaseline);
    if (lastSettingsSigRef.current === sig) return;
    lastSettingsSigRef.current = sig;
    setSaved(nextBaseline);
    applyBaselineToDraft(nextBaseline);
    if (keepErrorBannerOnNextSyncRef.current) {
      keepErrorBannerOnNextSyncRef.current = false;
    } else {
      setErrorBanner(null);
    }
  }, [settings]);

  const customAnalysis = useMemo(
    () => validateCustomDnsClient(customDns),
    [customDns],
  );

  const activeDnsAddr = useMemo(() => {
    if (selectedResolver === "custom") {
      return customAnalysis.valid
        ? customAnalysis.normalized
        : customDns.trim();
    }
    const preset = RESOLVER_PRESETS.find((p) => p.id === selectedResolver);
    return preset ? preset.address : "1.1.1.1";
  }, [selectedResolver, customAnalysis, customDns]);

  const activeDnsAnalysis = useMemo<CustomDnsValidation>(() => {
    if (selectedResolver === "custom") {
      return customAnalysis;
    }
    return {
      valid: true,
      kind: isKnownPublicDohIp(activeDnsAddr) ? "known_doh_ip" : "bare_udp_ip",
      normalized: activeDnsAddr,
      ipVersion: 4,
      error: null,
    };
  }, [selectedResolver, customAnalysis, activeDnsAddr]);

  const isCustomHttpsUrl =
    selectedResolver === "custom" &&
    customAnalysis.valid &&
    customAnalysis.kind === "doh_url";

  const isBareNonDohIp =
    selectedResolver === "custom" &&
    customAnalysis.valid &&
    customAnalysis.kind === "bare_udp_ip";

  const isIpv6CustomDns =
    selectedResolver === "custom" &&
    customAnalysis.valid &&
    (customAnalysis.ipVersion === 6 ||
      (customAnalysis.kind === "doh_url" &&
        /^https:\/\/\[/i.test(customAnalysis.normalized)));

  const effectiveDohChecked = isCustomHttpsUrl ? true : dohEnabled;

  const customIsSecretUrl = looksLikeSecretDnsUrl(customDns);
  const maskCustomInput = customIsSecretUrl && !revealCustom;

  const customPreview = useMemo(() => {
    const trimmed = customDns.trim();
    if (!trimmed) return "";
    return redactDnsPreview(trimmed);
  }, [customDns]);

  const overlappingDomains = useMemo(
    () => findDomainOverlaps(bypassDomains, includeDomains),
    [bypassDomains, includeDomains],
  );

  const dirtyChanges = useMemo(() => {
    if (!saved) return [] as string[];
    const changes: string[] = [];

    const savedValidation = validateCustomDnsClient(saved.dnsAddr);
    const savedNormalizedDns = savedValidation.valid
      ? savedValidation.normalized
      : saved.dnsAddr;
    if (activeDnsAddr !== savedNormalizedDns) {
      changes.push("DNS resolver");
    }

    const savedIsUrl = savedValidation.kind === "doh_url";
    const savedEffectiveDoh = savedIsUrl ? true : saved.dohEnabled;
    if (effectiveDohChecked !== savedEffectiveDoh) {
      changes.push("Encrypted DNS");
    }

    if (blockQuic !== saved.blockQuic) {
      changes.push("QUIC blocking");
    }
    if (tunIpv6 !== saved.tunIpv6 || ipv4Only !== saved.ipv4Only) {
      changes.push("IP stack");
    }
    if (vpnCoexistence !== saved.vpnCoexistence) {
      changes.push("VPN coexistence");
    }
    if (!areDomainListsEqual(bypassDomains, saved.bypassDomains)) {
      changes.push("Bypass domains");
    }
    if (!areDomainListsEqual(includeDomains, saved.includeDomains)) {
      changes.push("Include domains");
    }

    return changes;
  }, [
    saved,
    activeDnsAddr,
    effectiveDohChecked,
    blockQuic,
    tunIpv6,
    ipv4Only,
    vpnCoexistence,
    bypassDomains,
    includeDomains,
  ]);

  const isDirty = dirtyChanges.length > 0;
  const canSave = isDirty && activeDnsAnalysis.valid && !saving;

  useEffect(() => {
    onDirtyChange?.(isDirty);
  }, [isDirty, onDirtyChange]);

  const isLiveRunning = Boolean(status?.live?.running);
  const livePillLabel = isLiveRunning ? "Active" : "Configured";
  const rawLiveDnsDisplay =
    (isLiveRunning ? status?.live?.dnsDisplay : null) ||
    settings?.dnsDisplay ||
    status?.live?.dnsDisplay ||
    null;
  const liveDnsDisplay = rawLiveDnsDisplay
    ? redactDnsPreview(rawLiveDnsDisplay)
    : null;
  const liveDohActive = isLiveRunning
    ? Boolean(status?.live?.dohEnabled)
    : Boolean(settings?.effectiveDoh);
  const activeVpnConflict =
    (status?.live?.vpnConflict ?? status?.vpnConflict)?.trim() || null;
  const activeEngine =
    status?.live?.engine ?? settings?.engine ?? status?.configuredEngine ?? "tun";
  const isProxyMode = activeEngine === "proxy";

  const handleSelectResolver = (id: ResolverPresetId) => {
    if (saving || savingRef.current) return;
    setSelectedResolver(id);
    setRevealCustom(false);
    if (id !== "custom") {
      const savedPreset = saved ? findPresetByAddress(saved.dnsAddr) : null;
      setCustomDns(saved && !savedPreset ? saved.dnsAddr : "");
    }
    setErrorBanner(null);
  };

  const handleResolverKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    if (saving || savingRef.current) return;
    const count = RESOLVER_ORDER.length;
    let nextIndex = -1;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        nextIndex = (index + 1) % count;
        break;
      case "ArrowLeft":
      case "ArrowUp":
        nextIndex = (index - 1 + count) % count;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = count - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    const nextId = RESOLVER_ORDER[nextIndex];
    handleSelectResolver(nextId);
    resolverCardRefs.current[nextIndex]?.focus();
  };

  const handleDiscard = () => {
    if (!saved || saving || savingRef.current) return;
    applyBaselineToDraft(saved);
    setErrorBanner(null);
  };

  const handleSave = async () => {
    if (savingRef.current || !canSave) return;
    savingRef.current = true;
    setSaving(true);
    setErrorBanner(null);

    const payload: DnsConfigUpdate = {
      dnsAddr: activeDnsAddr,
      dohEnabled: effectiveDohChecked,
      blockQuic,
      tunIpv6,
      ipv4Only,
      vpnCoexistence,
      bypassDomains: [...bypassDomains],
      includeDomains: [...includeDomains],
    };

    try {
      const result = await saveDnsRules(payload);
      if (!mountedRef.current) return;

      if (result.cancelled) {
        setRevealCustom(false);
        const cancelMessage = scrubUrlsInText(
          result.message?.trim() || "DNS & rule changes were cancelled.",
        );
        setErrorBanner(null);
        onPushToast?.("info", cancelMessage);
        if (
          typeof result.needsRestart === "boolean" ||
          /\bsaved\b/i.test(result.message ?? "")
        ) {
          try {
            await onSaved?.();
          } catch {
            // Parent refresh errors are handled upstream.
          }
        }
        return;
      }

      if (!result.ok) {
        const message = scrubUrlsInText(
          result.message?.trim() || "Failed to save DNS and rule settings.",
        );
        setErrorBanner(message);
        onPushToast?.("error", message);

        const partialConfigPersisted =
          typeof result.needsRestart === "boolean" ||
          /\bsaved\b/i.test(result.message ?? "");
        if (partialConfigPersisted) {
          keepErrorBannerOnNextSyncRef.current = true;
          try {
            await onSaved?.();
          } catch {
            // Parent refresh errors are handled upstream.
          } finally {
            keepErrorBannerOnNextSyncRef.current = false;
          }
        }
        return;
      }

      const nextBaseline: SavedDnsBaseline = {
        dnsAddr: payload.dnsAddr,
        dohEnabled: payload.dohEnabled,
        blockQuic: payload.blockQuic,
        tunIpv6: payload.tunIpv6,
        ipv4Only: payload.ipv4Only,
        vpnCoexistence: payload.vpnCoexistence,
        bypassDomains: [...payload.bypassDomains],
        includeDomains: [...payload.includeDomains],
      };
      lastSettingsSigRef.current = serializeBaseline(nextBaseline);
      setSaved(nextBaseline);
      setDohEnabled(payload.dohEnabled);
      setCustomDns(selectedResolver === "custom" ? payload.dnsAddr : "");
      setRevealCustom(false);
      setResetNonce((prev) => prev + 1);

      const successMessage = scrubUrlsInText(
        result.message?.trim() ||
          (result.needsRestart
            ? "DNS & rule settings saved (restart service to apply)."
            : "DNS & rule settings saved and applied."),
      );
      onPushToast?.(result.needsRestart ? "warn" : "success", successMessage);

      try {
        await onSaved?.();
      } catch {
        // Parent refresh errors are handled upstream; keep saved baseline intact.
      }
    } catch (error) {
      if (!mountedRef.current) return;
      const message = scrubUrlsInText(
        getErrorMessage(error, "Failed to save DNS and rule settings."),
      );
      setErrorBanner(message);
      onPushToast?.("error", message);
    } finally {
      savingRef.current = false;
      if (mountedRef.current) {
        setSaving(false);
      }
    }
  };

  const canSaveRef = useRef(canSave);
  canSaveRef.current = canSave;
  const handleSaveRef = useRef(handleSave);
  handleSaveRef.current = handleSave;

  useEffect(() => {
    if (typeof window === "undefined") return;
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (
        typeof document !== "undefined" &&
        document.querySelector('[aria-modal="true"]') !== null
      ) {
        return;
      }
      if (
        event.defaultPrevented ||
        event.isComposing ||
        event.altKey ||
        event.shiftKey
      ) {
        return;
      }
      const isSaveKey =
        event.key.toLowerCase() === "s" || event.code === "KeyS";
      if ((event.ctrlKey || event.metaKey) && isSaveKey) {
        if (!canSaveRef.current || savingRef.current) {
          return;
        }
        event.preventDefault();
        void handleSaveRef.current();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, []);

  if (!settings) {
    return (
      <section className="dns-view" aria-label="DNS & Rules">
        <div className="dns-loading" role="status">
          <span className="dns-spinner" aria-hidden="true" />
          <span>Loading DNS &amp; rule settings...</span>
        </div>
      </section>
    );
  }

  return (
    <section className="dns-view" aria-label="DNS & Rules">
      <header className="dns-view__header">
        <div className="dns-view__heading">
          <h1 className="dns-view__title">DNS &amp; Rules</h1>
          <p className="dns-view__subtitle">
            Configure upstream DNS resolution, protocol guards, VPN coexistence,
            and per-domain routing overrides.
          </p>
        </div>

        {liveDnsDisplay ? (
          <div
            className="dns-view__live-pill"
            data-live={isLiveRunning ? "true" : "false"}
            title={`${livePillLabel}: ${liveDnsDisplay} (${liveDohActive ? "DoH" : "UDP"})`}
          >
            <span
              className={`dns-view__live-dot ${
                isLiveRunning ? "dns-view__live-dot--active" : ""
              }`}
              aria-hidden="true"
            />
            <span className="dns-view__live-label">{livePillLabel}</span>
            <span className="dns-view__live-sep" aria-hidden="true">
              ·
            </span>
            <span className="dns-view__live-addr">{liveDnsDisplay}</span>
            <span className="dns-view__live-sep" aria-hidden="true">
              ·
            </span>
            <span
              className={`dns-view__live-proto ${
                liveDohActive ? "dns-view__live-proto--doh" : ""
              }`}
            >
              {liveDohActive ? "DoH" : "UDP"}
            </span>
          </div>
        ) : null}
      </header>

      {errorBanner ? (
        <InlineBanner
          tone="error"
          title="Could not save DNS & rule settings"
          description={errorBanner}
        />
      ) : null}

      {activeVpnConflict ? (
        <InlineBanner
          tone="warn"
          title="Full-tunnel VPN detected"
          description={`Active VPN interface (${activeVpnConflict}) detected. Adjust VPN Coexistence below to choose whether vdpi auto-yields or warns.`}
        />
      ) : null}

      {/* 1. DNS Resolver Section */}
      <section className="dns-section" aria-labelledby="dns-resolver-heading">
        <div className="dns-section__head">
          <div>
            <div className="dns-section__title-row">
              <IconDns size={16} className="dns-section__icon" />
              <h2 id="dns-resolver-heading" className="dns-section__title">
                DNS Resolver
              </h2>
            </div>
            <p className="dns-section__desc">
              Choose a trusted public resolver or enter a custom IP / encrypted
              DNS-over-HTTPS endpoint.
            </p>
          </div>
        </div>

        <div
          className="dns-resolver-grid"
          role="radiogroup"
          aria-labelledby="dns-resolver-heading"
        >
          {RESOLVER_PRESETS.map((preset, index) => {
            const checked = selectedResolver === preset.id;
            return (
              <button
                key={preset.id}
                ref={(el) => {
                  resolverCardRefs.current[index] = el;
                }}
                type="button"
                role="radio"
                aria-checked={checked}
                tabIndex={checked ? 0 : -1}
                disabled={saving}
                className="dns-radio-card"
                onClick={() => handleSelectResolver(preset.id)}
                onKeyDown={(event) => handleResolverKeyDown(event, index)}
              >
                <div className="dns-radio-card__top">
                  <span className="dns-radio-card__name-wrap">
                    <span className="dns-radio-dot" aria-hidden="true">
                      {checked ? (
                        <span className="dns-radio-dot__inner" />
                      ) : null}
                    </span>
                    <span className="dns-radio-card__name">{preset.name}</span>
                  </span>
                  <span className="dns-badge">{preset.badge}</span>
                </div>
                <span className="dns-radio-card__addr">{preset.address}</span>
                <p className="dns-radio-card__summary">{preset.summary}</p>
              </button>
            );
          })}

          {(() => {
            const customIndex = RESOLVER_PRESETS.length;
            const checked = selectedResolver === "custom";
            return (
              <button
                key="custom"
                ref={(el) => {
                  resolverCardRefs.current[customIndex] = el;
                }}
                type="button"
                role="radio"
                aria-checked={checked}
                tabIndex={checked ? 0 : -1}
                disabled={saving}
                className="dns-radio-card"
                onClick={() => handleSelectResolver("custom")}
                onKeyDown={(event) => handleResolverKeyDown(event, customIndex)}
              >
                <div className="dns-radio-card__top">
                  <span className="dns-radio-card__name-wrap">
                    <span className="dns-radio-dot" aria-hidden="true">
                      {checked ? (
                        <span className="dns-radio-dot__inner" />
                      ) : null}
                    </span>
                    <span className="dns-radio-card__name">
                      Custom DNS
                    </span>
                  </span>
                  <span className="dns-badge">IP / DoH</span>
                </div>
                <span className="dns-radio-card__addr">
                  {customPreview || "IPv4 / IPv6 / https://"}
                </span>
                <p className="dns-radio-card__summary">
                  NextDNS, ControlD, local LAN resolver, or custom IP.
                </p>
              </button>
            );
          })()}
        </div>

        {selectedResolver === "custom" ? (
          <div className="dns-custom-panel">
            <div className="dns-custom-panel__label-row">
              <label
                htmlFor={customInputId}
                className="dns-custom-panel__label"
              >
                Custom IP Address or DoH Endpoint URL
              </label>

              {customPreview ? (
                <span
                  className="dns-preview-pill"
                  aria-label="Redacted DNS preview"
                >
                  <span>Preview</span>
                  <span className="dns-preview-pill__addr">
                    {customPreview}
                  </span>
                </span>
              ) : null}
            </div>

            <div className="dns-custom-input-wrap">
              <input
                id={customInputId}
                type={maskCustomInput ? "password" : "text"}
                className="dns-custom-input"
                value={customDns}
                disabled={saving}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                placeholder="e.g. 10.0.0.53, 2606:4700:4700::1111, or https://dns.nextdns.io/abc123"
                aria-invalid={
                  customDns.trim().length > 0 && !customAnalysis.valid
                }
                aria-describedby={customHintId}
                onChange={(event) => {
                  const nextValue = event.target.value;
                  setCustomDns(nextValue);
                  if (!looksLikeSecretDnsUrl(nextValue) && revealCustom) {
                    setRevealCustom(false);
                  }
                  if (errorBanner) setErrorBanner(null);
                }}
              />

              {customIsSecretUrl ? (
                <button
                  type="button"
                  className="dns-reveal-btn"
                  disabled={saving}
                  aria-label={
                    revealCustom ? "Hide DNS address" : "Reveal DNS address"
                  }
                  aria-pressed={revealCustom}
                  onClick={() => setRevealCustom((prev) => !prev)}
                >
                  {revealCustom ? (
                    <IconEyeOff size={15} />
                  ) : (
                    <IconEye size={15} />
                  )}
                  <span>{revealCustom ? "Hide" : "Reveal"}</span>
                </button>
              ) : null}
            </div>

            <div id={customHintId}>
              {!customAnalysis.valid && customDns.trim().length > 0 ? (
                <p className="dns-hint dns-hint--error" role="alert">
                  {customAnalysis.error}
                </p>
              ) : customAnalysis.kind === "doh_url" ? (
                <p className="dns-hint dns-hint--ok">
                  Valid <code>https://</code> DoH endpoint. Profile tokens in
                  the path/query stay masked by default.
                </p>
              ) : customAnalysis.kind === "known_doh_ip" ? (
                <p className="dns-hint dns-hint--ok">
                  Valid IPv{customAnalysis.ipVersion} address with known IP-SAN
                  DoH support.
                </p>
              ) : customAnalysis.kind === "bare_udp_ip" ? (
                dohEnabled ? (
                  <p className="dns-hint dns-hint--warn">
                    Valid bare IPv{customAnalysis.ipVersion} address. Custom
                    bare IPs do not serve IP-SAN DoH certificates and will be
                    queried over UDP first.
                  </p>
                ) : (
                  <p className="dns-hint">
                    Valid IPv{customAnalysis.ipVersion} address. Queries will be
                    sent over plain UDP.
                  </p>
                )
              ) : (
                <p className="dns-hint">
                  Accepts IPv4, IPv6, or <code>https://.../dns-query</code>.
                  URLs containing paths or credentials are masked automatically
                  to protect NextDNS / ControlD profile tokens.
                </p>
              )}
            </div>
          </div>
        ) : null}
      </section>

      {/* 2. Protocol & Coexistence Section */}
      <section className="dns-section" aria-labelledby="dns-protocol-heading">
        <div className="dns-section__head">
          <div>
            <div className="dns-section__title-row">
              <IconShield size={16} className="dns-section__icon" />
              <h2 id="dns-protocol-heading" className="dns-section__title">
                Protocol &amp; Coexistence
              </h2>
            </div>
            <p className="dns-section__desc">
              Control DNS encryption, QUIC handling, IP stack routing, and
              behavior alongside third-party VPNs.
            </p>
          </div>
        </div>

        <div className="dns-rows">
          {/* Encrypted DNS (DoH) */}
          <div className="dns-row">
            <div className="dns-row__info">
              <div className="dns-row__title-line">
                <span id={dohLabelId} className="dns-row__label">
                  Encrypted DNS (DoH)
                </span>
                {isCustomHttpsUrl ? (
                  <span className="dns-badge dns-badge--accent">Locked ON</span>
                ) : isBareNonDohIp ? (
                  dohEnabled ? (
                    <span className="dns-badge dns-badge--warn">UDP-first</span>
                  ) : (
                    <span className="dns-badge">Plain UDP</span>
                  )
                ) : !effectiveDohChecked ? (
                  <span className="dns-badge">Plain UDP</span>
                ) : null}
              </div>

              <p id={dohDescId} className="dns-row__desc">
                {isCustomHttpsUrl ? (
                  <>
                    Automatically locked ON because a custom{" "}
                    <code>https://</code> DoH URL is configured. Switch to a
                    bare IP resolver if you want plain UDP DNS.
                  </>
                ) : isBareNonDohIp && dohEnabled ? (
                  <>
                    Bare custom IPs (such as <code>10.0.0.53</code> or{" "}
                    <code>76.76.2.0</code>) do not serve IP-SAN DoH
                    certificates, so vdpi queries them over UDP first even while
                    this toggle is ON. Enter an <code>https://</code> URL above
                    for encrypted DoH with a custom provider.
                  </>
                ) : isBareNonDohIp ? (
                  <>
                    Encrypted DNS is OFF. Queries to this custom IP are sent
                    over plain UDP. Enter an <code>https://</code> URL above if
                    your provider supports DoH.
                  </>
                ) : (
                  "Encrypt DNS lookups over HTTPS (RFC 8484) to prevent ISP DNS hijacking and poisoning."
                )}
              </p>
            </div>

            <div className="dns-row__control">
              <Switch
                checked={effectiveDohChecked}
                disabled={saving || isCustomHttpsUrl}
                ariaLabelledBy={dohLabelId}
                ariaDescribedBy={dohDescId}
                onChange={setDohEnabled}
              />
            </div>
          </div>

          {isBareNonDohIp && dohEnabled ? (
            <InlineBanner
              tone="info"
              title="UDP-first resolution active for bare custom IP"
              description={`Because ${activeDnsAddr} is not a known IP-SAN DoH server, vdpi will send DNS queries over UDP instead of synthesizing https://${formatDohUrlHost(activeDnsAddr, activeDnsAnalysis.ipVersion)}/dns-query.`}
            />
          ) : null}

          {/* Block QUIC (UDP/443) */}
          <div className="dns-row">
            <div className="dns-row__info">
              <div className="dns-row__title-line">
                <span id={quicLabelId} className="dns-row__label">
                  Block QUIC (UDP/443)
                </span>
              </div>
              <p id={quicDescId} className="dns-row__desc">
                Forces browsers to fall back from HTTP/3 (QUIC) to desynced TCP
                TLS for reliable DPI bypass while preserving Discord and WebRTC
                voice/video UDP traffic.
              </p>
            </div>

            <div className="dns-row__control">
              <Switch
                checked={blockQuic}
                disabled={saving}
                ariaLabelledBy={quicLabelId}
                ariaDescribedBy={quicDescId}
                onChange={setBlockQuic}
              />
            </div>
          </div>

          {/* IPv6 Support (TUN) */}
          <div className="dns-row">
            <div className="dns-row__info">
              <div className="dns-row__title-line">
                <span id={ipv6LabelId} className="dns-row__label">
                  IPv6 Support (TUN)
                </span>
                {isProxyMode ? (
                  <span className="dns-badge">TUN mode only</span>
                ) : null}
              </div>
              <p id={ipv6DescId} className="dns-row__desc">
                {isProxyMode
                  ? "Unavailable in Proxy mode. Switch to the TUN engine to route IPv6 traffic through the virtual TUN adapter."
                  : "Route IPv6 traffic through the virtual TUN adapter on dual-stack networks. When IPv4 Only is also enabled, AAAA DNS lookups are suppressed while IPv6 TUN routes remain active for literal IPv6 addresses."}
              </p>
            </div>

            <div className="dns-row__control">
              <Switch
                checked={tunIpv6}
                disabled={saving || isProxyMode}
                ariaLabelledBy={ipv6LabelId}
                ariaDescribedBy={ipv6DescId}
                onChange={setTunIpv6}
              />
            </div>
          </div>

          {/* IPv4 Only */}
          <div className="dns-row">
            <div className="dns-row__info">
              <div className="dns-row__title-line">
                <span id={ipv4LabelId} className="dns-row__label">
                  IPv4 Only
                </span>
              </div>
              <p id={ipv4DescId} className="dns-row__desc">
                Suppress AAAA DNS lookups so hostnames resolve to IPv4 (A)
                records only when IPv6 paths are broken or throttled by your
                ISP. If IPv6 Support (TUN) is enabled, IPv6 TUN routes remain
                active for literal IPv6 addresses.
              </p>
            </div>

            <div className="dns-row__control">
              <Switch
                checked={ipv4Only}
                disabled={saving}
                ariaLabelledBy={ipv4LabelId}
                ariaDescribedBy={ipv4DescId}
                onChange={setIpv4Only}
              />
            </div>
          </div>

          {!isProxyMode && tunIpv6 && ipv4Only ? (
            <InlineBanner
              tone="warn"
              title="IPv4 Only paired with IPv6 Support (TUN)"
              description="Both IPv6 Support (TUN) and IPv4 Only are enabled. IPv4 Only suppresses AAAA DNS lookups so hostnames resolve to IPv4 (A) records only, while IPv6 TUN routes remain active for literal IPv6 addresses."
            />
          ) : null}

          {ipv4Only && isIpv6CustomDns ? (
            <InlineBanner
              tone="warn"
              title="IPv6 custom DNS paired with IPv4 Only"
              description="Your custom DNS server uses an IPv6 address while IPv4 Only is enabled. Disable IPv4 Only or switch to an IPv4 / hostname resolver so DNS lookups stay reachable."
            />
          ) : null}

          {/* VPN Coexistence */}
          <div className="dns-row dns-row--stacked">
            <div className="dns-row__info">
              <div className="dns-row__title-line">
                <span id={vpnLabelId} className="dns-row__label">
                  VPN Coexistence
                </span>
              </div>
              <p className="dns-row__desc">
                {VPN_COEXISTENCE_DESCRIPTIONS[vpnCoexistence]}
              </p>
            </div>

            <div className="dns-row__control">
              <SegmentedControl<VpnCoexistence>
                options={VPN_COEXISTENCE_OPTIONS}
                value={vpnCoexistence}
                disabled={saving}
                ariaLabelledBy={vpnLabelId}
                onChange={setVpnCoexistence}
              />
            </div>
          </div>
        </div>
      </section>

      {/* 3. Domain Rules Section */}
      <section className="dns-section" aria-labelledby="dns-domains-heading">
        <div className="dns-section__head">
          <div>
            <h2 id="dns-domains-heading" className="dns-section__title">
              Domain Rules
            </h2>
            <p className="dns-section__desc">
              Configure hostnames that bypass vdpi directly or restrict
              desyncing to an explicit allowlist. User Bypass rules always take
              precedence over Include rules.
            </p>
          </div>
        </div>

        {overlappingDomains.length > 0 ? (
          <InlineBanner
            tone="warn"
            title="Overlapping domain rules"
            description={`${
              overlappingDomains.length > 6
                ? `${overlappingDomains.slice(0, 6).join(", ")} (+${overlappingDomains.length - 6} more)`
                : overlappingDomains.join(", ")
            }. User Bypass rules take precedence over Include rules for overlapping hostnames and subdomains.`}
          />
        ) : null}

        <div className="dns-domains-grid">
          <div className="dns-domain-card">
            <DomainListEditor
              label="Bypass Domains"
              description="Always connect directly without vdpi desyncing. User Bypass rules take precedence over Include rules."
              placeholder="e.g. bank.com.tr or *.local.corp"
              emptyText="No custom bypass domains configured."
              domains={bypassDomains}
              maxEntries={MAX_DOMAIN_ENTRIES}
              disabled={saving}
              resetNonce={resetNonce}
              onChange={setBypassDomains}
            />
          </div>

          <div className="dns-domain-card">
            <DomainListEditor
              label="Include Domains"
              description="Allowlist filter: adding entries restricts vdpi to only matching domains (overriding built-in default bypasses such as .gov.tr) while all other traffic connects directly. User Bypass rules still take precedence over Include rules."
              placeholder="e.g. service.gov.tr or *.example.org"
              emptyText="No allowlist include domains configured."
              domains={includeDomains}
              maxEntries={MAX_DOMAIN_ENTRIES}
              disabled={saving}
              resetNonce={resetNonce}
              onChange={setIncludeDomains}
            />
          </div>
        </div>
      </section>

      {/* Sticky Save & Apply bar — rendered ONLY when dirty */}
      {isDirty ? (
        <div
          className="dns-sticky-bar"
          role="region"
          aria-label="Unsaved DNS and rule changes"
        >
          <div className="dns-sticky-bar__info">
            <p className="dns-sticky-bar__title">Unsaved Changes</p>
            <div className="dns-sticky-bar__tags">
              {!activeDnsAnalysis.valid ? (
                <span className="dns-badge dns-badge--warn">
                  Fix custom DNS address before saving
                </span>
              ) : (
                dirtyChanges.map((change) => (
                  <span key={change} className="dns-badge dns-badge--accent">
                    {change}
                  </span>
                ))
              )}
            </div>
          </div>

          <div className="dns-sticky-bar__actions">
            <button
              type="button"
              className="dns-btn"
              disabled={saving}
              onClick={handleDiscard}
            >
              Discard
            </button>
            <button
              type="button"
              className="dns-btn dns-btn--primary"
              disabled={!canSave}
              onClick={() => void handleSave()}
            >
              {saving ? (
                <span className="dns-spinner" aria-hidden="true" />
              ) : null}
              <span>{saving ? "Saving..." : "Save & Apply"}</span>
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function areDnsRulesPropsEqual(
  prev: DnsRulesViewProps,
  next: DnsRulesViewProps,
): boolean {
  if (
    prev.settings !== next.settings ||
    prev.busyAction !== next.busyAction ||
    prev.onSaved !== next.onSaved ||
    prev.onPushToast !== next.onPushToast ||
    prev.onDirtyChange !== next.onDirtyChange
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
    (prevLive?.running ?? false) === (nextLive?.running ?? false) &&
    prevLive?.engine === nextLive?.engine &&
    prevLive?.dnsDisplay === nextLive?.dnsDisplay &&
    prevLive?.dohEnabled === nextLive?.dohEnabled &&
    prevLive?.vpnConflict === nextLive?.vpnConflict
  );
}

export const DnsRulesView = memo(DnsRulesViewComponent, areDnsRulesPropsEqual);
DnsRulesView.displayName = "DnsRulesView";

export default DnsRulesView;
