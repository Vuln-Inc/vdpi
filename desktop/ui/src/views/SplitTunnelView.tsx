import {
  memo,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import type { FormEvent, KeyboardEvent } from "react";
import { IconPlus, IconRefresh, IconSearch } from "../components/Icons";
import { InlineBanner } from "../components/InlineBanner";
import type { ToastTone } from "../components/ToastStack";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import { localizePresetLabel, tSplit } from "../i18n/split";
import { extractExecutableName, foldTurkish } from "../lib/format";
import {
  getSplitTunnel,
  pickExecutableFile,
  saveSplitTunnel,
} from "../lib/ipc";
import type {
  ActionResult,
  AppCategory,
  DiscoveredAppItem,
  EngineMode,
  SplitTunnelMode,
  SplitTunnelPayload,
  SplitTunnelPreset,
} from "../types";
import { SplitTunnelAppRow } from "./SplitTunnelAppRow";
import { SplitTunnelPresets } from "./SplitTunnelPresets";

export interface SplitTunnelViewProps {
  activeEngine?: EngineMode;
  platform?: "windows" | "macos" | "linux";
  busyAction?: string | null;
  onSaved?: () => void | Promise<void>;
  onPushToast?: (tone: ToastTone, message: string) => void;
  onDirtyChange?: (dirty: boolean) => void;
  onSwitchToTun?: () => void | Promise<void>;
}

type FilterPillId =
  | "all"
  | "selected"
  | "running"
  | "games"
  | "browsers"
  | "communication"
  | "media";

interface ModeOption {
  value: SplitTunnelMode;
  label: string;
  description: string;
}

const MAX_SPLIT_TUNNEL_APPS = 256;

const APP_NAME_COLLATOR = new Intl.Collator(undefined, {
  sensitivity: "base",
});

const MODE_VALUES: readonly SplitTunnelMode[] = ["all", "exclude", "include"];

function getModeOptions(lang: ResolvedLanguage): readonly ModeOption[] {
  return [
    {
      value: "all",
      label: tSplit(lang, "modeAllLabel"),
      description: tSplit(lang, "modeAllDesc"),
    },
    {
      value: "exclude",
      label: tSplit(lang, "modeExcludeLabel"),
      description: tSplit(lang, "modeExcludeDesc"),
    },
    {
      value: "include",
      label: tSplit(lang, "modeIncludeLabel"),
      description: tSplit(lang, "modeIncludeDesc"),
    },
  ];
}

const FALLBACK_PRESETS: readonly SplitTunnelPreset[] = [
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

const CATEGORY_RANK: Record<AppCategory, number> = {
  running: 0,
  popular: 1,
  installed: 2,
  custom: 3,
};

const STYLE_ID = "vdpi-split-tunnel-view-styles";

const FALLBACK_STYLES = `
@keyframes vdpi-split-spin {
  to {
    transform: rotate(360deg);
  }
}

:where(.split-view) {
  --_sv-surface: var(--bg-surface, var(--surface, #131518));
  --_sv-surface-raised: var(--bg-surface-elevated, var(--surface-raised, #1b1e24));
  --_sv-surface-hover: var(--bg-surface-hover, rgba(255, 255, 255, 0.05));
  --_sv-surface-subtle: var(--bg-surface-subtle, rgba(255, 255, 255, 0.035));
  --_sv-input: var(--bg-input, var(--bg-surface, #0e1013));
  --_sv-border: var(--border-subtle, var(--border, rgba(255, 255, 255, 0.1)));
  --_sv-border-strong: var(--border-strong, rgba(255, 255, 255, 0.2));
  --_sv-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_sv-secondary: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_sv-muted: var(--ink-tertiary, var(--ink-muted, #7c828e));
  --_sv-accent: var(--accent, #3b82f6);
  --_sv-accent-fg: var(--accent-fg, var(--accent, #60a5fa));
  --_sv-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(59, 130, 246, 0.14)));
  --_sv-accent-border: var(--accent-border, rgba(59, 130, 246, 0.34));
  --_sv-signal: var(--status-green-fg, var(--signal, #30d158));
  --_sv-signal-tint: var(--status-green-bg, var(--signal-tint, rgba(48, 209, 88, 0.12)));
  --_sv-warn: var(--status-amber-fg, var(--warning, #ff9f0a));
  --_sv-warn-tint: var(--status-amber-bg, var(--warning-tint, rgba(255, 159, 10, 0.14)));
  --_sv-warn-border: var(--status-amber-border, rgba(255, 159, 10, 0.3));
  --_sv-danger: var(--status-crimson-fg, var(--danger, #ff453a));
  --_sv-danger-tint: var(--status-crimson-bg, var(--danger-tint, rgba(255, 69, 58, 0.12)));
  --_sv-primary-bg: var(--accent, var(--primary-button-bg, #3b82f6));
  --_sv-primary-bg-hover: var(--accent-hover, #1d4ed8);
  --_sv-primary-ink: var(--ink-on-accent, var(--primary-button-ink, #ffffff));
  --_sv-mono-font: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-direction: column;
  gap: 12px;
  color: var(--_sv-ink);
  box-sizing: border-box;
  min-height: 100%;
  padding-bottom: 12px;
}

:where([data-theme="light"] .split-view) {
  --_sv-surface: var(--bg-surface, var(--surface, #ffffff));
  --_sv-surface-raised: var(--bg-surface-elevated, var(--surface-raised, #ffffff));
  --_sv-surface-hover: var(--bg-surface-hover, #e9ecf1);
  --_sv-surface-subtle: var(--bg-surface-subtle, #f1f3f6);
  --_sv-input: var(--bg-input, #ffffff);
  --_sv-border: var(--border-subtle, var(--border, rgba(11, 12, 14, 0.1)));
  --_sv-border-strong: var(--border-strong, rgba(11, 12, 14, 0.24));
  --_sv-ink: var(--ink-primary, var(--text-primary, #111317));
  --_sv-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_sv-muted: var(--ink-tertiary, var(--ink-muted, #6b7280));
  --_sv-accent: var(--accent, #0066cc);
  --_sv-accent-fg: var(--accent-fg, #0066cc);
  --_sv-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(0, 102, 204, 0.1)));
  --_sv-accent-border: var(--accent-border, rgba(0, 102, 204, 0.3));
  --_sv-signal: var(--status-green-fg, #18793a);
  --_sv-signal-tint: var(--status-green-bg, rgba(48, 209, 88, 0.12));
  --_sv-warn: var(--status-amber-fg, #a15c00);
  --_sv-warn-tint: var(--status-amber-bg, rgba(255, 159, 10, 0.14));
  --_sv-warn-border: var(--status-amber-border, rgba(161, 92, 0, 0.24));
  --_sv-danger: var(--status-crimson-fg, #c82320);
  --_sv-danger-tint: var(--status-crimson-bg, rgba(255, 69, 58, 0.11));
  --_sv-primary-bg: var(--accent, #0066cc);
  --_sv-primary-bg-hover: var(--accent-hover, #0055b3);
}

:where([data-theme="light"] .split-mode-card),
:where([data-theme="light"] .split-list-card) {
  box-shadow: var(--shadow-sm);
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .split-view) {
    --_sv-surface: var(--bg-surface, var(--surface, #ffffff));
    --_sv-surface-raised: var(--bg-surface-elevated, var(--surface-raised, #ffffff));
    --_sv-surface-hover: var(--bg-surface-hover, #e9ecf1);
    --_sv-surface-subtle: var(--bg-surface-subtle, #f1f3f6);
    --_sv-input: var(--bg-input, #ffffff);
    --_sv-border: var(--border-subtle, var(--border, rgba(11, 12, 14, 0.1)));
    --_sv-border-strong: var(--border-strong, rgba(11, 12, 14, 0.24));
    --_sv-ink: var(--ink-primary, var(--text-primary, #111317));
    --_sv-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_sv-muted: var(--ink-tertiary, var(--ink-muted, #6b7280));
    --_sv-accent: var(--accent, #0066cc);
    --_sv-accent-fg: var(--accent-fg, #0066cc);
    --_sv-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(0, 102, 204, 0.1)));
    --_sv-accent-border: var(--accent-border, rgba(0, 102, 204, 0.3));
    --_sv-signal: var(--status-green-fg, #18793a);
    --_sv-signal-tint: var(--status-green-bg, rgba(48, 209, 88, 0.12));
    --_sv-warn: var(--status-amber-fg, #a15c00);
    --_sv-warn-tint: var(--status-amber-bg, rgba(255, 159, 10, 0.14));
    --_sv-warn-border: var(--status-amber-border, rgba(161, 92, 0, 0.24));
    --_sv-danger: var(--status-crimson-fg, #c82320);
    --_sv-danger-tint: var(--status-crimson-bg, rgba(255, 69, 58, 0.11));
    --_sv-primary-bg: var(--accent, #0066cc);
    --_sv-primary-bg-hover: var(--accent-hover, #0055b3);
  }

  :where(:root:not([data-theme="dark"]) .split-mode-card),
  :where(:root:not([data-theme="dark"]) .split-list-card) {
    box-shadow: var(--shadow-sm);
  }
}

:where(.split-view__header) {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

:where(.split-view__title) {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
  letter-spacing: -0.02em;
  line-height: 1.3;
  color: var(--_sv-ink);
}

:where(.split-view__subtitle) {
  margin: 0;
  font-size: 13px;
  line-height: 1.4;
  color: var(--_sv-secondary);
}

:where(.split-view__section) {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

:where(.split-view__section-head) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
}

:where(.split-view__section-label) {
  font-size: 11.5px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: var(--_sv-muted);
}

:where(.split-view__section-hint) {
  font-size: 12px;
  color: var(--_sv-secondary);
}

:where(.split-mode-grid) {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 8px;
}

@media (max-width: 720px) {
  :where(.split-mode-grid) {
    grid-template-columns: 1fr;
  }
}

:where(.split-mode-card) {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 5px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-surface);
  color: var(--_sv-ink);
  text-align: left;
  font: inherit;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 120ms ease, border-color 120ms ease, box-shadow 120ms ease;
}

:where(.split-mode-card:hover:not(:disabled)) {
  background: var(--_sv-surface-raised);
  border-color: var(--_sv-border-strong);
}

:where(.split-mode-card[data-active="true"]) {
  background: var(--_sv-accent-tint);
  border-color: var(--_sv-accent-border);
}

:where(.split-mode-card:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_sv-accent));
  outline-offset: 2px;
}

:where(.split-mode-card:disabled) {
  opacity: 0.6;
  cursor: not-allowed;
}

:where(.split-mode-card__top) {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
}

:where(.split-mode-card__radio) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  border: 1.5px solid var(--_sv-border-strong);
  flex-shrink: 0;
  box-sizing: border-box;
  transition: border-color 120ms ease;
}

:where(.split-mode-card[data-active="true"] .split-mode-card__radio) {
  border-color: var(--accent-fg, var(--_sv-accent-fg));
}

:where(.split-mode-card__radio-dot) {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--accent-fg, var(--_sv-accent-fg));
}

:where(.split-mode-card__title) {
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.25;
  color: var(--_sv-ink);
}

:where(.split-mode-card__desc) {
  padding-left: 24px;
  font-size: 12px;
  line-height: 1.4;
  color: var(--_sv-secondary);
}

:where(.split-toolbar) {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

:where(.split-toolbar__row) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.split-search) {
  position: relative;
  display: flex;
  align-items: center;
  flex: 1 1 200px;
  min-width: 0;
}

:where(.split-search__icon) {
  position: absolute;
  left: 10px;
  display: inline-flex;
  align-items: center;
  color: var(--_sv-muted);
  pointer-events: none;
}

:where(.split-search__input) {
  width: 100%;
  height: 32px;
  padding: 0 64px 0 32px;
  border-radius: 8px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-input);
  color: var(--_sv-ink);
  font: inherit;
  font-size: 13px;
  box-sizing: border-box;
  transition: border-color 120ms ease, background-color 120ms ease;
}

:where(.split-search__input::placeholder) {
  color: var(--_sv-muted);
}

:where(.split-search__input:focus) {
  outline: none;
  border-color: var(--_sv-accent);
}

:where(.split-search__clear) {
  position: absolute;
  right: 4px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 24px;
  min-height: 24px;
  height: 24px;
  padding: 0 8px;
  border-radius: 5px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-surface-raised);
  color: var(--_sv-secondary);
  font: inherit;
  font-size: 11.5px;
  font-weight: 500;
  line-height: 1;
  cursor: pointer;
  box-sizing: border-box;
}

:where(.split-search__clear:hover) {
  color: var(--_sv-ink);
  border-color: var(--_sv-border-strong);
}

:where(.split-search__clear:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_sv-accent));
  outline-offset: 1px;
}

:where(.split-btn) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  height: 32px;
  padding: 0 12px;
  border-radius: 8px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-surface);
  color: var(--_sv-ink);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 120ms ease, border-color 120ms ease, opacity 120ms ease;
}

:where(.split-btn:hover:not(:disabled)) {
  background: var(--_sv-surface-raised);
  border-color: var(--_sv-border-strong);
}

:where(.split-btn[aria-expanded="true"]) {
  background: var(--_sv-accent-tint);
  border-color: var(--_sv-accent-border);
  color: var(--_sv-ink);
}

:where(.split-btn:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_sv-accent));
  outline-offset: 2px;
}

:where(.split-btn:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.split-btn--primary) {
  border-color: transparent;
  background: var(--_sv-primary-bg);
  color: var(--_sv-primary-ink);
}

:where(.split-btn--primary:hover:not(:disabled)) {
  background: var(--accent-hover, var(--_sv-primary-bg-hover));
  border-color: transparent;
}

:where(.split-btn--ghost) {
  border-color: transparent;
  background: transparent;
  color: var(--_sv-secondary);
  height: 28px;
  padding: 0 8px;
  font-size: 12px;
}

:where(.split-btn--ghost:hover:not(:disabled)) {
  color: var(--_sv-ink);
  background: var(--_sv-surface-raised);
  border-color: transparent;
}

:where(.split-filters) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.split-filters__pills) {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

:where(.split-filter-pill) {
  display: inline-flex;
  align-items: center;
  height: 28px;
  padding: 0 11px;
  border-radius: 999px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-surface);
  color: var(--_sv-secondary);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  line-height: 1;
  cursor: pointer;
  transition: background-color 110ms ease, border-color 110ms ease, color 110ms ease;
}

:where(.split-filter-pill:hover) {
  background: var(--_sv-surface-raised);
  color: var(--_sv-ink);
}

:where(.split-filter-pill[aria-pressed="true"]) {
  background: var(--_sv-accent-tint);
  border-color: var(--_sv-accent-border);
  color: var(--_sv-ink);
}

:where(.split-filter-pill:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_sv-accent));
  outline-offset: 2px;
}

:where(.split-custom-form) {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

:where(.split-custom-row) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

:where(.split-custom-row__input) {
  flex: 1 1 260px;
  min-width: 0;
  height: 32px;
  padding: 0 11px;
  border-radius: 8px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-input);
  color: var(--_sv-ink);
  font-family: var(--_sv-mono-font);
  font-size: 12.5px;
  box-sizing: border-box;
  transition: border-color 120ms ease;
}

:where(.split-custom-row__input::placeholder) {
  font-family: inherit;
  color: var(--_sv-muted);
}

:where(.split-custom-row__input:focus) {
  outline: none;
  border-color: var(--_sv-accent);
}

:where(.split-custom-error) {
  margin: 0;
  font-size: 12px;
  color: var(--_sv-danger);
}

:where(.split-list-card) {
  border-radius: 10px;
  border: 1px solid var(--_sv-border);
  background: var(--_sv-surface);
  overflow: hidden;
}

:where(.split-list-meta) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  border-bottom: 1px solid var(--_sv-border);
  background: var(--_sv-surface-subtle);
  font-size: 12px;
  color: var(--_sv-secondary);
}

:where(.split-list-meta__count--limit) {
  display: inline-flex;
  align-items: center;
  padding: 1px 7px;
  border-radius: 999px;
  border: 1px solid var(--_sv-warn-border);
  background: var(--_sv-warn-tint);
  color: var(--_sv-warn);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

:where(.split-list-empty) {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 32px 16px;
  text-align: center;
  color: var(--_sv-secondary);
}

:where(.split-list-empty__title) {
  margin: 0;
  font-size: 13.5px;
  font-weight: 500;
  color: var(--_sv-ink);
}

:where(.split-list-empty__desc) {
  margin: 0;
  font-size: 12.5px;
  color: var(--_sv-muted);
}

:where(.split-unsaved-bar) {
  position: sticky;
  bottom: 0;
  z-index: 20;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: auto;
  padding: 12px 14px;
  border-radius: 12px;
  border: 1px solid var(--_sv-accent-border);
  background: var(--_sv-surface-raised);
  box-shadow: 0 12px 32px rgba(0, 0, 0, 0.34);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  box-sizing: border-box;
}

:where(.split-unsaved-bar__info) {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
}

:where(.split-unsaved-bar__title) {
  margin: 0;
  font-size: 13.5px;
  font-weight: 600;
  color: var(--_sv-ink);
}

:where(.split-unsaved-bar__summary) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 12px;
  color: var(--_sv-secondary);
}

:where(.split-diff-badge) {
  display: inline-flex;
  align-items: center;
  height: 20px;
  padding: 0 7px;
  border-radius: 999px;
  font-family: var(--_sv-mono-font);
  font-size: 11px;
  font-weight: 500;
}

:where(.split-diff-badge--added) {
  background: var(--_sv-signal-tint);
  color: var(--_sv-signal);
}

:where(.split-diff-badge--removed) {
  background: var(--_sv-danger-tint);
  color: var(--_sv-danger);
}

:where(.split-diff-badge--mode) {
  background: var(--_sv-accent-tint);
  color: var(--_sv-accent-fg);
  font-family: inherit;
}

:where(.split-diff-badge--warn) {
  background: var(--_sv-warn-tint);
  border: 1px solid var(--_sv-warn-border);
  color: var(--_sv-warn);
  font-family: inherit;
}

:where(.split-unsaved-bar__actions) {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

:where(.split-spinner) {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  border: 2px solid currentColor;
  border-right-color: transparent;
  animation: vdpi-split-spin 0.7s linear infinite;
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

/**
 * Matches Rust `normalize_split_app_name`: extracts filename, lowercases,
 * strips U+0307 from dotted `İ`, folds dotless `ı` (U+0131) to `i`, and strips
 * trailing `.exe` - intentionally preserving other diacritics (`ş`, `ç`, `ğ`, `ü`, `ö`).
 */
function normalizeAppKey(raw: string): string {
  const extracted = extractExecutableName(raw);
  if (!extracted) return "";
  const lowered = extracted
    .toLowerCase()
    .replace(/\u0307/g, "")
    .replace(/\u0131/g, "i")
    .trim();
  if (!lowered) return "";
  const stripped = lowered.endsWith(".exe") ? lowered.slice(0, -4) : lowered;
  return stripped.trim();
}

function deriveDisplayName(
  exeName: string,
  fallbackName = "Custom App",
): string {
  const stem = exeName
    .trim()
    .replace(/\.(exe|app|bin)$/i, "")
    .replace(/[_-]+/g, " ")
    .trim();
  if (!stem) return exeName.trim() || fallbackName;
  return stem
    .split(/\s+/)
    .map((part) => (part ? part[0].toUpperCase() + part.slice(1) : ""))
    .join(" ");
}

function extractCleanPath(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (!trimmed.includes("\\") && !trimmed.includes("/")) {
    return null;
  }
  const quoted = trimmed.match(/^["']([^"']+)["']/);
  if (quoted && quoted[1]) {
    return quoted[1].trim() || null;
  }
  return trimmed;
}

function toSelectionMap(
  apps: readonly string[],
  discovered: readonly DiscoveredAppItem[],
): Map<string, string> {
  const exeByKey = new Map<string, string>();
  for (const item of discovered) {
    const key = normalizeAppKey(item.normalizedKey || item.exeName);
    if (key && !exeByKey.has(key)) {
      exeByKey.set(key, item.exeName || `${key}.exe`);
    }
  }

  const result = new Map<string, string>();
  for (const raw of apps) {
    const extracted = extractExecutableName(raw) || raw.trim();
    const key = normalizeAppKey(extracted);
    if (!key) continue;
    if (!result.has(key)) {
      result.set(key, exeByKey.get(key) ?? extracted);
    }
  }
  return result;
}

function mergeDiscoveredItems(
  existing: DiscoveredAppItem,
  incoming: DiscoveredAppItem,
): DiscoveredAppItem {
  const existingRank = CATEGORY_RANK[existing.category] ?? 99;
  const incomingRank = CATEGORY_RANK[incoming.category] ?? 99;
  const preferred = incomingRank < existingRank ? incoming : existing;
  const secondary = preferred === incoming ? existing : incoming;

  const companionSet = new Set<string>([
    ...preferred.companions,
    ...secondary.companions,
  ]);

  return {
    displayName: preferred.displayName || secondary.displayName,
    exeName: preferred.exeName || secondary.exeName,
    normalizedKey: preferred.normalizedKey,
    path: preferred.path ?? secondary.path,
    isRunning: existing.isRunning || incoming.isRunning,
    category: preferred.category,
    companions: Array.from(companionSet),
    groupTag:
      preferred.groupTag !== "other" ? preferred.groupTag : secondary.groupTag,
  };
}

interface IndexedAppItem {
  app: DiscoveredAppItem;
  foldedDisplayName: string;
  foldedKey: string;
  haystackFields: readonly string[];
}

function buildIndexedApp(app: DiscoveredAppItem): IndexedAppItem {
  const foldedDisplayName = foldTurkish(app.displayName);
  const foldedKey = foldTurkish(app.normalizedKey);
  const haystackFields = [
    foldedDisplayName,
    foldTurkish(app.exeName),
    foldedKey,
    app.path ? foldTurkish(app.path) : "",
    ...app.companions.map((c) => foldTurkish(c)),
  ];
  return { app, foldedDisplayName, foldedKey, haystackFields };
}

function isWindowsShortcutInput(raw: string): boolean {
  return /\.lnk(?:["']?(?:\s|$))/i.test(raw.trim());
}

function getModeLabel(mode: SplitTunnelMode, lang: ResolvedLanguage): string {
  if (mode === "all") return tSplit(lang, "modeAllLabel");
  if (mode === "exclude") return tSplit(lang, "modeExcludeLabel");
  return tSplit(lang, "modeIncludeLabel");
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

export const SplitTunnelView = memo(function SplitTunnelView({
  activeEngine,
  platform,
  busyAction = null,
  onSaved,
  onPushToast,
  onDirtyChange,
  onSwitchToTun,
}: SplitTunnelViewProps) {
  const { lang } = useLang();
  const langRef = useRef(lang);
  langRef.current = lang;

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [browsing, setBrowsing] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);

  const [discoveredApps, setDiscoveredApps] = useState<DiscoveredAppItem[]>([]);
  const [presets, setPresets] = useState<SplitTunnelPreset[]>([]);
  const [customEntries, setCustomEntries] = useState<DiscoveredAppItem[]>([]);
  const [presetSyntheticEntries, setPresetSyntheticEntries] = useState<
    DiscoveredAppItem[]
  >([]);

  const [savedMode, setSavedMode] = useState<SplitTunnelMode>("all");
  const [savedSelected, setSavedSelected] = useState<Map<string, string>>(
    () => new Map(),
  );

  const [draftMode, setDraftMode] = useState<SplitTunnelMode>("all");
  const [draftSelected, setDraftSelected] = useState<Map<string, string>>(
    () => new Map(),
  );

  const [searchQuery, setSearchQuery] = useState("");
  const deferredSearchQuery = useDeferredValue(searchQuery);
  const [activeFilter, setActiveFilter] = useState<FilterPillId>("all");
  const [showCustomForm, setShowCustomForm] = useState(false);
  const [customInput, setCustomInput] = useState("");
  const [customError, setCustomError] = useState<string | null>(null);
  const [sortVersion, setSortVersion] = useState(0);

  const mountedRef = useRef(true);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const customInputRef = useRef<HTMLInputElement>(null);
  const modeRadioRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const draftModeRef = useRef(draftMode);
  draftModeRef.current = draftMode;
  const draftSelectedRef = useRef(draftSelected);
  draftSelectedRef.current = draftSelected;
  const savedSelectedRef = useRef(savedSelected);
  savedSelectedRef.current = savedSelected;
  const savingRef = useRef(saving);
  savingRef.current = saving;
  const onDirtyChangeRef = useRef(onDirtyChange);
  onDirtyChangeRef.current = onDirtyChange;
  const onPushToastRef = useRef(onPushToast);
  onPushToastRef.current = onPushToast;

  const sortSelectedSnapshotRef = useRef<Set<string>>(new Set());
  const sortOrderRef = useRef<Map<string, number>>(new Map());
  const sortOrderVersionRef = useRef<number>(-1);

  const isWindows = platform === undefined || platform === "windows";

  useEffect(() => {
    ensureStyles();
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      onDirtyChangeRef.current?.(false);
    };
  }, []);

  const resetSortSnapshot = useCallback((selectedKeys: Iterable<string>) => {
    sortSelectedSnapshotRef.current = new Set(selectedKeys);
    setSortVersion((prev) => prev + 1);
  }, []);

  const applyPayload = useCallback(
    (payload: SplitTunnelPayload, preserveDraft: boolean) => {
      const nextDiscovered = Array.isArray(payload.discoveredApps)
        ? payload.discoveredApps
        : [];
      const nextPresets = Array.isArray(payload.presets) ? payload.presets : [];
      const nextSavedMap = toSelectionMap(
        Array.isArray(payload.selectedApps) ? payload.selectedApps : [],
        nextDiscovered,
      );

      setDiscoveredApps(nextDiscovered);
      setPresets(nextPresets);
      setSavedMode(payload.mode);
      setSavedSelected(nextSavedMap);

      if (!preserveDraft) {
        draftModeRef.current = payload.mode;
        const freshDraft = new Map(nextSavedMap);
        draftSelectedRef.current = freshDraft;
        setDraftMode(payload.mode);
        setDraftSelected(freshDraft);
        setCustomEntries([]);
        setPresetSyntheticEntries([]);
        resetSortSnapshot(nextSavedMap.keys());
      } else {
        resetSortSnapshot(draftSelectedRef.current.keys());
      }
      setLoadedOnce(true);
    },
    [resetSortSnapshot],
  );

  const loadSplitTunnel = useCallback(
    async (options: { preserveDraft: boolean; silentToast?: boolean }) => {
      const { preserveDraft, silentToast = true } = options;
      if (preserveDraft) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setErrorBanner(null);

      try {
        const payload: SplitTunnelPayload = await getSplitTunnel();
        if (!mountedRef.current) return;
        applyPayload(payload, preserveDraft);
        if (preserveDraft && !silentToast) {
          const runningCount = payload.discoveredApps.filter(
            (item: DiscoveredAppItem) => item.isRunning,
          ).length;
          onPushToast?.(
            "info",
            tSplit(langRef.current, "refreshedToast", { count: runningCount }),
          );
        }
      } catch (error) {
        if (!mountedRef.current) return;
        const message = getErrorMessage(
          error,
          tSplit(langRef.current, "loadFailed"),
        );
        setErrorBanner(message);
        if (preserveDraft) {
          onPushToast?.("error", message);
        }
      } finally {
        if (mountedRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [applyPayload, onPushToast],
  );

  useEffect(() => {
    void loadSplitTunnel({ preserveDraft: false });
  }, [loadSplitTunnel]);

  const effectivePresets = useMemo<SplitTunnelPreset[]>(() => {
    return presets.length > 0 ? presets : [...FALLBACK_PRESETS];
  }, [presets]);

  const presetGroupByKey = useMemo(() => {
    const map = new Map<string, DiscoveredAppItem["groupTag"]>();
    for (const preset of effectivePresets) {
      for (const app of preset.apps) {
        const key = normalizeAppKey(app);
        if (key && !map.has(key)) {
          map.set(key, preset.groupTag);
        }
      }
    }
    return map;
  }, [effectivePresets]);

  const presetGroupByKeyRef = useRef(presetGroupByKey);
  presetGroupByKeyRef.current = presetGroupByKey;

  const baseDiscoveredApps = useMemo(() => {
    const byKey = new Map<string, DiscoveredAppItem>();

    for (const rawItem of discoveredApps) {
      const key = normalizeAppKey(rawItem.normalizedKey || rawItem.exeName);
      if (!key) continue;
      const normalizedItem: DiscoveredAppItem = {
        ...rawItem,
        normalizedKey: key,
        exeName: rawItem.exeName || `${key}.exe`,
        displayName: rawItem.displayName || deriveDisplayName(rawItem.exeName),
        companions: Array.isArray(rawItem.companions) ? rawItem.companions : [],
      };
      const existing = byKey.get(key);
      byKey.set(
        key,
        existing ? mergeDiscoveredItems(existing, normalizedItem) : normalizedItem,
      );
    }

    for (const custom of customEntries) {
      const key = normalizeAppKey(custom.normalizedKey || custom.exeName);
      if (!key || byKey.has(key)) continue;
      byKey.set(key, { ...custom, normalizedKey: key });
    }

    for (const [key, exeName] of savedSelected.entries()) {
      if (!key || byKey.has(key)) continue;
      byKey.set(key, {
        displayName: deriveDisplayName(exeName),
        exeName,
        normalizedKey: key,
        path: null,
        isRunning: false,
        category: "custom",
        companions: [],
        groupTag: presetGroupByKey.get(key) ?? "other",
      });
    }

    const items: IndexedAppItem[] = [];
    for (const app of byKey.values()) {
      items.push(buildIndexedApp(app));
    }
    return { items, byKey };
  }, [discoveredApps, customEntries, savedSelected, presetGroupByKey]);

  const allIndexedApps = useMemo(() => {
    if (presetSyntheticEntries.length === 0) {
      return baseDiscoveredApps;
    }

    const byKey = new Map(baseDiscoveredApps.byKey);
    const items = [...baseDiscoveredApps.items];
    for (const synthetic of presetSyntheticEntries) {
      const key = normalizeAppKey(synthetic.normalizedKey || synthetic.exeName);
      if (!key || byKey.has(key)) continue;
      const normalized: DiscoveredAppItem = { ...synthetic, normalizedKey: key };
      byKey.set(key, normalized);
      items.push(buildIndexedApp(normalized));
    }
    return { items, byKey };
  }, [baseDiscoveredApps, presetSyntheticEntries]);

  const appByKeyRef = useRef<Map<string, DiscoveredAppItem>>(
    allIndexedApps.byKey,
  );
  appByKeyRef.current = allIndexedApps.byKey;

  const draftSelectedKeys = useMemo(
    () => new Set<string>(draftSelected.keys()),
    [draftSelected],
  );

  const resolveCanonicalExe = useCallback(
    (key: string, fallbackRaw: string): string => {
      const discovered = appByKeyRef.current.get(key);
      if (discovered?.exeName) return discovered.exeName;
      const saved = savedSelectedRef.current.get(key);
      if (saved) return saved;
      const extracted = extractExecutableName(fallbackRaw);
      if (extracted) return extracted;
      return fallbackRaw.trim() || `${key}.exe`;
    },
    [],
  );

  const baseCounts = useMemo(() => {
    let running = 0;
    let games = 0;
    let browsers = 0;
    let communication = 0;
    let media = 0;
    for (const { app } of allIndexedApps.items) {
      if (app.isRunning) running += 1;
      if (app.groupTag === "games") games += 1;
      if (app.groupTag === "browsers") browsers += 1;
      if (app.groupTag === "communication") communication += 1;
      if (app.groupTag === "media") media += 1;
    }
    return {
      all: allIndexedApps.items.length,
      running,
      games,
      browsers,
      communication,
      media,
    };
  }, [allIndexedApps.items]);

  const counts = {
    ...baseCounts,
    selected: draftSelectedKeys.size,
  };

  const selectedFilterKeys =
    activeFilter === "selected" ? draftSelectedKeys : null;

  const visibleApps = useMemo<DiscoveredAppItem[]>(() => {
    const indexedItems = allIndexedApps.items;

    if (
      sortOrderVersionRef.current !== sortVersion &&
      indexedItems.length > 0
    ) {
      const snapshotSelected = sortSelectedSnapshotRef.current;
      const baseline = [...indexedItems].sort((a, b) => {
        const aSelected = snapshotSelected.has(a.app.normalizedKey);
        const bSelected = snapshotSelected.has(b.app.normalizedKey);
        if (aSelected !== bSelected) return aSelected ? -1 : 1;

        if (a.app.isRunning !== b.app.isRunning) {
          return a.app.isRunning ? -1 : 1;
        }

        const categoryDiff =
          (CATEGORY_RANK[a.app.category] ?? 99) -
          (CATEGORY_RANK[b.app.category] ?? 99);
        if (categoryDiff !== 0) return categoryDiff;

        return APP_NAME_COLLATOR.compare(a.app.displayName, b.app.displayName);
      });
      const nextOrder = new Map<string, number>();
      baseline.forEach((entry, idx) => {
        nextOrder.set(entry.app.normalizedKey, idx);
      });
      sortOrderRef.current = nextOrder;
      sortOrderVersionRef.current = sortVersion;
    }

    const foldedQuery = foldTurkish(deferredSearchQuery).trim();
    const tokens = foldedQuery ? foldedQuery.split(/\s+/).filter(Boolean) : [];

    const filtered = indexedItems.filter((entry) => {
      const { app } = entry;
      switch (activeFilter) {
        case "selected":
          if (!selectedFilterKeys?.has(app.normalizedKey)) return false;
          break;
        case "running":
          if (!app.isRunning) return false;
          break;
        case "games":
          if (app.groupTag !== "games") return false;
          break;
        case "browsers":
          if (app.groupTag !== "browsers") return false;
          break;
        case "communication":
          if (app.groupTag !== "communication") return false;
          break;
        case "media":
          if (app.groupTag !== "media") return false;
          break;
        case "all":
          break;
      }

      if (tokens.length === 0) return true;

      return tokens.every((token) =>
        entry.haystackFields.some((field) => field.includes(token)),
      );
    });

    const getMatchRank = (entry: IndexedAppItem): number => {
      if (!foldedQuery) return 0;
      if (
        entry.foldedDisplayName === foldedQuery ||
        entry.foldedKey === foldedQuery
      ) {
        return 0;
      }
      if (
        entry.foldedDisplayName.startsWith(foldedQuery) ||
        entry.foldedKey.startsWith(foldedQuery)
      ) {
        return 1;
      }
      return 2;
    };

    const frozenOrder = sortOrderRef.current;

    filtered.sort((a, b) => {
      if (foldedQuery) {
        const matchDiff = getMatchRank(a) - getMatchRank(b);
        if (matchDiff !== 0) return matchDiff;
      }

      const aRank = frozenOrder.get(a.app.normalizedKey);
      const bRank = frozenOrder.get(b.app.normalizedKey);
      if (aRank !== undefined && bRank !== undefined && aRank !== bRank) {
        return aRank - bRank;
      }
      if (aRank !== undefined && bRank === undefined) return -1;
      if (aRank === undefined && bRank !== undefined) return 1;

      if (a.app.isRunning !== b.app.isRunning) {
        return a.app.isRunning ? -1 : 1;
      }

      const categoryDiff =
        (CATEGORY_RANK[a.app.category] ?? 99) -
        (CATEGORY_RANK[b.app.category] ?? 99);
      if (categoryDiff !== 0) return categoryDiff;

      return APP_NAME_COLLATOR.compare(a.app.displayName, b.app.displayName);
    });

    return filtered.map((entry) => entry.app);
  }, [
    allIndexedApps.items,
    activeFilter,
    deferredSearchQuery,
    selectedFilterKeys,
    sortVersion,
  ]);

  const diff = useMemo(() => {
    const modeChanged = draftMode !== savedMode;
    let addedCount = 0;
    let removedCount = 0;

    for (const key of draftSelected.keys()) {
      if (!savedSelected.has(key)) addedCount += 1;
    }
    for (const key of savedSelected.keys()) {
      if (!draftSelected.has(key)) removedCount += 1;
    }

    const hasChanges = modeChanged || addedCount > 0 || removedCount > 0;
    return { modeChanged, addedCount, removedCount, hasChanges };
  }, [draftMode, savedMode, draftSelected, savedSelected]);

  const diffHasChangesRef = useRef(diff.hasChanges);
  diffHasChangesRef.current = diff.hasChanges;

  useEffect(() => {
    onDirtyChange?.(diff.hasChanges);
  }, [diff.hasChanges, onDirtyChange]);

  const handleSelectFilter = useCallback(
    (nextFilter: FilterPillId) => {
      setActiveFilter(nextFilter);
      resetSortSnapshot(draftSelectedRef.current.keys());
    },
    [resetSortSnapshot],
  );

  const handleToggleApp = useCallback(
    (normalizedKey: string) => {
      if (savingRef.current) return;
      const key = normalizeAppKey(normalizedKey);
      if (!key) return;

      const currentSelected = draftSelectedRef.current;
      const isCurrentlySelected = currentSelected.has(key);
      const wasAllMode = draftModeRef.current === "all";

      if (
        !isCurrentlySelected &&
        currentSelected.size >= MAX_SPLIT_TUNNEL_APPS
      ) {
        onPushToastRef.current?.(
          "warn",
          tSplit(langRef.current, "maxAppsLimit", {
            max: MAX_SPLIT_TUNNEL_APPS,
          }),
        );
        return;
      }

      const canonicalExe = resolveCanonicalExe(key, normalizedKey);
      const next = new Map(currentSelected);
      if (isCurrentlySelected) {
        next.delete(key);
      } else {
        next.set(key, canonicalExe);
      }

      draftSelectedRef.current = next;
      setDraftSelected(next);

      if (wasAllMode) {
        draftModeRef.current = "exclude";
        setDraftMode("exclude");
        const displayName =
          appByKeyRef.current.get(key)?.displayName || canonicalExe;
        onPushToastRef.current?.(
          "info",
          tSplit(
            langRef.current,
            isCurrentlySelected
              ? "toastSwitchExcludeUpdated"
              : "toastSwitchExcludeSkip",
            { name: displayName },
          ),
        );
      }
    },
    [resolveCanonicalExe],
  );

  const handleTogglePreset = useCallback(
    (preset: SplitTunnelPreset, nextSelected?: boolean) => {
      if (savingRef.current) return;

      const entries = preset.apps
        .map((raw) => ({ raw, key: normalizeAppKey(raw) }))
        .filter((entry) => entry.key.length > 0);
      if (entries.length === 0) return;

      const currentSelected = draftSelectedRef.current;
      const wasAllMode = draftModeRef.current === "all";
      const shouldAdd =
        typeof nextSelected === "boolean"
          ? nextSelected
          : !entries.every((entry) => currentSelected.has(entry.key));

      const next = new Map(currentSelected);
      const newlyAddedUnknown: DiscoveredAppItem[] = [];
      let addedCount = 0;
      let skippedCount = 0;

      if (shouldAdd) {
        for (const entry of entries) {
          if (next.has(entry.key)) continue;
          if (next.size >= MAX_SPLIT_TUNNEL_APPS) {
            skippedCount += 1;
            continue;
          }
          const canonicalExe = resolveCanonicalExe(entry.key, entry.raw);
          next.set(entry.key, canonicalExe);
          addedCount += 1;
          if (!appByKeyRef.current.has(entry.key)) {
            newlyAddedUnknown.push({
              displayName: deriveDisplayName(canonicalExe),
              exeName: canonicalExe,
              normalizedKey: entry.key,
              path: null,
              isRunning: false,
              category: "custom",
              companions: [],
              groupTag:
                presetGroupByKeyRef.current.get(entry.key) ?? preset.groupTag,
            });
          }
        }

        if (addedCount === 0 && skippedCount > 0) {
          onPushToastRef.current?.(
            "warn",
            tSplit(langRef.current, "maxAppsLimitPreset", {
              max: MAX_SPLIT_TUNNEL_APPS,
              label: localizePresetLabel(langRef.current, preset),
            }),
          );
          return;
        }
      } else {
        for (const entry of entries) {
          next.delete(entry.key);
        }
      }

      if (shouldAdd && newlyAddedUnknown.length > 0) {
        setPresetSyntheticEntries((prev) => {
          const existingKeys = new Set(prev.map((item) => item.normalizedKey));
          const toAppend = newlyAddedUnknown.filter(
            (item) => !existingKeys.has(item.normalizedKey),
          );
          return toAppend.length > 0 ? [...prev, ...toAppend] : prev;
        });
      } else if (!shouldAdd) {
        const removedKeys = new Set(entries.map((entry) => entry.key));
        setPresetSyntheticEntries((prev) => {
          if (prev.length === 0) return prev;
          const kept = prev.filter(
            (item) => !removedKeys.has(item.normalizedKey),
          );
          return kept.length === prev.length ? prev : kept;
        });
      }

      draftSelectedRef.current = next;
      setDraftSelected(next);

      const localizedPresetLabel = localizePresetLabel(langRef.current, preset);

      if (wasAllMode) {
        draftModeRef.current = "exclude";
        setDraftMode("exclude");
        onPushToastRef.current?.(
          "info",
          shouldAdd
            ? tSplit(langRef.current, "toastSwitchExcludeSkip", {
                name: localizedPresetLabel,
              })
            : tSplit(langRef.current, "toastSwitchExcludePresetRemoved", {
                label: localizedPresetLabel,
              }),
        );
      }

      if (skippedCount > 0) {
        onPushToastRef.current?.(
          "warn",
          tSplit(langRef.current, "maxAppsPartialPreset", {
            max: MAX_SPLIT_TUNNEL_APPS,
            added: addedCount,
            total: addedCount + skippedCount,
            label: localizedPresetLabel,
          }),
        );
      }
    },
    [resolveCanonicalExe],
  );

  const addCustomExecutable = useCallback(
    (rawInput: string) => {
      const extracted = extractExecutableName(rawInput);
      const key = normalizeAppKey(extracted || rawInput);
      if (!extracted || !key) {
        if (isWindowsShortcutInput(rawInput)) {
          setCustomError(tSplit(langRef.current, "customErrorShortcut"));
        } else {
          setCustomError(
            tSplit(
              langRef.current,
              isWindows ? "customErrorInvalidWin" : "customErrorInvalidUnix",
            ),
          );
        }
        return false;
      }

      const currentSelected = draftSelectedRef.current;
      const alreadySelected = currentSelected.has(key);
      if (!alreadySelected && currentSelected.size >= MAX_SPLIT_TUNNEL_APPS) {
        const limitMessage = tSplit(langRef.current, "maxAppsLimit", {
          max: MAX_SPLIT_TUNNEL_APPS,
        });
        setCustomError(limitMessage);
        onPushToastRef.current?.("warn", limitMessage);
        return false;
      }

      setCustomError(null);
      const canonicalExe = resolveCanonicalExe(key, extracted);

      if (!appByKeyRef.current.has(key)) {
        const cleanPath = extractCleanPath(rawInput);
        setCustomEntries((prev) => {
          if (prev.some((entry) => entry.normalizedKey === key)) {
            return prev;
          }
          return [
            ...prev,
            {
              displayName: deriveDisplayName(
                canonicalExe,
                tSplit(langRef.current, "customAppFallbackName"),
              ),
              exeName: canonicalExe,
              normalizedKey: key,
              path: cleanPath,
              isRunning: false,
              category: "custom",
              companions: [],
              groupTag: presetGroupByKeyRef.current.get(key) ?? "other",
            },
          ];
        });
      }

      if (!alreadySelected) {
        const next = new Map(currentSelected);
        next.set(key, canonicalExe);
        draftSelectedRef.current = next;
        setDraftSelected(next);
      }

      const wasAllMode = draftModeRef.current === "all";
      if (wasAllMode) {
        draftModeRef.current = "exclude";
        setDraftMode("exclude");
      }

      setCustomInput("");

      if (wasAllMode) {
        onPushToastRef.current?.(
          "info",
          alreadySelected
            ? tSplit(langRef.current, "toastSwitchExcludeAlready", {
                exe: canonicalExe,
              })
            : tSplit(langRef.current, "toastSwitchExcludeSkip", {
                name: canonicalExe,
              }),
        );
      } else if (alreadySelected) {
        onPushToastRef.current?.(
          "info",
          tSplit(langRef.current, "toastAlreadySelected", {
            exe: canonicalExe,
          }),
        );
      } else {
        onPushToastRef.current?.(
          "info",
          tSplit(langRef.current, "toastAddedCustom", { exe: canonicalExe }),
        );
      }

      return true;
    },
    [isWindows, resolveCanonicalExe],
  );

  const handleCustomSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (saving) return;
    addCustomExecutable(customInput);
  };

  const handleBrowseFile = async () => {
    if (saving || browsing) return;
    setBrowsing(true);
    setCustomError(null);

    try {
      const picked = await pickExecutableFile();
      if (!mountedRef.current || !picked) return;
      addCustomExecutable(picked);
    } catch (error) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(
        error,
        tSplit(langRef.current, "pickerError"),
      );
      setCustomError(message);
      onPushToast?.("error", message);
    } finally {
      if (mountedRef.current) {
        setBrowsing(false);
      }
    }
  };

  const handleDiscard = () => {
    if (saving) return;
    draftModeRef.current = savedMode;
    const restored = new Map(savedSelected);
    draftSelectedRef.current = restored;
    setDraftMode(savedMode);
    setDraftSelected(restored);
    setCustomEntries([]);
    setPresetSyntheticEntries([]);
    setCustomInput("");
    setErrorBanner(null);
    setCustomError(null);
    resetSortSnapshot(savedSelected.keys());
  };

  const handleSave = useCallback(async () => {
    if (savingRef.current || !diffHasChangesRef.current) return;

    const currentMode = draftModeRef.current;
    const currentSelected = draftSelectedRef.current;

    if (currentSelected.size > MAX_SPLIT_TUNNEL_APPS) {
      const msg = tSplit(langRef.current, "maxAppsSaveLimit", {
        max: MAX_SPLIT_TUNNEL_APPS,
        excess: currentSelected.size - MAX_SPLIT_TUNNEL_APPS,
      });
      setErrorBanner(msg);
      onPushToast?.("warn", msg);
      return;
    }

    savingRef.current = true;
    setSaving(true);
    setErrorBanner(null);

    const appsToSave = Array.from(currentSelected.entries())
      .sort(([keyA], [keyB]) => APP_NAME_COLLATOR.compare(keyA, keyB))
      .map(([, exeName]) => exeName);

    try {
      const result: ActionResult = await saveSplitTunnel({
        mode: currentMode,
        apps: appsToSave,
        applyLive: true,
      });
      if (!mountedRef.current) return;

      if (result.cancelled) {
        onPushToast?.(
          "info",
          result.message || tSplit(langRef.current, "saveCancelled"),
        );
        return;
      }

      if (!result.ok) {
        const message =
          result.message || tSplit(langRef.current, "saveFailed");
        setErrorBanner(message);
        onPushToast?.("error", message);
        return;
      }

      const savedCopy = new Map(currentSelected);
      setSavedMode(currentMode);
      setSavedSelected(savedCopy);
      setCustomEntries([]);
      setPresetSyntheticEntries([]);

      const isEmptyInclude =
        currentMode === "include" && appsToSave.length === 0;
      if (isEmptyInclude) {
        onPushToast?.(
          "warn",
          tSplit(
            langRef.current,
            result.needsRestart ? "saveEmptyIncludeRestart" : "saveEmptyInclude",
          ),
        );
      } else {
        const successMessage =
          result.message ||
          tSplit(
            langRef.current,
            result.needsRestart ? "saveSuccessRestart" : "saveSuccess",
          );
        onPushToast?.(result.needsRestart ? "warn" : "success", successMessage);
      }

      try {
        const freshPayload = await getSplitTunnel();
        if (mountedRef.current) {
          applyPayload(freshPayload, false);
        }
      } catch {
        if (mountedRef.current) {
          resetSortSnapshot(savedCopy.keys());
        }
      }

      try {
        await onSaved?.();
      } catch {
        // Parent refresh errors are handled upstream; keep local saved state intact.
      }
    } catch (error) {
      if (!mountedRef.current) return;
      const message = getErrorMessage(
        error,
        tSplit(langRef.current, "saveFailed"),
      );
      setErrorBanner(message);
      onPushToast?.("error", message);
    } finally {
      savingRef.current = false;
      if (mountedRef.current) {
        setSaving(false);
      }
    }
  }, [applyPayload, onPushToast, onSaved, resetSortSnapshot]);

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
        if (!diffHasChangesRef.current || savingRef.current) {
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

  const modeOptions = useMemo(() => getModeOptions(lang), [lang]);

  const handleModeKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    if (saving) return;
    let nextIndex: number | null = null;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") {
      nextIndex = (index + 1) % MODE_VALUES.length;
    } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
      nextIndex = (index - 1 + MODE_VALUES.length) % MODE_VALUES.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = MODE_VALUES.length - 1;
    }
    if (nextIndex === null) return;
    event.preventDefault();
    const nextMode = MODE_VALUES[nextIndex];
    draftModeRef.current = nextMode;
    setDraftMode(nextMode);
    modeRadioRefs.current[nextIndex]?.focus();
  };

  const subtitle = useMemo(() => {
    const count = draftSelectedKeys.size;
    if (draftMode === "all") {
      return tSplit(lang, "subtitleAll");
    }
    if (draftMode === "exclude") {
      if (count === 0) return tSplit(lang, "subtitleExcludeEmpty");
      return tSplit(
        lang,
        count === 1 ? "subtitleExcludeOne" : "subtitleExcludeMany",
        { count },
      );
    }
    if (count === 0) return tSplit(lang, "subtitleIncludeEmpty");
    return tSplit(
      lang,
      count === 1 ? "subtitleIncludeOne" : "subtitleIncludeMany",
      { count },
    );
  }, [draftMode, draftSelectedKeys.size, lang]);

  const filterPills: ReadonlyArray<{ id: FilterPillId; label: string }> = [
    { id: "all", label: tSplit(lang, "filterAll") },
    {
      id: "selected",
      label: tSplit(lang, "filterSelected", { count: counts.selected }),
    },
    {
      id: "running",
      label: tSplit(lang, "filterRunning", { count: counts.running }),
    },
    { id: "games", label: tSplit(lang, "filterGames") },
    { id: "browsers", label: tSplit(lang, "filterBrowsers") },
    { id: "communication", label: tSplit(lang, "filterCommunication") },
    { id: "media", label: tSplit(lang, "filterMedia") },
  ];

  const showIncludeEmptyWarning =
    draftMode === "include" && draftSelectedKeys.size === 0;

  const normalizedBusy = busyAction?.trim().toLowerCase() ?? null;
  const isAnyBusy = normalizedBusy !== null;
  const isSwitchingToTun =
    normalizedBusy === "switch-engine:tun" ||
    (normalizedBusy !== null && normalizedBusy.startsWith("switch-engine"));
  const atAppLimit =
    draftMode !== "all" && counts.selected >= MAX_SPLIT_TUNNEL_APPS;

  const customPlaceholder = tSplit(
    lang,
    isWindows ? "customPlaceholderWin" : "customPlaceholderUnix",
  );

  const searchPlaceholder = tSplit(
    lang,
    isWindows ? "searchPlaceholderWin" : "searchPlaceholderUnix",
  );

  return (
    <section className="split-view" aria-label={tSplit(lang, "title")}>
      <header className="split-view__header">
        <h1 className="split-view__title">{tSplit(lang, "title")}</h1>
        <p className="split-view__subtitle">{subtitle}</p>
      </header>

      {activeEngine === "proxy" ? (
        <InlineBanner
          tone="warn"
          title={tSplit(lang, "proxyBannerTitle")}
          description={tSplit(lang, "proxyBannerDesc")}
          action={
            onSwitchToTun ? (
              <button
                type="button"
                className="inline-banner__action"
                disabled={isAnyBusy || saving}
                aria-busy={isSwitchingToTun ? true : undefined}
                onClick={() => {
                  if (!isAnyBusy && !saving) {
                    void onSwitchToTun();
                  }
                }}
              >
                {tSplit(
                  lang,
                  isSwitchingToTun
                    ? "proxyBannerSwitching"
                    : "proxyBannerSwitch",
                )}
              </button>
            ) : undefined
          }
        />
      ) : null}

      {errorBanner ? (
        <InlineBanner
          tone="error"
          title={tSplit(lang, "errorBannerTitle")}
          description={errorBanner}
          actionLabel={!loadedOnce ? tSplit(lang, "retry") : undefined}
          onAction={
            !loadedOnce
              ? () => void loadSplitTunnel({ preserveDraft: false })
              : undefined
          }
        />
      ) : null}

      <div className="split-view__section">
        <span className="split-view__section-label">
          {tSplit(lang, "sectionRoutingMode")}
        </span>
        <div
          className="split-mode-grid"
          role="radiogroup"
          aria-label={tSplit(lang, "ariaModeGroup")}
        >
          {modeOptions.map((option, index) => {
            const active = draftMode === option.value;
            return (
              <button
                key={option.value}
                ref={(el) => {
                  modeRadioRefs.current[index] = el;
                }}
                type="button"
                role="radio"
                tabIndex={active ? 0 : -1}
                aria-checked={active}
                data-mode={option.value}
                data-active={active ? "true" : "false"}
                className="split-mode-card"
                disabled={saving}
                onClick={() => {
                  draftModeRef.current = option.value;
                  setDraftMode(option.value);
                }}
                onKeyDown={(event) => handleModeKeyDown(event, index)}
              >
                <span className="split-mode-card__top">
                  <span className="split-mode-card__radio" aria-hidden="true">
                    {active ? (
                      <span className="split-mode-card__radio-dot" />
                    ) : null}
                  </span>
                  <span className="split-mode-card__title">{option.label}</span>
                </span>
                <span className="split-mode-card__desc">
                  {option.description}
                </span>
              </button>
            );
          })}
        </div>

        {showIncludeEmptyWarning ? (
          <InlineBanner
            tone="warn"
            title={tSplit(lang, "emptyIncludeTitle")}
            description={tSplit(lang, "emptyIncludeDesc")}
          />
        ) : null}
      </div>

      <div className="split-view__section">
        <div className="split-view__section-head">
          <span className="split-view__section-label">
            {tSplit(lang, "sectionQuickPresets")}
          </span>
          {draftMode === "all" ? (
            <span className="split-view__section-hint">
              {tSplit(lang, "presetsAutoSwitchHint")}
            </span>
          ) : null}
        </div>
        <SplitTunnelPresets
          presets={effectivePresets}
          selectedKeys={draftSelectedKeys}
          mode={draftMode}
          disabled={saving}
          onTogglePreset={handleTogglePreset}
        />
      </div>

      <div className="split-view__section">
        <span className="split-view__section-label">
          {tSplit(lang, "sectionApplications")}
        </span>

        <div className="split-toolbar">
          <div className="split-toolbar__row">
            <div className="split-search">
              <span className="split-search__icon" aria-hidden="true">
                <IconSearch size={14} />
              </span>
              <input
                ref={searchInputRef}
                type="text"
                role="searchbox"
                className="split-search__input"
                data-shortcut="search"
                aria-label={tSplit(lang, "ariaSearchApps")}
                placeholder={searchPlaceholder}
                value={searchQuery}
                onChange={(event) => setSearchQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Escape" && searchQuery) {
                    event.preventDefault();
                    setSearchQuery("");
                  }
                }}
              />
              {searchQuery ? (
                <button
                  type="button"
                  className="split-search__clear"
                  aria-label={tSplit(lang, "ariaClearSearch")}
                  onClick={() => {
                    setSearchQuery("");
                    searchInputRef.current?.focus();
                  }}
                >
                  {tSplit(lang, "clear")}
                </button>
              ) : null}
            </div>

            <button
              type="button"
              className="split-btn"
              aria-expanded={showCustomForm}
              aria-controls="split-custom-app-form"
              disabled={saving}
              onClick={() => {
                setShowCustomForm((prev) => {
                  const next = !prev;
                  if (next) {
                    requestAnimationFrame(() => customInputRef.current?.focus());
                  }
                  return next;
                });
              }}
            >
              <IconPlus size={14} />
              <span>{tSplit(lang, "addCustomApp")}</span>
            </button>

            <button
              type="button"
              className="split-btn"
              title={tSplit(lang, "refreshTitle")}
              disabled={refreshing || loading || saving}
              onClick={() =>
                void loadSplitTunnel({
                  preserveDraft: true,
                  silentToast: false,
                })
              }
            >
              {refreshing ? (
                <span className="split-spinner" aria-hidden="true" />
              ) : (
                <IconRefresh size={14} />
              )}
              <span>
                {tSplit(lang, refreshing ? "refreshing" : "refresh")}
              </span>
            </button>
          </div>

          {showCustomForm ? (
            <form
              id="split-custom-app-form"
              className="split-custom-form"
              onSubmit={handleCustomSubmit}
            >
              <div className="split-custom-row">
                <input
                  ref={customInputRef}
                  type="text"
                  className="split-custom-row__input"
                  aria-label={tSplit(lang, "ariaCustomAppInput")}
                  placeholder={customPlaceholder}
                  value={customInput}
                  disabled={saving}
                  onChange={(event) => {
                    setCustomInput(event.target.value);
                    if (customError) setCustomError(null);
                  }}
                />
                <button
                  type="submit"
                  className="split-btn"
                  disabled={saving || !customInput.trim()}
                >
                  {tSplit(lang, "add")}
                </button>
                <button
                  type="button"
                  className="split-btn"
                  disabled={saving || browsing}
                  onClick={() => void handleBrowseFile()}
                >
                  {tSplit(lang, browsing ? "browsing" : "browse")}
                </button>
              </div>
              {customError ? (
                <p className="split-custom-error" role="alert">
                  {customError}
                </p>
              ) : null}
            </form>
          ) : null}

          <div className="split-filters">
            <div
              className="split-filters__pills"
              role="group"
              aria-label={tSplit(lang, "ariaFilterApps")}
            >
              {filterPills.map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  className="split-filter-pill"
                  data-filter={pill.id}
                  aria-pressed={activeFilter === pill.id}
                  onClick={() => handleSelectFilter(pill.id)}
                >
                  {pill.label}
                </button>
              ))}
            </div>

            {draftMode !== "all" && draftSelectedKeys.size > 0 ? (
              <button
                type="button"
                className="split-btn split-btn--ghost"
                disabled={saving}
                onClick={() => {
                  const empty = new Map<string, string>();
                  draftSelectedRef.current = empty;
                  setDraftSelected(empty);
                  setPresetSyntheticEntries([]);
                }}
              >
                {tSplit(lang, "clearSelected")}
              </button>
            ) : null}
          </div>
        </div>

        <div className="split-list-card">
          <div className="split-list-meta">
            <span>
              {tSplit(
                lang,
                counts.all === 1 ? "showingAppsOne" : "showingAppsMany",
                { visible: visibleApps.length, total: counts.all },
              )}
            </span>
            <span
              className={
                atAppLimit
                  ? "split-list-meta__count split-list-meta__count--limit"
                  : "split-list-meta__count"
              }
              data-at-limit={atAppLimit ? "true" : undefined}
            >
              {draftMode === "all"
                ? tSplit(lang, "metaToggleSwitchHint")
                : counts.selected >= 200
                  ? tSplit(lang, "metaSelectedOfMax", {
                      count: counts.selected,
                      max: MAX_SPLIT_TUNNEL_APPS,
                    })
                  : tSplit(lang, "metaSelected", { count: counts.selected })}
            </span>
          </div>

          {loading && !loadedOnce ? (
            <div className="split-list-empty" role="status">
              <span className="split-spinner" aria-hidden="true" />
              <p className="split-list-empty__title">
                {tSplit(lang, "loadingApps")}
              </p>
            </div>
          ) : visibleApps.length === 0 ? (
            <div className="split-list-empty">
              <p className="split-list-empty__title">
                {searchQuery.trim()
                  ? tSplit(lang, "emptySearchTitle", {
                      query: searchQuery.trim(),
                    })
                  : activeFilter === "selected"
                    ? tSplit(lang, "emptySelectedTitle")
                    : activeFilter === "running"
                      ? tSplit(lang, "emptyRunningTitle")
                      : tSplit(lang, "emptyCategoryTitle")}
              </p>
              <p className="split-list-empty__desc">
                {searchQuery.trim()
                  ? tSplit(lang, "emptySearchDesc")
                  : activeFilter === "selected"
                    ? tSplit(lang, "emptySelectedDesc")
                    : tSplit(lang, "emptyDefaultDesc")}
              </p>
              {searchQuery.trim() ? (
                <button
                  type="button"
                  className="split-btn"
                  onClick={() => setSearchQuery("")}
                >
                  {tSplit(lang, "emptyClearSearch")}
                </button>
              ) : activeFilter !== "all" ? (
                <button
                  type="button"
                  className="split-btn"
                  onClick={() => handleSelectFilter("all")}
                >
                  {tSplit(lang, "emptyShowAll")}
                </button>
              ) : null}
            </div>
          ) : (
            <div role="list" aria-label={tSplit(lang, "ariaAppList")}>
              {visibleApps.map((app) => (
                <SplitTunnelAppRow
                  key={app.normalizedKey}
                  app={app}
                  selected={draftSelectedKeys.has(app.normalizedKey)}
                  mode={draftMode}
                  disabled={saving}
                  onToggle={handleToggleApp}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {diff.hasChanges ? (
        <div
          className="split-unsaved-bar"
          role="region"
          aria-label={tSplit(lang, "unsavedTitle")}
        >
          <div className="split-unsaved-bar__info">
            <p className="split-unsaved-bar__title">
              {tSplit(lang, "unsavedTitle")}
            </p>
            <div className="split-unsaved-bar__summary">
              {diff.modeChanged ? (
                <span className="split-diff-badge split-diff-badge--mode">
                  {tSplit(lang, "diffMode", {
                    mode: getModeLabel(draftMode, lang),
                  })}
                </span>
              ) : null}
              {diff.addedCount > 0 ? (
                <span className="split-diff-badge split-diff-badge--added">
                  {tSplit(lang, "diffAdded", { count: diff.addedCount })}
                </span>
              ) : null}
              {diff.removedCount > 0 ? (
                <span className="split-diff-badge split-diff-badge--removed">
                  {tSplit(lang, "diffRemoved", { count: diff.removedCount })}
                </span>
              ) : null}
              {showIncludeEmptyWarning ? (
                <span className="split-diff-badge split-diff-badge--warn">
                  {tSplit(lang, "diffEmptyInclude")}
                </span>
              ) : null}
            </div>
          </div>

          <div className="split-unsaved-bar__actions">
            <button
              type="button"
              className="split-btn"
              disabled={saving}
              onClick={handleDiscard}
            >
              {tSplit(lang, "discard")}
            </button>
            <button
              type="button"
              className="split-btn split-btn--primary"
              disabled={saving}
              onClick={() => void handleSave()}
            >
              {saving ? (
                <span className="split-spinner" aria-hidden="true" />
              ) : null}
              <span>{tSplit(lang, saving ? "saving" : "saveApply")}</span>
            </button>
          </div>
        </div>
      ) : null}
    </section>
  );
});

export default SplitTunnelView;
