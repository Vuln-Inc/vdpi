import { memo, useEffect, useMemo } from "react";
import { IconCheck } from "../components/Icons";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import {
  localizePresetDescription,
  localizePresetLabel,
  tSplit,
} from "../i18n/split";
import type { SplitTunnelMode, SplitTunnelPreset } from "../types";

export type PresetSelectionState = "none" | "partial" | "all";

export interface SplitTunnelPresetsProps {
  presets: SplitTunnelPreset[];
  selectedKeys: ReadonlySet<string> | readonly string[];
  mode?: SplitTunnelMode;
  disabled?: boolean;
  onTogglePreset: (preset: SplitTunnelPreset, nextSelected: boolean) => void;
  className?: string;
}

export interface PresetSelectionSummary {
  state: PresetSelectionState;
  matchedCount: number;
  totalCount: number;
}

const STYLE_ID = "vdpi-split-tunnel-presets-styles";

const FALLBACK_STYLES = `
:where(.split-presets) {
  --_preset-bg: var(--bg-surface, var(--surface, rgba(255, 255, 255, 0.04)));
  --_preset-bg-hover: var(--bg-surface-elevated, var(--surface-raised, rgba(255, 255, 255, 0.08)));
  --_preset-border: var(--border-subtle, var(--border, rgba(255, 255, 255, 0.12)));
  --_preset-border-hover: var(--border-strong, rgba(255, 255, 255, 0.2));
  --_preset-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_preset-muted: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_preset-accent: var(--accent, #3b82f6);
  --_preset-accent-fg: var(--accent-fg, #60a5fa);
  --_preset-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(59, 130, 246, 0.14)));
  --_preset-accent-border: var(--accent-border, rgba(59, 130, 246, 0.36));
  --_preset-check-ink: var(--ink-on-accent, var(--primary-button-ink, #ffffff));
  --_preset-mono-font: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  padding: 4px 0;
  box-sizing: border-box;
}

:where([data-theme="light"] .split-presets) {
  --_preset-bg: var(--bg-surface, var(--surface, #ffffff));
  --_preset-bg-hover: var(--bg-surface-hover, var(--surface-raised, rgba(0, 0, 0, 0.045)));
  --_preset-border: var(--border-subtle, var(--border, rgba(0, 0, 0, 0.12)));
  --_preset-border-hover: var(--border-strong, rgba(0, 0, 0, 0.22));
  --_preset-ink: var(--ink-primary, var(--text-primary, #111317));
  --_preset-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_preset-accent: var(--accent, #0066cc);
  --_preset-accent-fg: var(--accent-fg, #0066cc);
  --_preset-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(0, 102, 204, 0.1)));
  --_preset-accent-border: var(--accent-border, rgba(0, 102, 204, 0.32));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .split-presets) {
    --_preset-bg: var(--bg-surface, var(--surface, #ffffff));
    --_preset-bg-hover: var(--bg-surface-hover, var(--surface-raised, rgba(0, 0, 0, 0.045)));
    --_preset-border: var(--border-subtle, var(--border, rgba(0, 0, 0, 0.12)));
    --_preset-border-hover: var(--border-strong, rgba(0, 0, 0, 0.22));
    --_preset-ink: var(--ink-primary, var(--text-primary, #111317));
    --_preset-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_preset-accent: var(--accent, #0066cc);
    --_preset-accent-fg: var(--accent-fg, #0066cc);
    --_preset-accent-tint: var(--accent-subtle, var(--accent-tint, rgba(0, 102, 204, 0.1)));
    --_preset-accent-border: var(--accent-border, rgba(0, 102, 204, 0.32));
  }
}

:where(.split-preset-chip) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  height: 28px;
  padding: 0 10px 0 8px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_preset-border);
  background: var(--_preset-bg);
  color: var(--_preset-ink);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 110ms ease, border-color 110ms ease, color 110ms ease, opacity 110ms ease;
}

:where(.split-preset-chip:hover:not(:disabled)) {
  background: var(--_preset-bg-hover);
  border-color: var(--_preset-border-hover);
}

:where(.split-preset-chip[data-state="all"]),
:where(.split-preset-chip[data-state="partial"]) {
  background: var(--_preset-accent-tint);
  border-color: var(--_preset-accent-border);
}

:where(.split-preset-chip:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_preset-accent));
  outline-offset: 2px;
}

:where(.split-preset-chip:disabled) {
  opacity: 0.5;
  cursor: not-allowed;
}

:where(.split-preset-chip__indicator) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 14px;
  height: 14px;
  border-radius: 4px;
  border: 1px solid var(--border-control, var(--_preset-border-hover));
  background: transparent;
  color: var(--_preset-check-ink);
  box-sizing: border-box;
  transition: background-color 110ms ease, border-color 110ms ease;
}

:where(.split-preset-chip[data-state="all"] .split-preset-chip__indicator) {
  background: var(--_preset-accent);
  border-color: var(--_preset-accent);
  color: var(--_preset-check-ink);
}

:where(.split-preset-chip[data-state="partial"] .split-preset-chip__indicator) {
  background: transparent;
  border-color: var(--accent-fg, var(--_preset-accent-fg));
  color: var(--accent-fg, var(--_preset-accent-fg));
}

:where(.split-preset-chip__check) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 10px;
  height: 10px;
}

:where(.split-preset-chip__check svg) {
  width: 10px;
  height: 10px;
  display: block;
}

:where(.split-preset-chip__partial-bar) {
  width: 7px;
  height: 1.5px;
  border-radius: 1px;
  background: var(--accent-fg, var(--_preset-accent-fg));
}

:where(.split-preset-chip__label) {
  line-height: 1;
}

:where(.split-preset-chip__count) {
  font-family: var(--_preset-mono-font);
  font-size: 10.5px;
  font-weight: 500;
  color: var(--_preset-muted);
  line-height: 1;
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

function normalizeAppKey(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/\u0307/g, "")
    .replace(/\u0131/g, "i")
    .replace(/\.exe$/i, "")
    .trim();
}

export function getPresetSelectionSummary(
  preset: SplitTunnelPreset,
  selectedNormalized: ReadonlySet<string>,
): PresetSelectionSummary {
  const uniqueKeys = new Set<string>();
  for (const app of preset.apps) {
    const normalized = normalizeAppKey(app);
    if (normalized) {
      uniqueKeys.add(normalized);
    }
  }

  const totalCount = uniqueKeys.size;
  if (totalCount === 0) {
    return { state: "none", matchedCount: 0, totalCount: 0 };
  }

  let matchedCount = 0;
  for (const key of uniqueKeys) {
    if (selectedNormalized.has(key)) {
      matchedCount += 1;
    }
  }

  const state: PresetSelectionState =
    matchedCount === 0 ? "none" : matchedCount === totalCount ? "all" : "partial";

  return { state, matchedCount, totalCount };
}

function buildPresetTooltip(
  preset: SplitTunnelPreset,
  summary: PresetSelectionSummary,
  lang: ResolvedLanguage,
): string {
  const label = localizePresetLabel(lang, preset);
  const desc = localizePresetDescription(lang, preset).trim();
  if (summary.totalCount === 0) {
    return desc || label;
  }
  const suffix =
    summary.matchedCount > 0
      ? tSplit(lang, "presetTooltipSelected", {
          matched: summary.matchedCount,
          total: summary.totalCount,
        })
      : tSplit(
          lang,
          summary.totalCount === 1
            ? "presetTooltipAppOne"
            : "presetTooltipAppMany",
          { total: summary.totalCount },
        );
  return desc ? `${desc} (${suffix})` : `${label} (${suffix})`;
}

export const SplitTunnelPresets = memo(function SplitTunnelPresets({
  presets,
  selectedKeys,
  mode,
  disabled = false,
  onTogglePreset,
  className,
}: SplitTunnelPresetsProps) {
  const { lang } = useLang();

  useEffect(() => {
    ensureStyles();
  }, []);

  const selectedNormalized = useMemo(() => {
    const next = new Set<string>();
    for (const key of selectedKeys) {
      const normalized = normalizeAppKey(key);
      if (normalized) {
        next.add(normalized);
      }
    }
    return next;
  }, [selectedKeys]);

  if (presets.length === 0) {
    return null;
  }

  const stripDisabled = disabled;
  const stripClasses = ["split-presets", className].filter(Boolean).join(" ");

  return (
    <div
      className={stripClasses}
      role="group"
      aria-label={tSplit(lang, "ariaPresetsGroup")}
      data-mode={mode ?? ""}
      data-disabled={stripDisabled ? "true" : "false"}
    >
      {presets.map((preset) => {
        const summary = getPresetSelectionSummary(preset, selectedNormalized);
        const isChipDisabled = stripDisabled || summary.totalCount === 0;
        const nextSelected = summary.state !== "all";
        const ariaPressed: boolean | "mixed" =
          summary.state === "all"
            ? true
            : summary.state === "partial"
              ? "mixed"
              : false;
        const presetLabel = localizePresetLabel(lang, preset);

        return (
          <button
            key={preset.id}
            type="button"
            className="split-preset-chip"
            data-preset-id={preset.id}
            data-group={preset.groupTag}
            data-state={summary.state}
            aria-pressed={ariaPressed}
            disabled={isChipDisabled}
            title={buildPresetTooltip(preset, summary, lang)}
            onClick={() => onTogglePreset(preset, nextSelected)}
          >
            <span className="split-preset-chip__indicator" aria-hidden="true">
              {summary.state === "all" ? (
                <span className="split-preset-chip__check">
                  <IconCheck />
                </span>
              ) : summary.state === "partial" ? (
                <span className="split-preset-chip__partial-bar" />
              ) : null}
            </span>

            <span className="split-preset-chip__label">{presetLabel}</span>

            {summary.state === "partial" ? (
              <span className="split-preset-chip__count">
                {summary.matchedCount}/{summary.totalCount}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
});

export default SplitTunnelPresets;
