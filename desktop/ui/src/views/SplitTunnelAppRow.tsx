import { memo, useEffect, useId, useState } from "react";
import type { KeyboardEvent, MouseEvent } from "react";
import { IconChevron } from "../components/Icons";
import { Switch } from "../components/Switch";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import { tSplit } from "../i18n/split";
import type { DiscoveredAppItem, SplitTunnelMode } from "../types";

export interface SplitTunnelAppRowProps {
  app: DiscoveredAppItem;
  selected: boolean;
  mode: SplitTunnelMode;
  disabled?: boolean;
  onToggle: (normalizedKey: string) => void;
  className?: string;
}

const STYLE_ID = "vdpi-split-tunnel-app-row-styles";
const MONOGRAM_TONE_COUNT = 6;

const FALLBACK_STYLES = `
:where(.split-app-row) {
  --_row-surface: transparent;
  --_row-hover: var(--bg-surface-hover, var(--surface-raised, rgba(255, 255, 255, 0.045)));
  --_row-selected: rgba(59, 130, 246, 0.08);
  --_row-border: var(--border-hairline, var(--border, rgba(255, 255, 255, 0.08)));
  --_row-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_row-secondary: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_row-accent: var(--accent, #3b82f6);
  --_row-accent-tint: var(--accent-subtle, rgba(59, 130, 246, 0.14));
  --_row-accent-border: var(--accent-border, rgba(59, 130, 246, 0.34));
  --_row-signal: var(--status-green-fg, var(--signal, #30d158));
  --_row-signal-tint: var(--status-green-bg, var(--signal-tint, rgba(48, 209, 88, 0.13)));
  --_row-signal-border: var(--status-green-border, rgba(48, 209, 88, 0.24));
  --_row-pill-bg: var(--bg-surface-elevated, var(--surface-raised, rgba(255, 255, 255, 0.06)));
  --_row-pill-border: var(--border-subtle, var(--border, rgba(255, 255, 255, 0.1)));
  --_row-pill-border-hover: var(--border-strong, rgba(255, 255, 255, 0.2));
  --_row-mono-font: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-direction: column;
  min-height: 44px;
  background: var(--_row-surface);
  color: var(--_row-ink);
  border-bottom: 1px solid var(--_row-border);
  box-sizing: border-box;
  cursor: pointer;
  user-select: none;
  transition: background-color 110ms ease, opacity 110ms ease;
}

:where(.split-app-row__main) {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  min-height: 44px;
  padding: 0 12px;
  width: 100%;
  box-sizing: border-box;
}

:where(.split-app-row:last-child) {
  border-bottom: none;
}

:where(.split-app-row:hover:not([data-disabled="true"])) {
  background: var(--_row-hover);
}

:where(.split-app-row[data-selected="true"]:not([data-disabled="true"])) {
  background: var(--_row-selected);
}

:where(.split-app-row[data-disabled="true"]) {
  cursor: default;
  opacity: 0.56;
}

:where([data-theme="light"] .split-app-row) {
  --_row-hover: var(--bg-surface-hover, var(--surface-raised, rgba(0, 0, 0, 0.035)));
  --_row-selected: rgba(0, 102, 204, 0.06);
  --_row-border: var(--border-hairline, var(--border, rgba(0, 0, 0, 0.08)));
  --_row-ink: var(--ink-primary, var(--text-primary, #111317));
  --_row-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_row-accent: var(--accent, #0066cc);
  --_row-accent-tint: var(--accent-subtle, rgba(0, 102, 204, 0.1));
  --_row-accent-border: var(--accent-border, rgba(0, 102, 204, 0.3));
  --_row-signal: var(--status-green-fg, var(--signal, #18793a));
  --_row-signal-tint: var(--status-green-bg, var(--signal-tint, rgba(52, 199, 89, 0.12)));
  --_row-signal-border: var(--status-green-border, rgba(24, 121, 58, 0.24));
  --_row-pill-bg: var(--bg-surface-subtle, var(--surface-raised, rgba(0, 0, 0, 0.045)));
  --_row-pill-border: var(--border-subtle, var(--border, rgba(0, 0, 0, 0.1)));
  --_row-pill-border-hover: var(--border-strong, rgba(0, 0, 0, 0.22));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .split-app-row) {
    --_row-hover: var(--bg-surface-hover, var(--surface-raised, rgba(0, 0, 0, 0.035)));
    --_row-selected: rgba(0, 102, 204, 0.06);
    --_row-border: var(--border-hairline, var(--border, rgba(0, 0, 0, 0.08)));
    --_row-ink: var(--ink-primary, var(--text-primary, #111317));
    --_row-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_row-accent: var(--accent, #0066cc);
    --_row-accent-tint: var(--accent-subtle, rgba(0, 102, 204, 0.1));
    --_row-accent-border: var(--accent-border, rgba(0, 102, 204, 0.3));
    --_row-signal: var(--status-green-fg, var(--signal, #18793a));
    --_row-signal-tint: var(--status-green-bg, var(--signal-tint, rgba(52, 199, 89, 0.12)));
    --_row-signal-border: var(--status-green-border, rgba(24, 121, 58, 0.24));
    --_row-pill-bg: var(--bg-surface-subtle, var(--surface-raised, rgba(0, 0, 0, 0.045)));
    --_row-pill-border: var(--border-subtle, var(--border, rgba(0, 0, 0, 0.1)));
    --_row-pill-border-hover: var(--border-strong, rgba(0, 0, 0, 0.22));
  }
}

:where(.split-app-row__identity) {
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.split-app-row__monogram) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 28px;
  height: 28px;
  border-radius: 7px;
  border: 1px solid rgba(142, 142, 147, 0.2);
  background: rgba(142, 142, 147, 0.12);
  color: var(--_row-secondary);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.03em;
  line-height: 1;
  box-sizing: border-box;
}

:where(.split-app-row__monogram[data-tone="0"]) {
  background: rgba(142, 142, 147, 0.12);
  border-color: rgba(142, 142, 147, 0.22);
}

:where(.split-app-row__monogram[data-tone="1"]) {
  background: rgba(108, 130, 156, 0.12);
  border-color: rgba(108, 130, 156, 0.22);
}

:where(.split-app-row__monogram[data-tone="2"]) {
  background: rgba(104, 140, 122, 0.12);
  border-color: rgba(104, 140, 122, 0.22);
}

:where(.split-app-row__monogram[data-tone="3"]) {
  background: rgba(148, 136, 118, 0.12);
  border-color: rgba(148, 136, 118, 0.22);
}

:where(.split-app-row__monogram[data-tone="4"]) {
  background: rgba(124, 126, 158, 0.12);
  border-color: rgba(124, 126, 158, 0.22);
}

:where(.split-app-row__monogram[data-tone="5"]) {
  background: rgba(144, 122, 136, 0.12);
  border-color: rgba(144, 122, 136, 0.22);
}

:where(.split-app-row__names) {
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 1px;
  min-width: 0;
  flex: 1 1 auto;
}

:where(.split-app-row__display-name) {
  font-size: 13px;
  font-weight: 500;
  line-height: 1.25;
  color: var(--_row-ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:where(.split-app-row__exe) {
  font-family: var(--_row-mono-font);
  font-size: 11px;
  font-weight: 400;
  line-height: 1.2;
  color: var(--ink-secondary, var(--_row-secondary));
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:where(.split-app-row__meta) {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  flex-shrink: 0;
  margin-left: auto;
}

:where(.split-app-row__pill) {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 20px;
  padding: 0 7px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  box-sizing: border-box;
}

:where(.split-app-row__pill--running) {
  background: var(--_row-signal-tint);
  border: 1px solid var(--_row-signal-border);
  color: var(--_row-signal);
}

:where(.split-app-row__running-dot) {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
  flex-shrink: 0;
}

:where(.split-app-row__pill--companions) {
  position: relative;
  background: var(--_row-pill-bg);
  border: 1px solid var(--_row-pill-border);
  color: var(--_row-secondary);
  font: inherit;
  font-size: 11px;
  font-weight: 500;
  line-height: 1;
  gap: 4px;
  cursor: pointer;
  transition: background-color 110ms ease, border-color 110ms ease, color 110ms ease;
}

:where(.split-app-row__pill--companions)::before {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  width: max(100%, 24px);
  height: max(100%, 24px);
  transform: translate(-50%, -50%);
}

:where(.split-app-row__pill--companions:hover) {
  color: var(--_row-ink);
  border-color: var(--_row-pill-border-hover);
}

:where(.split-app-row__pill--companions[aria-expanded="true"]) {
  background: var(--_row-accent-tint);
  border-color: var(--_row-accent-border);
  color: var(--_row-ink);
}

:where(.split-app-row__pill--companions:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_row-accent));
  outline-offset: 2px;
}

:where(.split-app-row__companions-details) {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 4px 6px;
  padding: 0 12px 9px 50px;
  font-size: 11.5px;
  line-height: 1.4;
  color: var(--_row-secondary);
  cursor: default;
  user-select: text;
  box-sizing: border-box;
}

:where(.split-app-row__companions-note) {
  color: var(--_row-secondary);
}

:where(.split-app-row__companions-list) {
  font-family: var(--_row-mono-font);
  font-size: 11px;
  color: var(--_row-ink);
  word-break: break-word;
}

:where(.split-app-row__control) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  margin-left: 2px;
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
 * Derive a deterministic 2-letter uppercase monogram from an app's display
 * name (falling back to the executable stem). Supports full Unicode letters
 * and digits (including Turkish characters such as İ/Ş/Ç/Ğ/Ü/Ö).
 */
export function getAppMonogram(displayName: string, exeName: string): string {
  const cleanedName = displayName.trim();
  const words = cleanedName
    .split(/[^\p{L}\p{N}]+/u)
    .filter((token) => token.length > 0);

  if (words.length >= 2) {
    const first = Array.from(words[0])[0] ?? "";
    const second = Array.from(words[1])[0] ?? "";
    return `${first}${second}`.toUpperCase();
  }
  if (words.length === 1) {
    const chars = Array.from(words[0]);
    if (chars.length >= 2) {
      return `${chars[0]}${chars[1]}`.toUpperCase();
    }
  }

  const exeStem = Array.from(
    exeName
      .trim()
      .replace(/\.(exe|app|bin)$/i, "")
      .replace(/[^\p{L}\p{N}]/gu, ""),
  );

  if (exeStem.length >= 2) {
    return `${exeStem[0]}${exeStem[1]}`.toUpperCase();
  }
  if (words.length === 1 && words[0].length === 1) {
    return words[0].toUpperCase();
  }
  if (exeStem.length === 1) {
    return exeStem[0].toUpperCase();
  }
  return "AP";
}

/**
 * Deterministic FNV-1a hash mapping an app key to a muted neutral surface tone.
 */
export function getMonogramToneIndex(key: string): number {
  let hash = 2166136261;
  const normalized = key.toLowerCase();
  for (let i = 0; i < normalized.length; i += 1) {
    hash ^= normalized.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % MONOGRAM_TONE_COUNT;
}

function buildSwitchLabel(
  app: DiscoveredAppItem,
  mode: SplitTunnelMode,
  lang: ResolvedLanguage,
): string {
  const vars = { name: app.displayName, exe: app.exeName };
  if (mode === "exclude") {
    return tSplit(lang, "switchExclude", vars);
  }
  if (mode === "include") {
    return tSplit(lang, "switchInclude", vars);
  }
  return tSplit(lang, "switchAll", vars);
}

export const SplitTunnelAppRow = memo(function SplitTunnelAppRow({
  app,
  selected,
  mode,
  disabled = false,
  onToggle,
  className,
}: SplitTunnelAppRowProps) {
  const { lang } = useLang();
  const [companionsOpen, setCompanionsOpen] = useState(false);
  const companionsPanelId = useId();

  useEffect(() => {
    ensureStyles();
  }, []);

  const isDisabled = disabled;
  const monogram = getAppMonogram(app.displayName, app.exeName);
  const toneIndex = getMonogramToneIndex(
    app.normalizedKey || app.exeName || app.displayName,
  );
  const companionCount = app.companions.length;
  const companionsTitle =
    companionCount > 0 ? app.companions.join(", ") : undefined;
  const companionsAriaLabel =
    companionCount > 0
      ? tSplit(
          lang,
          companionsOpen
            ? companionCount === 1
              ? "companionAriaHideOne"
              : "companionAriaHideMany"
            : companionCount === 1
              ? "companionAriaShowOne"
              : "companionAriaShowMany",
          { count: companionCount, name: app.displayName },
        )
      : undefined;
  const switchLabel = buildSwitchLabel(app, mode, lang);

  const handleRowClick = (event: MouseEvent<HTMLDivElement>) => {
    if (isDisabled) return;
    const target = event.target as HTMLElement | null;
    if (
      target?.closest(
        'button, input, [role="switch"], .split-app-row__pill--companions, .split-app-row__companions-details',
      )
    ) {
      return;
    }
    onToggle(app.normalizedKey);
  };

  const handleCompanionsClick = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    setCompanionsOpen((prev) => !prev);
  };

  const handleCompanionsKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "Escape" && companionsOpen) {
      event.preventDefault();
      event.stopPropagation();
      setCompanionsOpen(false);
    }
  };

  const rowClasses = ["split-app-row", className].filter(Boolean).join(" ");

  return (
    <div
      role="listitem"
      className={rowClasses}
      data-app-key={app.normalizedKey}
      data-selected={selected ? "true" : "false"}
      data-disabled={isDisabled ? "true" : "false"}
      data-running={app.isRunning ? "true" : "false"}
      onClick={handleRowClick}
    >
      <div className="split-app-row__main">
        <div className="split-app-row__identity">
          <span
            className="split-app-row__monogram"
            data-tone={toneIndex}
            aria-hidden="true"
          >
            {monogram}
          </span>

          <div className="split-app-row__names">
            <span
              className="split-app-row__display-name"
              title={app.displayName}
            >
              {app.displayName}
            </span>
            <span
              className="split-app-row__exe"
              title={app.path ?? app.exeName}
            >
              {app.exeName}
            </span>
          </div>
        </div>

        <div className="split-app-row__meta">
          {app.isRunning ? (
            <span className="split-app-row__pill split-app-row__pill--running">
              <span
                className="split-app-row__running-dot"
                aria-hidden="true"
              />
              {tSplit(lang, "badgeRunning")}
            </span>
          ) : null}

          {companionCount > 0 ? (
            <button
              type="button"
              className="split-app-row__pill split-app-row__pill--companions"
              aria-expanded={companionsOpen}
              aria-controls={companionsPanelId}
              aria-label={companionsAriaLabel}
              title={companionsTitle}
              onClick={handleCompanionsClick}
              onKeyDown={handleCompanionsKeyDown}
            >
              <span>
                {tSplit(
                  lang,
                  companionCount === 1
                    ? "companionBadgeOne"
                    : "companionBadgeMany",
                  { count: companionCount },
                )}
              </span>
              <IconChevron
                size={10}
                direction={companionsOpen ? "up" : "down"}
              />
            </button>
          ) : null}

          <div className="split-app-row__control">
            <Switch
              checked={selected}
              disabled={isDisabled}
              onChange={() => onToggle(app.normalizedKey)}
              ariaLabel={switchLabel}
            />
          </div>
        </div>
      </div>

      {companionsOpen && companionCount > 0 ? (
        <div
          id={companionsPanelId}
          className="split-app-row__companions-details"
          role="region"
          aria-label={tSplit(lang, "companionRegionAria", {
            name: app.displayName,
          })}
          onClick={(event) => event.stopPropagation()}
        >
          <span className="split-app-row__companions-note">
            {tSplit(lang, "companionNote", { name: app.displayName })}
          </span>
          <span className="split-app-row__companions-list">
            {app.companions.join(", ")}
          </span>
        </div>
      ) : null}
    </div>
  );
});

export default SplitTunnelAppRow;
