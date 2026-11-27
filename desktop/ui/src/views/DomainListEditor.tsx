import { useEffect, useId, useRef, useState } from "react";
import type { ChangeEvent, KeyboardEvent } from "react";
import { validateDomainRule } from "../lib/format";

export interface DomainListEditorProps {
  label: string;
  description?: string;
  placeholder?: string;
  domains: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  emptyText?: string;
  maxEntries?: number;
  className?: string;
  resetNonce?: number;
}

const DEFAULT_MAX_ENTRIES = 512;

const STYLE_ID = "vdpi-domain-list-editor-styles";

const FALLBACK_STYLES = `
:where(.domain-editor) {
  --_de-surface: var(--surface, rgba(255, 255, 255, 0.04));
  --_de-surface-raised: var(--surface-raised, rgba(255, 255, 255, 0.08));
  --_de-input-bg: var(--surface-sunken, rgba(255, 255, 255, 0.05));
  --_de-border: var(--border, rgba(255, 255, 255, 0.12));
  --_de-border-strong: var(--border-strong, rgba(255, 255, 255, 0.22));
  --_de-ink: var(--ink-primary, var(--text-primary, #ffffff));
  --_de-secondary: var(--ink-secondary, var(--text-secondary, #98989f));
  --_de-muted: var(--ink-muted, #8e8e93);
  --_de-accent: var(--accent, #409cff);
  --_de-danger: var(--danger, #ff453a);
  --_de-danger-tint: var(--danger-tint, rgba(255, 69, 58, 0.12));
  --_de-mono: var(--font-mono, "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  display: flex;
  flex-direction: column;
  gap: 10px;
  box-sizing: border-box;
  color: var(--_de-ink);
}

:where([data-theme="light"] .domain-editor) {
  --_de-surface: var(--surface, #ffffff);
  --_de-surface-raised: var(--surface-raised, rgba(0, 0, 0, 0.05));
  --_de-input-bg: var(--surface-sunken, rgba(0, 0, 0, 0.035));
  --_de-border: var(--border, rgba(0, 0, 0, 0.12));
  --_de-border-strong: var(--border-strong, rgba(0, 0, 0, 0.24));
  --_de-ink: var(--ink-primary, var(--text-primary, #000000));
  --_de-secondary: var(--ink-secondary, var(--text-secondary, #5c5c60));
  --_de-muted: var(--ink-muted, #6c6c70);
  --_de-accent: var(--accent, #0066cc);
  --_de-danger: var(--danger, #d70015);
  --_de-danger-tint: var(--danger-tint, rgba(255, 59, 48, 0.09));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .domain-editor) {
    --_de-surface: var(--surface, #ffffff);
    --_de-surface-raised: var(--surface-raised, rgba(0, 0, 0, 0.05));
    --_de-input-bg: var(--surface-sunken, rgba(0, 0, 0, 0.035));
    --_de-border: var(--border, rgba(0, 0, 0, 0.12));
    --_de-border-strong: var(--border-strong, rgba(0, 0, 0, 0.24));
    --_de-ink: var(--ink-primary, var(--text-primary, #000000));
    --_de-secondary: var(--ink-secondary, var(--text-secondary, #5c5c60));
    --_de-muted: var(--ink-muted, #6c6c70);
    --_de-accent: var(--accent, #0066cc);
    --_de-danger: var(--danger, #d70015);
    --_de-danger-tint: var(--danger-tint, rgba(255, 59, 48, 0.09));
  }
}

:where(.domain-editor__header) {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

:where(.domain-editor__heading) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  min-width: 0;
}

:where(.domain-editor__title-row) {
  display: flex;
  align-items: center;
  gap: 7px;
}

:where(.domain-editor__label) {
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_de-ink);
}

:where(.domain-editor__count) {
  font-family: var(--_de-mono);
  font-size: 11px;
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  line-height: 1;
  padding: 2px 6px;
  border-radius: 999px;
  border: 1px solid var(--_de-border);
  background: var(--_de-surface-raised);
  color: var(--_de-secondary);
}

:where(.domain-editor__description) {
  margin: 0;
  font-size: 12.5px;
  line-height: 1.45;
  color: var(--_de-secondary);
}

:where(.domain-editor__clear) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  min-height: 24px;
  padding: 3px 8px;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--_de-muted);
  font: inherit;
  font-size: 12px;
  font-weight: 500;
  line-height: 1.3;
  cursor: pointer;
  box-sizing: border-box;
  transition: color 110ms ease, background-color 110ms ease, opacity 110ms ease;
}

:where(.domain-editor__clear:hover:not(:disabled)) {
  color: var(--_de-ink);
  background: var(--_de-surface-raised);
}

:where(.domain-editor__clear:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_de-accent));
  outline-offset: 2px;
}

:where(.domain-editor__clear:disabled) {
  opacity: 0.45;
  cursor: not-allowed;
}

:where(.domain-editor__input-row) {
  display: flex;
  align-items: stretch;
  gap: 8px;
}

:where(.domain-editor__input) {
  flex: 1 1 auto;
  min-width: 0;
  height: 34px;
  padding: 0 11px;
  border-radius: 8px;
  border: 1px solid var(--border-control, var(--_de-border-strong));
  background: var(--_de-input-bg);
  color: var(--_de-ink);
  font-family: var(--_de-mono);
  font-size: 12.5px;
  line-height: 1.3;
  box-sizing: border-box;
  transition: border-color 120ms ease, box-shadow 120ms ease, background-color 120ms ease;
}

:where(.domain-editor__input::placeholder) {
  color: var(--_de-muted);
  opacity: 0.85;
}

:where(.domain-editor__input:hover:not(:disabled):not(:focus)) {
  border-color: var(--_de-border-strong);
}

:where(.domain-editor__input:focus) {
  outline: none;
  border-color: var(--_de-accent);
  box-shadow: 0 0 0 2px color-mix(in srgb, var(--_de-accent) 22%, transparent);
}

:where(.domain-editor__input[aria-invalid="true"]) {
  border-color: var(--_de-danger);
}

:where(.domain-editor__input[aria-invalid="true"]:focus) {
  border-color: var(--_de-danger);
  box-shadow: 0 0 0 2px var(--_de-danger-tint);
}

:where(.domain-editor__input:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.domain-editor__add) {
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  height: 34px;
  padding: 0 13px;
  border-radius: 8px;
  border: 1px solid var(--_de-border);
  background: var(--_de-surface-raised);
  color: var(--_de-ink);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: background-color 110ms ease, border-color 110ms ease, opacity 110ms ease;
}

:where(.domain-editor__add:hover:not(:disabled)) {
  border-color: var(--_de-border-strong);
  background: var(--_de-border);
}

:where(.domain-editor__add:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_de-accent));
  outline-offset: 2px;
}

:where(.domain-editor__add:disabled) {
  opacity: 0.45;
  cursor: not-allowed;
}

:where(.domain-editor__error) {
  margin: -4px 0 0;
  font-size: 12px;
  line-height: 1.4;
  color: var(--_de-danger);
}

:where(.domain-editor__hint) {
  margin: -4px 0 0;
  font-size: 11.5px;
  line-height: 1.4;
  color: var(--_de-muted);
}

:where(.domain-editor__list) {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}

:where(.domain-editor__pill) {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  max-width: 100%;
  height: 26px;
  padding: 0 4px 0 9px;
  border-radius: 999px;
  border: 1px solid var(--_de-border);
  background: var(--_de-surface-raised);
  color: var(--_de-ink);
  box-sizing: border-box;
  transition: border-color 110ms ease, background-color 110ms ease;
}

:where(.domain-editor__pill:hover) {
  border-color: var(--_de-border-strong);
}

:where(.domain-editor__pill-text) {
  font-family: var(--_de-mono);
  font-size: 11.5px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

:where(.domain-editor__pill-remove) {
  position: relative;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 18px;
  height: 18px;
  padding: 0;
  border: 0;
  border-radius: 999px;
  background: transparent;
  color: var(--_de-muted);
  cursor: pointer;
  transition: background-color 110ms ease, color 110ms ease;
}

:where(.domain-editor__pill-remove)::before {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  width: max(100%, 24px);
  height: max(100%, 24px);
  transform: translate(-50%, -50%);
}

:where(.domain-editor__pill-remove:hover:not(:disabled)) {
  background: var(--_de-border);
  color: var(--_de-ink);
}

:where(.domain-editor__pill-remove:focus-visible) {
  outline: 2px solid var(--focus-ring-color, var(--_de-accent));
  outline-offset: 1px;
}

:where(.domain-editor__pill-remove:disabled) {
  opacity: 0.4;
  cursor: not-allowed;
}

:where(.domain-editor__empty) {
  margin: 0;
  font-size: 12px;
  line-height: 1.4;
  color: var(--_de-muted);
}

@media (prefers-reduced-motion: reduce) {
  :where(.domain-editor__clear),
  :where(.domain-editor__input),
  :where(.domain-editor__add),
  :where(.domain-editor__pill),
  :where(.domain-editor__pill-remove) {
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

function RemoveIcon() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 10 10"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M2.5 2.5l5 5m0-5-5 5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function DomainListEditor({
  label,
  description,
  placeholder = "example.com, *.example.com",
  domains,
  onChange,
  disabled = false,
  emptyText = "No domains configured.",
  maxEntries = DEFAULT_MAX_ENTRIES,
  className,
  resetNonce,
}: DomainListEditorProps) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const prevResetNonceRef = useRef(resetNonce);

  const inputId = useId();
  const descriptionId = useId();
  const errorId = useId();
  const hintId = useId();

  const effectiveMaxEntries =
    Number.isFinite(maxEntries) && maxEntries > 0
      ? Math.floor(maxEntries)
      : DEFAULT_MAX_ENTRIES;

  useEffect(() => {
    ensureStyles();
  }, []);

  useEffect(() => {
    if (prevResetNonceRef.current !== resetNonce) {
      prevResetNonceRef.current = resetNonce;
      setDraft("");
      setError(null);
    }
  }, [resetNonce]);

  const commitDraft = () => {
    if (disabled) return;
    if (draft.trim().length === 0) {
      return;
    }

    if (domains.length >= effectiveMaxEntries) {
      setError(
        `Maximum of ${effectiveMaxEntries} domain entries reached. Remove an entry before adding more.`,
      );
      return;
    }

    const rawSegments = draft.split(",");
    const nonEmptySegments = rawSegments.filter(
      (segment) => segment.trim().length > 0,
    );

    if (nonEmptySegments.length === 0) {
      setError(validateDomainRule(""));
      return;
    }

    const existingLower = new Set(
      domains.map((domain) => domain.trim().toLowerCase()),
    );
    const additions: string[] = [];

    for (let i = 0; i < nonEmptySegments.length; i += 1) {
      const segment = nonEmptySegments[i];
      const validationError = validateDomainRule(segment);
      if (validationError !== null) {
        // PRIV-04: Never echo raw rejected input verbatim in alert text (may contain pasted DoH URLs/tokens).
        setError(
          nonEmptySegments.length > 1
            ? `Entry #${i + 1}: ${validationError}`
            : validationError,
        );
        return;
      }

      const normalized = segment.trim().toLowerCase();
      if (!existingLower.has(normalized)) {
        if (domains.length + additions.length >= effectiveMaxEntries) {
          const remaining = Math.max(0, effectiveMaxEntries - domains.length);
          setError(
            remaining === 0
              ? `Maximum of ${effectiveMaxEntries} domain entries reached. Remove an entry before adding more.`
              : `Domain list is limited to ${effectiveMaxEntries} entries (${remaining} remaining).`,
          );
          return;
        }
        existingLower.add(normalized);
        additions.push(normalized);
      }
    }

    setError(null);
    setDraft("");

    if (additions.length > 0) {
      onChange([...domains, ...additions]);
    }
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    setDraft(event.target.value);
    if (error !== null) {
      setError(null);
    }
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "Enter") {
      event.preventDefault();
      commitDraft();
    } else if (event.key === "Escape" && error !== null) {
      setError(null);
    }
  };

  const handleRemove = (indexToRemove: number) => {
    if (disabled) return;
    if (error !== null) {
      setError(null);
    }
    onChange(domains.filter((_, index) => index !== indexToRemove));
  };

  const handleClear = () => {
    if (disabled || domains.length === 0) return;
    setError(null);
    onChange([]);
  };

  const showDraftHint = !disabled && !error && draft.trim().length > 0;
  const describedBy = [
    description ? descriptionId : null,
    error ? errorId : null,
    showDraftHint ? hintId : null,
  ]
    .filter(Boolean)
    .join(" ");

  const rootClasses = ["domain-editor", className].filter(Boolean).join(" ");
  const canAdd = !disabled && draft.trim().length > 0;

  return (
    <div
      className={rootClasses}
      data-disabled={disabled ? "true" : "false"}
      data-empty={domains.length === 0 ? "true" : "false"}
    >
      <div className="domain-editor__header">
        <div className="domain-editor__heading">
          <div className="domain-editor__title-row">
            <label htmlFor={inputId} className="domain-editor__label">
              {label}
            </label>
            {domains.length > 0 ? (
              <span
                className="domain-editor__count"
                title={`${domains.length} of ${effectiveMaxEntries} maximum entries`}
              >
                {domains.length >= effectiveMaxEntries
                  ? `${domains.length}/${effectiveMaxEntries}`
                  : domains.length}
              </span>
            ) : null}
          </div>
          {description ? (
            <p id={descriptionId} className="domain-editor__description">
              {description}
            </p>
          ) : null}
        </div>

        {domains.length > 0 ? (
          <button
            type="button"
            className="domain-editor__clear"
            disabled={disabled}
            title={`Clear all ${label.toLowerCase()}`}
            onClick={handleClear}
          >
            Clear
          </button>
        ) : null}
      </div>

      <div className="domain-editor__input-row">
        <input
          id={inputId}
          type="text"
          className="domain-editor__input"
          value={draft}
          placeholder={placeholder}
          disabled={disabled}
          spellCheck={false}
          autoCapitalize="none"
          autoCorrect="off"
          autoComplete="off"
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
        />
        <button
          type="button"
          className="domain-editor__add"
          disabled={!canAdd}
          onClick={commitDraft}
        >
          Add
        </button>
      </div>

      {error ? (
        <p id={errorId} className="domain-editor__error" role="alert">
          {error}
        </p>
      ) : showDraftHint ? (
        <p id={hintId} className="domain-editor__hint">
          Press Enter or click Add to include this entry
        </p>
      ) : null}

      {domains.length > 0 ? (
        <ul className="domain-editor__list" aria-label={`${label} list`}>
          {domains.map((domain, index) => (
            <li
              key={`${domain.toLowerCase()}-${index}`}
              className="domain-editor__pill"
            >
              <span className="domain-editor__pill-text" title={domain}>
                {domain}
              </span>
              <button
                type="button"
                className="domain-editor__pill-remove"
                disabled={disabled}
                aria-label={`Remove ${domain}`}
                onClick={() => handleRemove(index)}
              >
                <RemoveIcon />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="domain-editor__empty">{emptyText}</p>
      )}
    </div>
  );
}

export default DomainListEditor;
