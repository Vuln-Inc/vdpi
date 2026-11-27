import { useEffect } from "react";
import type { ReactNode } from "react";

export type InlineBannerTone = "info" | "warn" | "error";

export interface InlineBannerProps {
  tone: InlineBannerTone;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  actionLabel?: string;
  onAction?: () => void;
  action?: ReactNode;
  className?: string;
}

const STYLE_ID = "vdpi-inline-banner-styles";

const FALLBACK_STYLES = `
:where(.inline-banner) {
  --_banner-accent: var(--accent, #409cff);
  --_banner-tint: var(--accent-tint, rgba(64, 156, 255, 0.1));
  --_banner-border: var(--border, rgba(255, 255, 255, 0.1));
  --_banner-ink: var(--ink-primary, var(--text-primary, #ffffff));
  --_banner-muted: var(--ink-secondary, var(--text-secondary, #98989f));
  --_banner-btn-bg: var(--surface-raised, rgba(255, 255, 255, 0.08));
  --_banner-btn-bg-hover: var(--border-strong, rgba(255, 255, 255, 0.14));
  display: flex;
  align-items: flex-start;
  gap: 12px;
  padding: 12px 14px;
  border-radius: 10px;
  border: 1px solid var(--_banner-border);
  border-left: 3px solid var(--_banner-accent);
  background: var(--_banner-tint);
  color: var(--_banner-ink);
  box-sizing: border-box;
}

:where(.inline-banner.inline-banner--warn) {
  --_banner-accent: var(--warning, #ff9f0a);
  --_banner-tint: var(--warning-tint, rgba(255, 159, 10, 0.12));
}

:where(.inline-banner.inline-banner--error) {
  --_banner-accent: var(--danger, #ff453a);
  --_banner-tint: var(--danger-tint, rgba(255, 69, 58, 0.12));
}

:where([data-theme="light"] .inline-banner) {
  --_banner-accent: var(--accent, #0066cc);
  --_banner-tint: var(--accent-tint, rgba(0, 102, 204, 0.08));
  --_banner-border: var(--border, rgba(0, 0, 0, 0.1));
  --_banner-ink: var(--ink-primary, var(--text-primary, #000000));
  --_banner-muted: var(--ink-secondary, var(--text-secondary, #5c5c60));
  --_banner-btn-bg: var(--surface-raised, rgba(0, 0, 0, 0.06));
  --_banner-btn-bg-hover: var(--border-strong, rgba(0, 0, 0, 0.11));
}

:where([data-theme="light"] .inline-banner.inline-banner--warn) {
  --_banner-accent: var(--warning, #c93400);
  --_banner-tint: var(--warning-tint, rgba(255, 149, 0, 0.1));
}

:where([data-theme="light"] .inline-banner.inline-banner--error) {
  --_banner-accent: var(--danger, #d70015);
  --_banner-tint: var(--danger-tint, rgba(255, 59, 48, 0.09));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .inline-banner) {
    --_banner-accent: var(--accent, #0066cc);
    --_banner-tint: var(--accent-tint, rgba(0, 102, 204, 0.08));
    --_banner-border: var(--border, rgba(0, 0, 0, 0.1));
    --_banner-ink: var(--ink-primary, var(--text-primary, #000000));
    --_banner-muted: var(--ink-secondary, var(--text-secondary, #5c5c60));
    --_banner-btn-bg: var(--surface-raised, rgba(0, 0, 0, 0.06));
    --_banner-btn-bg-hover: var(--border-strong, rgba(0, 0, 0, 0.11));
  }

  :where(:root:not([data-theme="dark"]) .inline-banner.inline-banner--warn) {
    --_banner-accent: var(--warning, #c93400);
    --_banner-tint: var(--warning-tint, rgba(255, 149, 0, 0.1));
  }

  :where(:root:not([data-theme="dark"]) .inline-banner.inline-banner--error) {
    --_banner-accent: var(--danger, #d70015);
    --_banner-tint: var(--danger-tint, rgba(255, 59, 48, 0.09));
  }
}

:where(.inline-banner__icon) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 18px;
  height: 18px;
  margin-top: 1px;
  color: var(--_banner-accent);
}

:where(.inline-banner__content) {
  flex: 1 1 auto;
  min-width: 0;
}

:where(.inline-banner__title) {
  margin: 0;
  font-size: 13.5px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_banner-ink);
}

:where(.inline-banner__description) {
  margin: 3px 0 0;
  font-size: 12.5px;
  font-weight: 400;
  line-height: 1.45;
  color: var(--_banner-muted);
}

:where(.inline-banner__description > p:first-child) {
  margin-top: 0;
}

:where(.inline-banner__description > p:last-child) {
  margin-bottom: 0;
}

:where(.inline-banner__actions) {
  display: flex;
  align-items: center;
  flex-shrink: 0;
  align-self: center;
}

:where(.inline-banner__action) {
  flex-shrink: 0;
  align-self: center;
  padding: 6px 12px;
  border-radius: 7px;
  border: 1px solid var(--_banner-border);
  background: var(--_banner-btn-bg);
  color: var(--_banner-ink);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  line-height: 1.2;
  cursor: pointer;
  white-space: nowrap;
  transition: background-color 120ms ease, border-color 120ms ease;
}

:where(.inline-banner__action:hover) {
  background: var(--_banner-btn-bg-hover);
}

:where(.inline-banner__action:focus-visible) {
  outline: 2px solid var(--_banner-accent);
  outline-offset: 2px;
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

function ToneIcon({ tone }: { tone: InlineBannerTone }) {
  if (tone === "warn") {
    return (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M7.134 2.5a1 1 0 0 1 1.732 0l5.4 9.353A1 1 0 0 1 13.4 13.35H2.6a1 1 0 0 1-.866-1.497l5.4-9.353Z"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinejoin="round"
        />
        <path
          d="M8 6v3.2"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
        <circle cx="8" cy="11.2" r="0.8" fill="currentColor" />
      </svg>
    );
  }

  if (tone === "error") {
    return (
      <svg
        width="16"
        height="16"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <circle
          cx="8"
          cy="8"
          r="6.25"
          stroke="currentColor"
          strokeWidth="1.4"
        />
        <path
          d="M8 4.8v3.7"
          stroke="currentColor"
          strokeWidth="1.4"
          strokeLinecap="round"
        />
        <circle cx="8" cy="10.9" r="0.8" fill="currentColor" />
      </svg>
    );
  }

  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 16 16"
      fill="none"
      aria-hidden="true"
    >
      <circle
        cx="8"
        cy="8"
        r="6.25"
        stroke="currentColor"
        strokeWidth="1.4"
      />
      <path
        d="M8 7.2v3.6"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <circle cx="8" cy="5.1" r="0.8" fill="currentColor" />
    </svg>
  );
}

export function InlineBanner({
  tone,
  title,
  description,
  children,
  actionLabel,
  onAction,
  action,
  className,
}: InlineBannerProps) {
  useEffect(() => {
    ensureStyles();
  }, []);

  const classes = ["inline-banner", `inline-banner--${tone}`, className]
    .filter(Boolean)
    .join(" ");

  const body = description ?? children;

  return (
    <div
      className={classes}
      data-tone={tone}
      role={tone === "error" ? "alert" : "status"}
    >
      <span className="inline-banner__icon" aria-hidden="true">
        <ToneIcon tone={tone} />
      </span>

      <div className="inline-banner__content">
        <p className="inline-banner__title">{title}</p>
        {body ? <div className="inline-banner__description">{body}</div> : null}
      </div>

      {action ? (
        <div className="inline-banner__actions">{action}</div>
      ) : actionLabel && onAction ? (
        <button
          type="button"
          className="inline-banner__action"
          onClick={onAction}
        >
          {actionLabel}
        </button>
      ) : null}
    </div>
  );
}

export default InlineBanner;
