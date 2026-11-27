import { useEffect, useId, useRef } from "react";
import type { MouseEvent, ReactNode } from "react";
import { createPortal } from "react-dom";
import { useLang } from "../i18n/context";
import { tShell } from "../i18n/shell";

export interface ConfirmDialogProps {
  open?: boolean;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  className?: string;
}

const STYLE_ID = "vdpi-confirm-dialog-styles";

const FALLBACK_STYLES = `
@keyframes vdpi-confirm-spin {
  to {
    transform: rotate(360deg);
  }
}

:where(.confirm-dialog-backdrop) {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: rgba(0, 0, 0, 0.56);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  box-sizing: border-box;
}

:where(.confirm-dialog) {
  --_dlg-surface: var(--bg-surface-elevated, var(--surface, #1c1c1e));
  --_dlg-border: var(--border-default, var(--border, #38383a));
  --_dlg-ink: var(--ink-primary, var(--text-primary, #ffffff));
  --_dlg-muted: var(--ink-secondary, var(--text-secondary, #98989f));
  --_dlg-cancel-bg: var(--bg-surface-subtle, var(--surface-raised, #2c2c2e));
  --_dlg-cancel-bg-hover: var(--bg-surface-hover, var(--border, #38383a));
  --_dlg-primary-bg: var(--primary-button-bg, var(--accent, #3b82f6));
  --_dlg-primary-ink: var(--primary-button-ink, var(--ink-on-accent, #ffffff));
  --_dlg-danger-bg: var(--status-crimson, var(--danger, #ff453a));
  --_dlg-focus: var(--focus-ring-color, var(--accent, #3b82f6));
  width: 100%;
  max-width: 420px;
  padding: 20px;
  border-radius: 14px;
  border: 1px solid var(--_dlg-border);
  background: var(--_dlg-surface);
  color: var(--_dlg-ink);
  box-shadow: 0 20px 48px rgba(0, 0, 0, 0.45);
  box-sizing: border-box;
  outline: none;
}

:where(.confirm-dialog:focus-visible),
:where(.confirm-dialog[aria-busy="true"]:focus) {
  outline: 2px solid var(--_dlg-focus);
  outline-offset: 2px;
}

:where([data-theme="light"] .confirm-dialog) {
  --_dlg-surface: var(--bg-surface-elevated, var(--surface, #ffffff));
  --_dlg-border: var(--border-default, var(--border, #c6c6c8));
  --_dlg-ink: var(--ink-primary, var(--text-primary, #111317));
  --_dlg-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_dlg-cancel-bg: var(--bg-surface-subtle, var(--surface-raised, #e5e5ea));
  --_dlg-cancel-bg-hover: var(--bg-surface-hover, var(--border, #d1d1d6));
  --_dlg-primary-bg: var(--primary-button-bg, var(--accent, #0066cc));
  --_dlg-danger-bg: var(--status-crimson-fg, var(--danger, #c82320));
  --_dlg-focus: var(--focus-ring-color, var(--accent, #0066cc));
  box-shadow: 0 20px 48px rgba(0, 0, 0, 0.18);
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .confirm-dialog) {
    --_dlg-surface: var(--bg-surface-elevated, var(--surface, #ffffff));
    --_dlg-border: var(--border-default, var(--border, #c6c6c8));
    --_dlg-ink: var(--ink-primary, var(--text-primary, #111317));
    --_dlg-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_dlg-cancel-bg: var(--bg-surface-subtle, var(--surface-raised, #e5e5ea));
    --_dlg-cancel-bg-hover: var(--bg-surface-hover, var(--border, #d1d1d6));
    --_dlg-primary-bg: var(--primary-button-bg, var(--accent, #0066cc));
    --_dlg-danger-bg: var(--status-crimson-fg, var(--danger, #c82320));
    --_dlg-focus: var(--focus-ring-color, var(--accent, #0066cc));
    box-shadow: 0 20px 48px rgba(0, 0, 0, 0.18);
  }
}

:where(.confirm-dialog__title) {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
  line-height: 1.35;
  letter-spacing: -0.01em;
  color: var(--_dlg-ink);
}

:where(.confirm-dialog__description) {
  margin: 8px 0 0;
  font-size: 13.5px;
  line-height: 1.5;
  color: var(--_dlg-muted);
}

:where(.confirm-dialog__description > p:first-child) {
  margin-top: 0;
}

:where(.confirm-dialog__description > p:last-child) {
  margin-bottom: 0;
}

:where(.confirm-dialog__actions) {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 20px;
}

:where(.confirm-dialog__cancel),
:where(.confirm-dialog__confirm) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  min-height: 34px;
  padding: 0 14px;
  border-radius: 8px;
  border: 1px solid transparent;
  font: inherit;
  font-size: 13.5px;
  font-weight: 500;
  line-height: 1;
  cursor: pointer;
  transition: background-color 120ms ease, opacity 120ms ease;
}

:where(.confirm-dialog__cancel) {
  background: var(--_dlg-cancel-bg);
  color: var(--_dlg-ink);
  border-color: var(--_dlg-border);
}

:where(.confirm-dialog__cancel:hover:not(:disabled)) {
  background: var(--_dlg-cancel-bg-hover);
}

:where(.confirm-dialog__confirm) {
  background: var(--_dlg-primary-bg);
  color: var(--_dlg-primary-ink);
}

:where(.confirm-dialog__confirm.confirm-dialog__confirm--danger) {
  background: var(--_dlg-danger-bg);
  color: var(--_dlg-primary-ink);
}

:where(.confirm-dialog__confirm:hover:not(:disabled)) {
  filter: brightness(1.08);
}

:where(.confirm-dialog__cancel:disabled),
:where(.confirm-dialog__confirm:disabled) {
  opacity: 0.55;
  cursor: not-allowed;
}

:where(.confirm-dialog__cancel:focus-visible),
:where(.confirm-dialog__confirm:focus-visible) {
  outline: 2px solid var(--_dlg-focus);
  outline-offset: 2px;
}

:where(.confirm-dialog__spinner) {
  width: 13px;
  height: 13px;
  border-radius: 50%;
  border: 2px solid currentColor;
  border-right-color: transparent;
  animation: vdpi-confirm-spin 0.7s linear infinite;
}
`;

const FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function ensureStyles(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = FALLBACK_STYLES;
  document.head.appendChild(style);
}

export function ConfirmDialog({
  open = true,
  title,
  description,
  children,
  confirmLabel,
  cancelLabel,
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
  className,
}: ConfirmDialogProps) {
  const { lang } = useLang();
  const effectiveCancelLabel = cancelLabel ?? tShell(lang, "cancel");
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const cancelBtnRef = useRef<HTMLButtonElement>(null);
  const confirmBtnRef = useRef<HTMLButtonElement>(null);
  const onCancelRef = useRef(onCancel);
  const busyRef = useRef(busy);
  const dangerRef = useRef(danger);

  onCancelRef.current = onCancel;
  busyRef.current = busy;
  dangerRef.current = danger;

  useEffect(() => {
    if (!open) return;
    ensureStyles();
  }, [open]);

  useEffect(() => {
    if (!open || typeof document === "undefined") return;

    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const appRoot = document.getElementById("root") as
      | (HTMLElement & { inert?: boolean })
      | null;
    const shouldSetInert = Boolean(
      appRoot &&
        !appRoot.contains(dialogRef.current) &&
        !appRoot.hasAttribute("inert") &&
        !appRoot.inert,
    );
    if (appRoot && shouldSetInert) {
      appRoot.inert = true;
      appRoot.setAttribute("inert", "");
    }

    const initialTarget = dangerRef.current
      ? cancelBtnRef.current
      : confirmBtnRef.current;
    if (initialTarget && !initialTarget.disabled) {
      initialTarget.focus();
    } else {
      dialogRef.current?.focus();
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        if (!busyRef.current) {
          onCancelRef.current();
        }
        return;
      }

      if (event.key === "Tab" && dialogRef.current) {
        const focusables = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
        );
        if (focusables.length === 0) {
          event.preventDefault();
          dialogRef.current.focus();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;

        if (event.shiftKey) {
          if (active === first || !dialogRef.current.contains(active)) {
            event.preventDefault();
            last.focus();
          }
        } else if (active === last || !dialogRef.current.contains(active)) {
          event.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      if (appRoot && shouldSetInert) {
        appRoot.inert = false;
        appRoot.removeAttribute("inert");
      }
      if (previouslyFocused && previouslyFocused.isConnected) {
        previouslyFocused.focus();
      }
    };
  }, [open]);

  useEffect(() => {
    if (!open || !busy || typeof document === "undefined") return;
    const dialogEl = dialogRef.current;
    if (!dialogEl) return;
    const active = document.activeElement;
    if (
      !active ||
      active === document.body ||
      !dialogEl.contains(active) ||
      (active instanceof HTMLButtonElement && active.disabled)
    ) {
      dialogEl.focus();
    }
  }, [open, busy]);

  if (!open) {
    return null;
  }

  const handleBackdropClick = (event: MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget && !busy) {
      onCancel();
    }
  };

  const dialogClasses = [
    "confirm-dialog",
    danger ? "confirm-dialog--danger" : null,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const confirmClasses = [
    "confirm-dialog__confirm",
    danger ? "confirm-dialog__confirm--danger" : "confirm-dialog__confirm--primary",
  ].join(" ");

  const body = description ?? children;

  const modal = (
    <div
      className="confirm-dialog-backdrop"
      data-testid="confirm-dialog-backdrop"
      onClick={handleBackdropClick}
    >
      <div
        ref={dialogRef}
        className={dialogClasses}
        role={danger ? "alertdialog" : "dialog"}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={body ? descriptionId : undefined}
        aria-busy={busy || undefined}
        data-danger={danger ? "true" : undefined}
        tabIndex={-1}
      >
        <h2 id={titleId} className="confirm-dialog__title">
          {title}
        </h2>
        {body ? (
          <div id={descriptionId} className="confirm-dialog__description">
            {body}
          </div>
        ) : null}

        <div className="confirm-dialog__actions">
          <button
            ref={cancelBtnRef}
            type="button"
            className="confirm-dialog__cancel"
            disabled={busy}
            onClick={onCancel}
          >
            {effectiveCancelLabel}
          </button>
          <button
            ref={confirmBtnRef}
            type="button"
            className={confirmClasses}
            disabled={busy}
            onClick={onConfirm}
          >
            {busy ? (
              <span className="confirm-dialog__spinner" aria-hidden="true" />
            ) : null}
            <span>{confirmLabel}</span>
          </button>
        </div>
      </div>
    </div>
  );

  if (typeof document !== "undefined" && document.body) {
    return createPortal(modal, document.body);
  }

  return modal;
}

export default ConfirmDialog;
