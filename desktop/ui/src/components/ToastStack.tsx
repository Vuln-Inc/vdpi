import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { FocusEvent } from "react";
import { createPortal } from "react-dom";
import { useLang } from "../i18n/context";
import { tShell } from "../i18n/shell";

export type ToastTone = "info" | "success" | "warn" | "error";

export interface ToastItem {
  id: string;
  tone?: ToastTone;
  message: string;
  title?: string;
}

export interface ToastStackProps {
  toasts: readonly ToastItem[];
  onDismiss: (id: string) => void;
  onPauseTimer?: (id: string) => void;
  onResumeTimer?: (id: string) => void;
  maxVisible?: number;
  className?: string;
}

const MAX_VISIBLE_CAP = 4;
const STYLE_ID = "vdpi-toast-stack-styles";

const FALLBACK_STYLES = `
@keyframes vdpi-toast-enter {
  from {
    opacity: 0;
    transform: translateY(-6px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}

:where(.toast-stack) {
  position: fixed;
  top: 16px;
  right: 16px;
  bottom: auto;
  z-index: 1100;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 8px;
  width: min(340px, calc(100vw - 32px));
  pointer-events: none;
  box-sizing: border-box;
}

.toast-stack[data-placement="top-right"] {
  top: 16px;
  right: 16px;
  bottom: auto;
}

:where(.toast) {
  --_toast-surface: var(--bg-surface-elevated, var(--surface-raised, var(--surface, #1c1c1e)));
  --_toast-border: var(--border-default, var(--border, rgba(255, 255, 255, 0.14)));
  --_toast-accent: var(--accent, #3b82f6);
  --_toast-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_toast-muted: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_toast-dismiss-hover: var(--bg-surface-hover, var(--border, rgba(255, 255, 255, 0.1)));
  --_toast-focus: var(--focus-ring-color, var(--accent, #3b82f6));
  position: relative;
  display: flex;
  align-items: flex-start;
  gap: 10px;
  width: 100%;
  padding: 10px 10px 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--_toast-border);
  border-left: 3px solid var(--_toast-accent);
  background: var(--_toast-surface);
  color: var(--_toast-ink);
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.38);
  pointer-events: auto;
  box-sizing: border-box;
  animation: vdpi-toast-enter 160ms cubic-bezier(0.22, 1, 0.36, 1);
}

:where(.toast.toast--success) {
  --_toast-accent: var(--status-green, var(--success, #30d158));
}

:where(.toast.toast--warn) {
  --_toast-accent: var(--status-amber, var(--warning, #ff9f0a));
}

:where(.toast.toast--error) {
  --_toast-accent: var(--status-crimson, var(--danger, #ff453a));
}

:where([data-theme="light"] .toast) {
  --_toast-surface: var(--bg-surface-elevated, var(--surface, #ffffff));
  --_toast-border: var(--border-default, var(--border, rgba(11, 12, 14, 0.14)));
  --_toast-accent: var(--accent, #0066cc);
  --_toast-ink: var(--ink-primary, var(--text-primary, #111317));
  --_toast-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_toast-dismiss-hover: var(--bg-surface-hover, var(--surface-raised, rgba(11, 12, 14, 0.06)));
  --_toast-focus: var(--focus-ring-color, var(--accent, #0066cc));
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.14);
}

:where([data-theme="light"] .toast.toast--success) {
  --_toast-accent: var(--status-green-fg, var(--success, #18793a));
}

:where([data-theme="light"] .toast.toast--warn) {
  --_toast-accent: var(--status-amber-fg, var(--warning, #a15c00));
}

:where([data-theme="light"] .toast.toast--error) {
  --_toast-accent: var(--status-crimson-fg, var(--danger, #c82320));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .toast) {
    --_toast-surface: var(--bg-surface-elevated, var(--surface, #ffffff));
    --_toast-border: var(--border-default, var(--border, rgba(11, 12, 14, 0.14)));
    --_toast-accent: var(--accent, #0066cc);
    --_toast-ink: var(--ink-primary, var(--text-primary, #111317));
    --_toast-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_toast-dismiss-hover: var(--bg-surface-hover, var(--surface-raised, rgba(11, 12, 14, 0.06)));
    --_toast-focus: var(--focus-ring-color, var(--accent, #0066cc));
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.14);
  }

  :where(:root:not([data-theme="dark"]) .toast.toast--success) {
    --_toast-accent: var(--status-green-fg, var(--success, #18793a));
  }

  :where(:root:not([data-theme="dark"]) .toast.toast--warn) {
    --_toast-accent: var(--status-amber-fg, var(--warning, #a15c00));
  }

  :where(:root:not([data-theme="dark"]) .toast.toast--error) {
    --_toast-accent: var(--status-crimson-fg, var(--danger, #c82320));
  }
}

:where(.toast__body) {
  flex: 1 1 auto;
  min-width: 0;
  padding-top: 1px;
}

:where(.toast__title) {
  margin: 0 0 2px;
  font-size: 13px;
  font-weight: 600;
  line-height: 1.35;
  color: var(--_toast-ink);
}

:where(.toast__message) {
  margin: 0;
  font-size: 13px;
  font-weight: 400;
  line-height: 1.4;
  color: var(--_toast-ink);
  word-break: break-word;
}

:where(.toast__title + .toast__message) {
  font-size: 12.5px;
  color: var(--_toast-muted);
}

:where(.toast__dismiss) {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  padding: 0;
  margin: -2px -2px -2px 0;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--_toast-muted);
  cursor: pointer;
  transition: background-color 120ms ease, color 120ms ease;
}

:where(.toast__dismiss:hover) {
  background: var(--_toast-dismiss-hover);
  color: var(--_toast-ink);
}

:where(.toast__dismiss:focus-visible) {
  outline: 2px solid var(--_toast-focus);
  outline-offset: 1px;
}

@media (prefers-reduced-motion: reduce) {
  :where(.toast) {
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

function CloseIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 14 14"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M3.5 3.5l7 7m0-7-7 7"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function ToastStackComponent({
  toasts,
  onDismiss,
  onPauseTimer,
  onResumeTimer,
  maxVisible = MAX_VISIBLE_CAP,
  className,
}: ToastStackProps) {
  const { lang } = useLang();
  const hoveredIdsRef = useRef<Set<string>>(new Set());
  const focusedIdsRef = useRef<Set<string>>(new Set());
  const onPauseTimerRef = useRef(onPauseTimer);
  const onResumeTimerRef = useRef(onResumeTimer);
  const [heldToasts, setHeldToasts] = useState<Record<string, ToastItem>>({});

  onPauseTimerRef.current = onPauseTimer;
  onResumeTimerRef.current = onResumeTimer;

  useEffect(() => {
    ensureStyles();
  }, []);

  const pauseToast = useCallback(
    (toast: ToastItem, source: "hover" | "focus") => {
      const id = toast.id;
      const wasPaused =
        hoveredIdsRef.current.has(id) || focusedIdsRef.current.has(id);
      if (source === "hover") {
        hoveredIdsRef.current.add(id);
      } else {
        focusedIdsRef.current.add(id);
      }
      setHeldToasts((prev) =>
        prev[id] === toast ? prev : { ...prev, [id]: toast },
      );
      if (!wasPaused) {
        onPauseTimerRef.current?.(id);
      }
    },
    [],
  );

  const resumeToast = useCallback((id: string, source: "hover" | "focus") => {
    const wasPaused =
      hoveredIdsRef.current.has(id) || focusedIdsRef.current.has(id);
    if (source === "hover") {
      hoveredIdsRef.current.delete(id);
    } else {
      focusedIdsRef.current.delete(id);
    }
    const stillPaused =
      hoveredIdsRef.current.has(id) || focusedIdsRef.current.has(id);
    if (!stillPaused) {
      setHeldToasts((prev) => {
        if (!(id in prev)) return prev;
        const next = { ...prev };
        delete next[id];
        return next;
      });
      if (wasPaused) {
        onResumeTimerRef.current?.(id);
      }
    }
  }, []);

  const handleDismiss = useCallback(
    (id: string) => {
      hoveredIdsRef.current.delete(id);
      focusedIdsRef.current.delete(id);
      setHeldToasts((prev) => {
        if (!(id in prev)) return prev;
        const next = { ...prev };
        delete next[id];
        return next;
      });
      onDismiss(id);
    },
    [onDismiss],
  );

  const mergedToasts = useMemo(() => {
    const activeIds = new Set(toasts.map((item) => item.id));
    const held: ToastItem[] = [];
    for (const [id, item] of Object.entries(heldToasts)) {
      if (!activeIds.has(id)) {
        held.push(item);
      }
    }
    return held.length > 0 ? [...held, ...toasts] : toasts;
  }, [toasts, heldToasts]);

  const effectiveMaxVisible = Math.max(
    1,
    Math.min(maxVisible, MAX_VISIBLE_CAP),
  );
  const visibleToasts = useMemo(
    () =>
      mergedToasts.length > effectiveMaxVisible
        ? mergedToasts.slice(-effectiveMaxVisible)
        : mergedToasts,
    [mergedToasts, effectiveMaxVisible],
  );

  useEffect(() => {
    const visibleIds = new Set(visibleToasts.map((item) => item.id));
    const resumedIds = new Set<string>();

    for (const id of Array.from(hoveredIdsRef.current)) {
      if (!visibleIds.has(id)) {
        hoveredIdsRef.current.delete(id);
        resumedIds.add(id);
      }
    }

    for (const id of Array.from(focusedIdsRef.current)) {
      if (!visibleIds.has(id)) {
        focusedIdsRef.current.delete(id);
        resumedIds.add(id);
      }
    }

    setHeldToasts((prev) => {
      let next: Record<string, ToastItem> | null = null;
      for (const id of Object.keys(prev)) {
        if (!visibleIds.has(id)) {
          if (!next) {
            next = { ...prev };
          }
          delete next[id];
        }
      }
      return next ?? prev;
    });

    for (const id of resumedIds) {
      onResumeTimerRef.current?.(id);
    }
  }, [visibleToasts]);

  const stackClasses = ["toast-stack", className].filter(Boolean).join(" ");

  const stack = (
    <div
      className={stackClasses}
      role="region"
      aria-label={tShell(lang, "notificationsAria")}
      data-placement="top-right"
    >
      {visibleToasts.map((toast) => {
        const tone: ToastTone = toast.tone ?? "info";
        const isPaused = toast.id in heldToasts;
        return (
          <div
            key={toast.id}
            role={tone === "error" ? "alert" : "status"}
            aria-atomic="true"
            data-tone={tone}
            data-paused={isPaused ? "true" : undefined}
            className={`toast toast--${tone}`}
            onMouseEnter={() => pauseToast(toast, "hover")}
            onMouseLeave={() => resumeToast(toast.id, "hover")}
            onFocus={() => pauseToast(toast, "focus")}
            onBlur={(event: FocusEvent<HTMLDivElement>) => {
              if (
                !event.currentTarget.contains(
                  event.relatedTarget as Node | null,
                )
              ) {
                resumeToast(toast.id, "focus");
              }
            }}
          >
            <div className="toast__body">
              {toast.title ? (
                <p className="toast__title">{toast.title}</p>
              ) : null}
              <p className="toast__message">{toast.message}</p>
            </div>
            <button
              type="button"
              className="toast__dismiss"
              aria-label={tShell(lang, "dismissNotificationAria")}
              onClick={() => handleDismiss(toast.id)}
            >
              <CloseIcon />
            </button>
          </div>
        );
      })}
    </div>
  );

  if (typeof document !== "undefined" && document.body) {
    return createPortal(stack, document.body);
  }

  return stack;
}

export const ToastStack = memo(ToastStackComponent);
ToastStack.displayName = "ToastStack";

export default ToastStack;
