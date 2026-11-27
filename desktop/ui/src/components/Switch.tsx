import { useEffect } from "react";

export type SwitchSize = "sm" | "md";

export interface SwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  ariaDescribedBy?: string;
  id?: string;
  name?: string;
  size?: SwitchSize;
  className?: string;
}

const STYLE_ID = "vdpi-switch-styles";

const FALLBACK_STYLES = `
:where(.switch) {
  --_sw-w: 36px;
  --_sw-h: 20px;
  --_sw-thumb: 16px;
  --_sw-travel: 16px;
  --_sw-track-off: var(--switch-track-off, rgba(255, 255, 255, 0.22));
  --_sw-track-off-hover: var(--switch-track-off-hover, rgba(255, 255, 255, 0.3));
  --_sw-track-on: var(--accent, #3b82f6);
  --_sw-track-on-hover: var(--accent-hover, #4b8df8);
  --_sw-border-off: var(--switch-border-off, rgba(255, 255, 255, 0.34));
  --_sw-border-off-hover: var(--switch-border-off-hover, var(--switch-border-off, rgba(255, 255, 255, 0.44)));
  --_sw-border-on: transparent;
  --_sw-thumb-bg: var(--ink-on-accent, #ffffff);
  --_sw-focus: var(--focus-ring-color, var(--accent, #3b82f6));
  position: relative;
  display: inline-flex;
  align-items: center;
  flex-shrink: 0;
  width: var(--_sw-w);
  height: var(--_sw-h);
  padding: 0;
  border-radius: 9999px;
  border: 1px solid var(--_sw-border-off);
  background: var(--_sw-track-off);
  cursor: pointer;
  appearance: none;
  -webkit-appearance: none;
  box-sizing: border-box;
  vertical-align: middle;
  transition:
    background-color 160ms cubic-bezier(0.22, 1, 0.36, 1),
    border-color 160ms cubic-bezier(0.22, 1, 0.36, 1),
    opacity 120ms ease;
}

:where(.switch)::before {
  content: "";
  position: absolute;
  top: 50%;
  left: 50%;
  width: max(100%, 36px);
  height: max(100%, 26px);
  transform: translate(-50%, -50%);
}

:where(.switch.switch--sm) {
  --_sw-w: 30px;
  --_sw-h: 17px;
  --_sw-thumb: 13px;
  --_sw-travel: 13px;
}

:where(.switch[data-state="unchecked"]) {
  background: var(--_sw-track-off);
  border-color: var(--switch-border-off, var(--_sw-border-off));
}

:where(.switch[data-state="unchecked"]:hover:not(:disabled)) {
  background: var(--_sw-track-off-hover);
  border-color: var(--switch-border-off-hover, var(--switch-border-off, var(--_sw-border-off-hover)));
}

:where(.switch[aria-checked="true"]) {
  background: var(--_sw-track-on);
  border-color: var(--_sw-border-on);
}

:where(.switch[aria-checked="true"]:hover:not(:disabled)) {
  background: var(--_sw-track-on-hover);
}

:where(.switch:disabled) {
  opacity: 0.45;
  cursor: not-allowed;
}

:where(.switch:focus-visible) {
  outline: 2px solid var(--_sw-focus);
  outline-offset: 2px;
}

:where(.switch__thumb) {
  position: absolute;
  top: 1px;
  left: 1px;
  width: var(--_sw-thumb);
  height: var(--_sw-thumb);
  border-radius: 9999px;
  background: var(--_sw-thumb-bg);
  box-shadow:
    0 1px 2px rgba(0, 0, 0, 0.32),
    0 0 0 0.5px rgba(0, 0, 0, 0.08);
  pointer-events: none;
  transform: translateX(0);
  transition: transform 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

:where(.switch[aria-checked="true"] .switch__thumb) {
  transform: translateX(var(--_sw-travel));
}

:where([data-theme="light"] .switch) {
  --_sw-track-off: var(--switch-track-off, #8b93a1);
  --_sw-track-off-hover: var(--switch-track-off-hover, #757e8f);
  --_sw-track-on: var(--accent, #0066cc);
  --_sw-track-on-hover: var(--accent-hover, #0055b3);
  --_sw-border-off: var(--switch-border-off, rgba(11, 12, 14, 0.36));
  --_sw-border-off-hover: var(--switch-border-off-hover, var(--switch-border-off, rgba(11, 12, 14, 0.48)));
  --_sw-focus: var(--focus-ring-color, var(--accent, #0066cc));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .switch) {
    --_sw-track-off: var(--switch-track-off, #8b93a1);
    --_sw-track-off-hover: var(--switch-track-off-hover, #757e8f);
    --_sw-track-on: var(--accent, #0066cc);
    --_sw-track-on-hover: var(--accent-hover, #0055b3);
    --_sw-border-off: var(--switch-border-off, rgba(11, 12, 14, 0.36));
    --_sw-border-off-hover: var(--switch-border-off-hover, var(--switch-border-off, rgba(11, 12, 14, 0.48)));
    --_sw-focus: var(--focus-ring-color, var(--accent, #0066cc));
  }
}

@media (prefers-reduced-motion: reduce) {
  :where(.switch),
  :where(.switch__thumb) {
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

export function Switch({
  checked,
  onChange,
  disabled = false,
  ariaLabel,
  ariaLabelledBy,
  ariaDescribedBy,
  id,
  name,
  size = "md",
  className,
}: SwitchProps) {
  useEffect(() => {
    ensureStyles();
  }, []);

  const classes = [
    "switch",
    size === "sm" ? "switch--sm" : null,
    checked ? "switch--checked" : null,
    disabled ? "switch--disabled" : null,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const handleClick = () => {
    if (disabled) return;
    onChange(!checked);
  };

  return (
    <button
      id={id}
      name={name}
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      aria-labelledby={ariaLabelledBy}
      aria-describedby={ariaDescribedBy}
      disabled={disabled}
      data-state={checked ? "checked" : "unchecked"}
      className={classes}
      onClick={handleClick}
    >
      <span className="switch__thumb" aria-hidden="true" />
    </button>
  );
}

export default Switch;
