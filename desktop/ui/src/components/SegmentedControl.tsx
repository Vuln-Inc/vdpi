import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { KeyboardEvent } from "react";

export type SegmentedControlSize = "sm" | "md";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  disabled?: boolean;
  title?: string;
}

export interface SegmentedControlProps<T extends string> {
  options: readonly SegmentedOption<T>[];
  value: T;
  onChange: (value: T) => void;
  disabled?: boolean;
  ariaLabel?: string;
  ariaLabelledBy?: string;
  ariaDescribedBy?: string;
  "aria-label"?: string;
  "aria-labelledby"?: string;
  "aria-describedby"?: string;
  id?: string;
  size?: SegmentedControlSize;
  fullWidth?: boolean;
  className?: string;
}

interface ThumbMetrics {
  left: number;
  width: number;
  visible: boolean;
  animated: boolean;
}

const STYLE_ID = "vdpi-segmented-control-styles";

const FALLBACK_STYLES = `
:where(.segmented-control) {
  --_seg-bg: var(--segmented-track, var(--segmented-track-bg, var(--bg-input, #0e1013)));
  --_seg-border: var(--segmented-track-border, var(--border-default, rgba(255, 255, 255, 0.14)));
  --_seg-thumb-bg: var(--segmented-thumb, var(--segmented-thumb-bg, var(--bg-surface-active, #2a303c)));
  --_seg-thumb-border: var(--segmented-thumb-border, var(--border-strong, #5b6577));
  --_seg-thumb-shadow: 0 1px 3px rgba(0, 0, 0, 0.44), 0 0.5px 1px rgba(0, 0, 0, 0.28);
  --_seg-ink: var(--ink-primary, var(--text-primary, #f3f4f6));
  --_seg-muted: var(--ink-secondary, var(--text-secondary, #a1a6b0));
  --_seg-focus: var(--focus-ring-color, var(--accent, #3b82f6));
  position: relative;
  display: inline-grid;
  grid-auto-flow: column;
  grid-auto-columns: minmax(0, 1fr);
  align-items: center;
  gap: 2px;
  padding: 2px;
  border-radius: var(--radius-md, 8px);
  border: 1px solid var(--_seg-border);
  background: var(--_seg-bg);
  box-sizing: border-box;
  user-select: none;
  -webkit-user-select: none;
}

:where(.segmented-control[role="radiogroup"]) {
  background: var(--_seg-bg);
  border-color: var(--_seg-border);
}

:where(.segmented-control.segmented-control--full) {
  display: grid;
  width: 100%;
}

:where(.segmented-control.segmented-control--disabled) {
  opacity: 0.55;
}

:where(.segmented-control__thumb) {
  position: absolute;
  top: 2px;
  bottom: 2px;
  left: 0;
  border-radius: var(--radius-sm, 6px);
  border: 1px solid var(--_seg-thumb-border);
  background: var(--_seg-thumb-bg);
  box-shadow: var(--_seg-thumb-shadow);
  pointer-events: none;
  z-index: 0;
  box-sizing: border-box;
}

:where(.segmented-control[role="radiogroup"] > .segmented-control__thumb) {
  background: var(--_seg-thumb-bg);
  border-color: var(--_seg-thumb-border);
  box-shadow: var(--_seg-thumb-shadow);
}

:where(.segmented-control__thumb.segmented-control__thumb--animated) {
  transition:
    transform 180ms cubic-bezier(0.22, 1, 0.36, 1),
    width 180ms cubic-bezier(0.22, 1, 0.36, 1);
}

:where(.segmented-control__option) {
  position: relative;
  z-index: 1;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 26px;
  padding: 0 12px;
  border-radius: var(--radius-sm, 6px);
  border: 1px solid transparent;
  background: transparent;
  color: var(--_seg-muted);
  font: inherit;
  font-size: 12.5px;
  font-weight: 500;
  line-height: 1;
  white-space: nowrap;
  cursor: pointer;
  box-sizing: border-box;
  transition: color 140ms ease, background-color 140ms ease;
}

:where(.segmented-control.segmented-control--sm .segmented-control__option) {
  min-height: 24px;
  padding: 0 10px;
  font-size: 12px;
}

:where(.segmented-control__option:hover:not(:disabled):not([aria-checked="true"])) {
  color: var(--_seg-ink);
}

:where(.segmented-control__option[aria-checked="true"]) {
  color: var(--_seg-ink);
  border-color: var(--_seg-thumb-border);
  background: var(--_seg-thumb-bg);
  box-shadow: var(--_seg-thumb-shadow);
}

:where(.segmented-control.segmented-control--has-thumb .segmented-control__option[aria-checked="true"]) {
  border-color: transparent;
  background: transparent;
  box-shadow: none;
}

:where(.segmented-control__option:disabled) {
  opacity: 0.45;
  cursor: not-allowed;
}

:where(.segmented-control.segmented-control--disabled .segmented-control__option:disabled) {
  opacity: 1;
}

:where(.segmented-control__option:focus-visible) {
  outline: 2px solid var(--_seg-focus);
  outline-offset: 1px;
}

:where([data-theme="light"] .segmented-control) {
  --_seg-bg: var(--segmented-track, var(--segmented-track-bg, #d8dde6));
  --_seg-border: var(--segmented-track-border, var(--border-default, rgba(11, 12, 14, 0.16)));
  --_seg-thumb-bg: var(--segmented-thumb, var(--segmented-thumb-bg, var(--bg-surface, #ffffff)));
  --_seg-thumb-border: var(--segmented-thumb-border, #747c8b);
  --_seg-thumb-shadow: 0 1px 2px rgba(11, 12, 14, 0.14), 0 0.5px 1px rgba(11, 12, 14, 0.08);
  --_seg-ink: var(--ink-primary, var(--text-primary, #111317));
  --_seg-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_seg-focus: var(--focus-ring-color, var(--accent, #0066cc));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .segmented-control) {
    --_seg-bg: var(--segmented-track, var(--segmented-track-bg, #d8dde6));
    --_seg-border: var(--segmented-track-border, var(--border-default, rgba(11, 12, 14, 0.16)));
    --_seg-thumb-bg: var(--segmented-thumb, var(--segmented-thumb-bg, var(--bg-surface, #ffffff)));
    --_seg-thumb-border: var(--segmented-thumb-border, #747c8b);
    --_seg-thumb-shadow: 0 1px 2px rgba(11, 12, 14, 0.14), 0 0.5px 1px rgba(11, 12, 14, 0.08);
    --_seg-ink: var(--ink-primary, var(--text-primary, #111317));
    --_seg-muted: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_seg-focus: var(--focus-ring-color, var(--accent, #0066cc));
  }
}

@media (prefers-reduced-motion: reduce) {
  :where(.segmented-control__thumb.segmented-control__thumb--animated),
  :where(.segmented-control__option) {
    transition: none;
  }
}
`;

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" ? useLayoutEffect : useEffect;

function ensureStyles(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = FALLBACK_STYLES;
  document.head.appendChild(style);
}

export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  disabled = false,
  ariaLabel,
  ariaLabelledBy,
  ariaDescribedBy,
  "aria-label": ariaLabelProp,
  "aria-labelledby": ariaLabelledByProp,
  "aria-describedby": ariaDescribedByProp,
  id,
  size = "md",
  fullWidth = false,
  className,
}: SegmentedControlProps<T>) {
  const groupRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const hasMeasuredRef = useRef(false);
  const [thumb, setThumb] = useState<ThumbMetrics>({
    left: 0,
    width: 0,
    visible: false,
    animated: false,
  });

  useEffect(() => {
    ensureStyles();
  }, []);

  const selectedIndex = options.findIndex((option) => option.value === value);

  const measureThumb = useCallback(() => {
    const activeButton =
      selectedIndex >= 0 ? itemRefs.current[selectedIndex] : null;
    if (!activeButton) {
      setThumb((prev) =>
        prev.visible ? { ...prev, visible: false } : prev,
      );
      return;
    }

    const left = activeButton.offsetLeft;
    const width = activeButton.offsetWidth;
    if (width <= 0) {
      return;
    }

    const animated = hasMeasuredRef.current;
    hasMeasuredRef.current = true;
    setThumb((prev) => {
      if (
        prev.left === left &&
        prev.width === width &&
        prev.visible &&
        prev.animated === animated
      ) {
        return prev;
      }
      return { left, width, visible: true, animated };
    });
  }, [selectedIndex]);

  useIsomorphicLayoutEffect(() => {
    measureThumb();
  }, [measureThumb, options, size, fullWidth]);

  useEffect(() => {
    const groupEl = groupRef.current;
    if (!groupEl || typeof window === "undefined") return;

    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(() => {
        measureThumb();
      });
      observer.observe(groupEl);
      return () => observer.disconnect();
    }

    window.addEventListener("resize", measureThumb);
    return () => window.removeEventListener("resize", measureThumb);
  }, [measureThumb]);

  const isOptionDisabled = (option: SegmentedOption<T>) =>
    disabled || Boolean(option.disabled);

  const tabbableIndex = (() => {
    if (disabled) return -1;
    if (selectedIndex >= 0 && !options[selectedIndex].disabled) {
      return selectedIndex;
    }
    return options.findIndex((option) => !option.disabled);
  })();

  const findEnabledIndex = (
    startIndex: number,
    direction: 1 | -1,
  ): number => {
    const count = options.length;
    if (count === 0) return -1;
    for (let step = 1; step <= count; step += 1) {
      const candidate = (startIndex + direction * step + count) % count;
      if (!isOptionDisabled(options[candidate])) {
        return candidate;
      }
    }
    return -1;
  };

  const selectIndex = (index: number) => {
    if (index < 0 || index >= options.length) return;
    const option = options[index];
    if (isOptionDisabled(option)) return;
    itemRefs.current[index]?.focus();
    if (option.value !== value) {
      onChange(option.value);
    }
  };

  const handleKeyDown = (
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
  ) => {
    if (disabled || options.length === 0) return;

    let nextIndex = -1;
    switch (event.key) {
      case "ArrowRight":
      case "ArrowDown":
        nextIndex = findEnabledIndex(index, 1);
        break;
      case "ArrowLeft":
      case "ArrowUp":
        nextIndex = findEnabledIndex(index, -1);
        break;
      case "Home":
        nextIndex = options.findIndex((option) => !isOptionDisabled(option));
        break;
      case "End":
        for (let i = options.length - 1; i >= 0; i -= 1) {
          if (!isOptionDisabled(options[i])) {
            nextIndex = i;
            break;
          }
        }
        break;
      default:
        return;
    }

    if (nextIndex >= 0) {
      event.preventDefault();
      selectIndex(nextIndex);
    }
  };

  const classes = [
    "segmented-control",
    size === "sm" ? "segmented-control--sm" : null,
    fullWidth ? "segmented-control--full" : null,
    disabled ? "segmented-control--disabled" : null,
    thumb.visible ? "segmented-control--has-thumb" : null,
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const resolvedAriaLabelledBy =
    (ariaLabelledBy ?? ariaLabelledByProp)?.trim() || undefined;
  const resolvedAriaLabel = resolvedAriaLabelledBy
    ? undefined
    : (ariaLabel ?? ariaLabelProp)?.trim() || undefined;
  const resolvedAriaDescribedBy =
    (ariaDescribedBy ?? ariaDescribedByProp)?.trim() || undefined;

  return (
    <div
      ref={groupRef}
      id={id}
      role="radiogroup"
      aria-label={resolvedAriaLabel}
      aria-labelledby={resolvedAriaLabelledBy}
      aria-describedby={resolvedAriaDescribedBy}
      aria-disabled={disabled || undefined}
      className={classes}
    >
      {thumb.visible ? (
        <span
          aria-hidden="true"
          className={
            thumb.animated
              ? "segmented-control__thumb segmented-control__thumb--animated"
              : "segmented-control__thumb"
          }
          style={{
            width: `${thumb.width}px`,
            transform: `translateX(${thumb.left}px)`,
          }}
        />
      ) : null}

      {options.map((option, index) => {
        const optionDisabled = isOptionDisabled(option);
        const checked = option.value === value;
        const tabIndex = index === tabbableIndex ? 0 : -1;

        return (
          <button
            key={option.value}
            ref={(el) => {
              itemRefs.current[index] = el;
            }}
            type="button"
            role="radio"
            aria-checked={checked}
            disabled={optionDisabled}
            tabIndex={tabIndex}
            title={option.title}
            data-state={checked ? "checked" : "unchecked"}
            className="segmented-control__option"
            onClick={() => {
              if (!optionDisabled && option.value !== value) {
                onChange(option.value);
              }
            }}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}

export default SegmentedControl;
