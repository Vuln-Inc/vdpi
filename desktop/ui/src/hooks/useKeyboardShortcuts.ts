import { useEffect, useRef } from "react";
import type { NavTab } from "../types";

export const NAV_TAB_ORDER: readonly NavTab[] = [
  "overview",
  "split",
  "dns",
  "diagnostics",
  "settings",
] as const;

const TAB_BY_DIGIT: Record<string, NavTab> = {
  "1": "overview",
  "2": "split",
  "3": "dns",
  "4": "diagnostics",
  "5": "settings",
};

const TAB_BY_CODE: Record<string, NavTab> = {
  Digit1: "overview",
  Digit2: "split",
  Digit3: "dns",
  Digit4: "diagnostics",
  Digit5: "settings",
  Comma: "settings",
};

const SEARCH_SHORTCUT_SELECTOR = '[data-shortcut="search"]';
const ARIA_MODAL_SELECTOR = '[aria-modal="true"]';

function hasActiveAriaModal(): boolean {
  if (typeof document === "undefined") {
    return false;
  }
  return document.querySelector(ARIA_MODAL_SELECTOR) !== null;
}

function resolveTabShortcut(event: KeyboardEvent): NavTab | undefined {
  if (event.key === ",") {
    return "settings";
  }
  const byKey = TAB_BY_DIGIT[event.key];
  if (byKey) {
    return byKey;
  }
  if (event.code) {
    return TAB_BY_CODE[event.code];
  }
  return undefined;
}

export interface UseKeyboardShortcutsOptions {
  onSelectTab?: (tab: NavTab) => void;
  onEscape?: () => void;
  onCloseModal?: () => void;
  hasOpenModal?: boolean;
  enabled?: boolean;
}

function isEditableElement(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) {
    return false;
  }
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    return true;
  }
  if (target.isContentEditable) {
    return true;
  }
  return Boolean(
    target.closest('[contenteditable="true"], [contenteditable=""]'),
  );
}

function isSearchElement(element: Element | null): element is HTMLElement {
  if (!(element instanceof HTMLElement)) {
    return false;
  }
  return (
    element.matches(SEARCH_SHORTCUT_SELECTOR) ||
    Boolean(element.closest(SEARCH_SHORTCUT_SELECTOR))
  );
}

function findSearchTarget(): HTMLElement | null {
  if (typeof document === "undefined") {
    return null;
  }
  const candidates = document.querySelectorAll<HTMLElement>(
    SEARCH_SHORTCUT_SELECTOR,
  );
  for (const el of candidates) {
    if (el.closest("[hidden]") || el.hasAttribute("disabled")) {
      continue;
    }
    if (
      el instanceof HTMLInputElement ||
      el instanceof HTMLTextAreaElement ||
      el.tabIndex >= 0
    ) {
      return el;
    }
    const inner = el.querySelector<HTMLElement>(
      "input:not([disabled]), textarea:not([disabled])",
    );
    if (inner) {
      return inner;
    }
    return el;
  }
  return null;
}

export function useKeyboardShortcuts(
  options: UseKeyboardShortcutsOptions,
): void {
  const { enabled = true } = options;

  const onSelectTabRef = useRef(options.onSelectTab);
  const onEscapeRef = useRef(options.onEscape);
  const onCloseModalRef = useRef(options.onCloseModal);
  const hasOpenModalRef = useRef(options.hasOpenModal);

  onSelectTabRef.current = options.onSelectTab;
  onEscapeRef.current = options.onEscape;
  onCloseModalRef.current = options.onCloseModal;
  hasOpenModalRef.current = options.hasOpenModal;

  useEffect(() => {
    if (!enabled || typeof window === "undefined") {
      return;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.isComposing || hasActiveAriaModal()) {
        return;
      }

      if (event.key === "Escape") {
        if (event.defaultPrevented) {
          return;
        }

        const active =
          typeof document !== "undefined" ? document.activeElement : null;
        const activeIsSearch = isSearchElement(active);
        const modalOpen = hasOpenModalRef.current;

        if (activeIsSearch && !modalOpen) {
          event.preventDefault();
          active.blur();
          return;
        }

        if (modalOpen !== false) {
          if (onCloseModalRef.current) {
            event.preventDefault();
            onCloseModalRef.current();
            return;
          }
          if (onEscapeRef.current) {
            event.preventDefault();
            onEscapeRef.current();
            return;
          }
        }

        if (activeIsSearch) {
          event.preventDefault();
          active.blur();
        }
        return;
      }

      if (event.defaultPrevented || hasOpenModalRef.current) {
        return;
      }

      if (
        (event.ctrlKey || event.metaKey) &&
        !event.altKey &&
        !event.shiftKey
      ) {
        const tab = resolveTabShortcut(event);
        if (tab && onSelectTabRef.current) {
          event.preventDefault();
          onSelectTabRef.current(tab);
        }
        return;
      }

      const active =
        typeof document !== "undefined" ? document.activeElement : null;
      if (isEditableElement(event.target) || isEditableElement(active)) {
        return;
      }

      if (
        event.key === "/" &&
        !event.ctrlKey &&
        !event.metaKey &&
        !event.altKey
      ) {
        const searchTarget = findSearchTarget();
        if (searchTarget) {
          event.preventDefault();
          searchTarget.focus();
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [enabled]);
}

export default useKeyboardShortcuts;
