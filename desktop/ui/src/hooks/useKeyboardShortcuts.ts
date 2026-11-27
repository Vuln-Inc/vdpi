import { useEffect, useRef } from "react";
import type { NavTab } from "../types";

export const NAV_TAB_ORDER: readonly NavTab[] = [
  "overview",
  "split",
  "dns",
  "diagnostics",
  "settings",
  "installation",
] as const;

const TAB_BY_DIGIT: Record<string, NavTab> = {
  "1": "overview",
  "2": "split",
  "3": "dns",
  "4": "diagnostics",
  "5": "settings",
  "6": "installation",
};

const TAB_BY_CODE: Record<string, NavTab> = {
  Digit1: "overview",
  Digit2: "split",
  Digit3: "dns",
  Digit4: "diagnostics",
  Digit5: "settings",
  Digit6: "installation",
  Comma: "settings",
};

const SEARCH_SHORTCUT_SELECTOR = '[data-shortcut="search"]';
const ARIA_MODAL_SELECTOR = '[aria-modal="true"]';
const MAIN_CONTENT_SELECTOR = "#main-content";

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

function isEmptySearchElement(element: HTMLElement): boolean {
  if (
    element instanceof HTMLInputElement ||
    element instanceof HTMLTextAreaElement
  ) {
    return element.value.length === 0;
  }
  const inner = element.querySelector<HTMLInputElement | HTMLTextAreaElement>(
    "input, textarea",
  );
  if (inner) {
    return inner.value.length === 0;
  }
  return true;
}

function moveFocusToMainContent(fallbackEl: HTMLElement): void {
  if (typeof document !== "undefined") {
    const mainContent = document.querySelector<HTMLElement>(
      MAIN_CONTENT_SELECTOR,
    );
    if (mainContent) {
      if (!mainContent.hasAttribute("tabindex")) {
        mainContent.tabIndex = -1;
      }
      mainContent.focus();
      return;
    }
  }
  fallbackEl.blur();
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
          if (isEmptySearchElement(active)) {
            event.preventDefault();
            moveFocusToMainContent(active);
          }
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

        if (activeIsSearch && isEmptySearchElement(active)) {
          event.preventDefault();
          moveFocusToMainContent(active);
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
        if (
          event.key === "k" ||
          event.key === "K" ||
          event.code === "KeyK"
        ) {
          const searchTarget = findSearchTarget();
          if (searchTarget) {
            event.preventDefault();
            searchTarget.focus();
            if (
              searchTarget instanceof HTMLInputElement ||
              searchTarget instanceof HTMLTextAreaElement
            ) {
              searchTarget.select();
            }
          }
          return;
        }

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
