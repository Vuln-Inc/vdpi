import { useEffect, useLayoutEffect, useState } from "react";
import type { ThemePreference } from "../types";

export type ResolvedTheme = "dark" | "light";

const DARK_SCHEME_QUERY = "(prefers-color-scheme: dark)";

const useIsomorphicLayoutEffect =
  typeof window !== "undefined" && typeof document !== "undefined"
    ? useLayoutEffect
    : useEffect;

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  if (preference === "dark" || preference === "light") {
    return preference;
  }
  if (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function"
  ) {
    return window.matchMedia(DARK_SCHEME_QUERY).matches ? "dark" : "light";
  }
  return "dark";
}

function applyThemeToDocument(theme: ResolvedTheme): void {
  if (typeof document === "undefined") {
    return;
  }
  const root = document.documentElement;
  root.setAttribute("data-theme", theme);
  root.style.colorScheme = theme;
}

export function useTheme(preference: ThemePreference = "system"): ResolvedTheme {
  const [resolved, setResolved] = useState<ResolvedTheme>(() =>
    resolveTheme(preference),
  );

  useIsomorphicLayoutEffect(() => {
    const apply = (next: ResolvedTheme) => {
      applyThemeToDocument(next);
      setResolved(next);
    };

    if (preference !== "system") {
      apply(preference);
      return;
    }

    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    ) {
      apply("dark");
      return;
    }

    const mediaQuery = window.matchMedia(DARK_SCHEME_QUERY);
    apply(mediaQuery.matches ? "dark" : "light");

    const handleChange = (event?: MediaQueryListEvent) => {
      const prefersDark =
        typeof event?.matches === "boolean"
          ? event.matches
          : mediaQuery.matches;
      apply(prefersDark ? "dark" : "light");
    };

    if (typeof mediaQuery.addEventListener === "function") {
      mediaQuery.addEventListener("change", handleChange);
      return () => {
        mediaQuery.removeEventListener("change", handleChange);
      };
    }

    if (typeof mediaQuery.addListener === "function") {
      mediaQuery.addListener(handleChange);
      return () => {
        mediaQuery.removeListener(handleChange);
      };
    }

    return;
  }, [preference]);

  return resolved;
}

export default useTheme;
