import React, { createContext, useContext, useEffect, useMemo } from "react";
import type { LanguagePreference } from "../types";

export type ResolvedLanguage = "en" | "tr";

export function detectSystemLanguage(): ResolvedLanguage {
  if (typeof navigator === "undefined") {
    return "en";
  }
  const candidates: string[] = [];
  if (Array.isArray(navigator.languages)) {
    candidates.push(...navigator.languages);
  }
  if (typeof navigator.language === "string") {
    candidates.push(navigator.language);
  }
  for (const tag of candidates) {
    if (/^tr(?:$|[-_])/i.test(tag.trim())) {
      return "tr";
    }
  }
  return "en";
}

export function resolveLanguage(pref?: LanguagePreference | null): ResolvedLanguage {
  if (pref === "tr") return "tr";
  if (pref === "en") return "en";
  return detectSystemLanguage();
}

export function interpolate(
  template: string,
  vars?: Record<string, string | number>,
): string {
  if (!vars) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key: string) => {
    const val = vars[key];
    return val === undefined ? match : String(val);
  });
}

export function createTranslator<T extends Record<string, string>>(dicts: {
  en: T;
  tr: T;
}) {
  return function translate(
    lang: ResolvedLanguage,
    key: keyof T,
    vars?: Record<string, string | number>,
  ): string {
    const table = lang === "tr" ? dicts.tr : dicts.en;
    const template = table[key] ?? dicts.en[key];
    return interpolate(template, vars);
  };
}

interface I18nContextValue {
  preference: LanguagePreference;
  lang: ResolvedLanguage;
}

const I18nContext = createContext<I18nContextValue>({
  preference: "system",
  lang: "en",
});

export function I18nProvider({
  preference,
  children,
}: {
  preference?: LanguagePreference;
  children: React.ReactNode;
}) {
  const effectivePref: LanguagePreference = preference ?? "system";
  const lang = useMemo(() => resolveLanguage(effectivePref), [effectivePref]);

  useEffect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.lang = lang;
    }
  }, [lang]);

  const value = useMemo(
    () => ({ preference: effectivePref, lang }),
    [effectivePref, lang],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useLang(): I18nContextValue {
  return useContext(I18nContext);
}
