import React from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resetMockIpcState } from "../lib/ipc";
import type { DesktopSettingsPayload, DesktopStatusSnapshot } from "../types";
import { DiagnosticsView } from "../views/DiagnosticsView";
import { DnsRulesView } from "../views/DnsRulesView";
import { SplitTunnelView } from "../views/SplitTunnelView";
import { I18nProvider, interpolate, resolveLanguage } from "./context";
import { DIAGNOSTICS_STRINGS, tDiagnostics } from "./diagnostics";
import {
  DNS_STRINGS,
  tDns,
  translateCustomDnsError,
  translateDomainRuleError,
} from "./dns";
import { INSTALLATION_STRINGS, tInstallation } from "./installation";
import { OVERVIEW_STRINGS } from "./overview";
import { SETTINGS_STRINGS } from "./settings";
import { SHELL_STRINGS } from "./shell";
import { SPLIT_STRINGS, tSplit } from "./split";

function extractPlaceholders(template: string): string[] {
  const matches = template.match(/\{[a-zA-Z0-9_]+\}/g) ?? [];
  return [...new Set(matches)].sort();
}

function makeSettings(
  overrides: Partial<DesktopSettingsPayload> = {},
): DesktopSettingsPayload {
  return {
    engine: "tun",
    dnsAddr: "1.1.1.1",
    dnsDisplay: "1.1.1.1",
    dnsIsCustomUrl: false,
    dohEnabled: true,
    effectiveDoh: true,
    blockQuic: true,
    tunIpv6: false,
    ipv4Only: false,
    vpnCoexistence: "auto_yield",
    bypassDomains: [],
    includeDomains: [],
    splitTunnelMode: "all",
    splitTunnelApps: [],
    gui: {
      theme: "system",
      language: "tr",
      keepInTrayOnClose: false,
      minimizeToTray: false,
      startMinimizedToTray: false,
      showTaskbarIconWhenMinimized: false,
    },
    ...overrides,
  };
}

function makeStatus(
  overrides: Partial<DesktopStatusSnapshot> = {},
): DesktopStatusSnapshot {
  return {
    appVersion: "0.6.0",
    platform: "windows",
    serviceState: "running",
    installedVersion: "0.6.0",
    configuredEngine: "tun",
    live: {
      running: true,
      engine: "tun",
      addr: "127.0.0.1",
      port: 18080,
      socksPort: 11080,
      tunInterface: "vdpi-tun0",
      physicalNic: "Ethernet",
      vpnConflict: null,
      version: "0.6.0",
      mode: "tun",
      dohEnabled: true,
      dnsDisplay: "1.1.1.1",
      blockQuic: true,
      activeConnections: 12,
      totalConnections: 100,
      learnedHosts: 8,
      ispStage: "ComboMultiRecord",
      udpFlowsActive: 4,
      quicBlocked: 2,
      dnsQueries: 25,
      rssKb: 18000,
      bytesRx: 1024000,
      bytesTx: 256000,
      rxRateBps: 120000,
      txRateBps: 32000,
      tlsHandshakes: 14,
      autoHealEscalations: 0,
    },
    vpnConflict: null,
    wintun: {
      required: true,
      ready: true,
      message: null,
    },
    splitTunnelMode: "all",
    splitTunnelCount: 0,
    configPath: "C:\\Users\\demo\\AppData\\Roaming\\vdpi\\config.toml",
    logsDir: "C:\\Users\\demo\\AppData\\Roaming\\vdpi\\logs",
    traySupported: true,
    configWarning: null,
    ...overrides,
  };
}

describe("i18n core utilities", () => {
  it("resolves explicit language preferences", () => {
    expect(resolveLanguage("tr")).toBe("tr");
    expect(resolveLanguage("en")).toBe("en");
  });

  it("resolves system language from navigator.languages", () => {
    const langSpy = vi
      .spyOn(window.navigator, "languages", "get")
      .mockReturnValue(["tr-TR", "en-US"]);
    try {
      expect(resolveLanguage("system")).toBe("tr");
    } finally {
      langSpy.mockRestore();
    }

    const enSpy = vi
      .spyOn(window.navigator, "languages", "get")
      .mockReturnValue(["en-US"]);
    const singleSpy = vi
      .spyOn(window.navigator, "language", "get")
      .mockReturnValue("en-US");
    try {
      expect(resolveLanguage("system")).toBe("en");
    } finally {
      enSpy.mockRestore();
      singleSpy.mockRestore();
    }
  });

  it("interpolates template variables cleanly and preserves missing tokens", () => {
    expect(interpolate("Showing {visible} of {total}", { visible: 3, total: 10 })).toBe(
      "Showing 3 of 10",
    );
    expect(interpolate("Keep {unknown} intact", { known: "x" })).toBe(
      "Keep {unknown} intact",
    );
    expect(interpolate("No vars here")).toBe("No vars here");
  });
});

describe("i18n dictionary completeness", () => {
  const dictionaries = [
    { name: "split", dict: SPLIT_STRINGS },
    { name: "dns", dict: DNS_STRINGS },
    { name: "diagnostics", dict: DIAGNOSTICS_STRINGS },
    { name: "overview", dict: OVERVIEW_STRINGS },
    { name: "settings", dict: SETTINGS_STRINGS },
    { name: "shell", dict: SHELL_STRINGS },
    { name: "installation", dict: INSTALLATION_STRINGS },
  ] as const;

  for (const { name, dict } of dictionaries) {
    it(`has complete, non-empty, placeholder-consistent en & tr entries for ${name}`, () => {
      const enKeys = Object.keys(dict.en).sort();
      const trKeys = Object.keys(dict.tr).sort();
      expect(trKeys).toEqual(enKeys);
      expect(enKeys.length).toBeGreaterThan(0);

      for (const key of enKeys) {
        const enMap = dict.en as Record<string, string>;
        const trMap = dict.tr as Record<string, string>;
        const enVal = enMap[key];
        const trVal = trMap[key];
        expect(typeof enVal).toBe("string");
        expect(typeof trVal).toBe("string");
        expect(enVal.trim().length).toBeGreaterThan(0);
        expect(trVal.trim().length).toBeGreaterThan(0);
        expect(enVal).not.toContain("\u2014");
        expect(trVal).not.toContain("\u2014");
        expect(trVal).not.toContain("vdpi'ı");
        expect(extractPlaceholders(trVal)).toEqual(extractPlaceholders(enVal));
      }
    });
  }

  it("translates custom DNS and domain rule validation errors in Turkish and preserves English", () => {
    const dnsErr = "Plain http:// is not supported for DoH. Use https:// instead.";
    expect(translateCustomDnsError("en", dnsErr)).toBe(dnsErr);
    expect(translateCustomDnsError("tr", dnsErr)).toContain("desteklenmez");

    const domainErr = "Domain rule cannot contain spaces.";
    expect(translateDomainRuleError("en", domainErr)).toBe(domainErr);
    expect(translateDomainRuleError("tr", domainErr)).toContain("boşluk");

    expect(tSplit("tr", "title")).toBe("Bölünmüş Tünel");
    expect(tDns("tr", "title")).toBe("DNS ve Kurallar");
    expect(tDiagnostics("tr", "title")).toBe("Tanılama");
    expect(tInstallation("tr", "title")).toBe("Kurulum");
  });
});

describe("Turkish view rendering under I18nProvider", () => {
  beforeEach(() => {
    resetMockIpcState();
  });

  afterEach(() => {
    resetMockIpcState();
  });

  it("renders SplitTunnelView in Turkish without untranslated primary copy", async () => {
    render(
      React.createElement(I18nProvider, {
        preference: "tr",
        children: React.createElement(SplitTunnelView, { activeEngine: "tun" }),
      }),
    );

    expect(
      await screen.findByRole("heading", { name: "Bölünmüş Tünel" }),
    ).toBeInTheDocument();
    await screen.findByText("Google Chrome");

    expect(screen.queryByText("Split Tunneling")).not.toBeInTheDocument();
    expect(screen.queryByText("Protect All Apps")).not.toBeInTheDocument();

    const modeGroup = screen.getByRole("radiogroup", {
      name: "Bölünmüş tünel modu",
    });
    expect(
      within(modeGroup).getByRole("radio", { name: /Tüm Uygulamaları Koru/i }),
    ).toBeInTheDocument();
    expect(
      within(modeGroup).getByRole("radio", { name: /Seçilenleri Hariç Tut/i }),
    ).toBeInTheDocument();
    expect(
      within(modeGroup).getByRole("radio", { name: /Yalnızca Seçilenler/i }),
    ).toBeInTheDocument();

    expect(screen.getByText("Hızlı Ayarlar")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Web Tarayıcıları/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Özel uygulama ekle/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Yenile/i })).toBeInTheDocument();
    expect(screen.getAllByText("Çalışıyor").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/\+\d+ yardımcı/).length).toBeGreaterThan(0);
  });

  it("renders DnsRulesView and DomainListEditor in Turkish with localized validation", () => {
    render(
      React.createElement(I18nProvider, {
        preference: "tr",
        children: React.createElement(DnsRulesView, {
          settings: makeSettings(),
          status: makeStatus(),
        }),
      }),
    );

    expect(
      screen.getByRole("heading", { name: "DNS ve Kurallar" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("DNS & Rules")).not.toBeInTheDocument();

    expect(
      screen.getByRole("heading", { name: "DNS Sunucusu" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Protokol ve Uyumluluk" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Alan Adı Kuralları" }),
    ).toBeInTheDocument();
    expect(screen.getByText("Şifreli DNS (DoH)")).toBeInTheDocument();
    expect(screen.getByText("QUIC Engelle (UDP/443)")).toBeInTheDocument();
    expect(screen.getByText("VPN Uyumluluğu")).toBeInTheDocument();
    expect(screen.getByText("Hariç Tutulan Alan Adları")).toBeInTheDocument();
    expect(screen.getByText("Dahil Edilen Alan Adları")).toBeInTheDocument();

    // Select Custom DNS and verify Turkish validation & sticky bar copy
    fireEvent.click(screen.getByRole("radio", { name: /Özel DNS/i }));
    const customInput = screen.getByLabelText(
      "Özel IP Adresi veya DoH Uç Nokta URL'si",
    );
    fireEvent.change(customInput, {
      target: { value: "http://dns.example.com/dns-query" },
    });
    expect(screen.getByRole("alert")).toHaveTextContent(
      /DoH için düz http:\/\/ desteklenmez/i,
    );
    expect(screen.getByText("Kaydedilmemiş Değişiklikler")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Vazgeç" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Kaydet ve Uygula" }),
    ).toBeDisabled();
  });

  it("renders DiagnosticsView in Turkish and runs checks cleanly", async () => {
    render(
      React.createElement(I18nProvider, {
        preference: "tr",
        children: React.createElement(DiagnosticsView, {
          status: makeStatus(),
        }),
      }),
    );

    expect(
      screen.getByRole("heading", { name: "Tanılama" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("Ready to run diagnostics")).not.toBeInTheDocument();
    expect(
      screen.getByText("Tanılamayı çalıştırmaya hazır"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("%100 salt okunur ve güvenli"),
    ).toBeInTheDocument();
    expect(screen.getByText("VPN uyumluluğu")).toBeInTheDocument();
    expect(screen.getByText("Wintun sürücüsü")).toBeInTheDocument();

    const runBtn = screen.getByRole("button", {
      name: "Tanılamayı Çalıştır",
    });
    const copyBtn = screen.getByRole("button", {
      name: "Maskeli Raporu Kopyala",
    });
    expect(copyBtn).toBeDisabled();

    fireEvent.click(runBtn);

    expect(
      await screen.findByText(/Tüm denetimler geçti \(6\/6\)/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Denetim Sonuçları" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Geçti").length).toBeGreaterThan(0);
    expect(screen.getByText("Maskeli raporu önizle")).toBeInTheDocument();
    expect(copyBtn).toBeEnabled();
  });
});
