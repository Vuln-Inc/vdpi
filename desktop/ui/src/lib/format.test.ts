import { describe, expect, it } from "vitest";
import {
  extractExecutableName,
  foldTurkish,
  formatBytes,
  formatClockTime,
  formatCount,
  formatLatency,
  formatRate,
  isKnownPublicDohIp,
  redactDnsPreview,
  scrubUrlsInText,
  validateCustomDnsClient,
  validateDomainRule,
} from "./format";

describe("formatBytes", () => {
  it("handles zero, negative, and non-finite inputs", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(-512)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
    expect(formatBytes(Number.POSITIVE_INFINITY)).toBe("0 B");
    expect(formatBytes(Number.NEGATIVE_INFINITY)).toBe("0 B");
  });

  it("formats B, KB, MB, GB, and TB cleanly", () => {
    expect(formatBytes(1)).toBe("1 B");
    expect(formatBytes(999)).toBe("999 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1.0 KB");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(2.5 * 1024 * 1024)).toBe("2.5 MB");
    expect(formatBytes(1024 ** 3)).toBe("1.00 GB");
    expect(formatBytes(3.75 * 1024 ** 3)).toBe("3.75 GB");
    expect(formatBytes(1.25 * 1024 ** 4)).toBe("1.25 TB");
  });
});

describe("formatRate", () => {
  it("appends /s to formatted byte throughput", () => {
    expect(formatRate(0)).toBe("0 B/s");
    expect(formatRate(-10)).toBe("0 B/s");
    expect(formatRate(Number.NaN)).toBe("0 B/s");
    expect(formatRate(512)).toBe("512 B/s");
    expect(formatRate(1536)).toBe("1.5 KB/s");
    expect(formatRate(5 * 1024 * 1024)).toBe("5.0 MB/s");
    expect(formatRate(1.5 * 1024 ** 3)).toBe("1.50 GB/s");
  });
});

describe("formatLatency", () => {
  it("returns placeholder for null, negative, or non-finite values", () => {
    expect(formatLatency(null)).toBe("--");
    expect(formatLatency(-1)).toBe("--");
    expect(formatLatency(Number.NaN)).toBe("--");
    expect(formatLatency(Number.POSITIVE_INFINITY)).toBe("--");
  });

  it("formats sub-millisecond, millisecond, and second latencies", () => {
    expect(formatLatency(0)).toBe("0 ms");
    expect(formatLatency(0.4)).toBe("<1 ms");
    expect(formatLatency(1)).toBe("1 ms");
    expect(formatLatency(42.4)).toBe("42 ms");
    expect(formatLatency(999)).toBe("999 ms");
    expect(formatLatency(999.6)).toBe("1.00 s");
    expect(formatLatency(1000)).toBe("1.00 s");
    expect(formatLatency(1250)).toBe("1.25 s");
  });
});

describe("formatClockTime", () => {
  it("formats valid timestamps as zero-padded 24-hour HH:MM:SS", () => {
    const morning = new Date(2026, 4, 10, 7, 5, 9).getTime();
    const evening = new Date(2026, 4, 10, 23, 59, 58).getTime();
    const midnight = new Date(2026, 4, 10, 0, 0, 0).getTime();

    expect(formatClockTime(morning)).toBe("07:05:09");
    expect(formatClockTime(evening)).toBe("23:59:58");
    expect(formatClockTime(midnight)).toBe("00:00:00");
  });

  it("handles non-finite or out-of-range timestamps", () => {
    expect(formatClockTime(Number.NaN)).toBe("--:--:--");
    expect(formatClockTime(Number.POSITIVE_INFINITY)).toBe("--:--:--");
    expect(formatClockTime(1e20)).toBe("--:--:--");
  });
});

describe("formatCount", () => {
  it("handles zero, negative, and non-finite inputs", () => {
    expect(formatCount(0)).toBe("0");
    expect(formatCount(-42)).toBe("0");
    expect(formatCount(Number.NaN)).toBe("0");
    expect(formatCount(Number.POSITIVE_INFINITY)).toBe("0");
  });

  it("formats raw, K, M, and B values without 1000K rounding artifacts", () => {
    expect(formatCount(1)).toBe("1");
    expect(formatCount(999)).toBe("999");
    expect(formatCount(1_000)).toBe("1K");
    expect(formatCount(1_240)).toBe("1.2K");
    expect(formatCount(1_260)).toBe("1.3K");
    expect(formatCount(15_000)).toBe("15K");
    expect(formatCount(999_950)).toBe("1M");
    expect(formatCount(1_500_000)).toBe("1.5M");
    expect(formatCount(999_950_000)).toBe("1B");
    expect(formatCount(2_340_000_000)).toBe("2.3B");
  });
});

describe("foldTurkish", () => {
  it("folds all Turkish uppercase and lowercase letters to plain ASCII", () => {
    expect(foldTurkish("İstanbul")).toBe("istanbul");
    expect(foldTurkish("IĞDIR")).toBe("igdir");
    expect(foldTurkish("ısparta")).toBe("isparta");
    expect(foldTurkish("Şifreli Bağlantı")).toBe("sifreli baglanti");
    expect(foldTurkish("Ücretsiz Önizleme Çıktısı")).toBe(
      "ucretsiz onizleme ciktisi",
    );
    expect(foldTurkish("ĞŞÜÖÇİIığşüöç")).toBe("gsuociiigsuoc");
  });

  it("does not leave combining dot-above artifacts from İ", () => {
    const folded = foldTurkish("İSTANBUL");
    expect(folded).toBe("istanbul");
    expect(folded).not.toContain("\u0307");
    expect(folded.length).toBe(8);
  });

  it("handles decomposed Unicode, circumflexes, and empty strings", () => {
    expect(foldTurkish("")).toBe("");
    expect(foldTurkish("I\u0307stanbul")).toBe("istanbul");
    expect(foldTurkish("Kâğıt Îmâl Ûslup")).toBe("kagit imal uslup");
    expect(foldTurkish("Discord")).toBe("discord");
  });

  it("supports instant search matching across Turkish and ASCII queries", () => {
    const appName = foldTurkish("Görüntülü Görüşme İstasyonu");
    expect(appName.includes(foldTurkish("goruntulu"))).toBe(true);
    expect(appName.includes(foldTurkish("GÖRÜŞME"))).toBe(true);
    expect(appName.includes(foldTurkish("istasyon"))).toBe(true);
    expect(appName.includes(foldTurkish("İSTASYON"))).toBe(true);
    expect(appName.includes(foldTurkish("ISTASYON"))).toBe(true);
  });
});

describe("redactDnsPreview", () => {
  it("preserves plain IPv4 and IPv6 addresses", () => {
    expect(redactDnsPreview("")).toBe("");
    expect(redactDnsPreview("   ")).toBe("");
    expect(redactDnsPreview("1.1.1.1")).toBe("1.1.1.1");
    expect(redactDnsPreview("  8.8.8.8  ")).toBe("8.8.8.8");
    expect(redactDnsPreview("2606:4700:4700::1111")).toBe(
      "2606:4700:4700::1111",
    );
  });

  it("masks NextDNS, ControlD, and custom DoH paths, queries, fragments, and userinfo", () => {
    expect(redactDnsPreview("https://dns.nextdns.io/abc123")).toBe(
      "https://dns.nextdns.io/[hidden]",
    );
    expect(
      redactDnsPreview("https://dns.nextdns.io/abc123/My-Desktop?foo=bar"),
    ).toBe("https://dns.nextdns.io/[hidden]");
    expect(redactDnsPreview("https://freedns.controld.com/p2")).toBe(
      "https://freedns.controld.com/[hidden]",
    );
    expect(redactDnsPreview("https://dns.controld.com/secret-profile-id")).toBe(
      "https://dns.controld.com/[hidden]",
    );
    expect(redactDnsPreview("HTTPS://dns.nextdns.io?token=secret")).toBe(
      "https://dns.nextdns.io/[hidden]",
    );
    expect(redactDnsPreview("https://dns.nextdns.io#secret-frag")).toBe(
      "https://dns.nextdns.io/[hidden]",
    );
    expect(
      redactDnsPreview("https://user:pass@dns.example.com/secret-id"),
    ).toBe("https://dns.example.com/[hidden]");
    expect(
      redactDnsPreview("https://user:p@ss@dns.example.com:8443/secret-id"),
    ).toBe("https://dns.example.com:8443/[hidden]");
  });

  it("preserves clean origins without trailing sensitive segments", () => {
    expect(redactDnsPreview("https://dns.nextdns.io")).toBe(
      "https://dns.nextdns.io",
    );
    expect(redactDnsPreview("https://dns.nextdns.io/")).toBe(
      "https://dns.nextdns.io",
    );
    expect(redactDnsPreview("https://user:pass@dns.example.com")).toBe(
      "https://dns.example.com",
    );
  });

  it("handles bracketed IPv6 DoH URLs with and without ports", () => {
    expect(
      redactDnsPreview("https://[2606:4700:4700::1111]/dns-query"),
    ).toBe("https://[2606:4700:4700::1111]/[hidden]");
    expect(
      redactDnsPreview("https://[2606:4700:4700::1111]:8443/secret?k=v"),
    ).toBe("https://[2606:4700:4700::1111]:8443/[hidden]");
    expect(
      redactDnsPreview(
        "HTTPS://user:pass@[2606:4700:4700::1111]:8443/secret#frag",
      ),
    ).toBe("https://[2606:4700:4700::1111]:8443/[hidden]");
    expect(redactDnsPreview("https://[2606:4700:4700::1111]")).toBe(
      "https://[2606:4700:4700::1111]",
    );
    expect(redactDnsPreview("https://[2606:4700:4700::1111]/")).toBe(
      "https://[2606:4700:4700::1111]",
    );
  });

  it("collapses malformed URLs without leaking secrets", () => {
    const malformed = [
      "https://",
      "https:///secret-token",
      "https://?token=secret",
      "https://user:secret@",
      "https://user:secret@/path",
      "https://[2606:4700:4700::1111/secret-token",
      "https://[not-ipv6-secret]/dns-query",
      "https://[2606:4700:4700::1111]extra-secret/dns-query",
      "https://[2606:4700:4700::1111]:notaport/secret",
      "https://dns.nextdns.io:secret-token/path",
      "https://dns.nextdns.io\\secret-token",
      "https://2606:4700:4700::1111/secret-token",
      "https://dns.nextdns.io secret-token",
    ];

    for (const raw of malformed) {
      const preview = redactDnsPreview(raw);
      expect(preview).toBe("https://[hidden]");
      expect(preview).not.toContain("secret");
      expect(preview).not.toContain("notaport");
    }
  });

  it("fails closed on scheme-without-slashes and single-label scheme-less URLs", () => {
    expect(redactDnsPreview("https:dns.nextdns.io/a1b2c3")).toBe(
      "https://[hidden]",
    );
    expect(redactDnsPreview("HTTP:dns.nextdns.io/a1b2c3?foo=bar")).toBe(
      "http://[hidden]",
    );
    expect(redactDnsPreview("https:user:pass@dns.nextdns.io/a1b2c3")).toBe(
      "https://[hidden]",
    );
    expect(redactDnsPreview("https:dns.nextdns.io")).toBe("https://[hidden]");
    expect(redactDnsPreview("https:mysecrettoken")).toBe("https://[hidden]");
    expect(redactDnsPreview("http:mysecrettoken")).toBe("http://[hidden]");
    expect(redactDnsPreview("https:/secret-token")).toBe("https://[hidden]");

    expect(redactDnsPreview("mysecrettoken/dns-query")).toBe("[hidden]");
    expect(redactDnsPreview("mysecrettoken?token=abc")).toBe("[hidden]");
    expect(redactDnsPreview("mysecrettoken#frag")).toBe("[hidden]");
    expect(redactDnsPreview("//mysecrettoken/dns-query")).toBe("[hidden]");

    expect(redactDnsPreview("dns.nextdns.io/a1b2c3")).toBe(
      "dns.nextdns.io/[hidden]",
    );
    expect(redactDnsPreview("dns.nextdns.io/a1b2c3?foo=bar")).toBe(
      "dns.nextdns.io/[hidden]",
    );
    expect(redactDnsPreview("dns.nextdns.io?token=secret")).toBe(
      "dns.nextdns.io/[hidden]",
    );
    expect(redactDnsPreview("dns.nextdns.io#secret")).toBe(
      "dns.nextdns.io/[hidden]",
    );
    expect(redactDnsPreview("dns.nextdns.io/")).toBe("dns.nextdns.io");
    expect(redactDnsPreview("1.1.1.1/dns-query")).toBe("1.1.1.1/[hidden]");
    expect(redactDnsPreview("user:pass@host/secret")).toBe("[hidden]");
    expect(redactDnsPreview("user:pass@dns.nextdns.io:8443/secret")).toBe(
      "dns.nextdns.io:8443/[hidden]",
    );
    expect(redactDnsPreview("user:pass@host")).toBe("[hidden]");
    expect(redactDnsPreview("//dns.nextdns.io/a1b2c3")).toBe(
      "//dns.nextdns.io/[hidden]",
    );
  });

  it("does not leak username as hostname when '@' occurs after '?', '/', or '#'", () => {
    const schemeCases = [
      "https://secret-user?pass@dns.nextdns.io/abc",
      "https://secret-user/pass@dns.nextdns.io/abc",
      "https://secret-user#pass@dns.nextdns.io/abc",
      "https://secret-user:1234?pass@dns.nextdns.io/abc",
      "https://secret-user:1234/pass@dns.nextdns.io/abc",
      "https://secret-user:1234#pass@dns.nextdns.io/abc",
    ];
    for (const raw of schemeCases) {
      const preview = redactDnsPreview(raw);
      expect(preview).toBe("https://[hidden]");
      expect(preview).not.toContain("secret-user");
      expect(preview).not.toContain("pass");
      expect(preview).not.toContain("1234");
    }

    const schemelessCases = [
      "secret-user?pass@dns.nextdns.io/abc",
      "secret-user/pass@dns.nextdns.io",
      "secret-user#pass@dns.nextdns.io",
    ];
    for (const raw of schemelessCases) {
      const preview = redactDnsPreview(raw);
      expect(preview).toBe("[hidden]");
      expect(preview).not.toContain("secret-user");
      expect(preview).not.toContain("pass");
    }
  });

  it("accepts IPv4-mapped IPv6 and rejects leading-zero IPv4 addresses", () => {
    expect(redactDnsPreview("https://[::ffff:1.1.1.1]/secret")).toBe(
      "https://[::ffff:1.1.1.1]/[hidden]",
    );
    expect(redactDnsPreview("https://[::FFFF:1.1.1.1]:8443/secret")).toBe(
      "https://[::ffff:1.1.1.1]:8443/[hidden]",
    );
    expect(redactDnsPreview("https://[::ffff:1.1.1.1]")).toBe(
      "https://[::ffff:1.1.1.1]",
    );
    expect(redactDnsPreview("[::ffff:1.1.1.1]")).toBe("[::ffff:1.1.1.1]");
    expect(redactDnsPreview("::ffff:1.1.1.1")).toBe("::ffff:1.1.1.1");

    expect(redactDnsPreview("https://01.02.03.04/secret")).toBe(
      "https://[hidden]",
    );
    expect(redactDnsPreview("https://01.02.03.04")).toBe("https://[hidden]");
    expect(redactDnsPreview("https://[::ffff:01.02.03.04]/secret")).toBe(
      "https://[hidden]",
    );
    expect(redactDnsPreview("01.02.03.04/secret")).toBe("[hidden]");
    expect(redactDnsPreview("01.02.03.04")).toBe("[hidden]");
  });
});

describe("scrubUrlsInText", () => {
  it("redacts embedded http/https URLs while preserving surrounding prose and punctuation", () => {
    expect(scrubUrlsInText("")).toBe("");
    expect(
      scrubUrlsInText("No URLs here: 1.1.1.1 and 2606:4700:4700::1111."),
    ).toBe("No URLs here: 1.1.1.1 and 2606:4700:4700::1111.");

    const scrubbed = scrubUrlsInText(
      "failed https://dns.nextdns.io/secret-profile?foo=bar and http://user:pw@example.com/tok.",
    );
    expect(scrubbed).toBe(
      "failed https://dns.nextdns.io/[hidden] and http://example.com/[hidden].",
    );
    expect(scrubbed).not.toContain("secret-profile");
    expect(scrubbed).not.toContain("foo=bar");
    expect(scrubbed).not.toContain("user:pw");
    expect(scrubbed).not.toContain("/tok");
  });

  it("handles parens, quotes, brackets, IPv6 URLs, scheme-without-slashes, and bare scheme hints", () => {
    expect(
      scrubUrlsInText(
        "TLS error (https://[2606:4700:4700::1111]:8443/secret-token): timeout",
      ),
    ).toBe("TLS error (https://[2606:4700:4700::1111]:8443/[hidden]): timeout");

    expect(
      scrubUrlsInText("Config [https://dns.nextdns.io/abc123] rejected"),
    ).toBe("Config [https://dns.nextdns.io/[hidden]] rejected");

    expect(
      scrubUrlsInText("Bad URL 'https:dns.nextdns.io/a1b2c3' in settings"),
    ).toBe("Bad URL 'https://[hidden]' in settings");

    expect(
      scrubUrlsInText("Plain http:// is not supported. Use https:// instead."),
    ).toBe("Plain http:// is not supported. Use https:// instead.");

    expect(
      scrubUrlsInText(
        "Line 1: https://secret-user?pass@dns.nextdns.io/tok\nLine 2: HTTPS://freedns.controld.com/p2",
      ),
    ).toBe(
      "Line 1: https://[hidden]\nLine 2: https://freedns.controld.com/[hidden]",
    );
  });

  it("does not stop URL scanning early on (), comma, semicolon, or apostrophe and fails closed on https:token", () => {
    expect(
      scrubUrlsInText("failed https://dns.nextdns.io/a1b2c3/My(PC)"),
    ).toBe("failed https://dns.nextdns.io/[hidden]");

    expect(
      scrubUrlsInText(
        "error sending request for url (https://dns.nextdns.io/a1b2c3/My(PC)): timed out",
      ),
    ).toBe(
      "error sending request for url (https://dns.nextdns.io/[hidden]): timed out",
    );

    expect(
      scrubUrlsInText(
        "failed https://dns.nextdns.io/a1b2c3?tags=a,secret_token, retrying",
      ),
    ).toBe("failed https://dns.nextdns.io/[hidden], retrying");

    expect(
      scrubUrlsInText(
        "failed https://dns.nextdns.io/a1b2c3/Arda's-PC;k=secret_val; next",
      ),
    ).toBe("failed https://dns.nextdns.io/[hidden]; next");

    expect(
      scrubUrlsInText(
        "DoH failed for 'HTTPS://user:pass@dns.nextdns.io/prof1?a=1', fallback <https://[2606:4700:4700::1111]/prof2>.",
      ),
    ).toBe(
      "DoH failed for 'https://dns.nextdns.io/[hidden]', fallback <https://[2606:4700:4700::1111]/[hidden]>.",
    );

    const opaque = scrubUrlsInText(
      "bad https:mysecrettoken and (http:host/secret), ok",
    );
    expect(opaque).toBe("bad https://[hidden] and (http://[hidden]), ok");
    expect(opaque).not.toContain("mysecrettoken");
    expect(opaque).not.toContain("secret");

    expect(
      scrubUrlsInText("http: timeout while checking 'https:'"),
    ).toBe("http: timeout while checking 'https:'");
  });
});

describe("isKnownPublicDohIp", () => {
  it("recognizes Cloudflare, Google, Quad9, and AdGuard IPv4/IPv6 including DNS64", () => {
    const known = [
      "1.1.1.1",
      "1.1.1.2",
      "1.1.1.3",
      "1.0.0.1",
      "1.0.0.2",
      "1.0.0.3",
      "8.8.8.8",
      "8.8.4.4",
      "9.9.9.9",
      "149.112.112.112",
      "94.140.14.14",
      "94.140.14.15",
      "94.140.14.140",
      "94.140.14.141",
      "94.140.15.15",
      "94.140.15.16",
      // Cloudflare IPv6 (Standard, Security, Family, DNS64)
      "2606:4700:4700::1111",
      "[2606:4700:4700::1111]",
      "2606:4700:4700:0000:0000:0000:0000:1001",
      "2606:4700:4700::1112",
      "2606:4700:4700::1003",
      "2606:4700:4700::64",
      "2606:4700:4700::6400",
      "[2606:4700:4700::64]",
      // Google IPv6 (Standard, DNS64)
      "2001:4860:4860::8888",
      "2001:4860:4860::8844",
      "2001:4860:4860::64",
      "2001:4860:4860::6464",
      // Quad9 IPv6
      "2620:fe::fe",
      "2620:fe::9",
      // AdGuard IPv6
      "2a10:50c0::ad1:ff",
      "2a10:50c0::ad2:ff",
      "2a10:50c0::bad1:ff",
      "2a10:50c0::bad2:ff",
      "2a10:50c0::1:ff",
      "2a10:50c0::2:ff",
    ];
    for (const ip of known) {
      expect(isKnownPublicDohIp(ip), `expected known DoH IP: ${ip}`).toBe(true);
    }
  });

  it("returns false for custom/private IPs, leading-zero IPv4, URLs, and invalid strings", () => {
    const unknown = [
      "",
      "   ",
      "76.76.2.0",
      "10.0.0.53",
      "192.168.1.1",
      "127.0.0.1",
      "::1",
      "::ffff:1.1.1.1",
      "01.01.01.01",
      "[1.1.1.1]",
      "[2606:4700:4700::1111",
      "https://1.1.1.1/dns-query",
      "dns.google",
    ];
    for (const ip of unknown) {
      expect(isKnownPublicDohIp(ip), `expected non-DoH IP: ${ip}`).toBe(false);
    }
  });
});

describe("validateCustomDnsClient", () => {
  it("accepts and normalizes IPv4, bare/bracketed IPv6, DNS64 IPv6, and https:// DoH URLs", () => {
    expect(validateCustomDnsClient("1.1.1.1")).toEqual({
      valid: true,
      kind: "known_doh_ip",
      normalized: "1.1.1.1",
      ipVersion: 4,
      error: null,
    });
    expect(validateCustomDnsClient("  76.76.2.0  ")).toEqual({
      valid: true,
      kind: "bare_udp_ip",
      normalized: "76.76.2.0",
      ipVersion: 4,
      error: null,
    });
    expect(validateCustomDnsClient("127.0.0.1")).toEqual({
      valid: true,
      kind: "bare_udp_ip",
      normalized: "127.0.0.1",
      ipVersion: 4,
      error: null,
    });
    expect(validateCustomDnsClient("[2606:4700:4700::1111]")).toEqual({
      valid: true,
      kind: "known_doh_ip",
      normalized: "2606:4700:4700::1111",
      ipVersion: 6,
      error: null,
    });
    expect(
      validateCustomDnsClient("[2606:4700:4700:0000:0000:0000:0000:1111]"),
    ).toEqual({
      valid: true,
      kind: "known_doh_ip",
      normalized: "2606:4700:4700::1111",
      ipVersion: 6,
      error: null,
    });
    expect(validateCustomDnsClient("2001:4860:4860::6464")).toEqual({
      valid: true,
      kind: "known_doh_ip",
      normalized: "2001:4860:4860::6464",
      ipVersion: 6,
      error: null,
    });
    expect(validateCustomDnsClient("::1")).toEqual({
      valid: true,
      kind: "bare_udp_ip",
      normalized: "::1",
      ipVersion: 6,
      error: null,
    });
    expect(validateCustomDnsClient("::ffff:1.1.1.1")).toEqual({
      valid: true,
      kind: "bare_udp_ip",
      normalized: "::ffff:1.1.1.1",
      ipVersion: 6,
      error: null,
    });

    expect(
      validateCustomDnsClient("  HTTPS://DNS.NextDNS.io/AbC123  "),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://dns.nextdns.io/AbC123",
      error: null,
    });
    expect(
      validateCustomDnsClient(
        "https://[2606:4700:4700:0::1111]:8443/dns-query",
      ),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://[2606:4700:4700::1111]:8443/dns-query",
      error: null,
    });
    expect(
      validateCustomDnsClient("https://doh.example.com?no-ecs=1"),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://doh.example.com/dns-query?no-ecs=1",
      error: null,
    });
    expect(
      validateCustomDnsClient("https://doh.example.com/?no-ecs=1"),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://doh.example.com/dns-query?no-ecs=1",
      error: null,
    });
    expect(
      validateCustomDnsClient("https://dns.nextdns.io/abc%20123"),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://dns.nextdns.io/abc%20123",
      error: null,
    });
    expect(validateCustomDnsClient("\t1.1.1.1\r\n")).toEqual({
      valid: true,
      kind: "known_doh_ip",
      normalized: "1.1.1.1",
      ipVersion: 4,
      error: null,
    });
    expect(
      validateCustomDnsClient("\n  https://dns.nextdns.io/abc123\r\n"),
    ).toEqual({
      valid: true,
      kind: "doh_url",
      normalized: "https://dns.nextdns.io/abc123",
      error: null,
    });
  });

  it("rejects unspecified, broadcast, multicast, leading-zero IPv4, bad percent-encoding, and malformed inputs", () => {
    expect(validateCustomDnsClient("").kind).toBe("empty");
    expect(validateCustomDnsClient("   ").kind).toBe("empty");

    const invalidCases = [
      "0.0.0.0",
      "255.255.255.255",
      "224.0.0.1",
      "239.255.255.250",
      "::",
      "[::]",
      "ff00::1",
      "ff02::1",
      "[ff02::1]",
      "::ffff:0.0.0.0",
      "::ffff:224.0.0.1",
      "::ffff:255.255.255.255",
      "01.02.03.04",
      "https://0.0.0.0/dns-query",
      "https://255.255.255.255/dns-query",
      "https://224.0.0.1/dns-query",
      "https://[::]/dns-query",
      "https://[ff02::1]/dns-query",
      "https://[::ffff:0.0.0.0]/dns-query",
      "https://01.02.03.04/dns-query",
      "https://dns.nextdns.io/abc%ZZ",
      "https://dns.nextdns.io/abc%2G",
      "https://dns.nextdns.io/abc%2",
      "https://dns.nextdns.io/abc%",
      "http://1.1.1.1/dns-query",
      "ftp://1.1.1.1/dns-query",
      "https://",
      "https:///dns-query",
      "https://garbage",
      "https://user:pass@dns.nextdns.io/abc123",
      "https://dns.nextdns.io/abc123#frag",
      "https://dns.nextdns.io/abc\\def",
      "https://dns.quad9.net:0/dns-query",
      "https://dns.quad9.net:65536/dns-query",
      "https://2606:4700:4700::1111/dns-query",
      "[1.1.1.1]",
      "[2606:4700:4700::1111",
      "dns.nextdns.io/abc123",
      "76.76.2.0 1.1.1.1",
      "76.76.2.0\u0000",
      "https://dns.nextdns.io/abc\r\nX-Injected: 1",
    ];

    for (const raw of invalidCases) {
      const res = validateCustomDnsClient(raw);
      expect(res.valid, `expected invalid DNS input: ${JSON.stringify(raw)}`).toBe(false);
      expect(res.error).toBeTruthy();
    }
  });
});

describe("extractExecutableName", () => {
  it("strips Windows shortcut quotes, paths, and CLI arguments and resolves Squirrel shortcuts", () => {
    expect(
      extractExecutableName(
        '"C:\\Program Files\\Discord\\Update.exe" --processStart Discord.exe',
      ),
    ).toBe("Discord.exe");
    expect(
      extractExecutableName(
        'C:\\Users\\Arda\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe',
      ),
    ).toBe("Discord.exe");
    expect(
      extractExecutableName(
        '"C:\\Users\\Arda\\AppData\\Local\\Slack\\Update.exe" --processStart=slack.exe',
      ),
    ).toBe("slack.exe");
    expect(
      extractExecutableName(
        '"C:\\Users\\Arda\\AppData\\Local\\Discord\\Update.exe" --processStart "My App.exe" --process-start-args "--minimized"',
      ),
    ).toBe("My App.exe");
    expect(
      extractExecutableName('"C:\\Program Files\\Discord\\Update.exe"'),
    ).toBe("Update.exe");
    expect(
      extractExecutableName(
        '"C:\\Program Files (x86)\\Steam\\steam.exe" -silent -no-browser',
      ),
    ).toBe("steam.exe");
    expect(
      extractExecutableName(
        'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe --profile-directory="Default"',
      ),
    ).toBe("chrome.exe");
    expect(
      extractExecutableName(
        '"C:\\Games\\My Game\\game.exe" /fullscreen -dx12',
      ),
    ).toBe("game.exe");
    expect(
      extractExecutableName("C:\\Games\\My Game\\game.exe"),
    ).toBe("game.exe");
  });

  it("preserves UTF-16 slice indices when Turkish capital İ precedes an executable extension", () => {
    expect(
      extractExecutableName("C:\\Users\\İbrahim\\Discord.exe --minimized"),
    ).toBe("Discord.exe");
    expect(
      extractExecutableName("C:\\Users\\İSTANBUL\\İletişim.exe --flag"),
    ).toBe("İletişim.exe");
    expect(
      extractExecutableName("C:\\İİİ\\App.EXE --silent"),
    ).toBe("App.EXE");
    expect(
      extractExecutableName(
        "C:\\Users\\İbrahim\\AppData\\Local\\Discord\\Update.exe --processStart Discord.exe",
      ),
    ).toBe("Discord.exe");
  });

  it("strips stray unmatched quotes and single-dash Unix flags, and rejects .lnk files", () => {
    expect(extractExecutableName('C:\\Games\\game.exe"')).toBe("game.exe");
    expect(extractExecutableName('"C:\\Games\\game.exe')).toBe("game.exe");
    expect(extractExecutableName('C:\\Games\\game.exe" --fullscreen')).toBe(
      "game.exe",
    );
    expect(extractExecutableName("'C:\\Games\\game.exe")).toBe("game.exe");
    expect(extractExecutableName("C:\\Games\\game.exe'")).toBe("game.exe");
    expect(extractExecutableName('"')).toBe("");
    expect(extractExecutableName("'")).toBe("");

    expect(extractExecutableName("/usr/bin/firefox -P work")).toBe("firefox");
    expect(extractExecutableName("/usr/bin/firefox -no-remote -P work")).toBe(
      "firefox",
    );
    expect(extractExecutableName("/usr/local/bin/my-app -v")).toBe("my-app");

    expect(extractExecutableName("C:\\Users\\Arda\\Desktop\\Discord.lnk")).toBe(
      "",
    );
    expect(
      extractExecutableName('"C:\\Users\\Arda\\Desktop\\Discord.LNK"'),
    ).toBe("");
    expect(extractExecutableName("Discord.lnk")).toBe("");
    expect(
      extractExecutableName("C:\\Users\\Arda\\Desktop\\Discord.lnk /arg"),
    ).toBe("");
  });

  it("handles macOS, Linux, single-quoted, and plain executable inputs", () => {
    expect(
      extractExecutableName("'/Applications/Discord.app' --minimized"),
    ).toBe("Discord.app");
    expect(
      extractExecutableName(
        "'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'",
      ),
    ).toBe("Google Chrome");
    expect(extractExecutableName("/usr/bin/firefox --new-window")).toBe(
      "firefox",
    );
    expect(
      extractExecutableName("/opt/apps/MyApp.AppImage --no-sandbox"),
    ).toBe("MyApp.AppImage");
    expect(extractExecutableName("  discord.exe  ")).toBe("discord.exe");
  });

  it("rejects empty, invalid, drive-only, traversal, and control-char inputs", () => {
    expect(extractExecutableName("")).toBe("");
    expect(extractExecutableName("   ")).toBe("");
    expect(extractExecutableName('""')).toBe("");
    expect(extractExecutableName("C:\\")).toBe("");
    expect(extractExecutableName("C:")).toBe("");
    expect(extractExecutableName("/")).toBe("");
    expect(extractExecutableName(".")).toBe("");
    expect(extractExecutableName("..")).toBe("");
    expect(extractExecutableName("discord.exe\n--evil")).toBe("");
    expect(extractExecutableName("discord.exe\u0000")).toBe("");
  });
});

describe("validateDomainRule", () => {
  it("accepts valid standard domains, subdomains, wildcards, punycode, and localhost", () => {
    expect(validateDomainRule("discord.com")).toBeNull();
    expect(validateDomainRule("  Sub-1.Example.CO.UK  ")).toBeNull();
    expect(validateDomainRule("*.example.com")).toBeNull();
    expect(validateDomainRule("*.discord.com")).toBeNull();
    expect(validateDomainRule("*.gov.tr")).toBeNull();
    expect(validateDomainRule("*.local")).toBeNull();
    expect(validateDomainRule("a.io")).toBeNull();
    expect(validateDomainRule("localhost")).toBeNull();
    expect(validateDomainRule("xn--bcher-kva.example")).toBeNull();
  });

  it("rejects bare TLD wildcards cleanly", () => {
    expect(validateDomainRule("*.com")).not.toBeNull();
    expect(validateDomainRule("*.tr")).not.toBeNull();
    expect(validateDomainRule("*.COM")).not.toBeNull();
    expect(validateDomainRule("*.TR")).not.toBeNull();
    expect(validateDomainRule("*.net")).not.toBeNull();
    expect(validateDomainRule("*.org")).not.toBeNull();
    expect(validateDomainRule("*.io")).not.toBeNull();
  });

  it("rejects empty, whitespace, and control character inputs", () => {
    expect(validateDomainRule("")).not.toBeNull();
    expect(validateDomainRule("   ")).not.toBeNull();
    expect(validateDomainRule("foo bar.com")).not.toBeNull();
    expect(validateDomainRule("discord.com\nfoo.com")).not.toBeNull();
  });

  it("rejects URL schemes, paths, queries, fragments, and ports", () => {
    expect(validateDomainRule("https://discord.com")).not.toBeNull();
    expect(validateDomainRule("http://example.com")).not.toBeNull();
    expect(validateDomainRule("discord.com/channels")).not.toBeNull();
    expect(validateDomainRule("discord.com?foo=bar")).not.toBeNull();
    expect(validateDomainRule("discord.com#top")).not.toBeNull();
    expect(validateDomainRule("discord.com:443")).not.toBeNull();
  });

  it("rejects invalid wildcards, dots, hyphens, characters, IPs, and length violations", () => {
    expect(validateDomainRule("*")).not.toBeNull();
    expect(validateDomainRule("*.")).not.toBeNull();
    expect(validateDomainRule("*.*.example.com")).not.toBeNull();
    expect(validateDomainRule("foo.*.example.com")).not.toBeNull();
    expect(validateDomainRule("*example.com")).not.toBeNull();
    expect(validateDomainRule(".example.com")).not.toBeNull();
    expect(validateDomainRule("example.com.")).not.toBeNull();
    expect(validateDomainRule("foo..bar.com")).not.toBeNull();
    expect(validateDomainRule("-bad.example.com")).not.toBeNull();
    expect(validateDomainRule("bad-.example.com")).not.toBeNull();
    expect(validateDomainRule("bad_host.example.com")).not.toBeNull();
    expect(validateDomainRule("discord")).not.toBeNull();
    expect(validateDomainRule("1.1.1.1")).not.toBeNull();
    expect(validateDomainRule("example.123")).not.toBeNull();
    expect(validateDomainRule("a.b")).not.toBeNull();
    expect(validateDomainRule(`${"a".repeat(64)}.com`)).not.toBeNull();
    expect(
      validateDomainRule(
        `${"a".repeat(60)}.${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(60)}.example.com`,
      ),
    ).not.toBeNull();
  });
});
