const KB = 1024;
const MB = KB * 1024;
const GB = MB * 1024;
const TB = GB * 1024;

const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH = 63;

const SCHEME_RE = /^[a-z][a-z0-9+.-]*$/;
const KNOWN_SCHEME_NO_SLASH_RE = /^(https?|doh|dot|dns|ftp|wss?):(.*)$/i;
const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;
const URL_STOP_CHAR_RE = /[\s\u0000-\u001f\u007f"`<>{}]/;
const EXECUTABLE_EXTENSIONS = [
  ".exe",
  ".app",
  ".appimage",
  ".bat",
  ".cmd",
  ".lnk",
] as const;
const SQUIRREL_PROCESS_START_RE =
  /(?:^|\s)--process-?start(?:=|\s+)(?:"([^"]+)"|'([^']+)'|(\S+))/i;
const LOCAL_WILDCARD_TLDS = new Set([
  "local",
  "lan",
  "internal",
  "localdomain",
  "localhost",
]);

const TURKISH_FOLD_MAP: Record<string, string> = {
  "\u0130": "i", // İ
  I: "i",
  "\u0131": "i", // ı
  "\u011e": "g", // Ğ
  "\u011f": "g", // ğ
  "\u015e": "s", // Ş
  "\u015f": "s", // ş
  "\u00dc": "u", // Ü
  "\u00fc": "u", // ü
  "\u00d6": "o", // Ö
  "\u00f6": "o", // ö
  "\u00c7": "c", // Ç
  "\u00e7": "c", // ç
};

const TURKISH_FOLD_RE = /[\u0130I\u0131\u011e\u011f\u015e\u015f\u00dc\u00fc\u00d6\u00f6\u00c7\u00e7]/g;

export type CustomDnsKind =
  | "empty"
  | "invalid"
  | "doh_url"
  | "known_doh_ip"
  | "bare_udp_ip";

export interface CustomDnsValidation {
  valid: boolean;
  kind: CustomDnsKind;
  normalized: string;
  ipVersion?: 4 | 6;
  error: string | null;
}

function toAsciiLower(input: string): string {
  return input.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function trimTrailingZero(formatted: string): string {
  return formatted.endsWith(".0") ? formatted.slice(0, -2) : formatted;
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function isValidPort(raw: string): boolean {
  if (!/^\d{1,5}$/.test(raw)) {
    return false;
  }
  const port = Number(raw);
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

function parseIpv4Octets(
  raw: string,
): [number, number, number, number] | null {
  if (!IPV4_RE.test(raw)) {
    return null;
  }
  const parts = raw.split(".");
  const octets: number[] = [];
  for (const part of parts) {
    if (part.length > 1 && part.startsWith("0")) {
      return null;
    }
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      return null;
    }
    octets.push(n);
  }
  return [octets[0], octets[1], octets[2], octets[3]];
}

function parseIpv6Segments(raw: string): number[] | null {
  if (!raw.includes(":") || raw.includes("[") || raw.includes("]")) {
    return null;
  }
  const doubleColonParts = raw.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const parseSide = (side: string, allowIpv4Tail: boolean): number[] | null => {
    if (side === "") {
      return [];
    }
    const tokens = side.split(":");
    const out: number[] = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (token.includes(".")) {
        if (!allowIpv4Tail || i !== tokens.length - 1) {
          return null;
        }
        const v4 = parseIpv4Octets(token);
        if (!v4) {
          return null;
        }
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(token)) {
          return null;
        }
        out.push(Number.parseInt(token, 16));
      }
    }
    return out;
  };

  if (doubleColonParts.length === 1) {
    const segs = parseSide(doubleColonParts[0], true);
    return segs && segs.length === 8 ? segs : null;
  }

  const left = parseSide(doubleColonParts[0], false);
  const right = parseSide(doubleColonParts[1], true);
  if (!left || !right) {
    return null;
  }
  const missing = 8 - (left.length + right.length);
  if (missing < 1) {
    return null;
  }
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function formatIpv6Canonical(segments: readonly number[]): string {
  if (
    segments[0] === 0 &&
    segments[1] === 0 &&
    segments[2] === 0 &&
    segments[3] === 0 &&
    segments[4] === 0 &&
    segments[5] === 0xffff
  ) {
    const a = (segments[6] >> 8) & 0xff;
    const b = segments[6] & 0xff;
    const c = (segments[7] >> 8) & 0xff;
    const d = segments[7] & 0xff;
    return `::ffff:${a}.${b}.${c}.${d}`;
  }

  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i += 1) {
    if (segments[i] === 0) {
      if (curStart < 0) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }

  if (bestLen < 2) {
    return segments.map((s) => s.toString(16)).join(":");
  }

  const left = segments
    .slice(0, bestStart)
    .map((s) => s.toString(16))
    .join(":");
  const right = segments
    .slice(bestStart + bestLen)
    .map((s) => s.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function validateDnsIpv4Octets(
  octets: readonly [number, number, number, number],
): string | null {
  const [a, b, c, d] = octets;
  if (a === 0 && b === 0 && c === 0 && d === 0) {
    return "DNS IP cannot be 0.0.0.0.";
  }
  if (a >= 224 && a <= 239) {
    return "DNS IP cannot be a multicast address.";
  }
  if (a === 255 && b === 255 && c === 255 && d === 255) {
    return "DNS IP cannot be a broadcast address.";
  }
  return null;
}

function validateDnsIpv6Segments(segments: readonly number[]): string | null {
  if (segments.every((s) => s === 0)) {
    return "DNS IP cannot be ::.";
  }
  if ((segments[0] & 0xff00) === 0xff00) {
    return "DNS IP cannot be a multicast address.";
  }
  if (
    segments[0] === 0 &&
    segments[1] === 0 &&
    segments[2] === 0 &&
    segments[3] === 0 &&
    segments[4] === 0 &&
    segments[5] === 0xffff
  ) {
    return validateDnsIpv4Octets([
      (segments[6] >> 8) & 0xff,
      segments[6] & 0xff,
      (segments[7] >> 8) & 0xff,
      segments[7] & 0xff,
    ]);
  }
  return null;
}

function isKnownPublicDohIpv4Octets(
  octets: readonly [number, number, number, number],
): boolean {
  const [a, b, c, d] = octets;
  // Cloudflare (Standard, Security, Family)
  if (a === 1 && b === 1 && c === 1 && d >= 1 && d <= 3) return true;
  if (a === 1 && b === 0 && c === 0 && d >= 1 && d <= 3) return true;
  // Google Public DNS
  if (a === 8 && b === 8 && c === 8 && d === 8) return true;
  if (a === 8 && b === 8 && c === 4 && d === 4) return true;
  // Quad9
  if (a === 9 && b === 9 && c === 9 && d === 9) return true;
  if (a === 149 && b === 112 && c === 112 && d === 112) return true;
  // AdGuard DNS (Default, Family, Unfiltered)
  if (
    a === 94 &&
    b === 140 &&
    c === 14 &&
    (d === 14 || d === 15 || d === 140 || d === 141)
  ) {
    return true;
  }
  if (a === 94 && b === 140 && c === 15 && (d === 15 || d === 16)) return true;
  return false;
}

function isKnownPublicDohIpv6Segments(s: readonly number[]): boolean {
  if (s.length !== 8) return false;
  if (s[3] !== 0 || s[4] !== 0 || s[5] !== 0) return false;
  // Cloudflare IPv6 (Standard, Security, Family, DNS64)
  if (
    s[0] === 0x2606 &&
    s[1] === 0x4700 &&
    s[2] === 0x4700 &&
    s[6] === 0 &&
    (s[7] === 0x1111 ||
      s[7] === 0x1001 ||
      s[7] === 0x1112 ||
      s[7] === 0x1002 ||
      s[7] === 0x1113 ||
      s[7] === 0x1003 ||
      s[7] === 0x0064 ||
      s[7] === 0x6400)
  ) {
    return true;
  }
  // Google IPv6 (Standard, DNS64)
  if (
    s[0] === 0x2001 &&
    s[1] === 0x4860 &&
    s[2] === 0x4860 &&
    s[6] === 0 &&
    (s[7] === 0x8888 ||
      s[7] === 0x8844 ||
      s[7] === 0x6464 ||
      s[7] === 0x0064)
  ) {
    return true;
  }
  // Quad9 IPv6
  if (
    s[0] === 0x2620 &&
    s[1] === 0x00fe &&
    s[2] === 0 &&
    s[6] === 0 &&
    (s[7] === 0x00fe || s[7] === 0x0009)
  ) {
    return true;
  }
  // AdGuard IPv6 (Default, Family, Unfiltered)
  if (
    s[0] === 0x2a10 &&
    s[1] === 0x50c0 &&
    s[2] === 0 &&
    (s[6] === 0x0ad1 ||
      s[6] === 0x0ad2 ||
      s[6] === 0xbad1 ||
      s[6] === 0xbad2 ||
      s[6] === 0x0001 ||
      s[6] === 0x0002) &&
    s[7] === 0x00ff
  ) {
    return true;
  }
  return false;
}

function isValidHostname(host: string, allowSingleLabel = true): boolean {
  const normalized = host.endsWith(".") ? host.slice(0, -1) : host;
  if (normalized.length === 0 || normalized.length > MAX_DOMAIN_LENGTH) {
    return false;
  }
  const labels = normalized.split(".");
  if (!allowSingleLabel && labels.length < 2) {
    return false;
  }
  if (!labels.every((label) => DNS_LABEL_RE.test(label))) {
    return false;
  }
  const tld = labels[labels.length - 1];
  return /[a-z]/i.test(tld);
}

function isValidDohHostname(host: string): boolean {
  const normalized = host.endsWith(".") ? host.slice(0, -1) : host;
  if (normalized.length === 0 || normalized.length > MAX_DOMAIN_LENGTH) {
    return false;
  }
  if (normalized.includes("..")) {
    return false;
  }
  const labels = normalized.split(".");
  if (labels.length < 2) {
    return false;
  }
  if (!labels.every((label) => DNS_LABEL_RE.test(label))) {
    return false;
  }
  const tld = labels[labels.length - 1];
  return tld.length >= 2 && /[a-z]/i.test(tld);
}

function isAsciiHexDigit(ch: string): boolean {
  const code = ch.charCodeAt(0);
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x46) ||
    (code >= 0x61 && code <= 0x66)
  );
}

function validateDohPathAndQuery(suffix: string): string | null {
  for (let i = 0; i < suffix.length; ) {
    const ch = suffix[i];
    if (ch === "%") {
      if (
        i + 2 >= suffix.length ||
        !isAsciiHexDigit(suffix[i + 1]) ||
        !isAsciiHexDigit(suffix[i + 2])
      ) {
        return "Invalid percent-encoding in DoH URL path.";
      }
      i += 3;
      continue;
    }
    if (!/^[A-Za-z0-9\-._~/?:@!$&'()*+,;=]$/.test(ch)) {
      return "Invalid character in DoH URL path or query.";
    }
    i += 1;
  }
  return null;
}

function parseValidDohAuthority(
  authority: string,
  allowSingleLabel = true,
): string | null {
  if (
    authority.length === 0 ||
    CONTROL_CHAR_RE.test(authority) ||
    /[\s\\]/.test(authority)
  ) {
    return null;
  }

  // Strip userinfo using the last '@' so passwords containing '@' cannot leak.
  const atIdx = authority.lastIndexOf("@");
  const hostPort = atIdx >= 0 ? authority.slice(atIdx + 1) : authority;
  if (hostPort.length === 0) {
    return null;
  }

  if (hostPort.startsWith("[")) {
    const closeIdx = hostPort.indexOf("]");
    if (closeIdx < 0) {
      return null;
    }
    const ipv6Inner = hostPort.slice(1, closeIdx);
    if (!parseIpv6Segments(ipv6Inner)) {
      return null;
    }
    const tail = hostPort.slice(closeIdx + 1);
    if (tail === "") {
      return `[${toAsciiLower(ipv6Inner)}]`;
    }
    if (!tail.startsWith(":")) {
      return null;
    }
    const port = tail.slice(1);
    if (!isValidPort(port)) {
      return null;
    }
    return `[${toAsciiLower(ipv6Inner)}]:${Number(port)}`;
  }

  if (hostPort.includes("[") || hostPort.includes("]")) {
    return null;
  }

  const colonIdx = hostPort.indexOf(":");
  if (colonIdx !== hostPort.lastIndexOf(":")) {
    return null;
  }

  let hostRaw = hostPort;
  let portNum: number | null = null;
  if (colonIdx >= 0) {
    hostRaw = hostPort.slice(0, colonIdx);
    const portStr = hostPort.slice(colonIdx + 1);
    if (!isValidPort(portStr)) {
      return null;
    }
    portNum = Number(portStr);
  }

  if (hostRaw.length === 0) {
    return null;
  }

  const lowerHost = toAsciiLower(hostRaw);
  if (
    !parseIpv4Octets(lowerHost) &&
    !isValidHostname(lowerHost, allowSingleLabel)
  ) {
    return null;
  }

  return portNum === null ? lowerHost : `${lowerHost}:${portNum}`;
}

function redactAuthorityAndSuffix(
  rest: string,
  prefix: string,
  fallback: string,
  allowSingleLabel = true,
): string {
  const suffixIdx = rest.search(/[/?#]/);
  const authority = suffixIdx >= 0 ? rest.slice(0, suffixIdx) : rest;
  const suffix = suffixIdx >= 0 ? rest.slice(suffixIdx) : "";

  // Reject userinfo '@' appearing after '?', '/', or '#' so username/credentials
  // before the delimiter can never leak as the displayed hostname.
  if (suffix.includes("@")) {
    return fallback;
  }

  const hostPort = parseValidDohAuthority(authority, allowSingleLabel);
  if (hostPort === null) {
    return fallback;
  }

  if (suffix.length > 0 && suffix !== "/") {
    return `${prefix}${hostPort}/[hidden]`;
  }
  return `${prefix}${hostPort}`;
}

function stripCliArgsAfterExtension(
  input: string,
  allowExtensionlessFlags = true,
): { executablePart: string; argsPart: string } {
  // Use ASCII-only lowercasing so characters like Turkish capital 'İ' (U+0130)
  // never expand to 2 UTF-16 code units and shift slice indices.
  const lower = input.replace(/[A-Z]/g, (c) => c.toLowerCase());
  let earliestEnd: number | null = null;
  let argsStart: number | null = null;

  for (const ext of EXECUTABLE_EXTENSIONS) {
    let searchFrom = 0;
    while (searchFrom < lower.length) {
      const idx = lower.indexOf(ext, searchFrom);
      if (idx < 0) {
        break;
      }
      const extEnd = idx + ext.length;
      const prevChar = idx > 0 ? lower[idx - 1] : "";
      const nextChar = extEnd < lower.length ? lower[extEnd] : "";
      const precededByName =
        idx > 0 &&
        prevChar !== "/" &&
        prevChar !== "\\" &&
        prevChar !== " " &&
        prevChar !== "\t" &&
        prevChar !== '"' &&
        prevChar !== "'";
      const followedByWhitespace = nextChar !== "" && /\s/.test(nextChar);
      const followedByStrayQuote =
        (nextChar === '"' || nextChar === "'") &&
        (extEnd + 1 === lower.length || /\s/.test(lower[extEnd + 1]));

      if (precededByName && (followedByWhitespace || followedByStrayQuote)) {
        if (earliestEnd === null || extEnd < earliestEnd) {
          earliestEnd = extEnd;
          argsStart = followedByStrayQuote ? extEnd + 1 : extEnd;
        }
        break;
      }
      searchFrom = extEnd;
    }
  }

  if (earliestEnd !== null) {
    return {
      executablePart: input.slice(0, earliestEnd),
      argsPart: input.slice(argsStart ?? earliestEnd).trim(),
    };
  }

  if (allowExtensionlessFlags) {
    // Fallback for unquoted extensionless command lines
    // (e.g. "/usr/bin/firefox --new-window" or "/usr/bin/firefox -P work").
    const flagMatch = /\s+-{1,2}[a-zA-Z0-9]/.exec(input);
    if (flagMatch && flagMatch.index > 0) {
      return {
        executablePart: input.slice(0, flagMatch.index).trimEnd(),
        argsPart: input.slice(flagMatch.index).trim(),
      };
    }
  }

  return { executablePart: input, argsPart: "" };
}

function extractExecutableNameInternal(raw: string, depth: number): string {
  if (CONTROL_CHAR_RE.test(raw)) {
    return "";
  }

  let cleaned = raw.trim();
  let argsTail = "";
  let wasQuoted = false;

  while (cleaned.length >= 2 && (cleaned[0] === '"' || cleaned[0] === "'")) {
    const quote = cleaned[0];
    const closeIdx = cleaned.indexOf(quote, 1);
    if (closeIdx < 0) {
      break;
    }
    const afterClose = cleaned.slice(closeIdx + 1);
    if (afterClose.length === 0 || /^\s/.test(afterClose)) {
      wasQuoted = true;
      const trimmedAfter = afterClose.trim();
      if (trimmedAfter.length > 0) {
        argsTail =
          argsTail.length > 0 ? `${trimmedAfter} ${argsTail}` : trimmedAfter;
      }
      cleaned = cleaned.slice(1, closeIdx).trim();
    } else {
      break;
    }
  }

  // Strip stray leading unmatched quotes (e.g. `"C:\Games\game.exe`).
  cleaned = cleaned.replace(/^["']+/, "").trim();

  const split = stripCliArgsAfterExtension(cleaned, !wasQuoted);
  cleaned = split.executablePart.replace(/^["']+|["']+$/g, "").trim();
  if (split.argsPart.length > 0) {
    argsTail =
      argsTail.length > 0 ? `${split.argsPart} ${argsTail}` : split.argsPart;
  }

  if (cleaned.length === 0) {
    return "";
  }

  const withoutTrailingSep = cleaned.replace(/[/\\]+$/, "");
  if (withoutTrailingSep.length === 0) {
    return "";
  }

  const lastSlash = Math.max(
    withoutTrailingSep.lastIndexOf("/"),
    withoutTrailingSep.lastIndexOf("\\"),
  );
  const fileName = (
    lastSlash >= 0 ? withoutTrailingSep.slice(lastSlash + 1) : withoutTrailingSep
  )
    .replace(/^["']+|["']+$/g, "")
    .trim();

  if (
    fileName.length === 0 ||
    fileName === "." ||
    fileName === ".." ||
    fileName.endsWith(":") ||
    toAsciiLower(fileName).endsWith(".lnk")
  ) {
    return "";
  }

  // Resolve Windows Squirrel shortcuts (e.g. `"C:\...\Update.exe" --processStart Discord.exe`).
  if (
    depth === 0 &&
    toAsciiLower(fileName) === "update.exe" &&
    argsTail.length > 0
  ) {
    const startMatch = SQUIRREL_PROCESS_START_RE.exec(argsTail);
    const target = startMatch?.[1] ?? startMatch?.[2] ?? startMatch?.[3];
    if (target) {
      return extractExecutableNameInternal(target, depth + 1);
    }
  }

  return fileName;
}

/**
 * Formats a byte count into a human-readable binary unit string (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  if (bytes < KB) {
    return `${Math.round(bytes)} B`;
  }
  if (bytes < MB) {
    return `${(bytes / KB).toFixed(1)} KB`;
  }
  if (bytes < GB) {
    return `${(bytes / MB).toFixed(1)} MB`;
  }
  if (bytes < TB) {
    return `${(bytes / GB).toFixed(2)} GB`;
  }
  return `${(bytes / TB).toFixed(2)} TB`;
}

/**
 * Formats a throughput rate in bytes per second into a human-readable string (e.g. "2.4 MB/s").
 */
export function formatRate(bps: number): string {
  return `${formatBytes(bps)}/s`;
}

/**
 * Formats a latency measurement in milliseconds, or "--" when unavailable.
 */
export function formatLatency(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms) || ms < 0) {
    return "--";
  }
  if (ms > 0 && ms < 1) {
    return "<1 ms";
  }
  const rounded = Math.round(ms);
  if (rounded < 1000) {
    return `${rounded} ms`;
  }
  return `${(ms / 1000).toFixed(2)} s`;
}

/**
 * Formats an epoch timestamp (in milliseconds) as 24-hour local clock time "HH:MM:SS".
 */
export function formatClockTime(tsMs: number): string {
  if (!Number.isFinite(tsMs)) {
    return "--:--:--";
  }
  const date = new Date(tsMs);
  if (Number.isNaN(date.getTime())) {
    return "--:--:--";
  }
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

/**
 * Formats a non-negative counter into compact notation (e.g. "999", "1.2K", "3.4M", "2B").
 */
export function formatCount(n: number): string {
  if (!Number.isFinite(n) || n <= 0) {
    return "0";
  }
  const safe = Math.round(n);
  if (safe < 1_000) {
    return String(safe);
  }
  if (safe < 999_950) {
    return `${trimTrailingZero((safe / 1_000).toFixed(1))}K`;
  }
  if (safe < 999_950_000) {
    return `${trimTrailingZero((safe / 1_000_000).toFixed(1))}M`;
  }
  return `${trimTrailingZero((safe / 1_000_000_000).toFixed(1))}B`;
}

/**
 * Folds Turkish letters (İ/I/ı/ğ/ş/ü/ö/ç) and Latin diacritics to lowercase ASCII
 * for accent- and case-insensitive instant search.
 */
export function foldTurkish(input: string): string {
  if (input.length === 0) {
    return "";
  }
  return input
    .replace(TURKISH_FOLD_RE, (ch) => TURKISH_FOLD_MAP[ch] ?? ch)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();
}

/**
 * Masks sensitive userinfo, paths, query strings, and fragments in DoH/DNS URLs
 * for safe UI previews (e.g. "https://dns.nextdns.io/abc123" -> "https://dns.nextdns.io/[hidden]").
 * Handles scheme-with-slashes, scheme-without-slashes, and scheme-less URLs.
 * Plain valid IP addresses and hostnames are returned trimmed.
 */
export function redactDnsPreview(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return "";
  }

  const schemeSepIdx = trimmed.indexOf("://");
  if (schemeSepIdx >= 0) {
    const scheme = toAsciiLower(trimmed.slice(0, schemeSepIdx));
    const validScheme = SCHEME_RE.test(scheme);
    const fallback = validScheme ? `${scheme}://[hidden]` : "[hidden]";
    if (!validScheme) {
      return fallback;
    }
    const rest = trimmed.slice(schemeSepIdx + 3);
    return redactAuthorityAndSuffix(rest, `${scheme}://`, fallback);
  }

  // Plain bare or bracketed IPv6 address with no path/query/fragment/userinfo.
  if (
    parseIpv6Segments(trimmed) !== null ||
    (trimmed.startsWith("[") &&
      trimmed.endsWith("]") &&
      parseIpv6Segments(trimmed.slice(1, -1)) !== null)
  ) {
    return trimmed;
  }

  // Scheme-without-slashes (e.g. "https:dns.nextdns.io/a1b2c3" or "https:mysecrettoken"):
  // fail closed so opaque tokens after "scheme:" can never leak as hostnames.
  const schemeNoSlash = KNOWN_SCHEME_NO_SLASH_RE.exec(trimmed);
  if (schemeNoSlash) {
    const scheme = toAsciiLower(schemeNoSlash[1]);
    return `${scheme}://[hidden]`;
  }

  // Protocol-relative URLs (e.g. "//dns.nextdns.io/a1b2c3").
  if (trimmed.startsWith("//")) {
    return redactAuthorityAndSuffix(trimmed.slice(2), "//", "[hidden]", false);
  }

  // Scheme-less URLs containing paths, queries, fragments, credentials, or malformed delimiters.
  // Require a multi-label hostname or valid IP (allowSingleLabel = false) so bare tokens like
  // "mysecrettoken/dns-query" fail closed without leaking the token.
  if (
    /[/?#@\\]/.test(trimmed) ||
    /\s/.test(trimmed) ||
    CONTROL_CHAR_RE.test(trimmed)
  ) {
    return redactAuthorityAndSuffix(trimmed, "", "[hidden]", false);
  }

  const plainHostPort = parseValidDohAuthority(trimmed);
  if (plainHostPort !== null) {
    return plainHostPort;
  }
  return "[hidden]";
}

/**
 * Defense-in-depth URL redactor for free-form frontend text (error banners, toasts,
 * ErrorBoundary fallbacks). Scrubs embedded http/https URLs (both with and without
 * slashes) using `redactDnsPreview` while preserving surrounding prose and bare
 * scheme mentions (such as "Use https:// instead").
 */
export function scrubUrlsInText(text: string): string {
  if (text.length === 0) {
    return "";
  }

  let out = "";
  let cursor = 0;

  while (cursor < text.length) {
    let matchIdx = -1;
    let prefixLen = 0;
    let hasSlashes = false;
    for (let i = cursor; i < text.length; i += 1) {
      const ch = text[i];
      if (ch !== "h" && ch !== "H") {
        continue;
      }
      const slice = toAsciiLower(text.slice(i, i + 8));
      if (slice.startsWith("https://")) {
        matchIdx = i;
        prefixLen = 8;
        hasSlashes = true;
        break;
      }
      if (slice.startsWith("http://")) {
        matchIdx = i;
        prefixLen = 7;
        hasSlashes = true;
        break;
      }
      const schemeColonLen = slice.startsWith("https:")
        ? 6
        : slice.startsWith("http:")
          ? 5
          : 0;
      if (schemeColonLen > 0) {
        if (i > 0 && /[a-zA-Z0-9]/.test(text[i - 1])) {
          continue;
        }
        matchIdx = i;
        prefixLen = schemeColonLen;
        hasSlashes = false;
        break;
      }
    }

    if (matchIdx < 0) {
      out += text.slice(cursor);
      break;
    }

    out += text.slice(cursor, matchIdx);

    let endIdx = matchIdx;
    while (endIdx < text.length && !URL_STOP_CHAR_RE.test(text[endIdx])) {
      endIdx += 1;
    }

    let tokenEnd = endIdx;
    const minTokenEnd = matchIdx + prefixLen;
    while (tokenEnd > minTokenEnd) {
      const last = text[tokenEnd - 1];
      let shouldStrip = false;
      if (
        last === "." ||
        last === ":" ||
        last === "," ||
        last === ";" ||
        last === "'"
      ) {
        shouldStrip = true;
      } else if (last === ")" || last === "]") {
        const openChar = last === ")" ? "(" : "[";
        let openCount = 0;
        let closeCount = 0;
        for (let k = matchIdx; k < tokenEnd; k += 1) {
          if (text[k] === openChar) {
            openCount += 1;
          } else if (text[k] === last) {
            closeCount += 1;
          }
        }
        shouldStrip = closeCount > openCount;
      }
      if (shouldStrip) {
        tokenEnd -= 1;
      } else {
        break;
      }
    }

    const token = text.slice(matchIdx, tokenEnd);
    if (
      (!hasSlashes && tokenEnd <= minTokenEnd) ||
      token.length === 0 ||
      /^https?:?(?:\/\/)?$/i.test(token)
    ) {
      out += text.slice(matchIdx, tokenEnd);
      cursor = tokenEnd;
      continue;
    }

    out += redactDnsPreview(token);
    cursor = tokenEnd;
  }

  return out;
}

/**
 * Returns true only for known public DNS IPv4/IPv6 addresses whose TLS certificates
 * include an IP Subject Alternative Name (IP-SAN) and serve RFC 8484 DoH at
 * `https://<ip>/dns-query` (mirroring Rust `is_known_public_doh_ip`, including
 * Cloudflare and Google DNS64 IPv6 addresses).
 */
export function isKnownPublicDohIp(ip: string): boolean {
  const trimmed = ip.trim();
  if (trimmed.length === 0 || CONTROL_CHAR_RE.test(trimmed)) {
    return false;
  }
  if (trimmed.startsWith("[") || trimmed.endsWith("]")) {
    if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) {
      return false;
    }
    const v6 = parseIpv6Segments(trimmed.slice(1, -1));
    return v6 !== null && isKnownPublicDohIpv6Segments(v6);
  }
  const v4 = parseIpv4Octets(trimmed);
  if (v4 !== null) {
    return isKnownPublicDohIpv4Octets(v4);
  }
  const v6 = parseIpv6Segments(trimmed);
  if (v6 !== null) {
    return isKnownPublicDohIpv6Segments(v6);
  }
  return false;
}

/**
 * Client-side custom DNS validator mirroring Rust `vdpi_core::dns::validate_custom_dns_input`.
 * Accepts valid IPv4, bare or bracketed IPv6, and `https://` DoH URLs while rejecting
 * unspecified (`0.0.0.0`, `::`), broadcast (`255.255.255.255`), multicast (`224.0.0.0/4`,
 * `ff00::/8`), IPv4-mapped invalid ranges, leading-zero IPv4, userinfo, fragments,
 * and invalid percent-encoding (`%ZZ`).
 */
export function validateCustomDnsClient(raw: string): CustomDnsValidation {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return {
      valid: false,
      kind: "empty",
      normalized: "",
      error:
        "Enter an IPv4 address, IPv6 address, or https://.../dns-query URL.",
    };
  }

  if (CONTROL_CHAR_RE.test(trimmed)) {
    return {
      valid: false,
      kind: "invalid",
      normalized: trimmed,
      error: "DNS server cannot contain control characters or newlines.",
    };
  }

  if (/\s/.test(trimmed)) {
    return {
      valid: false,
      kind: "invalid",
      normalized: trimmed,
      error: "DNS server cannot contain spaces.",
    };
  }

  const schemeSepIdx = trimmed.indexOf("://");
  if (schemeSepIdx >= 0) {
    const scheme = toAsciiLower(trimmed.slice(0, schemeSepIdx));
    if (scheme === "http") {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error:
          "Plain http:// is not supported for DoH. Use https:// instead.",
      };
    }
    if (scheme !== "https") {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "Only https:// URLs are supported for DNS-over-HTTPS.",
      };
    }

    const rest = trimmed.slice(schemeSepIdx + 3);
    if (rest.length === 0) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error:
          "Enter a hostname or IP after https:// (e.g. https://dns.nextdns.io/profile).",
      };
    }
    if (rest.includes("#")) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "DoH URL cannot contain a '#' fragment.",
      };
    }
    if (rest.includes("\\")) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "DoH URL cannot contain backslashes.",
      };
    }

    const suffixIdx = rest.search(/[/?]/);
    const authority = suffixIdx >= 0 ? rest.slice(0, suffixIdx) : rest;
    const rawSuffix = suffixIdx >= 0 ? rest.slice(suffixIdx) : "";

    if (authority.length === 0) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "DoH URL is missing a hostname or IP before the path.",
      };
    }
    if (authority.includes("@")) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "DoH URL cannot contain username or password credentials (@).",
      };
    }

    let hostForUrl: string;
    let explicitPort: number | null = null;

    if (authority.startsWith("[")) {
      const closeIdx = authority.indexOf("]");
      if (closeIdx < 0) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: "Unclosed IPv6 bracket in DoH URL.",
        };
      }
      const ipv6Inner = authority.slice(1, closeIdx);
      const v6 = parseIpv6Segments(ipv6Inner);
      if (!v6) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: "Invalid IPv6 host inside DoH URL.",
        };
      }
      const v6Err = validateDnsIpv6Segments(v6);
      if (v6Err) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: v6Err,
        };
      }
      const tail = authority.slice(closeIdx + 1);
      if (tail.length > 0) {
        if (!tail.startsWith(":") || !isValidPort(tail.slice(1))) {
          return {
            valid: false,
            kind: "invalid",
            normalized: trimmed,
            error: "Invalid port number in DoH URL (must be 1-65535).",
          };
        }
        explicitPort = Number(tail.slice(1));
      }
      hostForUrl = `[${formatIpv6Canonical(v6)}]`;
    } else {
      if (authority.includes("[") || authority.includes("]")) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: "Malformed brackets in DoH URL authority.",
        };
      }
      const colonIdx = authority.indexOf(":");
      if (colonIdx !== authority.lastIndexOf(":")) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error:
            "Wrap IPv6 addresses in brackets inside DoH URLs (e.g. https://[2606:4700:4700::1111]/dns-query).",
        };
      }
      const hostRaw = colonIdx >= 0 ? authority.slice(0, colonIdx) : authority;
      if (colonIdx >= 0) {
        const portStr = authority.slice(colonIdx + 1);
        if (!isValidPort(portStr)) {
          return {
            valid: false,
            kind: "invalid",
            normalized: trimmed,
            error: "Invalid port number in DoH URL (must be 1-65535).",
          };
        }
        explicitPort = Number(portStr);
      }
      if (hostRaw.length === 0) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: "DoH URL is missing a hostname or IP.",
        };
      }
      const v4 = parseIpv4Octets(hostRaw);
      if (v4) {
        const v4Err = validateDnsIpv4Octets(v4);
        if (v4Err) {
          return {
            valid: false,
            kind: "invalid",
            normalized: trimmed,
            error: v4Err,
          };
        }
        hostForUrl = v4.join(".");
      } else if (isValidDohHostname(hostRaw)) {
        const strippedDot = hostRaw.endsWith(".")
          ? hostRaw.slice(0, -1)
          : hostRaw;
        hostForUrl = toAsciiLower(strippedDot);
      } else {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error:
            "Enter a valid hostname or IP address in the https:// DoH URL.",
        };
      }
    }

    if (rawSuffix.length > 0) {
      const pathErr = validateDohPathAndQuery(rawSuffix);
      if (pathErr) {
        return {
          valid: false,
          kind: "invalid",
          normalized: trimmed,
          error: pathErr,
        };
      }
    }

    const authorityNorm =
      explicitPort !== null ? `${hostForUrl}:${explicitPort}` : hostForUrl;
    let normalizedSuffix = rawSuffix;
    if (rawSuffix.startsWith("?")) {
      normalizedSuffix = `/dns-query${rawSuffix}`;
    } else if (rawSuffix.startsWith("/?")) {
      normalizedSuffix = `/dns-query?${rawSuffix.slice(2)}`;
    }

    return {
      valid: true,
      kind: "doh_url",
      normalized: `https://${authorityNorm}${normalizedSuffix}`,
      error: null,
    };
  }

  // Bracketed bare IPv6 (e.g. "[2606:4700:4700::1111]")
  if (trimmed.startsWith("[") || trimmed.endsWith("]")) {
    if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "Unmatched IPv6 brackets.",
      };
    }
    const inner = trimmed.slice(1, -1);
    const v6 = parseIpv6Segments(inner);
    if (!v6) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: "Enter a valid IPv6 address inside brackets.",
      };
    }
    const v6Err = validateDnsIpv6Segments(v6);
    if (v6Err) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: v6Err,
      };
    }
    return {
      valid: true,
      kind: isKnownPublicDohIpv6Segments(v6) ? "known_doh_ip" : "bare_udp_ip",
      normalized: formatIpv6Canonical(v6),
      ipVersion: 6,
      error: null,
    };
  }

  const v4 = parseIpv4Octets(trimmed);
  if (v4) {
    const v4Err = validateDnsIpv4Octets(v4);
    if (v4Err) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: v4Err,
      };
    }
    return {
      valid: true,
      kind: isKnownPublicDohIpv4Octets(v4) ? "known_doh_ip" : "bare_udp_ip",
      normalized: v4.join("."),
      ipVersion: 4,
      error: null,
    };
  }

  const v6 = parseIpv6Segments(trimmed);
  if (v6) {
    const v6Err = validateDnsIpv6Segments(v6);
    if (v6Err) {
      return {
        valid: false,
        kind: "invalid",
        normalized: trimmed,
        error: v6Err,
      };
    }
    return {
      valid: true,
      kind: isKnownPublicDohIpv6Segments(v6) ? "known_doh_ip" : "bare_udp_ip",
      normalized: formatIpv6Canonical(v6),
      ipVersion: 6,
      error: null,
    };
  }

  const hostCandidate = trimmed.split(/[/?]/)[0];
  if (hostCandidate && isValidDohHostname(hostCandidate)) {
    return {
      valid: false,
      kind: "invalid",
      normalized: trimmed,
      error:
        "For a DoH hostname, include the https:// prefix (e.g. https://dns.nextdns.io/profile-id).",
    };
  }

  return {
    valid: false,
    kind: "invalid",
    normalized: trimmed,
    error:
      "Enter a valid IPv4 address (e.g. 1.1.1.1), IPv6 address, or https://.../dns-query URL.",
  };
}

/**
 * Extracts a clean executable filename from a raw user input, full path,
 * or Windows/macOS/Linux shortcut command line with quotes and CLI arguments.
 * Resolves Windows Squirrel shortcuts (`Update.exe --processStart <exe>`) and
 * rejects `.lnk` shortcut files.
 */
export function extractExecutableName(raw: string): string {
  return extractExecutableNameInternal(raw, 0);
}

/**
 * Validates a domain or wildcard domain rule (e.g. "example.com" or "*.example.com").
 * Rejects bare public TLD wildcards (e.g. "*.com", "*.tr") while allowing standard
 * domains, subdomains, multi-label wildcards, reserved local wildcards, and "localhost".
 * Returns null when valid, or a short user-facing error message when invalid.
 */
export function validateDomainRule(raw: string): string | null {
  if (CONTROL_CHAR_RE.test(raw)) {
    return "Domain rule cannot contain control characters or newlines.";
  }

  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    return "Domain rule cannot be empty.";
  }

  if (/\s/.test(trimmed)) {
    return "Domain rule cannot contain spaces.";
  }

  if (trimmed.includes("://")) {
    return "Enter a domain name without a URL scheme (e.g. example.com or *.example.com).";
  }

  if (/[/?#]/.test(trimmed)) {
    return "Enter a domain name without paths or query strings.";
  }

  if (trimmed.includes(":")) {
    return "Enter a domain name without a port number.";
  }

  const isWildcard = trimmed.startsWith("*.");
  const host = isWildcard ? trimmed.slice(2) : trimmed;

  if (isWildcard && host.length === 0) {
    return "Enter a domain name after '*.'.";
  }

  if (host.includes("*")) {
    return "Wildcards are only supported as a leading '*.' prefix (e.g. *.example.com).";
  }

  if (host.startsWith(".") || host.endsWith(".")) {
    return "Domain name cannot start or end with a dot.";
  }

  if (host.includes("..")) {
    return "Domain name cannot contain consecutive dots.";
  }

  if (host.length > MAX_DOMAIN_LENGTH) {
    return `Domain name is too long (maximum ${MAX_DOMAIN_LENGTH} characters).`;
  }

  const labels = host.split(".");
  const lowerHost = toAsciiLower(host);
  if (isWildcard && labels.length < 2) {
    if (!LOCAL_WILDCARD_TLDS.has(lowerHost)) {
      return "Wildcard rules cannot target a bare top-level domain (e.g. use *.example.com).";
    }
  } else if (!isWildcard && labels.length < 2 && lowerHost !== "localhost") {
    return "Enter a full domain name (e.g. example.com or *.example.com).";
  }

  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LENGTH) {
      return `Each domain label must be between 1 and ${MAX_LABEL_LENGTH} characters.`;
    }
    if (!DNS_LABEL_RE.test(label)) {
      return "Domain labels may only use letters, digits, and interior hyphens.";
    }
  }

  const tld = labels[labels.length - 1];
  if (tld.length < 2 || !/[a-z]/i.test(tld)) {
    return "Domain must end with a valid top-level domain (not an IP address).";
  }

  return null;
}
