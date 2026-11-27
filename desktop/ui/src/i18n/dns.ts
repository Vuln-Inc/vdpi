import { createTranslator, type ResolvedLanguage } from "./context";

const en = {
  title: "DNS & Rules",
    loading: "Loading DNS & rule settings...",
    subtitle:
      "Configure upstream DNS resolution, protocol guards, VPN coexistence, and per-domain routing overrides.",
    liveActive: "Active",
    liveConfigured: "Configured",
    errorBannerTitle: "Could not save DNS & rule settings",
    notInstalledBannerTitle: "Service not installed yet",
    notInstalledBannerDesc:
      "DNS and domain rules save to config.toml now and take effect once vdpi is installed.",
    notInstalledBannerAction: "Open Installation",
    vpnConflictTitle: "Full-tunnel VPN detected",
    vpnConflictDesc:
      "Active VPN interface ({iface}) detected. Adjust VPN Coexistence below to choose whether vdpi auto-yields or warns.",
    saveCancelled: "DNS & rule changes were cancelled.",
    saveFailed: "Failed to save DNS and rule settings.",
    saveSuccessRestart:
      "DNS & rule settings saved (restart service to apply).",
    saveSuccess: "DNS & rule settings saved and applied.",
    dirtyDnsResolver: "DNS resolver",
    dirtyEncryptedDns: "Encrypted DNS",
    dirtyQuicBlocking: "QUIC blocking",
    dirtyIpStack: "IP stack",
    dirtyVpnCoexistence: "VPN coexistence",
    dirtyBypassDomains: "Bypass domains",
    dirtyIncludeDomains: "Include domains",
    resolverHeading: "DNS Resolver",
    resolverDesc:
      "Choose a trusted public resolver or enter a custom IP / encrypted DNS-over-HTTPS endpoint.",
    presetCloudflareBadge: "Fast",
    presetCloudflareSummary:
      "Low-latency public DNS with IP-SAN DoH support.",
    presetQuad9Badge: "Security",
    presetQuad9Summary:
      "Security-focused DNS with malicious domain blocking.",
    presetGoogleBadge: "Global",
    presetGoogleSummary: "Global anycast public resolver with IP-SAN DoH.",
    presetAdguardBadge: "Ad-block",
    presetAdguardSummary: "Blocks ads, trackers, and phishing domains.",
    presetAdguardUnfilteredBadge: "Unfiltered",
    presetAdguardUnfilteredSummary:
      "AdGuard infrastructure without content filtering.",
    customDnsName: "Custom DNS",
    customDnsBadge: "IP / DoH",
    customDnsSummary: "NextDNS, ControlD, local LAN resolver, or custom IP.",
    customInputLabel: "Custom IP Address or DoH Endpoint URL",
    ariaRedactedPreview: "Redacted DNS preview",
    previewLabel: "Preview",
    customInputPlaceholder:
      "e.g. 10.0.0.53, 2606:4700:4700::1111, or https://dns.nextdns.io/abc123",
    ariaHideDns: "Hide DNS address",
    ariaRevealDns: "Reveal DNS address",
    hide: "Hide",
    reveal: "Reveal",
    hintValidDohPrefix: "Valid ",
    hintValidDohSuffix:
      " DoH endpoint. Profile tokens in the path/query stay masked by default.",
    hintKnownDohIp:
      "Valid IPv{version} address with known IP-SAN DoH support.",
    hintBareIpDohOn:
      "Valid bare IPv{version} address. Custom bare IPs do not serve IP-SAN DoH certificates and will be queried over UDP first.",
    hintBareIpDohOff:
      "Valid IPv{version} address. Queries will be sent over plain UDP.",
    hintDefaultPrefix: "Accepts IPv4, IPv6, or ",
    hintDefaultSuffix:
      ". URLs containing paths or credentials are masked automatically to protect NextDNS / ControlD profile tokens.",
    protocolHeading: "Protocol & Coexistence",
    protocolDesc:
      "Control DNS encryption, QUIC handling, IP stack routing, and behavior alongside third-party VPNs.",
    dohLabel: "Encrypted DNS (DoH)",
    badgeLockedOn: "Locked ON",
    badgeUdpFirst: "UDP-first",
    badgePlainUdp: "Plain UDP",
    dohDescCustomUrlPrefix: "Automatically locked ON because a custom ",
    dohDescCustomUrlSuffix:
      " DoH URL is configured. Switch to a bare IP resolver if you want plain UDP DNS.",
    dohDescBareIpOnPart1: "Bare custom IPs (such as ",
    dohDescBareIpOnPart2: " or ",
    dohDescBareIpOnPart3:
      ") do not serve IP-SAN DoH certificates, so vdpi queries them over UDP first even while this toggle is ON. Enter an ",
    dohDescBareIpOnPart4:
      " URL above for encrypted DoH with a custom provider.",
    dohDescBareIpOffPrefix:
      "Encrypted DNS is OFF. Queries to this custom IP are sent over plain UDP. Enter an ",
    dohDescBareIpOffSuffix: " URL above if your provider supports DoH.",
    dohDescDefault:
      "Encrypt DNS lookups over HTTPS (RFC 8484) to prevent ISP DNS hijacking and poisoning.",
    udpFirstBannerTitle: "UDP-first resolution active for bare custom IP",
    udpFirstBannerDesc:
      "Because {addr} is not a known IP-SAN DoH server, vdpi will send DNS queries over UDP instead of synthesizing https://{host}/dns-query.",
    quicLabel: "Block QUIC (UDP/443)",
    quicDesc:
      "Forces browsers to fall back from HTTP/3 (QUIC) to desynced TCP TLS for reliable DPI bypass while preserving Discord and WebRTC voice/video UDP traffic.",
    ipv6Label: "IPv6 Support (TUN)",
    badgeTunOnly: "TUN mode only",
    ipv6DescProxy:
      "Unavailable in Proxy mode. Switch to the TUN engine to route IPv6 traffic through the virtual TUN adapter.",
    ipv6DescTun:
      "Route IPv6 traffic through the virtual TUN adapter on dual-stack networks. When IPv4 Only is also enabled, AAAA DNS lookups are suppressed while IPv6 TUN routes remain active for literal IPv6 addresses.",
    ipv4Label: "IPv4 Only",
    ipv4Desc:
      "Suppress AAAA DNS lookups so hostnames resolve to IPv4 (A) records only when IPv6 paths are broken or throttled by your ISP. If IPv6 Support (TUN) is enabled, IPv6 TUN routes remain active for literal IPv6 addresses.",
    warnIpv4AndIpv6Title: "IPv4 Only paired with IPv6 Support (TUN)",
    warnIpv4AndIpv6Desc:
      "Both IPv6 Support (TUN) and IPv4 Only are enabled. IPv4 Only suppresses AAAA DNS lookups so hostnames resolve to IPv4 (A) records only, while IPv6 TUN routes remain active for literal IPv6 addresses.",
    warnIpv4AndIpv6DnsTitle: "IPv6 custom DNS paired with IPv4 Only",
    warnIpv4AndIpv6DnsDesc:
      "Your custom DNS server uses an IPv6 address while IPv4 Only is enabled. Disable IPv4 Only or switch to an IPv4 / hostname resolver so DNS lookups stay reachable.",
    vpnLabel: "VPN Coexistence",
    vpnOptAutoYield: "Auto-yield",
    vpnOptWarn: "Warn",
    vpnOptOff: "Off",
    vpnDescAutoYield:
      "Automatically pauses vdpi when a full-tunnel VPN is detected and resumes once the VPN disconnects.",
    vpnDescWarn:
      "Keeps vdpi running alongside full-tunnel VPNs and shows a conflict warning banner.",
    vpnDescOff:
      "Disables VPN interface conflict checks. Use only if you manage routing tables manually.",
    domainsHeading: "Domain Rules",
    domainsDesc:
      "Configure hostnames that bypass vdpi directly or restrict desyncing to an explicit allowlist. User Bypass rules always take precedence over Include rules.",
    overlapTitle: "Overlapping domain rules",
    overlapMore: "{list} (+{extra} more)",
    overlapDesc:
      "{items}. User Bypass rules take precedence over Include rules for overlapping hostnames and subdomains.",
    bypassLabel: "Bypass Domains",
    bypassDesc:
      "Always connect directly without vdpi desyncing. User Bypass rules take precedence over Include rules.",
    bypassPlaceholder: "e.g. bank.com.tr or *.local.corp",
    bypassEmpty: "No custom bypass domains configured.",
    includeLabel: "Include Domains",
    includeDesc:
      "Allowlist filter: adding entries restricts vdpi to only matching domains (overriding built-in default bypasses such as .gov.tr) while all other traffic connects directly. User Bypass rules still take precedence over Include rules.",
    includePlaceholder: "e.g. service.gov.tr or *.example.org",
    includeEmpty: "No allowlist include domains configured.",
    ariaUnsavedRegion: "Unsaved DNS and rule changes",
    unsavedTitle: "Unsaved Changes",
    fixCustomDnsBadge: "Fix custom DNS address before saving",
    discard: "Discard",
    saving: "Saving...",
    saveApply: "Save & Apply",
    saveConfig: "Save to Config",
    editorDefaultPlaceholder: "example.com, *.example.com",
    editorDefaultEmpty: "No domains configured.",
    editorMaxReached:
      "Maximum of {max} domain entries reached. Remove an entry before adding more.",
    editorLimitedRemaining:
      "Domain list is limited to {max} entries ({remaining} remaining).",
    editorEntryPrefix: "Entry #{index}: {error}",
    editorCountTitle: "{count} of {max} maximum entries",
    editorClearTitle: "Clear all {label}",
    editorClear: "Clear",
    editorAdd: "Add",
    editorDraftHint: "Press Enter or click Add to include this entry",
    editorListAria: "{label} list",
    editorRemoveAria: "Remove {domain}",
};

export type DnsStringKey = keyof typeof en;

const tr: Record<DnsStringKey, string> = {
    title: "DNS ve Kurallar",
    loading: "DNS ve kural ayarları yükleniyor...",
    subtitle:
      "Üst DNS çözümlemeyi, protokol korumalarını, VPN uyumluluğunu ve alan adı yönlendirme kurallarını yapılandırın.",
    liveActive: "Etkin",
    liveConfigured: "Yapılandırıldı",
    errorBannerTitle: "DNS ve kural ayarları kaydedilemedi",
    notInstalledBannerTitle: "Servis henüz kurulmadı",
    notInstalledBannerDesc:
      "DNS ve alan adı kurallarınız şimdi config.toml dosyasına kaydedilir ve vdpi kurulduğunda etkinleşir.",
    notInstalledBannerAction: "Kuruluma Git",
    vpnConflictTitle: "Tam tünelli VPN algılandı",
    vpnConflictDesc:
      "Etkin VPN arayüzü ({iface}) algılandı. vdpi'nin otomatik duraklatılmasını veya uyarmasını seçmek için aşağıdaki VPN Uyumluluğu ayarını değiştirin.",
    saveCancelled: "DNS ve kural değişiklikleri iptal edildi.",
    saveFailed: "DNS ve kural ayarları kaydedilemedi.",
    saveSuccessRestart:
      "DNS ve kural ayarları kaydedildi (uygulamak için servisi yeniden başlatın).",
    saveSuccess: "DNS ve kural ayarları kaydedildi ve uygulandı.",
    dirtyDnsResolver: "DNS sunucusu",
    dirtyEncryptedDns: "Şifreli DNS",
    dirtyQuicBlocking: "QUIC engelleme",
    dirtyIpStack: "IP yığını",
    dirtyVpnCoexistence: "VPN uyumluluğu",
    dirtyBypassDomains: "Hariç alan adları",
    dirtyIncludeDomains: "Dahil alan adları",
    resolverHeading: "DNS Sunucusu",
    resolverDesc:
      "Güvenilir bir genel DNS sunucusu seçin veya özel bir IP / şifreli DNS-over-HTTPS adresi girin.",
    presetCloudflareBadge: "Hızlı",
    presetCloudflareSummary:
      "IP-SAN DoH destekli düşük gecikmeli genel DNS.",
    presetQuad9Badge: "Güvenlik",
    presetQuad9Summary:
      "Zararlı alan adlarını engelleyen güvenlik odaklı DNS.",
    presetGoogleBadge: "Küresel",
    presetGoogleSummary: "IP-SAN DoH destekli küresel anycast DNS sunucusu.",
    presetAdguardBadge: "Reklamsız",
    presetAdguardSummary:
      "Reklam, izleyici ve oltalama alan adlarını engeller.",
    presetAdguardUnfilteredBadge: "Filtresiz",
    presetAdguardUnfilteredSummary:
      "İçerik filtrelemesi olmadan AdGuard altyapısı.",
    customDnsName: "Özel DNS",
    customDnsBadge: "IP / DoH",
    customDnsSummary: "NextDNS, ControlD, yerel LAN sunucusu veya özel IP.",
    customInputLabel: "Özel IP Adresi veya DoH Uç Nokta URL'si",
    ariaRedactedPreview: "Maskelenmiş DNS önizlemesi",
    previewLabel: "Önizleme",
    customInputPlaceholder:
      "örn. 10.0.0.53, 2606:4700:4700::1111 veya https://dns.nextdns.io/abc123",
    ariaHideDns: "DNS adresini gizle",
    ariaRevealDns: "DNS adresini göster",
    hide: "Gizle",
    reveal: "Göster",
    hintValidDohPrefix: "Geçerli ",
    hintValidDohSuffix:
      " DoH uç noktası. Yol/sorgudaki profil belirteçleri varsayılan olarak gizli kalır.",
    hintKnownDohIp:
      "Bilinen IP-SAN DoH desteğine sahip geçerli IPv{version} adresi.",
    hintBareIpDohOn:
      "Geçerli yalın IPv{version} adresi. Özel yalın IP'ler IP-SAN DoH sertifikası sunmaz ve önce UDP üzerinden sorgulanır.",
    hintBareIpDohOff:
      "Geçerli IPv{version} adresi. Sorgular düz UDP üzerinden gönderilecek.",
    hintDefaultPrefix: "IPv4, IPv6 veya ",
    hintDefaultSuffix:
      " kabul eder. NextDNS / ControlD profil belirteçlerini korumak için yol veya kimlik bilgisi içeren URL'ler otomatik gizlenir.",
    protocolHeading: "Protokol ve Uyumluluk",
    protocolDesc:
      "DNS şifreleme, QUIC yönetimi, IP yığını yönlendirmesi ve üçüncü parti VPN'lerle çalışma davranışını yönetin.",
    dohLabel: "Şifreli DNS (DoH)",
    badgeLockedOn: "Zorunlu Açık",
    badgeUdpFirst: "Önce UDP",
    badgePlainUdp: "Düz UDP",
    dohDescCustomUrlPrefix: "Özel bir ",
    dohDescCustomUrlSuffix:
      " DoH URL'si yapılandırıldığı için otomatik kilitli. Düz UDP DNS için yalın IP sunucusuna geçin.",
    dohDescBareIpOnPart1: "Özel yalın IP'ler (örn. ",
    dohDescBareIpOnPart2: " veya ",
    dohDescBareIpOnPart3:
      ") IP-SAN DoH sertifikası sunmaz; bu nedenle anahtar açık olsa bile vdpi önce UDP üzerinden sorgular. Özel sağlayıcıyla şifreli DoH için yukarıya bir ",
    dohDescBareIpOnPart4: " URL'si girin.",
    dohDescBareIpOffPrefix:
      "Şifreli DNS kapalı. Bu özel IP'ye sorgular düz UDP ile gönderilir. Sağlayıcınız DoH destekliyorsa yukarıya bir ",
    dohDescBareIpOffSuffix: " URL'si girin.",
    dohDescDefault:
      "İSS DNS yönlendirmesini ve zehirlenmesini önlemek için DNS sorgularını HTTPS (RFC 8484) üzerinden şifreleyin.",
    udpFirstBannerTitle: "Yalın özel IP için önce UDP çözümleme etkin",
    udpFirstBannerDesc:
      "{addr} bilinen bir IP-SAN DoH sunucusu olmadığından vdpi, https://{host}/dns-query oluşturmak yerine DNS sorgularını UDP üzerinden gönderecek.",
    quicLabel: "QUIC Engelle (UDP/443)",
    quicDesc:
      "Discord ve WebRTC ses/görüntü UDP trafiğini korurken, güvenilir DPI aşımı için tarayıcıları HTTP/3 (QUIC) yerine bölünmüş TCP TLS'ye yönlendirir.",
    ipv6Label: "IPv6 Desteği (TUN)",
    badgeTunOnly: "Yalnızca TUN",
    ipv6DescProxy:
      "Proxy modunda kullanılamaz. IPv6 trafiğini sanal TUN bağdaştırıcısından yönlendirmek için TUN motoruna geçin.",
    ipv6DescTun:
      "Çift yığınlı ağlarda IPv6 trafiğini sanal TUN bağdaştırıcısından yönlendirin. Yalnızca IPv4 de etkinse AAAA DNS sorguları bastırılır; doğrudan IPv6 adresleri için TUN rotaları etkin kalır.",
    ipv4Label: "Yalnızca IPv4",
    ipv4Desc:
      "İSS'nizde IPv6 yolları bozuk veya yavaşlatılmışsa alan adlarının yalnızca IPv4 (A) kayıtlarına çözümlenmesi için AAAA DNS sorgularını bastırın. IPv6 Desteği (TUN) açıksa doğrudan IPv6 adresleri için TUN rotaları etkin kalır.",
    warnIpv4AndIpv6Title: "Yalnızca IPv4 ile IPv6 Desteği (TUN) birlikte açık",
    warnIpv4AndIpv6Desc:
      "Hem IPv6 Desteği (TUN) hem de Yalnızca IPv4 etkin. Yalnızca IPv4, alan adlarının sadece IPv4 (A) kayıtlarına çözümlenmesi için AAAA sorgularını bastırır; doğrudan IPv6 adresleri için TUN rotaları etkin kalır.",
    warnIpv4AndIpv6DnsTitle: "IPv6 özel DNS ile Yalnızca IPv4 birlikte açık",
    warnIpv4AndIpv6DnsDesc:
      "Yalnızca IPv4 etkinken özel DNS sunucunuz bir IPv6 adresi kullanıyor. DNS sorgularının ulaşılabilir kalması için Yalnızca IPv4'ü kapatın veya IPv4 / alan adı tabanlı bir sunucuya geçin.",
    vpnLabel: "VPN Uyumluluğu",
    vpnOptAutoYield: "Oto-duraklat",
    vpnOptWarn: "Uyar",
    vpnOptOff: "Kapalı",
    vpnDescAutoYield:
      "Tam tünelli bir VPN algılandığında vdpi'yi otomatik duraklatır, VPN kesildiğinde devam ettirir.",
    vpnDescWarn:
      "Tam tünelli VPN'lerle birlikte vdpi'yi çalışır tutar ve bir çakışma uyarısı gösterir.",
    vpnDescOff:
      "VPN arayüzü çakışma denetimlerini kapatır. Yalnızca yönlendirme tablolarını elle yönetiyorsanız kullanın.",
    domainsHeading: "Alan Adı Kuralları",
    domainsDesc:
      "vdpi'yi doğrudan atlayacak alan adlarını belirleyin veya işlemi yalnızca belirli bir izin listesiyle sınırlayın. Hariç Tut kuralları her zaman Dahil Et kurallarından önceliklidir.",
    overlapTitle: "Çakışan alan adı kuralları",
    overlapMore: "{list} (+{extra} daha)",
    overlapDesc:
      "{items}. Çakışan alan adları ve alt alan adlarında Hariç Tut kuralları Dahil Et kurallarından önceliklidir.",
    bypassLabel: "Hariç Tutulan Alan Adları",
    bypassDesc:
      "Her zaman vdpi uygulanmadan doğrudan bağlanılır. Hariç Tut kuralları Dahil Et kurallarından önceliklidir.",
    bypassPlaceholder: "örn. bank.com.tr veya *.local.corp",
    bypassEmpty: "Özel hariç tutma alan adı yapılandırılmadı.",
    includeLabel: "Dahil Edilen Alan Adları",
    includeDesc:
      "İzin listesi filtresi: kayıt eklemek vdpi'yi yalnızca eşleşen alan adlarıyla sınırlar (.gov.tr gibi yerleşik hariç tutmaları geçersiz kılar); diğer tüm trafik doğrudan bağlanır. Hariç Tut kuralları yine önceliklidir.",
    includePlaceholder: "örn. servis.gov.tr veya *.ornek.org",
    includeEmpty: "İzin listesi için alan adı yapılandırılmadı.",
    ariaUnsavedRegion: "Kaydedilmemiş DNS ve kural değişiklikleri",
    unsavedTitle: "Kaydedilmemiş Değişiklikler",
    fixCustomDnsBadge: "Kaydetmeden önce özel DNS adresini düzeltin",
    discard: "Vazgeç",
    saving: "Kaydediliyor...",
    saveApply: "Kaydet ve Uygula",
    saveConfig: "Yapılandırmaya Kaydet",
    editorDefaultPlaceholder: "ornek.com, *.ornek.com",
    editorDefaultEmpty: "Yapılandırılmış alan adı yok.",
    editorMaxReached:
      "En fazla {max} alan adı sınırına ulaşıldı. Yeni eklemeden önce bir kayıt kaldırın.",
    editorLimitedRemaining:
      "Alan adı listesi en fazla {max} kayıtla sınırlıdır ({remaining} kaldı).",
    editorEntryPrefix: "Kayıt #{index}: {error}",
    editorCountTitle: "En fazla {max} kayıttan {count} tanesi",
    editorClearTitle: "Tümünü temizle ({label})",
    editorClear: "Temizle",
    editorAdd: "Ekle",
    editorDraftHint: "Eklemek için Enter'a basın veya Ekle'ye tıklayın",
    editorListAria: "{label} listesi",
    editorRemoveAria: "{domain} kaydını kaldır",
};

export const DNS_STRINGS: {
  en: Record<DnsStringKey, string>;
  tr: Record<DnsStringKey, string>;
} = { en, tr };

export const tDns = createTranslator(DNS_STRINGS);

const CUSTOM_DNS_ERRORS_TR: Record<string, string> = {
  "DNS IP cannot be 0.0.0.0.": "DNS IP adresi 0.0.0.0 olamaz.",
  "DNS IP cannot be a multicast address.":
    "DNS IP adresi çoklu yayın (multicast) adresi olamaz.",
  "DNS IP cannot be a broadcast address.":
    "DNS IP adresi yayın (broadcast) adresi olamaz.",
  "DNS IP cannot be ::.": "DNS IP adresi :: olamaz.",
  "Invalid percent-encoding in DoH URL path.":
    "DoH URL yolunda geçersiz yüzde kodlaması var.",
  "Invalid character in DoH URL path or query.":
    "DoH URL yolunda veya sorgusunda geçersiz karakter var.",
  "Enter an IPv4 address, IPv6 address, or https://.../dns-query URL.":
    "Bir IPv4 adresi, IPv6 adresi veya https://.../dns-query URL'si girin.",
  "DNS server cannot contain control characters or newlines.":
    "DNS sunucusu kontrol karakterleri veya yeni satır içeremez.",
  "DNS server cannot contain spaces.": "DNS sunucusu boşluk içeremez.",
  "Plain http:// is not supported for DoH. Use https:// instead.":
    "DoH için düz http:// desteklenmez. Bunun yerine https:// kullanın.",
  "Only https:// URLs are supported for DNS-over-HTTPS.":
    "DNS-over-HTTPS için yalnızca https:// URL'leri desteklenir.",
  "Enter a hostname or IP after https:// (e.g. https://dns.nextdns.io/profile).":
    "https:// sonrasında bir alan adı veya IP girin (örn. https://dns.nextdns.io/profil).",
  "DoH URL cannot contain a '#' fragment.":
    "DoH URL'si '#' parçası içeremez.",
  "DoH URL cannot contain backslashes.":
    "DoH URL'si ters eğik çizgi içeremez.",
  "DoH URL is missing a hostname or IP before the path.":
    "DoH URL'sinde yoldan önce alan adı veya IP eksik.",
  "DoH URL cannot contain username or password credentials (@).":
    "DoH URL'si kullanıcı adı veya parola bilgisi (@) içeremez.",
  "Unclosed IPv6 bracket in DoH URL.":
    "DoH URL'sinde kapatılmamış IPv6 köşeli parantezi var.",
  "Invalid IPv6 host inside DoH URL.":
    "DoH URL'si içinde geçersiz IPv6 adresi var.",
  "Invalid port number in DoH URL (must be 1-65535).":
    "DoH URL'sinde geçersiz port numarası (1-65535 arası olmalı).",
  "Malformed brackets in DoH URL authority.":
    "DoH URL adres kısmında hatalı köşeli parantezler var.",
  "Wrap IPv6 addresses in brackets inside DoH URLs (e.g. https://[2606:4700:4700::1111]/dns-query).":
    "DoH URL'lerinde IPv6 adreslerini köşeli parantez içine alın (örn. https://[2606:4700:4700::1111]/dns-query).",
  "DoH URL is missing a hostname or IP.":
    "DoH URL'sinde alan adı veya IP eksik.",
  "Enter a valid hostname or IP address in the https:// DoH URL.":
    "https:// DoH URL'sinde geçerli bir alan adı veya IP adresi girin.",
  "Unmatched IPv6 brackets.": "Eşleşmeyen IPv6 köşeli parantezleri.",
  "Enter a valid IPv6 address inside brackets.":
    "Köşeli parantez içine geçerli bir IPv6 adresi girin.",
  "For a DoH hostname, include the https:// prefix (e.g. https://dns.nextdns.io/profile-id).":
    "DoH alan adı için https:// önekini ekleyin (örn. https://dns.nextdns.io/profil-id).",
  "Enter a valid IPv4 address (e.g. 1.1.1.1), IPv6 address, or https://.../dns-query URL.":
    "Geçerli bir IPv4 adresi (örn. 1.1.1.1), IPv6 adresi veya https://.../dns-query URL'si girin.",
};

const DOMAIN_RULE_ERRORS_TR: Record<string, string> = {
  "Domain rule cannot contain control characters or newlines.":
    "Alan adı kuralı kontrol karakterleri veya yeni satır içeremez.",
  "Domain rule cannot be empty.": "Alan adı kuralı boş olamaz.",
  "Domain rule cannot contain spaces.": "Alan adı kuralı boşluk içeremez.",
  "Enter a domain name without a URL scheme (e.g. example.com or *.example.com).":
    "URL şeması olmadan bir alan adı girin (örn. ornek.com veya *.ornek.com).",
  "Enter a domain name without paths or query strings.":
    "Yol veya sorgu dizgisi olmadan bir alan adı girin.",
  "Enter a domain name without a port number.":
    "Port numarası olmadan bir alan adı girin.",
  "Enter a domain name after '*.'.": "'*.' sonrasına bir alan adı girin.",
  "Wildcards are only supported as a leading '*.' prefix (e.g. *.example.com).":
    "Joker karakterler yalnızca baştaki '*.' öneki olarak desteklenir (örn. *.ornek.com).",
  "Domain name cannot start or end with a dot.":
    "Alan adı nokta ile başlayamaz veya bitemez.",
  "Domain name cannot contain consecutive dots.":
    "Alan adı art arda nokta içeremez.",
  "Domain name is too long (maximum 253 characters).":
    "Alan adı çok uzun (en fazla 253 karakter).",
  "Wildcard rules cannot target a bare top-level domain (e.g. use *.example.com).":
    "Joker kurallar tek başına üst düzey alan adını hedefleyemez (örn. *.ornek.com kullanın).",
  "Enter a full domain name (e.g. example.com or *.example.com).":
    "Tam bir alan adı girin (örn. ornek.com veya *.ornek.com).",
  "Each domain label must be between 1 and 63 characters.":
    "Her alan adı etiketi 1 ile 63 karakter arasında olmalıdır.",
  "Domain labels may only use letters, digits, and interior hyphens.":
    "Alan adı etiketleri yalnızca harf, rakam ve iç tire içerebilir.",
  "Domain must end with a valid top-level domain (not an IP address).":
    "Alan adı geçerli bir üst düzey alan adıyla bitmelidir (IP adresi olmamalı).",
};

export function translateCustomDnsError(
  lang: ResolvedLanguage,
  error: string | null,
): string | null {
  if (!error || lang === "en") return error;
  return CUSTOM_DNS_ERRORS_TR[error] ?? error;
}

export function translateDomainRuleError(
  lang: ResolvedLanguage,
  error: string | null,
): string | null {
  if (!error || lang === "en") return error;
  return DOMAIN_RULE_ERRORS_TR[error] ?? error;
}
