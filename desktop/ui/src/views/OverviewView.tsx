import { useEffect, useId, useMemo, useRef, useState } from "react";
import type {
  ActivityEvent,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  EngineMode,
  NavTab,
  SplitTunnelMode,
  ThroughputPoint,
} from "../types";
import { ThroughputChart } from "../components/ThroughputChart";
import { SegmentedControl } from "../components/SegmentedControl";
import { InlineBanner } from "../components/InlineBanner";
import { ConfirmDialog } from "../components/ConfirmDialog";
import {
  IconCheck,
  IconChevron,
  IconCopy,
  IconTrash,
} from "../components/Icons";
import type { ToastTone } from "../components/ToastStack";
import { formatBytes, formatClockTime, formatCount } from "../lib/format";

export interface OverviewViewProps {
  status: DesktopStatusSnapshot | null;
  settings: DesktopSettingsPayload | null;
  history: ThroughputPoint[];
  activity: ActivityEvent[];
  busyAction: string | null;
  onToggleProtection: (connect?: boolean) => void | Promise<void>;
  onSwitchEngine: (engine: EngineMode) => void | Promise<void>;
  onInstallService?: () => void | Promise<void>;
  onOpenAppFolder?: () => void | Promise<void>;
  onRefreshStatus?: () =>
    | DesktopStatusSnapshot
    | null
    | void
    | Promise<DesktopStatusSnapshot | null | void>;
  onPushToast?: (tone: ToastTone, message: string) => void;
  onNavigate: (tab: NavTab) => void;
  onClearActivity: () => void;
  onCopyActivity: () => boolean | void | Promise<boolean | void>;
}

type ProtectionHeadline =
  | "Checking status..."
  | "Starting..."
  | "Protected"
  | "Paused"
  | "Yielded to VPN"
  | "Service Not Installed";

type StatusTone = "active" | "idle" | "warn" | "muted";

const ENGINE_OPTIONS: ReadonlyArray<{ value: EngineMode; label: string }> = [
  { value: "tun", label: "TUN" },
  { value: "proxy", label: "Proxy" },
];

const ENGINE_DESCRIPTIONS: Record<EngineMode, string> = {
  tun: "Full-PC virtual adapter covering all apps, games, Discord voice (UDP), and DNS without proxy setup.",
  proxy:
    "Local HTTP/SOCKS5 proxy on 127.0.0.1 for web browsers and proxy-aware TCP apps (does not cover Discord voice or most games).",
};

const ACTIVITY_CATEGORY_LABELS: Record<ActivityEvent["category"], string> = {
  engine: "Engine",
  dns: "DNS",
  vpn: "VPN",
  split: "Split",
  system: "System",
};

function formatVersion(version: string | null | undefined): string | null {
  if (!version) return null;
  const trimmed = version.trim();
  if (!trimmed) return null;
  return trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
}

function formatStageLabel(stage: string): string {
  switch (stage) {
    case "ComboMultiRecord":
      return "Combo";
    case "OobSniDesync":
      return "OOB SNI";
    case "MultiRecordOob":
      return "Multi + OOB";
    case "FineFragment":
      return "Fine Fragment";
    case "DeepRecordStorm":
      return "Deep Storm";
    case "SlowSniSlice":
      return "Slow SNI";
    case "DirectPassthrough":
      return "Passthrough";
    default:
      return stage;
  }
}

function formatSplitSummary(mode: SplitTunnelMode, count: number): string {
  switch (mode) {
    case "all":
      return "Split: All apps";
    case "exclude":
      return count === 1 ? "Split: 1 excluded" : `Split: ${count} excluded`;
    case "include":
      return count === 1 ? "Split: 1 included" : `Split: ${count} included`;
  }
}

export function OverviewView({
  status,
  settings,
  history,
  activity,
  busyAction,
  onToggleProtection,
  onSwitchEngine,
  onInstallService,
  onOpenAppFolder,
  onRefreshStatus,
  onPushToast,
  onNavigate,
  onClearActivity,
  onCopyActivity,
}: OverviewViewProps) {
  const engineLabelId = useId();
  const [activityOpen, setActivityOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [pendingEngine, setPendingEngine] = useState<EngineMode | null>(null);
  const [isRecheckingWintun, setIsRecheckingWintun] = useState(false);
  const [wintunRecheckFeedback, setWintunRecheckFeedback] = useState<
    string | null
  >(null);
  const [wintunRecheckDoneSeq, setWintunRecheckDoneSeq] = useState(0);
  const copyTimerRef = useRef<number | null>(null);
  const wintunFeedbackTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);
  const pendingToggleIntentRef = useRef<"connecting" | "pausing" | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      if (wintunFeedbackTimerRef.current !== null) {
        window.clearTimeout(wintunFeedbackTimerRef.current);
      }
    };
  }, []);

  const isLoadingStatus = status === null;
  const live = status?.live ?? null;
  const serviceState = status?.serviceState ?? null;
  const isNotInstalled = serviceState === "not_installed";
  const activeEngine: EngineMode =
    live?.engine ?? settings?.engine ?? status?.configuredEngine ?? "tun";
  const vpnConflict =
    (live?.vpnConflict ?? status?.vpnConflict)?.trim() || null;

  const isYielded = Boolean(
    status !== null &&
      serviceState === "running" &&
      Boolean(vpnConflict) &&
      !live?.running &&
      settings?.vpnCoexistence === "auto_yield",
  );
  const isStarting = Boolean(
    status !== null && serviceState === "running" && !live && !isYielded,
  );
  const isRunning = Boolean(live?.running);

  const normalizedBusy = busyAction?.trim().toLowerCase() ?? null;
  const isAnyBusy = normalizedBusy !== null;
  const switchTargetEngine: EngineMode | null =
    normalizedBusy === "switch-engine:tun"
      ? "tun"
      : normalizedBusy === "switch-engine:proxy"
        ? "proxy"
        : null;
  const isSwitchingEngine =
    switchTargetEngine !== null ||
    (normalizedBusy !== null && normalizedBusy.startsWith("switch-engine"));
  const isConnecting = normalizedBusy === "connecting";
  const isPausing = normalizedBusy === "pausing";
  const isInstallingService = normalizedBusy === "install-service";
  const isPrimaryBusy = isAnyBusy && !isSwitchingEngine;

  useEffect(() => {
    if (!isPrimaryBusy) {
      pendingToggleIntentRef.current = null;
    }
  }, [isPrimaryBusy]);

  useEffect(() => {
    if (
      pendingEngine !== null &&
      (pendingEngine === activeEngine || !isRunning)
    ) {
      setPendingEngine(null);
    }
  }, [activeEngine, isRunning, pendingEngine]);

  const wintunMissing = Boolean(
    status?.platform === "windows" &&
      activeEngine === "tun" &&
      status.wintun.required &&
      !status.wintun.ready,
  );

  const { headline, statusTone } = useMemo<{
    headline: ProtectionHeadline;
    statusTone: StatusTone;
  }>(() => {
    if (isLoadingStatus) {
      return { headline: "Checking status...", statusTone: "muted" };
    }
    if (isNotInstalled) {
      return { headline: "Service Not Installed", statusTone: "muted" };
    }
    if (isYielded) {
      return { headline: "Yielded to VPN", statusTone: "warn" };
    }
    if (isStarting) {
      return { headline: "Starting...", statusTone: "warn" };
    }
    if (isRunning) {
      return { headline: "Protected", statusTone: "active" };
    }
    return { headline: "Paused", statusTone: "idle" };
  }, [isLoadingStatus, isNotInstalled, isRunning, isStarting, isYielded]);

  const subtitle = useMemo(() => {
    if (!status) {
      return "Reading service status...";
    }

    const versionTag = formatVersion(
      live?.version ?? status.installedVersion ?? status.appVersion,
    );

    if (isNotInstalled) {
      const parts = ["Background service required", "Admin prompt may appear"];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isYielded && vpnConflict) {
      const parts = [
        `Active tunnel: ${vpnConflict}`,
        "Auto-resumes on VPN disconnect",
      ];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isStarting) {
      const parts = [
        activeEngine === "tun" ? "TUN adapter" : "Local proxy",
        "Waiting for live telemetry...",
      ];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isRunning && live) {
      const parts: string[] = [];
      if (activeEngine === "tun") {
        const iface = live.tunInterface?.trim() || "TUN adapter";
        parts.push(
          live.physicalNic ? `${iface} via ${live.physicalNic}` : iface,
        );
      } else {
        parts.push(`${live.addr}:${live.port}`);
        if (live.socksPort !== null) {
          parts.push(`SOCKS5 :${live.socksPort}`);
        }
      }
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    const parts = [
      activeEngine === "tun" ? "TUN adapter" : "Local proxy",
      serviceState === "running" ? "Protection paused" : "Service stopped",
    ];
    if (versionTag) parts.push(versionTag);
    return parts.join(" · ");
  }, [
    activeEngine,
    isNotInstalled,
    isRunning,
    isStarting,
    isYielded,
    live,
    serviceState,
    status,
    vpnConflict,
  ]);

  const primaryButtonLabel = useMemo(() => {
    if (isInstallingService) {
      return "Setting up...";
    }
    if (isConnecting) {
      return "Connecting...";
    }
    if (isPausing) {
      return "Pausing...";
    }
    if (isPrimaryBusy) {
      if (pendingToggleIntentRef.current === "pausing") {
        return "Pausing...";
      }
      if (pendingToggleIntentRef.current === "connecting") {
        return "Connecting...";
      }
      return "Updating...";
    }
    if (isLoadingStatus) {
      return "Checking...";
    }
    if (isNotInstalled) {
      return "Set Up & Connect";
    }
    return (isRunning || isStarting) && !isYielded ? "Pause" : "Connect";
  }, [
    isConnecting,
    isInstallingService,
    isLoadingStatus,
    isNotInstalled,
    isPausing,
    isPrimaryBusy,
    isRunning,
    isStarting,
    isYielded,
  ]);

  const primaryButtonVariant = useMemo(() => {
    if (isPausing) return "btn-secondary";
    if (isConnecting || isInstallingService) return "btn-primary";
    if (isPrimaryBusy && pendingToggleIntentRef.current === "pausing") {
      return "btn-secondary";
    }
    if (isPrimaryBusy && pendingToggleIntentRef.current === "connecting") {
      return "btn-primary";
    }
    return (isRunning || isStarting) && !isYielded
      ? "btn-secondary"
      : "btn-primary";
  }, [
    isConnecting,
    isInstallingService,
    isPausing,
    isPrimaryBusy,
    isRunning,
    isStarting,
    isYielded,
  ]);

  const primaryDisabled =
    !status || isAnyBusy || (wintunMissing && !isRunning);

  const rxRateBps = live?.rxRateBps ?? 0;
  const txRateBps = live?.txRateBps ?? 0;
  const bytesRx = live?.bytesRx ?? 0;
  const bytesTx = live?.bytesTx ?? 0;

  const dnsDisplay =
    live?.dnsDisplay || settings?.dnsDisplay || "System default";
  const dohActive = live
    ? live.dohEnabled
    : Boolean(settings?.effectiveDoh ?? settings?.dohEnabled);
  const dnsQueries = live?.dnsQueries ?? 0;

  const activeConnections = live?.activeConnections ?? 0;
  const udpFlowsActive = live?.udpFlowsActive ?? 0;
  const connectionModeLabel = useMemo(() => {
    if (live?.ispStage) {
      return `Adaptive: ${formatStageLabel(live.ispStage)}`;
    }
    if (live?.mode) {
      return `Mode: ${live.mode}`;
    }
    if (isLoadingStatus) {
      return "Checking...";
    }
    if (isStarting) {
      return "Starting...";
    }
    return isRunning ? "Adaptive ready" : "Idle";
  }, [isLoadingStatus, isRunning, isStarting, live?.ispStage, live?.mode]);

  const quicBlocked = live?.quicBlocked ?? 0;
  const splitMode: SplitTunnelMode =
    status?.splitTunnelMode ?? settings?.splitTunnelMode ?? "all";
  const splitCount =
    status?.splitTunnelCount ?? settings?.splitTunnelApps.length ?? 0;
  const splitSummary = formatSplitSummary(splitMode, splitCount);

  const handlePrimaryClick = () => {
    if (primaryDisabled) return;
    if (isNotInstalled) {
      if (onInstallService) {
        void onInstallService();
      } else {
        onNavigate("settings");
      }
      return;
    }
    const shouldConnect = !(isRunning || isStarting) || isYielded;
    pendingToggleIntentRef.current = shouldConnect ? "connecting" : "pausing";
    void onToggleProtection(shouldConnect);
  };

  const handleEngineChange = (next: EngineMode) => {
    if (next === activeEngine || isAnyBusy) return;
    if (isRunning) {
      setPendingEngine(next);
      return;
    }
    void onSwitchEngine(next);
  };

  const handleConfirmEngineSwitch = () => {
    if (!pendingEngine || isAnyBusy) return;
    const target = pendingEngine;
    setPendingEngine(null);
    void onSwitchEngine(target);
  };

  const handleOpenAppFolder = () => {
    if (onOpenAppFolder) {
      void onOpenAppFolder();
    } else {
      onNavigate("settings");
    }
  };

  const showWintunFeedback = (tone: ToastTone, feedback: string) => {
    if (onPushToast) {
      onPushToast(tone, feedback);
      return;
    }
    setWintunRecheckFeedback(feedback);
    if (wintunFeedbackTimerRef.current !== null) {
      window.clearTimeout(wintunFeedbackTimerRef.current);
    }
    wintunFeedbackTimerRef.current = window.setTimeout(() => {
      if (mountedRef.current) {
        setWintunRecheckFeedback(null);
      }
      wintunFeedbackTimerRef.current = null;
    }, 5000);
  };

  useEffect(() => {
    if (!wintunMissing && wintunRecheckFeedback !== null) {
      setWintunRecheckFeedback(null);
    }
  }, [wintunMissing, wintunRecheckFeedback]);

  const wintunDetail = status?.wintun.message?.trim();
  const wintunInvalid = Boolean(
    wintunDetail && /(?:sha-?256|\bhash\b|\bcorrupt(?:ed)?\b)/i.test(wintunDetail),
  );
  const wintunBannerTitle = wintunInvalid
    ? "Full-PC driver invalid (wintun.dll)"
    : "Full-PC driver missing (wintun.dll)";

  useEffect(() => {
    if (wintunRecheckDoneSeq === 0) return;
    if (wintunMissing) {
      const feedback = wintunInvalid
        ? "wintun.dll is still invalid (hash verification failed). Replace it with an official copy and re-check."
        : "wintun.dll is still missing from the app folder.";
      showWintunFeedback("warn", feedback);
    } else if (status?.wintun.ready) {
      onPushToast?.(
        "success",
        "wintun.dll detected. Full-PC (TUN) mode is ready.",
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [wintunRecheckDoneSeq]);

  const handleRecheckWintun = async () => {
    if (!onRefreshStatus || isAnyBusy || isRecheckingWintun) return;
    setIsRecheckingWintun(true);
    setWintunRecheckFeedback(null);
    try {
      const refreshed = await onRefreshStatus();
      if (!mountedRef.current) return;
      if (refreshed && typeof refreshed === "object" && "wintun" in refreshed) {
        const refreshedEngine =
          refreshed.live?.engine ??
          settings?.engine ??
          refreshed.configuredEngine ??
          "tun";
        const stillMissing = Boolean(
          refreshed.platform === "windows" &&
            refreshedEngine === "tun" &&
            refreshed.wintun.required &&
            !refreshed.wintun.ready,
        );
        if (stillMissing) {
          const detail = refreshed.wintun.message?.trim();
          const isInvalid = Boolean(
            detail && /(?:sha-?256|\bhash\b|\bcorrupt(?:ed)?\b)/i.test(detail),
          );
          showWintunFeedback(
            "warn",
            isInvalid
              ? "wintun.dll is still invalid (hash verification failed). Replace it with an official copy and re-check."
              : "wintun.dll is still missing from the app folder.",
          );
        } else if (refreshed.wintun.ready) {
          onPushToast?.(
            "success",
            "wintun.dll detected. Full-PC (TUN) mode is ready.",
          );
        }
      } else {
        setWintunRecheckDoneSeq((prev) => prev + 1);
      }
    } catch {
      if (mountedRef.current) {
        showWintunFeedback("error", "Could not re-check wintun.dll status.");
      }
    } finally {
      if (mountedRef.current) {
        setIsRecheckingWintun(false);
      }
    }
  };

  const chartPausedLabel = useMemo(() => {
    if (isLoadingStatus) {
      return "Checking status...";
    }
    if (isNotInstalled || wintunMissing) {
      return "Setup required";
    }
    if (isYielded) {
      return "Yielded to VPN";
    }
    if (isStarting) {
      return "Starting...";
    }
    return "Protection paused";
  }, [isLoadingStatus, isNotInstalled, isStarting, isYielded, wintunMissing]);

  const engineSwitchAdminNote =
    status?.platform === "windows"
      ? " A Windows administrator prompt may appear to restart the background service."
      : status?.platform === "macos"
        ? " A macOS administrator password prompt may appear to restart the background service."
        : "";

  const handleCopyActivity = async () => {
    if (activity.length === 0) return;
    try {
      const ok = await onCopyActivity();
      if (!mountedRef.current || ok === false) return;
      setCopied(true);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopied(false);
        copyTimerRef.current = null;
      }, 1800);
    } catch {
      // Do not show copied confirmation when clipboard write fails.
    }
  };

  const wintunDescription = wintunDetail
    ? `${wintunDetail.replace(/\.$/, "")}. Proxy mode only covers web browsers (not Discord voice or games).`
    : "Place wintun.dll in the app folder for full-PC TUN protection. Proxy mode only covers web browsers (not Discord voice or games).";

  const engineHintText = isSwitchingEngine
    ? switchTargetEngine
      ? `Switching engine to ${switchTargetEngine === "tun" ? "TUN" : "Proxy"}...`
      : "Switching engine..."
    : ENGINE_DESCRIPTIONS[activeEngine];

  return (
    <div className="view-stack view-overview">
      <section className="card control-card">
        <div className="control-card-top">
          <div className="control-status" aria-live="polite">
            <div className="control-headline-row">
              <span
                className={`status-dot status-dot-${statusTone}`}
                aria-hidden="true"
              />
              <h1 className="control-headline">{headline}</h1>
            </div>
            <p className="control-subtitle tabular-nums" title={subtitle}>
              {subtitle}
            </p>
          </div>

          <button
            type="button"
            className={`btn ${primaryButtonVariant} control-primary-btn`}
            disabled={primaryDisabled}
            aria-busy={isPrimaryBusy}
            onClick={handlePrimaryClick}
          >
            {isPrimaryBusy && <span className="spinner" aria-hidden="true" />}
            <span>{primaryButtonLabel}</span>
          </button>
        </div>

        <div className="control-engine-row">
          <div className="control-engine-header">
            <span id={engineLabelId} className="control-engine-label">
              Engine
            </span>
            <SegmentedControl<EngineMode>
              options={ENGINE_OPTIONS}
              value={activeEngine}
              disabled={!status || isAnyBusy}
              ariaLabelledBy={engineLabelId}
              onChange={handleEngineChange}
            />
          </div>
          <p className="control-engine-hint">{engineHintText}</p>
        </div>
      </section>

      {vpnConflict &&
        !isNotInstalled &&
        settings?.vpnCoexistence !== "off" && (
          <InlineBanner
            tone="warn"
            title={
              isYielded ? "Yielded to active VPN" : "Full-tunnel VPN detected"
            }
            description={
              isYielded
                ? `Active full-tunnel interface (${vpnConflict}) detected. Protection paused automatically to prevent routing conflicts and will resume once the VPN disconnects.`
                : settings?.vpnCoexistence === "warn"
                  ? `Active full-tunnel interface (${vpnConflict}) detected while coexistence is set to warn. Traffic may bypass or conflict with the VPN tunnel.`
                  : isRunning
                    ? `Active full-tunnel interface (${vpnConflict}) detected while protection is running. Traffic may bypass or conflict with the VPN tunnel.`
                    : `Active full-tunnel interface (${vpnConflict}) detected. Protection will yield automatically if connected while this VPN is active.`
            }
            actionLabel="VPN Coexistence"
            onAction={() => onNavigate("dns")}
          />
        )}

      {wintunMissing && (
        <InlineBanner
          tone="warn"
          title={wintunBannerTitle}
          description={
            wintunRecheckFeedback ? (
              <>
                <span>{wintunDescription}</span>
                <p style={{ margin: "4px 0 0", fontWeight: 500 }}>
                  {wintunRecheckFeedback}
                </p>
              </>
            ) : (
              wintunDescription
            )
          }
          action={
            <div className="banner-actions">
              <button
                type="button"
                className="inline-banner__action"
                disabled={isAnyBusy}
                onClick={handleOpenAppFolder}
              >
                Open App Folder
              </button>
              {onRefreshStatus && (
                <button
                  type="button"
                  className="inline-banner__action"
                  disabled={isAnyBusy || isRecheckingWintun}
                  onClick={() => {
                    void handleRecheckWintun();
                  }}
                >
                  {isRecheckingWintun ? "Checking..." : "Re-check"}
                </button>
              )}
              <button
                type="button"
                className="inline-banner__action"
                disabled={isAnyBusy}
                onClick={() => handleEngineChange("proxy")}
              >
                Switch to Proxy
              </button>
            </div>
          }
        />
      )}

      {isNotInstalled && !wintunMissing && (
        <InlineBanner
          tone="info"
          title="One-time setup required"
          description="Click Set Up & Connect above to install the background service and start protection. An administrator prompt may appear to approve the setup."
          actionLabel="Open Settings"
          onAction={() => onNavigate("settings")}
        />
      )}

      <section className="metrics-grid" aria-label="Live telemetry">
        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">Session Transfer</span>
          </div>
          <div className="metric-value-stack tabular-nums">
            <span className="metric-rate-down">↓ {formatBytes(bytesRx)}</span>
            <span className="metric-rate-up">↑ {formatBytes(bytesTx)}</span>
          </div>
          <div className="metric-meta tabular-nums">
            Total {formatBytes(bytesRx + bytesTx)}
          </div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">DNS</span>
            <span
              className={`pill ${dohActive ? "pill-accent" : "pill-neutral"}`}
            >
              {dohActive ? "DoH" : "UDP"}
            </span>
          </div>
          <div
            className="metric-value metric-value-truncate mono tabular-nums"
            title={dnsDisplay}
          >
            {dnsDisplay}
          </div>
          <div className="metric-meta tabular-nums">
            {formatCount(dnsQueries)} queries
          </div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">Connections</span>
          </div>
          <div className="metric-value tabular-nums">
            {formatCount(activeConnections)} TCP · {formatCount(udpFlowsActive)}{" "}
            UDP
          </div>
          <div className="metric-meta">{connectionModeLabel}</div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">Protection</span>
          </div>
          <div className="metric-value tabular-nums">
            {formatCount(quicBlocked)} QUIC blocked
          </div>
          <div className="metric-meta">
            <button
              type="button"
              className="pill pill-interactive tabular-nums"
              title={splitSummary}
              onClick={() => onNavigate("split")}
            >
              <span className="pill-interactive-label">{splitSummary}</span>
              <IconChevron size={11} direction="right" />
            </button>
          </div>
        </article>
      </section>

      <section className="card chart-card" aria-label="Throughput history">
        <ThroughputChart
          points={history}
          running={isRunning}
          rxRateBps={rxRateBps}
          txRateBps={txRateBps}
          title="Throughput"
          caption="60s window"
          pausedLabel={chartPausedLabel}
        />
      </section>

      <section className="card activity-card" aria-label="Recent activity">
        <div className="card-header activity-header">
          <button
            type="button"
            className="activity-toggle"
            aria-expanded={activityOpen}
            aria-controls="overview-activity-panel"
            onClick={() => setActivityOpen((open) => !open)}
          >
            <IconChevron
              direction="down"
              className={`activity-chevron${activityOpen ? "" : " is-collapsed"}`}
            />
            <span className="card-title">Activity</span>
            <span className="pill pill-neutral tabular-nums">
              {activity.length}
            </span>
          </button>

          <div className="activity-actions">
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={activity.length === 0}
              onClick={() => {
                void handleCopyActivity();
              }}
            >
              {copied ? <IconCheck /> : <IconCopy />}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={activity.length === 0}
              onClick={onClearActivity}
            >
              <IconTrash />
              <span>Clear</span>
            </button>
          </div>
        </div>

        {activityOpen && (
          <div id="overview-activity-panel" className="activity-body">
            {activity.length === 0 ? (
              <p className="activity-empty">
                No activity recorded in this session.
              </p>
            ) : (
              <ul className="activity-list">
                {activity.map((event) => (
                  <li
                    key={event.id}
                    className={`activity-row activity-level-${event.level}`}
                  >
                    <time
                      className="activity-time tabular-nums"
                      dateTime={new Date(event.tsMs).toISOString()}
                    >
                      {formatClockTime(event.tsMs)}
                    </time>
                    <span
                      className={`pill pill-cat pill-cat-${event.category}`}
                    >
                      {ACTIVITY_CATEGORY_LABELS[event.category]}
                    </span>
                    <span className="activity-message">{event.message}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </section>

      <ConfirmDialog
        open={pendingEngine !== null}
        title={
          pendingEngine === "proxy"
            ? "Switch engine to Proxy?"
            : "Switch engine to TUN?"
        }
        description={
          pendingEngine === "proxy"
            ? `Switching engines restarts protection and will briefly interrupt active games, voice calls, and ongoing connections. Proxy mode only covers web browsers (not Discord voice or most games).${engineSwitchAdminNote}`
            : `Switching engines restarts protection and will briefly interrupt active games, voice calls, and ongoing connections while the full-PC TUN adapter starts.${engineSwitchAdminNote}`
        }
        confirmLabel={
          pendingEngine === "proxy" ? "Switch to Proxy" : "Switch to TUN"
        }
        cancelLabel="Cancel"
        onConfirm={handleConfirmEngineSwitch}
        onCancel={() => setPendingEngine(null)}
      />
    </div>
  );
}

export default OverviewView;
