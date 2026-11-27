import { useEffect, useId, useMemo, useRef, useState } from "react";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import {
  formatStageLabelLocalized,
  localizeActivityMessage,
  tOverview,
} from "../i18n/overview";
import { localizeActionMessage } from "../i18n/shell";
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
import {
  SegmentedControl,
  type SegmentedOption,
} from "../components/SegmentedControl";
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
  dismissedUpgradeKey?: string | null;
  onDismissUpgrade?: (key: string) => void;
  onToggleProtection: (connect?: boolean) => void | Promise<void>;
  onSwitchEngine: (engine: EngineMode) => void | Promise<void>;
  onInstallService?: (engine?: EngineMode) => void | Promise<void>;
  onUpgradeService?: () => void | Promise<void>;
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

type StatusTone = "active" | "idle" | "warn" | "muted";

function formatVersion(version: string | null | undefined): string | null {
  if (!version) return null;
  const trimmed = version.trim();
  if (!trimmed) return null;
  return trimmed.startsWith("v") ? trimmed : `v${trimmed}`;
}

function formatSplitSummary(
  lang: ResolvedLanguage,
  mode: SplitTunnelMode,
  count: number,
): string {
  switch (mode) {
    case "all":
      return tOverview(lang, "splitAll");
    case "exclude":
      return count === 1
        ? tOverview(lang, "splitExcludeOne")
        : tOverview(lang, "splitExcludeMany", { count });
    case "include":
      return count === 1
        ? tOverview(lang, "splitIncludeOne")
        : tOverview(lang, "splitIncludeMany", { count });
  }
}

function formatActivityCategory(
  lang: ResolvedLanguage,
  category: ActivityEvent["category"],
): string {
  switch (category) {
    case "engine":
      return tOverview(lang, "catEngine");
    case "dns":
      return tOverview(lang, "catDns");
    case "vpn":
      return tOverview(lang, "catVpn");
    case "split":
      return tOverview(lang, "catSplit");
    case "system":
      return tOverview(lang, "catSystem");
  }
}

export function OverviewView({
  status,
  settings,
  history,
  activity,
  busyAction,
  dismissedUpgradeKey,
  onDismissUpgrade,
  onToggleProtection,
  onSwitchEngine,
  onInstallService,
  onUpgradeService,
  onOpenAppFolder,
  onRefreshStatus,
  onPushToast,
  onNavigate,
  onClearActivity,
  onCopyActivity,
}: OverviewViewProps) {
  const { lang } = useLang();
  const engineLabelId = useId();
  const [activityOpen, setActivityOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [pendingEngine, setPendingEngine] = useState<EngineMode | null>(null);
  const [isRecheckingWintun, setIsRecheckingWintun] = useState(false);
  const [wintunRecheckFeedback, setWintunRecheckFeedback] = useState<
    string | null
  >(null);
  const [wintunRecheckDoneSeq, setWintunRecheckDoneSeq] = useState(0);
  const [localDismissedUpgradeKey, setLocalDismissedUpgradeKey] = useState<
    string | null
  >(null);
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
  const bundleMissing = status?.canInstallFromBundle === false;
  const isRepairNeeded = Boolean(
    status !== null &&
      !isNotInstalled &&
      status.cliVersionRelation === "repair_needed",
  );
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
  const pendingOp = status?.pendingOperation ?? null;
  const isAnyBusy = normalizedBusy !== null || pendingOp !== null;
  const switchTargetEngine: EngineMode | null =
    normalizedBusy === "switch-engine:tun"
      ? "tun"
      : normalizedBusy === "switch-engine:proxy"
        ? "proxy"
        : null;
  const isSwitchingEngine =
    switchTargetEngine !== null ||
    (normalizedBusy !== null && normalizedBusy.startsWith("switch-engine")) ||
    pendingOp === "switching_engine";
  const isConnecting =
    normalizedBusy === "connecting" || pendingOp === "resuming";
  const isPausing = normalizedBusy === "pausing" || pendingOp === "pausing";
  const isInstallingService =
    normalizedBusy === "install-service" || pendingOp === "installing";
  const isUpgradingService =
    normalizedBusy === "upgrade-service" || pendingOp === "upgrading";
  const isRepairingService =
    normalizedBusy === "repair-service" || pendingOp === "repairing";
  const isUninstallingService =
    normalizedBusy === "uninstall-service" || pendingOp === "uninstalling";
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

  const wintunNotReady = Boolean(
    status?.platform === "windows" && !status.wintun.ready,
  );
  const wintunMissing = Boolean(wintunNotReady && activeEngine === "tun");
  const tunSwitchBlockedByWintun = Boolean(
    wintunNotReady && activeEngine !== "tun",
  );

  const engineOptions = useMemo<readonly SegmentedOption<EngineMode>[]>(
    () => [
      {
        value: "tun",
        label: tOverview(lang, "engineTun"),
        disabled: tunSwitchBlockedByWintun,
        title: tunSwitchBlockedByWintun
          ? tOverview(lang, "engineTunDisabledWintun")
          : undefined,
      },
      { value: "proxy", label: tOverview(lang, "engineProxy") },
    ],
    [lang, tunSwitchBlockedByWintun],
  );

  const effectiveDismissedUpgradeKey =
    dismissedUpgradeKey !== undefined
      ? dismissedUpgradeKey
      : localDismissedUpgradeKey;

  const handleDismissUpgrade = (key: string) => {
    if (onDismissUpgrade) {
      onDismissUpgrade(key);
    } else {
      setLocalDismissedUpgradeKey(key);
    }
  };

  const { headline, statusTone } = useMemo<{
    headline: string;
    statusTone: StatusTone;
  }>(() => {
    if (isLoadingStatus) {
      return {
        headline: tOverview(lang, "headlineChecking"),
        statusTone: "muted",
      };
    }
    if (isNotInstalled) {
      return {
        headline: tOverview(lang, "headlineNotInstalled"),
        statusTone: "muted",
      };
    }
    if (isYielded) {
      return {
        headline: tOverview(lang, "headlineYielded"),
        statusTone: "warn",
      };
    }
    if (isStarting) {
      return {
        headline: tOverview(lang, "headlineStarting"),
        statusTone: "warn",
      };
    }
    if (isRunning) {
      return {
        headline: tOverview(lang, "headlineProtected"),
        statusTone: "active",
      };
    }
    return {
      headline: tOverview(lang, "headlinePaused"),
      statusTone: "idle",
    };
  }, [isLoadingStatus, isNotInstalled, isRunning, isStarting, isYielded, lang]);

  const subtitle = useMemo(() => {
    if (!status) {
      return tOverview(lang, "subtitleReadingStatus");
    }

    const versionTag = formatVersion(
      live?.version ?? status.installedVersion,
    );

    if (isNotInstalled) {
      const elevationNote =
        status.platform === "windows"
          ? tOverview(lang, "subtitleAdminPrompt")
          : activeEngine === "proxy"
            ? tOverview(lang, "subtitleUserServiceNoAdmin")
            : status.platform === "macos"
              ? tOverview(lang, "subtitleMacAdminPrompt")
              : tOverview(lang, "subtitleLinuxAuthPrompt");
      const parts = [
        tOverview(lang, "subtitleServiceRequired"),
        elevationNote,
      ];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isYielded && vpnConflict) {
      const parts = [
        tOverview(lang, "subtitleActiveTunnel", { vpn: vpnConflict }),
        tOverview(lang, "subtitleAutoResumes"),
      ];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isStarting) {
      const parts = [
        activeEngine === "tun"
          ? tOverview(lang, "subtitleTunAdapter")
          : tOverview(lang, "subtitleLocalProxy"),
        tOverview(lang, "subtitleWaitingTelemetry"),
      ];
      if (versionTag) parts.push(versionTag);
      return parts.join(" · ");
    }

    if (isRunning && live) {
      const parts: string[] = [];
      if (activeEngine === "tun") {
        const iface =
          live.tunInterface?.trim() || tOverview(lang, "subtitleTunAdapter");
        parts.push(
          live.physicalNic
            ? tOverview(lang, "subtitleVia", {
                iface,
                nic: live.physicalNic,
              })
            : iface,
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
      activeEngine === "tun"
        ? tOverview(lang, "subtitleTunAdapter")
        : tOverview(lang, "subtitleLocalProxy"),
      serviceState === "running"
        ? tOverview(lang, "subtitleProtectionPaused")
        : tOverview(lang, "subtitleServiceStopped"),
    ];
    if (versionTag) parts.push(versionTag);
    return parts.join(" · ");
  }, [
    activeEngine,
    isNotInstalled,
    isRunning,
    isStarting,
    isYielded,
    lang,
    live,
    serviceState,
    status,
    vpnConflict,
  ]);

  const primaryButtonLabel = useMemo(() => {
    if (isInstallingService) {
      return tOverview(lang, "btnSettingUp");
    }
    if (isRepairingService) {
      return tOverview(lang, "btnRepairing");
    }
    if (isUninstallingService) {
      return tOverview(lang, "btnUninstalling");
    }
    if (isConnecting) {
      return tOverview(lang, "btnConnecting");
    }
    if (isPausing) {
      return tOverview(lang, "btnPausing");
    }
    if (isPrimaryBusy) {
      if (pendingToggleIntentRef.current === "pausing") {
        return tOverview(lang, "btnPausing");
      }
      if (pendingToggleIntentRef.current === "connecting") {
        return tOverview(lang, "btnConnecting");
      }
      return tOverview(lang, "btnUpdating");
    }
    if (isLoadingStatus) {
      return tOverview(lang, "btnChecking");
    }
    if (isNotInstalled) {
      return tOverview(lang, "btnSetUpAndConnect");
    }
    return (isRunning || isStarting) && !isYielded
      ? tOverview(lang, "btnPause")
      : tOverview(lang, "btnConnect");
  }, [
    isConnecting,
    isInstallingService,
    isLoadingStatus,
    isNotInstalled,
    isPausing,
    isPrimaryBusy,
    isRepairingService,
    isRunning,
    isStarting,
    isUninstallingService,
    isYielded,
    lang,
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
    !status ||
    isAnyBusy ||
    (wintunMissing && !isRunning) ||
    (isNotInstalled && bundleMissing);

  const rxRateBps = live?.rxRateBps ?? 0;
  const txRateBps = live?.txRateBps ?? 0;
  const bytesRx = live?.bytesRx ?? 0;
  const bytesTx = live?.bytesTx ?? 0;

  const dnsDisplay =
    live?.dnsDisplay ||
    settings?.dnsDisplay ||
    tOverview(lang, "dnsSystemDefault");
  const dohActive = live
    ? live.dohEnabled
    : Boolean(settings?.effectiveDoh ?? settings?.dohEnabled);
  const dnsQueries = live?.dnsQueries ?? 0;

  const activeConnections = live?.activeConnections ?? 0;
  const udpFlowsActive = live?.udpFlowsActive ?? 0;
  const connectionModeLabel = useMemo(() => {
    if (live?.ispStage) {
      return tOverview(lang, "connAdaptive", {
        stage: formatStageLabelLocalized(lang, live.ispStage),
      });
    }
    if (live?.mode) {
      return tOverview(lang, "connMode", { mode: live.mode });
    }
    if (isLoadingStatus) {
      return tOverview(lang, "btnChecking");
    }
    if (isStarting) {
      return tOverview(lang, "headlineStarting");
    }
    return isRunning
      ? tOverview(lang, "connAdaptiveReady")
      : tOverview(lang, "connIdle");
  }, [isLoadingStatus, isRunning, isStarting, lang, live?.ispStage, live?.mode]);

  const quicBlocked = live?.quicBlocked ?? 0;
  const splitMode: SplitTunnelMode =
    status?.splitTunnelMode ?? settings?.splitTunnelMode ?? "all";
  const splitCount =
    status?.splitTunnelCount ?? settings?.splitTunnelApps.length ?? 0;
  const splitSummary = formatSplitSummary(lang, splitMode, splitCount);

  const handlePrimaryClick = () => {
    if (primaryDisabled) return;
    if (isNotInstalled) {
      if (onInstallService) {
        void onInstallService(activeEngine);
      } else {
        onNavigate("installation");
      }
      return;
    }
    const shouldConnect = !(isRunning || isStarting) || isYielded;
    pendingToggleIntentRef.current = shouldConnect ? "connecting" : "pausing";
    void onToggleProtection(shouldConnect);
  };

  const handleUpgradeService = () => {
    if (isAnyBusy || isUpgradingService) return;
    if (onUpgradeService) {
      void onUpgradeService();
    } else {
      onNavigate("installation");
    }
  };

  const handleEngineChange = (next: EngineMode) => {
    if (next === activeEngine || isAnyBusy) return;
    if (next === "tun" && tunSwitchBlockedByWintun) return;
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

  const wintunRawDetail = status?.wintun.message?.trim();
  const wintunDetail = wintunRawDetail
    ? localizeActionMessage(lang, wintunRawDetail).trim()
    : undefined;
  const wintunInvalid = Boolean(
    wintunRawDetail &&
      /(?:sha-?256|\bhash\b|\bcorrupt(?:ed)?\b)/i.test(wintunRawDetail),
  );
  const wintunBannerTitle = wintunInvalid
    ? tOverview(lang, "wintunInvalidTitle")
    : tOverview(lang, "wintunMissingTitle");

  useEffect(() => {
    if (wintunRecheckDoneSeq === 0) return;
    if (wintunMissing) {
      const feedback = wintunInvalid
        ? tOverview(lang, "wintunStillInvalid")
        : tOverview(lang, "wintunStillMissing");
      showWintunFeedback("warn", feedback);
    } else if (status?.wintun.ready) {
      onPushToast?.("success", tOverview(lang, "wintunDetectedReady"));
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
              ? tOverview(lang, "wintunStillInvalid")
              : tOverview(lang, "wintunStillMissing"),
          );
        } else if (refreshed.wintun.ready) {
          onPushToast?.("success", tOverview(lang, "wintunDetectedReady"));
        }
      } else {
        setWintunRecheckDoneSeq((prev) => prev + 1);
      }
    } catch {
      if (mountedRef.current) {
        showWintunFeedback("error", tOverview(lang, "wintunRecheckError"));
      }
    } finally {
      if (mountedRef.current) {
        setIsRecheckingWintun(false);
      }
    }
  };

  const chartPausedLabel = useMemo(() => {
    if (isLoadingStatus) {
      return tOverview(lang, "headlineChecking");
    }
    if (isNotInstalled || wintunMissing) {
      return tOverview(lang, "chartPausedSetup");
    }
    if (isYielded) {
      return tOverview(lang, "headlineYielded");
    }
    if (isStarting) {
      return tOverview(lang, "headlineStarting");
    }
    return tOverview(lang, "chartPausedDefault");
  }, [isLoadingStatus, isNotInstalled, isStarting, isYielded, lang, wintunMissing]);

  const engineSwitchAdminNote =
    status?.platform === "windows"
      ? tOverview(lang, "confirmAdminWindows")
      : status?.platform === "macos"
        ? tOverview(lang, "confirmAdminMac")
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
    ? tOverview(lang, "wintunDetailWithNote", {
        detail: wintunDetail.replace(/\.$/, ""),
      })
    : tOverview(lang, "wintunDefaultDesc");

  const installedVersionTag = formatVersion(
    status?.installedVersion ?? live?.version,
  );
  const bundledVersionTag = formatVersion(status?.bundledEngineVersion);
  const upgradeVersionKey = `${status?.installedVersion ?? ""}=>${status?.bundledEngineVersion ?? ""}`;
  const showUpgradeBanner = Boolean(
    status !== null &&
      !isNotInstalled &&
      status.cliVersionRelation === "upgrade_available" &&
      effectiveDismissedUpgradeKey !== upgradeVersionKey,
  );
  const upgradeBannerDesc =
    bundledVersionTag && installedVersionTag
      ? tOverview(lang, "upgradeAvailableDescVersions", {
          bundled: bundledVersionTag,
          installed: installedVersionTag,
        })
      : tOverview(lang, "upgradeAvailableDesc");

  const isUnixProxySetup = Boolean(
    status &&
      (status.platform === "macos" || status.platform === "linux") &&
      activeEngine === "proxy",
  );

  const engineHintText = isSwitchingEngine
    ? switchTargetEngine
      ? tOverview(lang, "engineSwitchingTo", {
          engine:
            switchTargetEngine === "tun"
              ? tOverview(lang, "engineTun")
              : tOverview(lang, "engineProxy"),
        })
      : tOverview(lang, "engineSwitching")
    : activeEngine === "tun"
      ? tOverview(lang, "engineDescTun")
      : tunSwitchBlockedByWintun
        ? tOverview(lang, "engineDescProxyWintunMissing")
        : tOverview(lang, "engineDescProxy");

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
              {tOverview(lang, "engineLabel")}
            </span>
            <SegmentedControl<EngineMode>
              options={engineOptions}
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
              isYielded
                ? tOverview(lang, "vpnYieldedTitle")
                : tOverview(lang, "vpnDetectedTitle")
            }
            description={
              isYielded
                ? tOverview(lang, "vpnYieldedDesc", { vpn: vpnConflict })
                : settings?.vpnCoexistence === "warn"
                  ? tOverview(lang, "vpnWarnDesc", { vpn: vpnConflict })
                  : isRunning
                    ? tOverview(lang, "vpnRunningDesc", { vpn: vpnConflict })
                    : tOverview(lang, "vpnIdleDesc", { vpn: vpnConflict })
            }
            actionLabel={tOverview(lang, "vpnAction")}
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
                {tOverview(lang, "btnOpenAppFolder")}
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
                  {isRecheckingWintun
                    ? tOverview(lang, "btnChecking")
                    : tOverview(lang, "btnRecheck")}
                </button>
              )}
              <button
                type="button"
                className="inline-banner__action"
                disabled={isAnyBusy}
                onClick={() => handleEngineChange("proxy")}
              >
                {tOverview(lang, "btnSwitchToProxy")}
              </button>
            </div>
          }
        />
      )}

      {isNotInstalled && bundleMissing && (
        <InlineBanner
          tone="warn"
          title={tOverview(lang, "bundleMissingTitle")}
          description={tOverview(lang, "bundleMissingDesc")}
          actionLabel={tOverview(lang, "btnOpenInstallation")}
          onAction={() => onNavigate("installation")}
        />
      )}

      {isNotInstalled && !wintunMissing && !bundleMissing && (
        <InlineBanner
          tone="info"
          title={tOverview(lang, "setupRequiredTitle")}
          description={
            isUnixProxySetup
              ? tOverview(lang, "setupRequiredDescNoAdmin")
              : tOverview(lang, "setupRequiredDesc")
          }
          actionLabel={tOverview(lang, "btnOpenInstallation")}
          onAction={() => onNavigate("installation")}
        />
      )}

      {isRepairNeeded && (
        <InlineBanner
          tone="warn"
          title={tOverview(lang, "repairNeededTitle")}
          description={tOverview(lang, "repairNeededDesc")}
          actionLabel={tOverview(lang, "btnOpenInstallation")}
          onAction={() => onNavigate("installation")}
        />
      )}

      {showUpgradeBanner && (
        <InlineBanner
          tone="info"
          title={tOverview(lang, "upgradeAvailableTitle")}
          description={upgradeBannerDesc}
          action={
            <div className="banner-actions">
              <button
                type="button"
                className="inline-banner__action"
                disabled={
                  isAnyBusy ||
                  isUpgradingService ||
                  status?.canInstallFromBundle === false
                }
                aria-busy={isUpgradingService || undefined}
                onClick={handleUpgradeService}
              >
                {isUpgradingService
                  ? tOverview(lang, "btnUpdating")
                  : tOverview(lang, "btnUpdateEngine")}
              </button>
              <button
                type="button"
                className="inline-banner__action"
                disabled={isUpgradingService}
                onClick={() => handleDismissUpgrade(upgradeVersionKey)}
              >
                {tOverview(lang, "btnLater")}
              </button>
            </div>
          }
        />
      )}

      <section
        className="metrics-grid"
        aria-label={tOverview(lang, "metricsAria")}
      >
        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">
              {tOverview(lang, "metricSessionTransfer")}
            </span>
          </div>
          <div className="metric-value-stack tabular-nums">
            <span className="metric-rate-down">↓ {formatBytes(bytesRx)}</span>
            <span className="metric-rate-up">↑ {formatBytes(bytesTx)}</span>
          </div>
          <div className="metric-meta tabular-nums">
            {tOverview(lang, "metricTotal", {
              value: formatBytes(bytesRx + bytesTx),
            })}
          </div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">
              {tOverview(lang, "metricDns")}
            </span>
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
            {tOverview(lang, "metricQueries", {
              count: formatCount(dnsQueries),
            })}
          </div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">
              {tOverview(lang, "metricConnections")}
            </span>
          </div>
          <div className="metric-value tabular-nums">
            {formatCount(activeConnections)} TCP · {formatCount(udpFlowsActive)}{" "}
            UDP
          </div>
          <div className="metric-meta">{connectionModeLabel}</div>
        </article>

        <article className="card metric-card">
          <div className="metric-header">
            <span className="metric-label">
              {tOverview(lang, "metricProtection")}
            </span>
          </div>
          <div className="metric-value tabular-nums">
            {tOverview(lang, "metricQuicBlocked", {
              count: formatCount(quicBlocked),
            })}
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

      <section
        className="card chart-card"
        aria-label={tOverview(lang, "chartAria")}
      >
        <ThroughputChart
          points={history}
          running={isRunning}
          rxRateBps={rxRateBps}
          txRateBps={txRateBps}
          title={tOverview(lang, "chartTitle")}
          caption={tOverview(lang, "chartCaption")}
          pausedLabel={chartPausedLabel}
        />
      </section>

      <section
        className="card activity-card"
        aria-label={tOverview(lang, "activityAria")}
      >
        <div className="card-header activity-header">
          <button
            type="button"
            className="activity-toggle"
            aria-expanded={activityOpen}
            aria-controls={activityOpen ? "overview-activity-panel" : undefined}
            onClick={() => setActivityOpen((open) => !open)}
          >
            <IconChevron
              direction="down"
              className={`activity-chevron${activityOpen ? "" : " is-collapsed"}`}
            />
            <span className="card-title">
              {tOverview(lang, "activityTitle")}
            </span>
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
              <span>
                {copied
                  ? tOverview(lang, "btnCopied")
                  : tOverview(lang, "btnCopy")}
              </span>
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              disabled={activity.length === 0}
              onClick={onClearActivity}
            >
              <IconTrash />
              <span>{tOverview(lang, "btnClear")}</span>
            </button>
          </div>
        </div>

        {activityOpen && (
          <div id="overview-activity-panel" className="activity-body">
            {activity.length === 0 ? (
              <p className="activity-empty">
                {tOverview(lang, "activityEmpty")}
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
                      {formatActivityCategory(lang, event.category)}
                    </span>
                    <span className="activity-message">
                      {localizeActivityMessage(lang, event.message)}
                    </span>
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
            ? tOverview(lang, "confirmProxyTitle")
            : tOverview(lang, "confirmTunTitle")
        }
        description={
          pendingEngine === "proxy"
            ? tOverview(lang, "confirmProxyDesc", {
                adminNote: engineSwitchAdminNote,
              })
            : tOverview(lang, "confirmTunDesc", {
                adminNote: engineSwitchAdminNote,
              })
        }
        confirmLabel={
          pendingEngine === "proxy"
            ? tOverview(lang, "confirmProxyBtn")
            : tOverview(lang, "confirmTunBtn")
        }
        cancelLabel={tOverview(lang, "cancel")}
        onConfirm={handleConfirmEngineSwitch}
        onCancel={() => setPendingEngine(null)}
      />
    </div>
  );
}

export default OverviewView;
