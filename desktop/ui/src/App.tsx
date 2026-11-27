import {
  Component,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ErrorInfo,
  type ReactNode,
} from "react";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { InlineBanner } from "./components/InlineBanner";
import { Sidebar } from "./components/Sidebar";
import {
  ToastStack,
  type ToastItem,
  type ToastTone,
} from "./components/ToastStack";
import { useDesktopStatus } from "./hooks/useDesktopStatus";
import { useKeyboardShortcuts } from "./hooks/useKeyboardShortcuts";
import { useTheme } from "./hooks/useTheme";
import { formatClockTime, scrubUrlsInText } from "./lib/format";
import {
  installService,
  isTauriRuntime,
  openAppFolder,
  switchEngine,
  toggleProtection,
  type AppFolderTarget,
} from "./lib/ipc";
import type {
  ActionResult,
  ActivityEvent,
  DesktopSettingsPayload,
  EngineMode,
  GuiPreferences,
  NavTab,
  ThemePreference,
} from "./types";
import { DiagnosticsView } from "./views/DiagnosticsView";
import { DnsRulesView } from "./views/DnsRulesView";
import { OverviewView } from "./views/OverviewView";
import { SettingsView } from "./views/SettingsView";
import { SplitTunnelView } from "./views/SplitTunnelView";

const TRAY_ACTION_RESULT_EVENT = "vdpi://tray-action-result";

interface ErrorBoundaryProps {
  children: ReactNode;
  resetKey?: string;
  compact?: boolean;
  onReset?: () => void;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class AppErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(
      "vdpi UI render error:",
      scrubUrlsInText(error.message || "Unexpected render error"),
      info.componentStack,
    );
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps): void {
    if (
      this.state.error !== null &&
      this.props.resetKey !== undefined &&
      prevProps.resetKey !== this.props.resetKey
    ) {
      this.setState({ error: null });
    }
  }

  private handleReset = (): void => {
    this.setState({ error: null });
    this.props.onReset?.();
  };

  private handleReload = (): void => {
    if (typeof window !== "undefined") {
      window.location.reload();
    }
  };

  render(): ReactNode {
    const { error } = this.state;
    if (!error) {
      return this.props.children;
    }

    const safeMessage = scrubUrlsInText(
      error.message || "Unexpected render error",
    );

    const content = (
      <section className="card" role="alert">
        <div className="card-header">
          <div className="card-title-group">
            <h1 className="card-title">Something went wrong</h1>
          </div>
        </div>
        <p className="text-secondary">
          An unexpected interface error occurred. The background vdpi service is
          unaffected.
        </p>
        <pre>
          <code>{safeMessage}</code>
        </pre>
        <div className="card-footer">
          <div className="form-row">
            <button
              type="button"
              className="btn btn-primary"
              onClick={this.handleReset}
            >
              Try Again
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={this.handleReload}
            >
              Reload Window
            </button>
          </div>
        </div>
      </section>
    );

    if (this.props.compact) {
      return content;
    }

    return (
      <div className="main-content">
        <div className="view-container">{content}</div>
      </div>
    );
  }
}

function getErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error && err.message.trim().length > 0) {
    return scrubUrlsInText(err.message.trim());
  }
  if (typeof err === "string" && err.trim().length > 0) {
    return scrubUrlsInText(err.trim());
  }
  return fallback;
}

function safeActionMessage(
  message: string | null | undefined,
  fallback: string,
): string {
  const trimmed = message?.trim();
  return trimmed ? scrubUrlsInText(trimmed) : fallback;
}

async function copyTextToClipboard(text: string): Promise<void> {
  if (
    typeof navigator !== "undefined" &&
    navigator.clipboard &&
    typeof navigator.clipboard.writeText === "function"
  ) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      // Fall through to execCommand("copy") when Clipboard API rejects
      // (e.g. unfocused webview, WKWebView, or restricted clipboard permission).
    }
  }

  if (typeof document === "undefined") {
    throw new Error("Clipboard API unavailable.");
  }

  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-9999px";
  textarea.style.left = "-9999px";
  textarea.style.opacity = "0";
  textarea.style.pointerEvents = "none";
  document.body.appendChild(textarea);
  try {
    textarea.focus();
    textarea.select();
    const ok =
      typeof document.execCommand === "function" &&
      document.execCommand("copy");
    if (!ok) {
      throw new Error("Copy command failed.");
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

function formatActivityForClipboard(events: readonly ActivityEvent[]): string {
  return events
    .map(
      (event) =>
        `[${formatClockTime(event.tsMs)}] [${event.category.toUpperCase()}] [${event.level.toUpperCase()}] ${event.message}`,
    )
    .join("\n");
}

function AppShell() {
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [guiPrefsOverride, setGuiPrefsOverride] =
    useState<GuiPreferences | null>(null);
  const [splitDirty, setSplitDirty] = useState(false);
  const [dnsDirty, setDnsDirty] = useState(false);
  const [pendingTab, setPendingTab] = useState<NavTab | null>(null);
  const [confirmSwitchToTunOpen, setConfirmSwitchToTunOpen] = useState(false);

  const busyActionRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const mainContentRef = useRef<HTMLElement | null>(null);
  const platformRef = useRef<"windows" | "macos" | "linux" | undefined>(
    undefined,
  );

  const {
    status,
    settings,
    loading,
    error,
    statusError,
    history,
    activity,
    toasts,
    refreshStatus,
    refreshSettings,
    pushToast,
    dismissToast,
    pauseToastTimer,
    resumeToastTimer,
    clearActivity,
  } = useDesktopStatus();

  platformRef.current = status?.platform;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (!isTauriRuntime()) {
      return;
    }

    let disposed = false;
    let unlisten: UnlistenFn | null = null;

    void listen<ActionResult>(TRAY_ACTION_RESULT_EVENT, (event) => {
      if (disposed || !mountedRef.current) {
        return;
      }
      const payload = event.payload;
      if (!payload || typeof payload !== "object") {
        return;
      }
      const surfaceLabel =
        platformRef.current === "macos" ? "Menu bar" : "Tray";
      if (payload.cancelled) {
        pushToast(
          "info",
          safeActionMessage(
            payload.message,
            `${surfaceLabel} action cancelled.`,
          ),
        );
      } else if (!payload.ok) {
        pushToast(
          "error",
          safeActionMessage(payload.message, `${surfaceLabel} action failed.`),
        );
      } else if (payload.needsRestart) {
        pushToast(
          "warn",
          safeActionMessage(
            payload.message,
            "Action completed. Restart service to apply.",
          ),
        );
      }
    })
      .then((fn) => {
        if (disposed) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch(() => {
        // Ignore subscription errors outside native Tauri webview.
      });

    return () => {
      disposed = true;
      if (unlisten) {
        unlisten();
        unlisten = null;
      }
    };
  }, [pushToast]);

  useEffect(() => {
    if (settings !== null) {
      setGuiPrefsOverride(null);
    }
  }, [settings]);

  const effectiveSettings = useMemo<DesktopSettingsPayload | null>(() => {
    if (!settings) {
      return null;
    }
    if (!guiPrefsOverride) {
      return settings;
    }
    return {
      ...settings,
      gui: guiPrefsOverride,
    };
  }, [settings, guiPrefsOverride]);

  const effectiveGuiPrefs = guiPrefsOverride ?? settings?.gui ?? null;
  const themePreference: ThemePreference =
    effectiveGuiPrefs?.theme ?? "system";
  const keepInTrayOnClose = Boolean(effectiveGuiPrefs?.keepInTrayOnClose);
  const trayPrefsActive = Boolean(
    effectiveGuiPrefs?.keepInTrayOnClose ||
      effectiveGuiPrefs?.minimizeToTray ||
      effectiveGuiPrefs?.startMinimizedToTray,
  );

  const activeEngine: EngineMode =
    status?.live?.engine ??
    effectiveSettings?.engine ??
    status?.configuredEngine ??
    "tun";
  const isProtectionActive = Boolean(status?.live?.running);

  useEffect(() => {
    if (
      confirmSwitchToTunOpen &&
      (activeEngine === "tun" || !isProtectionActive)
    ) {
      setConfirmSwitchToTunOpen(false);
    }
  }, [activeEngine, confirmSwitchToTunOpen, isProtectionActive]);

  useTheme(themePreference);

  const navigateToTab = useCallback((tab: NavTab) => {
    setActiveTab(tab);
    setPendingTab(null);
    setConfirmSwitchToTunOpen(false);
    if (tab !== "split") {
      setSplitDirty(false);
    }
    if (tab !== "dns") {
      setDnsDirty(false);
    }
    if (mainContentRef.current) {
      mainContentRef.current.scrollTop = 0;
    }
  }, []);

  const handleSelectTab = useCallback(
    (tab: NavTab) => {
      if (tab === activeTab) {
        return;
      }
      if (
        (activeTab === "split" && splitDirty) ||
        (activeTab === "dns" && dnsDirty)
      ) {
        setPendingTab(tab);
        return;
      }
      navigateToTab(tab);
    },
    [activeTab, dnsDirty, navigateToTab, splitDirty],
  );

  const handleCancelLeaveDirty = useCallback(() => {
    setPendingTab(null);
  }, []);

  const handleConfirmLeaveDirty = useCallback(() => {
    if (pendingTab) {
      navigateToTab(pendingTab);
    }
  }, [navigateToTab, pendingTab]);

  const handleCancelSwitchToTun = useCallback(() => {
    setConfirmSwitchToTunOpen(false);
  }, []);

  const handleCloseModal = useCallback(() => {
    if (confirmSwitchToTunOpen) {
      setConfirmSwitchToTunOpen(false);
      return;
    }
    setPendingTab(null);
  }, [confirmSwitchToTunOpen]);

  useKeyboardShortcuts({
    onSelectTab: handleSelectTab,
    hasOpenModal: pendingTab !== null || confirmSwitchToTunOpen,
    onCloseModal: handleCloseModal,
  });

  const handlePushToast = useCallback(
    (tone: ToastTone, message: string) => {
      pushToast(tone, message);
    },
    [pushToast],
  );

  const toastItems = useMemo<ToastItem[]>(
    () =>
      toasts.map((toast) => ({
        id: toast.id,
        tone: toast.kind,
        message: toast.text,
      })),
    [toasts],
  );

  const setBusy = useCallback((next: string | null) => {
    busyActionRef.current = next;
    if (mountedRef.current) {
      setBusyAction(next);
    }
  }, []);

  const handleToggleProtection = useCallback(
    async (connect?: boolean) => {
      if (busyActionRef.current !== null) {
        return;
      }

      const currentlyRunning = Boolean(
        status?.live?.running || status?.serviceState === "running",
      );
      const shouldConnect =
        typeof connect === "boolean" ? connect : !currentlyRunning;
      setBusy(shouldConnect ? "connecting" : "pausing");

      try {
        const result = await toggleProtection(shouldConnect);
        if (!mountedRef.current) {
          return;
        }

        // In Tauri runtime, toggle_protection broadcasts vdpi://status directly.
        if (!isTauriRuntime()) {
          await refreshStatus();
          if (!mountedRef.current) {
            return;
          }
        }

        if (result.cancelled) {
          pushToast(
            "info",
            safeActionMessage(result.message, "Protection change cancelled."),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              result.message,
              "Failed to update protection state.",
            ),
          );
        } else if (result.needsRestart) {
          pushToast(
            "warn",
            safeActionMessage(
              result.message,
              "Protection updated. Restart service to apply.",
            ),
          );
        } else if (result.message?.trim()) {
          pushToast("success", scrubUrlsInText(result.message.trim()));
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(err, "Failed to toggle protection."),
          );
        }
      } finally {
        setBusy(null);
      }
    },
    [
      pushToast,
      refreshStatus,
      setBusy,
      status?.live?.running,
      status?.serviceState,
    ],
  );

  const handleStartProtection = useCallback(
    () => handleToggleProtection(true),
    [handleToggleProtection],
  );

  const handleRefreshSettings = useCallback(async () => {
    const refreshed = await refreshSettings();
    if (mountedRef.current && refreshed) {
      setGuiPrefsOverride(null);
    }
    return refreshed;
  }, [refreshSettings]);

  const handleSwitchEngine = useCallback(
    async (engine: EngineMode) => {
      if (busyActionRef.current !== null) {
        return;
      }

      if (activeEngine === engine) {
        return;
      }

      setBusy(engine === "tun" ? "switch-engine:tun" : "switch-engine:proxy");
      try {
        const result = await switchEngine(engine);
        if (!mountedRef.current) {
          return;
        }

        // In Tauri runtime, switch_engine broadcasts vdpi://status directly.
        if (isTauriRuntime()) {
          await handleRefreshSettings();
        } else {
          await Promise.all([refreshStatus(), handleRefreshSettings()]);
        }
        if (!mountedRef.current) {
          return;
        }

        const label = engine === "tun" ? "TUN" : "Proxy";
        if (result.cancelled) {
          pushToast(
            "info",
            safeActionMessage(
              result.message,
              `Engine switch to ${label} cancelled.`,
            ),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              result.message,
              `Failed to switch engine to ${label}.`,
            ),
          );
        } else if (result.needsRestart) {
          pushToast(
            "warn",
            safeActionMessage(
              result.message,
              `Switched engine to ${label}. Restart service to apply.`,
            ),
          );
        } else {
          pushToast(
            "success",
            safeActionMessage(result.message, `Switched engine to ${label}.`),
          );
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(err, "Failed to switch protection engine."),
          );
        }
      } finally {
        setBusy(null);
      }
    },
    [activeEngine, handleRefreshSettings, pushToast, refreshStatus, setBusy],
  );

  const handleSwitchToTun = useCallback(() => {
    if (busyActionRef.current !== null || activeEngine === "tun") {
      return;
    }
    if (isProtectionActive) {
      setConfirmSwitchToTunOpen(true);
      return;
    }
    return handleSwitchEngine("tun");
  }, [activeEngine, handleSwitchEngine, isProtectionActive]);

  const handleConfirmSwitchToTun = useCallback(() => {
    if (busyActionRef.current !== null) {
      return;
    }
    setConfirmSwitchToTunOpen(false);
    void handleSwitchEngine("tun");
  }, [handleSwitchEngine]);

  const handleInstallService = useCallback(async () => {
    if (busyActionRef.current !== null) {
      return;
    }

    setBusy("install-service");
    try {
      const result = await installService();
      if (!mountedRef.current) {
        return;
      }

      // In Tauri runtime, install_service broadcasts vdpi://status directly.
      if (isTauriRuntime()) {
        await handleRefreshSettings();
      } else {
        await Promise.all([refreshStatus(), handleRefreshSettings()]);
      }
      if (!mountedRef.current) {
        return;
      }

      if (result.cancelled) {
        pushToast(
          "info",
          safeActionMessage(result.message, "Service installation cancelled."),
        );
      } else if (!result.ok) {
        pushToast(
          "error",
          safeActionMessage(
            result.message,
            "Failed to install background service.",
          ),
        );
      } else if (result.needsRestart) {
        pushToast(
          "warn",
          safeActionMessage(
            result.message,
            "Background service installed. Restart to apply.",
          ),
        );
      } else {
        pushToast(
          "success",
          safeActionMessage(result.message, "Background service installed."),
        );
      }
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getErrorMessage(err, "Failed to install background service."),
        );
      }
    } finally {
      setBusy(null);
    }
  }, [handleRefreshSettings, pushToast, refreshStatus, setBusy]);

  const handleOpenAppFolder = useCallback(
    async (kind: AppFolderTarget = "app") => {
      try {
        const result = await openAppFolder(kind);
        if (!mountedRef.current) {
          return;
        }
        if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(result.message, `Failed to open ${kind} folder.`),
          );
        } else if (!isTauriRuntime() && result.message?.trim()) {
          pushToast("info", scrubUrlsInText(result.message.trim()));
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(err, `Failed to open ${kind} folder.`),
          );
        }
      }
    },
    [pushToast],
  );

  const handleOpenOverviewAppFolder = useCallback(
    () => handleOpenAppFolder("app"),
    [handleOpenAppFolder],
  );

  const handleRefreshStatus = useCallback(async () => {
    const next = await refreshStatus(true);
    if (!next) {
      throw new Error("Could not refresh vdpi status.");
    }
    return next;
  }, [refreshStatus]);

  const handlePreferencesChanged = useCallback(
    async (nextPrefs: GuiPreferences) => {
      setGuiPrefsOverride(nextPrefs);
      await handleRefreshSettings();
    },
    [handleRefreshSettings],
  );

  const handleSyncAll = useCallback(async () => {
    if (isTauriRuntime()) {
      await handleRefreshSettings();
      return;
    }
    await Promise.all([refreshStatus(), handleRefreshSettings()]);
  }, [handleRefreshSettings, refreshStatus]);

  const handleRetrySync = useCallback(async () => {
    await Promise.all([refreshStatus(true), handleRefreshSettings()]);
  }, [handleRefreshSettings, refreshStatus]);

  const handleBoundaryReset = useCallback(() => {
    setSplitDirty(false);
    setDnsDirty(false);
    setPendingTab(null);
    setConfirmSwitchToTunOpen(false);
    setActiveTab("overview");
    if (mainContentRef.current) {
      mainContentRef.current.scrollTop = 0;
    }
    void Promise.all([refreshStatus(true), handleRefreshSettings()]);
  }, [handleRefreshSettings, refreshStatus]);

  const handleCopyActivity = useCallback(async (): Promise<boolean> => {
    if (activity.length === 0) {
      return false;
    }

    try {
      await copyTextToClipboard(formatActivityForClipboard(activity));
      if (mountedRef.current) {
        pushToast("success", "Activity log copied to clipboard.");
      }
      return true;
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getErrorMessage(err, "Failed to copy activity log."),
        );
      }
      return false;
    }
  }, [activity, pushToast]);

  const isLeavingDns = activeTab === "dns";
  const switchToTunAdminNote =
    status?.platform === "windows"
      ? " A Windows administrator prompt may appear to restart the background service."
      : status?.platform === "macos"
        ? " A macOS administrator prompt may appear to restart the background service."
        : "";

  return (
    <div className="app-shell">
      <a
        href="#main-content"
        className="skip-link"
        onClick={() => {
          mainContentRef.current?.focus();
        }}
      >
        Skip to main content
      </a>

      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        status={status}
        keepInTrayOnClose={keepInTrayOnClose}
        trayActive={trayPrefsActive}
        vpnCoexistence={effectiveSettings?.vpnCoexistence}
      />

      <main
        id="main-content"
        ref={mainContentRef}
        className="main-content"
        tabIndex={-1}
        aria-label="Workspace"
      >
        <div className="view-container">
          {error && !loading ? (
            <InlineBanner
              tone="error"
              title={
                statusError
                  ? "Unable to reach vdpi desktop backend"
                  : "Unable to load vdpi settings"
              }
              description={scrubUrlsInText(error)}
              actionLabel="Retry"
              onAction={() => {
                void handleRetrySync();
              }}
            />
          ) : null}

          {status?.configWarning ? (
            <InlineBanner
              tone="warn"
              title="Configuration warning"
              description={scrubUrlsInText(status.configWarning)}
            />
          ) : null}

          <AppErrorBoundary
            resetKey={activeTab}
            compact
            onReset={handleBoundaryReset}
          >
            {activeTab === "overview" ? (
              <OverviewView
                status={status}
                settings={effectiveSettings}
                history={history}
                activity={activity}
                busyAction={busyAction}
                onToggleProtection={handleToggleProtection}
                onSwitchEngine={handleSwitchEngine}
                onInstallService={handleInstallService}
                onOpenAppFolder={handleOpenOverviewAppFolder}
                onRefreshStatus={handleRefreshStatus}
                onPushToast={handlePushToast}
                onNavigate={handleSelectTab}
                onClearActivity={clearActivity}
                onCopyActivity={handleCopyActivity}
              />
            ) : null}

            {activeTab === "split" ? (
              <SplitTunnelView
                activeEngine={activeEngine}
                platform={status?.platform}
                busyAction={busyAction}
                onSaved={handleSyncAll}
                onPushToast={handlePushToast}
                onDirtyChange={setSplitDirty}
                onSwitchToTun={handleSwitchToTun}
              />
            ) : null}

            {activeTab === "dns" ? (
              <DnsRulesView
                settings={effectiveSettings}
                status={status}
                onSaved={handleSyncAll}
                onPushToast={handlePushToast}
                onDirtyChange={setDnsDirty}
              />
            ) : null}

            {activeTab === "diagnostics" ? (
              <DiagnosticsView
                status={status}
                busyAction={busyAction}
                onPushToast={handlePushToast}
                onNavigate={handleSelectTab}
                onSwitchEngine={handleSwitchEngine}
                onStartProtection={handleStartProtection}
                onOpenAppFolder={handleOpenAppFolder}
              />
            ) : null}

            {activeTab === "settings" ? (
              <SettingsView
                status={status}
                settings={effectiveSettings}
                onPreferencesChanged={handlePreferencesChanged}
                onRefreshSettings={handleRefreshSettings}
                onServiceChanged={handleSyncAll}
                onPushToast={handlePushToast}
              />
            ) : null}
          </AppErrorBoundary>
        </div>
      </main>

      <ConfirmDialog
        open={pendingTab !== null}
        title={
          isLeavingDns
            ? "Discard unsaved DNS & Rules changes?"
            : "Discard unsaved split tunnel changes?"
        }
        description={
          isLeavingDns
            ? "You have unsaved changes in DNS & Rules. Leaving this tab will discard your edits."
            : "You have unsaved changes in Split Tunneling. Leaving this tab will discard your edits."
        }
        confirmLabel="Discard & Leave"
        cancelLabel="Stay"
        danger
        onConfirm={handleConfirmLeaveDirty}
        onCancel={handleCancelLeaveDirty}
      />

      <ConfirmDialog
        open={confirmSwitchToTunOpen}
        title="Switch to Full-PC (TUN)?"
        description={`Switching to Full-PC (TUN) mode restarts protection, so active connections will reconnect briefly while the virtual adapter starts.${switchToTunAdminNote}`}
        confirmLabel="Switch to Full-PC (TUN)"
        cancelLabel="Cancel"
        onConfirm={handleConfirmSwitchToTun}
        onCancel={handleCancelSwitchToTun}
      />

      <ToastStack
        toasts={toastItems}
        onDismiss={dismissToast}
        onPauseTimer={pauseToastTimer}
        onResumeTimer={resumeToastTimer}
      />
    </div>
  );
}

export function App() {
  return (
    <AppErrorBoundary>
      <AppShell />
    </AppErrorBoundary>
  );
}

export default App;
