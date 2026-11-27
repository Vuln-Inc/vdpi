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
import {
  I18nProvider,
  resolveLanguage,
  useLang,
  type ResolvedLanguage,
} from "./i18n/context";
import { localizeActivityMessage } from "./i18n/overview";
import {
  LANGUAGE_STORAGE_KEY,
  localizeActionMessage,
  tShell,
} from "./i18n/shell";
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
  LanguagePreference,
  NavTab,
  ThemePreference,
} from "./types";
import { DiagnosticsView } from "./views/DiagnosticsView";
import { DnsRulesView } from "./views/DnsRulesView";
import { OverviewView } from "./views/OverviewView";
import { SettingsView } from "./views/SettingsView";
import { SplitTunnelView } from "./views/SplitTunnelView";

const TRAY_ACTION_RESULT_EVENT = "vdpi://tray-action-result";

function readStoredLanguage(): LanguagePreference | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }
  try {
    const raw = window.localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (raw === "system" || raw === "en" || raw === "tr") {
      return raw;
    }
  } catch {
    // Ignore storage access errors in restricted webviews.
  }
  return undefined;
}

function writeStoredLanguage(language: LanguagePreference): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, language);
  } catch {
    // Ignore storage access errors in restricted webviews.
  }
}

function resolveBoundaryLang(explicit?: ResolvedLanguage): ResolvedLanguage {
  if (explicit) return explicit;
  if (typeof document !== "undefined") {
    const docLang = document.documentElement.lang?.trim().toLowerCase();
    if (docLang === "tr") return "tr";
    if (docLang === "en") return "en";
  }
  return resolveLanguage(readStoredLanguage());
}

interface ErrorBoundaryProps {
  children: ReactNode;
  resetKey?: string;
  compact?: boolean;
  lang?: ResolvedLanguage;
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

    const lang = resolveBoundaryLang(this.props.lang);
    const safeMessage = scrubUrlsInText(
      error.message || tShell(lang, "errorBoundaryUnexpected"),
    );

    const content = (
      <section className="card" role="alert">
        <div className="card-header">
          <div className="card-title-group">
            <h1 className="card-title">
              {tShell(lang, "errorBoundaryTitle")}
            </h1>
          </div>
        </div>
        <p className="text-secondary">{tShell(lang, "errorBoundaryDesc")}</p>
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
              {tShell(lang, "errorBoundaryTryAgain")}
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={this.handleReload}
            >
              {tShell(lang, "errorBoundaryReload")}
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
  lang: ResolvedLanguage,
  message: string | null | undefined,
  fallback: string,
): string {
  const trimmed = message?.trim();
  return trimmed
    ? localizeActionMessage(lang, scrubUrlsInText(trimmed))
    : fallback;
}

async function copyTextToClipboard(
  text: string,
  lang: ResolvedLanguage,
): Promise<void> {
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
    throw new Error(tShell(lang, "clipboardUnavailable"));
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
      throw new Error(tShell(lang, "copyCommandFailed"));
    }
  } finally {
    document.body.removeChild(textarea);
  }
}

function formatActivityForClipboard(
  events: readonly ActivityEvent[],
  lang: ResolvedLanguage,
): string {
  return events
    .map(
      (event) =>
        `[${formatClockTime(event.tsMs)}] [${event.category.toUpperCase()}] [${event.level.toUpperCase()}] ${localizeActivityMessage(lang, event.message)}`,
    )
    .join("\n");
}

interface AppShellContentProps {
  desktop: ReturnType<typeof useDesktopStatus>;
  effectiveSettings: DesktopSettingsPayload | null;
  keepInTrayOnClose: boolean;
  trayPrefsActive: boolean;
  onPreferencesPreview: (nextPrefs: GuiPreferences) => void;
  onPreferencesChanged: (nextPrefs: GuiPreferences) => Promise<void>;
  onRefreshSettings: () => Promise<DesktopSettingsPayload | null>;
}

function AppShellContent({
  desktop,
  effectiveSettings,
  keepInTrayOnClose,
  trayPrefsActive,
  onPreferencesPreview,
  onPreferencesChanged,
  onRefreshSettings,
}: AppShellContentProps) {
  const { lang } = useLang();
  const [activeTab, setActiveTab] = useState<NavTab>("overview");
  const [busyAction, setBusyAction] = useState<string | null>(null);
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
  const langRef = useRef<ResolvedLanguage>(lang);

  const {
    status,
    loading,
    error,
    statusError,
    history,
    activity,
    toasts,
    refreshStatus,
    pushToast,
    dismissToast,
    pauseToastTimer,
    resumeToastTimer,
    clearActivity,
  } = desktop;

  platformRef.current = status?.platform;
  langRef.current = lang;

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
      const currentLang = langRef.current;
      const surfaceLabel =
        platformRef.current === "macos"
          ? tShell(currentLang, "surfaceMenuBar")
          : tShell(currentLang, "surfaceTray");
      if (payload.cancelled) {
        pushToast(
          "info",
          safeActionMessage(
            currentLang,
            payload.message,
            tShell(currentLang, "trayActionCancelled", {
              surface: surfaceLabel,
            }),
          ),
        );
      } else if (!payload.ok) {
        pushToast(
          "error",
          safeActionMessage(
            currentLang,
            payload.message,
            tShell(currentLang, "trayActionFailed", {
              surface: surfaceLabel,
            }),
          ),
        );
      } else if (payload.needsRestart) {
        pushToast(
          "warn",
          safeActionMessage(
            currentLang,
            payload.message,
            tShell(currentLang, "actionNeedsRestart"),
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

        const currentLang = langRef.current;
        if (result.cancelled) {
          pushToast(
            "info",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "protectionCancelled"),
            ),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "protectionUpdateFailed"),
            ),
          );
        } else if (result.needsRestart) {
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "protectionNeedsRestart"),
            ),
          );
        } else if (result.message?.trim()) {
          pushToast(
            "success",
            localizeActionMessage(
              currentLang,
              scrubUrlsInText(result.message.trim()),
            ),
          );
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(err, tShell(langRef.current, "protectionToggleFailed")),
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
          await onRefreshSettings();
        } else {
          await Promise.all([refreshStatus(), onRefreshSettings()]);
        }
        if (!mountedRef.current) {
          return;
        }

        const currentLang = langRef.current;
        const label = engine === "tun" ? "TUN" : "Proxy";
        if (result.cancelled) {
          pushToast(
            "info",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "engineSwitchCancelled", { engine: label }),
            ),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "engineSwitchFailed", { engine: label }),
            ),
          );
        } else if (result.needsRestart) {
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "engineSwitchNeedsRestart", {
                engine: label,
              }),
            ),
          );
        } else {
          pushToast(
            "success",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "engineSwitchSuccess", { engine: label }),
            ),
          );
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(
              err,
              tShell(langRef.current, "engineSwitchGenericFailed"),
            ),
          );
        }
      } finally {
        setBusy(null);
      }
    },
    [activeEngine, onRefreshSettings, pushToast, refreshStatus, setBusy],
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
        await onRefreshSettings();
      } else {
        await Promise.all([refreshStatus(), onRefreshSettings()]);
      }
      if (!mountedRef.current) {
        return;
      }

      const currentLang = langRef.current;
      if (result.cancelled) {
        pushToast(
          "info",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "installCancelled"),
          ),
        );
      } else if (!result.ok) {
        pushToast(
          "error",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "installFailed"),
          ),
        );
      } else if (result.needsRestart) {
        pushToast(
          "warn",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "installNeedsRestart"),
          ),
        );
      } else {
        pushToast(
          "success",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "installSuccess"),
          ),
        );
      }
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getErrorMessage(err, tShell(langRef.current, "installFailed")),
        );
      }
    } finally {
      setBusy(null);
    }
  }, [onRefreshSettings, pushToast, refreshStatus, setBusy]);

  const handleOpenAppFolder = useCallback(
    async (kind: AppFolderTarget = "app") => {
      const currentLang = langRef.current;
      const folderLabel =
        kind === "config"
          ? tShell(currentLang, "folderKindConfig")
          : kind === "logs"
            ? tShell(currentLang, "folderKindLogs")
            : tShell(currentLang, "folderKindApp");
      try {
        const result = await openAppFolder(kind);
        if (!mountedRef.current) {
          return;
        }
        if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "openFolderFailed", { kind: folderLabel }),
            ),
          );
        } else if (!isTauriRuntime() && result.message?.trim()) {
          pushToast(
            "info",
            localizeActionMessage(
              currentLang,
              scrubUrlsInText(result.message.trim()),
            ),
          );
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getErrorMessage(
              err,
              tShell(currentLang, "openFolderFailed", { kind: folderLabel }),
            ),
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
      throw new Error(tShell(langRef.current, "refreshStatusFailed"));
    }
    return next;
  }, [refreshStatus]);

  const handleSyncAll = useCallback(async () => {
    if (isTauriRuntime()) {
      await onRefreshSettings();
      return;
    }
    await Promise.all([refreshStatus(), onRefreshSettings()]);
  }, [onRefreshSettings, refreshStatus]);

  const handleRetrySync = useCallback(async () => {
    await Promise.all([refreshStatus(true), onRefreshSettings()]);
  }, [onRefreshSettings, refreshStatus]);

  const handleBoundaryReset = useCallback(() => {
    setSplitDirty(false);
    setDnsDirty(false);
    setPendingTab(null);
    setConfirmSwitchToTunOpen(false);
    setActiveTab("overview");
    if (mainContentRef.current) {
      mainContentRef.current.scrollTop = 0;
    }
    void Promise.all([refreshStatus(true), onRefreshSettings()]);
  }, [onRefreshSettings, refreshStatus]);

  const handleCopyActivity = useCallback(async (): Promise<boolean> => {
    if (activity.length === 0) {
      return false;
    }

    const currentLang = langRef.current;
    try {
      await copyTextToClipboard(
        formatActivityForClipboard(activity, currentLang),
        currentLang,
      );
      if (mountedRef.current) {
        pushToast("success", tShell(currentLang, "activityCopied"));
      }
      return true;
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getErrorMessage(err, tShell(currentLang, "activityCopyFailed")),
        );
      }
      return false;
    }
  }, [activity, pushToast]);

  const isLeavingDns = activeTab === "dns";
  const switchToTunAdminNote =
    status?.platform === "windows"
      ? tShell(lang, "switchToTunAdminWindows")
      : status?.platform === "macos"
        ? tShell(lang, "switchToTunAdminMac")
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
        {tShell(lang, "skipToMain")}
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
        aria-label={tShell(lang, "workspaceAria")}
      >
        <div className="view-container">
          {error && !loading ? (
            <InlineBanner
              tone="error"
              title={
                statusError
                  ? tShell(lang, "backendUnreachableTitle")
                  : tShell(lang, "settingsLoadErrorTitle")
              }
              description={scrubUrlsInText(error)}
              actionLabel={tShell(lang, "retryAction")}
              onAction={() => {
                void handleRetrySync();
              }}
            />
          ) : null}

          {status?.configWarning ? (
            <InlineBanner
              tone="warn"
              title={tShell(lang, "configWarningTitle")}
              description={scrubUrlsInText(status.configWarning)}
            />
          ) : null}

          <AppErrorBoundary
            resetKey={activeTab}
            compact
            lang={lang}
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
                onPreferencesPreview={onPreferencesPreview}
                onPreferencesChanged={onPreferencesChanged}
                onRefreshSettings={onRefreshSettings}
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
            ? tShell(lang, "discardDnsTitle")
            : tShell(lang, "discardSplitTitle")
        }
        description={
          isLeavingDns
            ? tShell(lang, "discardDnsDesc")
            : tShell(lang, "discardSplitDesc")
        }
        confirmLabel={tShell(lang, "discardConfirm")}
        cancelLabel={tShell(lang, "discardCancel")}
        danger
        onConfirm={handleConfirmLeaveDirty}
        onCancel={handleCancelLeaveDirty}
      />

      <ConfirmDialog
        open={confirmSwitchToTunOpen}
        title={tShell(lang, "switchToTunTitle")}
        description={tShell(lang, "switchToTunDesc", {
          adminNote: switchToTunAdminNote,
        })}
        confirmLabel={tShell(lang, "switchToTunConfirm")}
        cancelLabel={tShell(lang, "cancel")}
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

function AppShell() {
  const desktop = useDesktopStatus();
  const { settings, refreshSettings } = desktop;

  const [guiPrefsOverride, setGuiPrefsOverride] =
    useState<GuiPreferences | null>(null);
  const [storedLanguage, setStoredLanguage] = useState<
    LanguagePreference | undefined
  >(() => readStoredLanguage());
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (settings !== null) {
      setGuiPrefsOverride(null);
      if (settings.gui.language !== undefined) {
        setStoredLanguage(settings.gui.language);
        writeStoredLanguage(settings.gui.language);
      }
    }
  }, [settings]);

  const effectiveSettings = useMemo<DesktopSettingsPayload | null>(() => {
    if (!settings) {
      return null;
    }
    const baseGui = guiPrefsOverride ?? settings.gui;
    const resolvedPrefLang: LanguagePreference =
      baseGui.language ?? storedLanguage ?? "system";
    if (!guiPrefsOverride && baseGui.language === resolvedPrefLang) {
      return settings;
    }
    return {
      ...settings,
      gui: {
        ...baseGui,
        language: resolvedPrefLang,
      },
    };
  }, [settings, guiPrefsOverride, storedLanguage]);

  const effectiveGuiPrefs = guiPrefsOverride ?? settings?.gui ?? null;
  const themePreference: ThemePreference =
    effectiveGuiPrefs?.theme ?? "system";
  const languagePreference: LanguagePreference =
    guiPrefsOverride?.language ??
    settings?.gui?.language ??
    storedLanguage ??
    "system";
  const keepInTrayOnClose = Boolean(effectiveGuiPrefs?.keepInTrayOnClose);
  const trayPrefsActive = Boolean(
    effectiveGuiPrefs?.keepInTrayOnClose ||
      effectiveGuiPrefs?.minimizeToTray ||
      effectiveGuiPrefs?.startMinimizedToTray,
  );

  useTheme(themePreference);

  const handleRefreshSettings = useCallback(async () => {
    const refreshed = await refreshSettings();
    if (mountedRef.current && refreshed) {
      setGuiPrefsOverride(null);
    }
    return refreshed;
  }, [refreshSettings]);

  const handlePreferencesPreview = useCallback((nextPrefs: GuiPreferences) => {
    setGuiPrefsOverride(nextPrefs);
    if (nextPrefs.language) {
      setStoredLanguage(nextPrefs.language);
      writeStoredLanguage(nextPrefs.language);
    }
  }, []);

  const handlePreferencesChanged = useCallback(
    async (nextPrefs: GuiPreferences) => {
      setGuiPrefsOverride(nextPrefs);
      if (nextPrefs.language) {
        setStoredLanguage(nextPrefs.language);
        writeStoredLanguage(nextPrefs.language);
      }
      await handleRefreshSettings();
    },
    [handleRefreshSettings],
  );

  return (
    <I18nProvider preference={languagePreference}>
      <AppShellContent
        desktop={desktop}
        effectiveSettings={effectiveSettings}
        keepInTrayOnClose={keepInTrayOnClose}
        trayPrefsActive={trayPrefsActive}
        onPreferencesPreview={handlePreferencesPreview}
        onPreferencesChanged={handlePreferencesChanged}
        onRefreshSettings={handleRefreshSettings}
      />
    </I18nProvider>
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
