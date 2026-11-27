import {
  Component,
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ErrorInfo,
  type MouseEvent,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { ConfirmDialog } from "./components/ConfirmDialog";
import { IconExternal } from "./components/Icons";
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
import { acquireModalLock } from "./lib/modalLock";
import {
  checkUpdates,
  installService,
  isTauriRuntime,
  openAppFolder,
  openExternalUrl,
  repairService,
  resetNetworkSettings,
  switchEngine,
  toggleProtection,
  uninstallService,
  upgradeService,
  type AppFolderTarget,
} from "./lib/ipc";
import type {
  ActionErrorCode,
  ActionResult,
  ActivityEvent,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  EngineMode,
  GuiPreferences,
  LanguagePreference,
  NavTab,
  ThemePreference,
  UpdateCheckPayload,
} from "./types";
import { DiagnosticsView } from "./views/DiagnosticsView";
import { DnsRulesView } from "./views/DnsRulesView";
import { InstallationView } from "./views/InstallationView";
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

function getLocalizedErrorMessage(
  lang: ResolvedLanguage,
  err: unknown,
  fallback: string,
): string {
  const raw = getErrorMessage(err, "");
  return raw ? localizeActionMessage(lang, raw) : fallback;
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

export type InstallErrorOperation = "install" | "upgrade" | "repair";

export interface InstallErrorState {
  message: string;
  kind: "cancelled" | "wintun" | "antivirus" | "generic";
  attemptedEngine?: EngineMode;
  operation?: InstallErrorOperation;
}

function isCalmTransientCode(code: ActionErrorCode | undefined): boolean {
  return code === "busy" || code === "shutting_down";
}

function formatVersionTag(version: string | null | undefined): string | null {
  const trimmed = version?.trim();
  if (!trimmed) {
    return null;
  }
  const normalized = trimmed.replace(/^v/i, "");
  return normalized.length > 0 ? `v${normalized}` : null;
}

function resolveActionResultMessage(
  lang: ResolvedLanguage,
  result: ActionResult,
  fallback: string,
): string {
  switch (result.code) {
    case "busy":
      return tShell(lang, "actionBusy");
    case "shutting_down":
      return tShell(lang, "actionShuttingDown");
    case "downgrade_blocked":
      return tShell(lang, "upgradeDowngradeBlocked");
    case "version_unknown":
      return tShell(lang, "upgradeVersionUnknown");
    case "bundled_cli_missing":
      return tShell(lang, "upgradeBundledMissing");
    case "wintun_invalid":
      return tShell(lang, "installWintunInvalid");
    case "wintun_missing":
      return tShell(lang, "installWintunMissing");
    case "already_up_to_date":
      return tShell(lang, "upgradeAlreadyUpToDate");
    default:
      return safeActionMessage(lang, result.message, fallback);
  }
}

function classifyInstallError(
  message: string,
  options?: {
    cancelled?: boolean;
    code?: ActionErrorCode;
    attemptedEngine?: EngineMode;
    operation?: InstallErrorOperation;
  },
): InstallErrorState {
  const normalized = message.trim();
  const code = options?.code;
  let kind: InstallErrorState["kind"] = "generic";
  if (
    options?.cancelled ||
    /cancel(l)?ed|iptal|uac.*cancel|aborted by user|user cancelled|elevation.*denied|\b1223\b/i.test(
      normalized,
    )
  ) {
    kind = "cancelled";
  } else if (
    code === "wintun_missing" ||
    code === "wintun_invalid" ||
    /wintun|wintun\.dll|tun driver|adapter driver|sürücü/i.test(normalized)
  ) {
    kind = "wintun";
  } else if (
    code === "bundled_cli_missing" ||
    /antivirus|antivirüs|defender|quarantin|virus|virüs|smartscreen|blocked by|winerror\s*225|error\s*225|\b577\b|security software|güvenlik yazılımı|karantina/i.test(
      normalized,
    )
  ) {
    kind = "antivirus";
  }

  return {
    message: normalized,
    kind,
    attemptedEngine: options?.attemptedEngine,
    operation: options?.operation,
  };
}

const DIALOG_FOCUSABLE_SELECTOR =
  'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

const UPDATE_PROMPT_DIALOG_TESTID = "update-prompt-dialog";

function stripLeadingBullet(line: string): string {
  return line.replace(/^\s*(?:[-*\u2022]\s+)+/, "").trim();
}

function getNavTabTitle(lang: ResolvedLanguage, tab: NavTab): string {
  switch (tab) {
    case "overview":
      return tShell(lang, "navOverview");
    case "split":
      return tShell(lang, "navSplit");
    case "dns":
      return tShell(lang, "navDns");
    case "diagnostics":
      return tShell(lang, "navDiagnostics");
    case "installation":
      return tShell(lang, "navInstallation");
    case "settings":
      return tShell(lang, "navSettings");
  }
}

function guiPrefsEqual(a: GuiPreferences, b: GuiPreferences): boolean {
  return (
    a.theme === b.theme &&
    (a.language ?? "system") === (b.language ?? "system") &&
    a.keepInTrayOnClose === b.keepInTrayOnClose &&
    a.minimizeToTray === b.minimizeToTray &&
    a.startMinimizedToTray === b.startMinimizedToTray &&
    a.showTaskbarIconWhenMinimized === b.showTaskbarIconWhenMinimized
  );
}

type UpdatePromptKind = "engine" | "app";

interface UpdatePromptFeedback {
  tone: "info" | "error";
  message: string;
}

interface UpdatePromptDialogProps {
  open: boolean;
  kind: UpdatePromptKind;
  fromVersion: string | null;
  toVersion: string | null;
  releaseNotes: readonly string[];
  busy: boolean;
  feedback?: UpdatePromptFeedback | null;
  onUpdateNow: () => void;
  onViewInstallation: () => void;
  onDismiss: () => void;
}

function UpdatePromptDialog({
  open,
  kind,
  fromVersion,
  toVersion,
  releaseNotes,
  busy,
  feedback,
  onUpdateNow,
  onViewInstallation,
  onDismiss,
}: UpdatePromptDialogProps) {
  const { lang } = useLang();
  const titleId = useId();
  const descId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const primaryBtnRef = useRef<HTMLButtonElement>(null);
  const onDismissRef = useRef(onDismiss);
  const busyRef = useRef(busy);

  onDismissRef.current = onDismiss;
  busyRef.current = busy;

  useEffect(() => {
    if (!open || typeof document === "undefined") {
      return;
    }

    const previouslyFocused =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;

    const releaseModalLock = acquireModalLock();

    if (primaryBtnRef.current && !primaryBtnRef.current.disabled) {
      primaryBtnRef.current.focus();
    } else {
      dialogRef.current?.focus();
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();
        if (!busyRef.current) {
          onDismissRef.current();
        }
        return;
      }

      if (event.key === "Tab" && dialogRef.current) {
        const focusables = Array.from(
          dialogRef.current.querySelectorAll<HTMLElement>(
            DIALOG_FOCUSABLE_SELECTOR,
          ),
        );
        if (focusables.length === 0) {
          event.preventDefault();
          dialogRef.current.focus();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        const active = document.activeElement;

        if (event.shiftKey) {
          if (active === first || !dialogRef.current.contains(active)) {
            event.preventDefault();
            last.focus();
          }
        } else if (active === last || !dialogRef.current.contains(active)) {
          event.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      releaseModalLock();
      if (previouslyFocused && previouslyFocused.isConnected) {
        previouslyFocused.focus();
      }
    };
  }, [open]);

  useEffect(() => {
    if (!open || !busy || typeof document === "undefined") {
      return;
    }
    const dialogEl = dialogRef.current;
    if (!dialogEl) {
      return;
    }
    const active = document.activeElement;
    if (
      !active ||
      active === document.body ||
      !dialogEl.contains(active) ||
      (active instanceof HTMLButtonElement && active.disabled)
    ) {
      dialogEl.focus();
    }
  }, [open, busy]);

  if (!open) {
    return null;
  }

  const handleBackdropClick = (event: MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget && !busy) {
      onDismiss();
    }
  };

  const title =
    kind === "engine"
      ? tShell(lang, "updatePromptTitleEngine")
      : tShell(lang, "updatePromptTitleApp");
  const description =
    kind === "engine"
      ? tShell(lang, "updatePromptDescEngine")
      : tShell(lang, "updatePromptDescApp");
  const sanitizedNotes =
    kind === "app"
      ? releaseNotes
          .map((line) => scrubUrlsInText(stripLeadingBullet(line)))
          .filter((line) => line.length > 0)
          .slice(0, 4)
      : [tShell(lang, "updatePromptEngineSummary")];

  const versionAria =
    fromVersion && toVersion
      ? tShell(lang, "updatePromptVersionAria", {
          from: fromVersion,
          to: toVersion,
        })
      : toVersion ?? undefined;

  const primaryLabel = busy
    ? tShell(lang, "updatePromptUpdating")
    : kind === "app"
      ? tShell(lang, "updatePromptDownloadLatest")
      : tShell(lang, "updatePromptUpdateNow");

  const modal = (
    <div
      className="modal-backdrop"
      data-testid="update-prompt-backdrop"
      onClick={handleBackdropClick}
    >
      <div
        ref={dialogRef}
        className="modal-card update-prompt-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        aria-busy={busy || undefined}
        data-testid={UPDATE_PROMPT_DIALOG_TESTID}
        tabIndex={-1}
      >
        <div className="update-prompt-header">
          <h2 id={titleId} className="modal-title">
            {title}
          </h2>
          {toVersion ? (
            <span className="badge badge-accent update-prompt-version-badge">
              {versionAria ? (
                <span className="sr-only">{versionAria}</span>
              ) : null}
              {fromVersion ? (
                <>
                  <span aria-hidden="true">{fromVersion}</span>
                  <span
                    className="update-prompt-version-arrow"
                    aria-hidden="true"
                  >
                    -&gt;
                  </span>
                </>
              ) : null}
              <span aria-hidden="true">{toVersion}</span>
            </span>
          ) : null}
        </div>

        <p id={descId} className="update-prompt-desc">
          {description}
        </p>

        {sanitizedNotes.length > 0 ? (
          <div className="update-prompt-notes">
            <span className="update-prompt-notes-title">
              {tShell(lang, "updatePromptNotesHeading")}
            </span>
            <ul className="update-prompt-notes-list">
              {sanitizedNotes.map((note, idx) => (
                <li key={`${idx}-${note.slice(0, 24)}`}>{note}</li>
              ))}
            </ul>
          </div>
        ) : null}

        {feedback ? (
          <InlineBanner tone={feedback.tone} title={feedback.message} />
        ) : null}

        <div className="update-prompt-actions">
          <button
            type="button"
            className="btn btn-ghost"
            disabled={busy}
            onClick={onViewInstallation}
          >
            {tShell(lang, "updatePromptViewInstallation")}
          </button>

          <div className="update-prompt-actions-right">
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              onClick={onDismiss}
            >
              {tShell(lang, "updatePromptNotNow")}
            </button>
            <button
              ref={primaryBtnRef}
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={onUpdateNow}
            >
              {busy ? <span className="spinner" aria-hidden="true" /> : null}
              <span>{primaryLabel}</span>
              {!busy && kind === "app" ? <IconExternal size={14} /> : null}
            </button>
          </div>
        </div>
      </div>
    </div>
  );

  if (typeof document !== "undefined" && document.body) {
    return createPortal(modal, document.body);
  }

  return modal;
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
  const [confirmResetNetworkOpen, setConfirmResetNetworkOpen] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckPayload | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState(false);
  const [updatePromptDismissed, setUpdatePromptDismissed] = useState(false);
  const [updatePromptUpgrading, setUpdatePromptUpgrading] = useState(false);
  const [updatePromptFeedback, setUpdatePromptFeedback] =
    useState<UpdatePromptFeedback | null>(null);
  const [childModalOpen, setChildModalOpen] = useState(false);
  const [dismissedUpgradeKey, setDismissedUpgradeKey] = useState<string | null>(
    null,
  );
  const [navAnnouncement, setNavAnnouncement] = useState("");
  const [installError, setInstallError] = useState<InstallErrorState | null>(
    null,
  );

  const busyActionRef = useRef<string | null>(null);
  const checkingUpdatesRef = useRef(false);
  const autoCheckedUpdatesRef = useRef(false);
  const mountedRef = useRef(true);
  const mainContentRef = useRef<HTMLElement | null>(null);
  const platformRef = useRef<"windows" | "macos" | "linux" | undefined>(
    undefined,
  );
  const langRef = useRef<ResolvedLanguage>(lang);
  const prevLangRef = useRef<ResolvedLanguage>(lang);
  const activeTabRef = useRef<NavTab>(activeTab);
  const splitDirtyRef = useRef(splitDirty);
  const dnsDirtyRef = useRef(dnsDirty);
  const prevStatusRef = useRef<DesktopStatusSnapshot | null>(null);
  const pendingMainFocusRef = useRef(false);
  const pendingTabFocusMainRef = useRef(false);
  const hasMountedTabRef = useRef(false);

  const {
    status,
    loading,
    error,
    statusError,
    history,
    activity,
    toasts,
    refreshStatus,
    applySnapshot,
    pushToast,
    dismissToast,
    pauseToastTimer,
    resumeToastTimer,
    clearActivity,
  } = desktop;

  const toastsRef = useRef(toasts);
  toastsRef.current = toasts;
  activeTabRef.current = activeTab;
  splitDirtyRef.current = splitDirty;
  dnsDirtyRef.current = dnsDirty;

  const ingestActionSnapshot = useCallback(
    (snapshot: DesktopStatusSnapshot | undefined): boolean => {
      if (snapshot && typeof applySnapshot === "function") {
        applySnapshot(snapshot);
        return true;
      }
      return false;
    },
    [applySnapshot],
  );

  platformRef.current = status?.platform;
  langRef.current = lang;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  // Clear stale transient toasts and live announcements when language changes
  // so Turkish screens never display leftover English messages.
  useEffect(() => {
    if (prevLangRef.current === lang) {
      return;
    }
    prevLangRef.current = lang;
    for (const toast of toastsRef.current) {
      dismissToast(toast.id);
    }
    setNavAnnouncement("");
    setUpdatePromptFeedback(null);
  }, [dismissToast, lang]);

  // Clear installError when the underlying lifecycle issue is resolved by a
  // status transition (install completed, upgrade applied, repair finished,
  // wintun restored, or bundled binary restored).
  useEffect(() => {
    const prev = prevStatusRef.current;
    prevStatusRef.current = status;
    if (!prev || !status) {
      return;
    }

    const becameInstalled =
      prev.serviceState === "not_installed" &&
      status.serviceState !== "not_installed";
    const becameRunning =
      prev.serviceState !== "running" && status.serviceState === "running";
    const becameUninstalled =
      prev.serviceState !== "not_installed" &&
      status.serviceState === "not_installed";
    const upgradeResolved =
      prev.cliVersionRelation === "upgrade_available" &&
      (status.cliVersionRelation === "up_to_date" ||
        status.cliVersionRelation === "newer_installed");
    const repairResolved =
      prev.cliVersionRelation === "repair_needed" &&
      status.cliVersionRelation === "up_to_date";
    const staleResolved =
      prev.liveVersionStale === true && status.liveVersionStale === false;
    const wintunRestored = !prev.wintun.ready && status.wintun.ready;
    const bundleRestored =
      prev.canInstallFromBundle === false &&
      status.canInstallFromBundle === true;

    if (
      becameInstalled ||
      becameRunning ||
      becameUninstalled ||
      upgradeResolved ||
      repairResolved ||
      staleResolved
    ) {
      setInstallError(null);
      return;
    }

    if (wintunRestored) {
      setInstallError((current) =>
        current?.kind === "wintun" ? null : current,
      );
    }
    if (bundleRestored) {
      setInstallError((current) =>
        current?.kind === "antivirus" ? null : current,
      );
    }
  }, [status]);

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
      if (!ingestActionSnapshot(payload.snapshot)) {
        void refreshStatus();
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
      } else if (!payload.ok && isCalmTransientCode(payload.code)) {
        pushToast(
          "info",
          resolveActionResultMessage(
            currentLang,
            payload,
            tShell(currentLang, "actionBusy"),
          ),
        );
      } else if (!payload.ok) {
        pushToast(
          "error",
          resolveActionResultMessage(
            currentLang,
            payload,
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
  }, [ingestActionSnapshot, pushToast, refreshStatus]);

  const effectiveBusyAction = busyAction ?? status?.pendingOperation ?? null;
  const effectiveBusyActionRef = useRef<string | null>(effectiveBusyAction);
  effectiveBusyActionRef.current = effectiveBusyAction;
  const resetNetworkBusy =
    effectiveBusyAction === "reset-network" ||
    effectiveBusyAction === "resetting_network";
  const activeEngine: EngineMode =
    status?.live?.engine ??
    status?.configuredEngine ??
    effectiveSettings?.engine ??
    "tun";
  const configuredEngine = status?.configuredEngine ?? effectiveSettings?.engine;
  const isEngineEffective = useCallback(
    (engine: EngineMode): boolean =>
      (!status?.live || status.live.engine === engine) &&
      configuredEngine === engine,
    [configuredEngine, status?.live],
  );
  const isProtectionActive = Boolean(
    status?.live?.running || status?.serviceState === "running",
  );
  const hasAppUpdate = Boolean(updateInfo?.hasUpdate);
  const hasEngineUpgrade =
    status?.cliVersionRelation === "upgrade_available";
  const updatePromptKind: UpdatePromptKind | null = updatePromptUpgrading
    ? "engine"
    : hasEngineUpgrade
      ? "engine"
      : hasAppUpdate
        ? "app"
        : null;

  const updatePromptOpen =
    updatePromptKind !== null &&
    !updatePromptDismissed &&
    !loading &&
    status !== null &&
    pendingTab === null &&
    !confirmSwitchToTunOpen &&
    !confirmResetNetworkOpen &&
    !childModalOpen &&
    (updatePromptUpgrading || effectiveBusyAction === null);

  useEffect(() => {
    if (
      confirmSwitchToTunOpen &&
      (isEngineEffective("tun") || !isProtectionActive)
    ) {
      setConfirmSwitchToTunOpen(false);
    }
  }, [confirmSwitchToTunOpen, isEngineEffective, isProtectionActive]);

  const navigateToTab = useCallback(
    (tab: NavTab, options?: { focusMain?: boolean }) => {
      if (options?.focusMain) {
        pendingMainFocusRef.current = true;
      }
      setActiveTab(tab);
      setPendingTab(null);
      setConfirmSwitchToTunOpen(false);
      setChildModalOpen(false);
      if (
        busyActionRef.current === null &&
        effectiveBusyActionRef.current === null
      ) {
        setConfirmResetNetworkOpen(false);
      }
      if (tab === "installation") {
        setUpdatePromptDismissed(true);
        setUpdatePromptFeedback(null);
      } else {
        setInstallError(null);
      }
      if (tab !== "split") {
        setSplitDirty(false);
      }
      if (tab !== "dns") {
        setDnsDirty(false);
      }
      if (mainContentRef.current) {
        mainContentRef.current.scrollTop = 0;
      }
    },
    [],
  );

  useEffect(() => {
    if (!hasMountedTabRef.current) {
      hasMountedTabRef.current = true;
      return;
    }
    const currentLang = langRef.current;
    const viewTitle = getNavTabTitle(currentLang, activeTab);
    setNavAnnouncement(
      tShell(currentLang, "navAnnouncement", { view: viewTitle }),
    );
    if (pendingMainFocusRef.current) {
      pendingMainFocusRef.current = false;
      mainContentRef.current?.focus({ preventScroll: true });
    }
  }, [activeTab]);

  const requestTabNavigation = useCallback(
    (tab: NavTab, focusMain: boolean) => {
      if (tab === activeTab) {
        if (focusMain) {
          mainContentRef.current?.focus({ preventScroll: true });
        }
        return;
      }
      if (
        (activeTab === "split" && splitDirty) ||
        (activeTab === "dns" && dnsDirty)
      ) {
        pendingTabFocusMainRef.current = focusMain;
        setPendingTab(tab);
        return;
      }
      navigateToTab(tab, { focusMain });
    },
    [activeTab, dnsDirty, navigateToTab, splitDirty],
  );

  const handleSelectTab = useCallback(
    (tab: NavTab) => {
      requestTabNavigation(tab, false);
    },
    [requestTabNavigation],
  );

  const handleProgrammaticNavigate = useCallback(
    (tab: NavTab) => {
      requestTabNavigation(tab, true);
    },
    [requestTabNavigation],
  );

  const handleCancelLeaveDirty = useCallback(() => {
    pendingTabFocusMainRef.current = false;
    setPendingTab(null);
  }, []);

  const handleConfirmLeaveDirty = useCallback(() => {
    if (pendingTab) {
      const shouldFocusMain = pendingTabFocusMainRef.current;
      pendingTabFocusMainRef.current = false;
      navigateToTab(pendingTab, { focusMain: shouldFocusMain });
    }
  }, [navigateToTab, pendingTab]);

  const handleCancelSwitchToTun = useCallback(() => {
    setConfirmSwitchToTunOpen(false);
  }, []);

  const handleDismissUpdatePrompt = useCallback(() => {
    if (updatePromptUpgrading) {
      return;
    }
    setUpdatePromptFeedback(null);
    setUpdatePromptDismissed(true);
  }, [updatePromptUpgrading]);

  const handleDismissUpgrade = useCallback((key: string) => {
    setDismissedUpgradeKey(key);
  }, []);

  const handleCloseModal = useCallback(() => {
    if (confirmResetNetworkOpen) {
      if (!resetNetworkBusy) {
        setConfirmResetNetworkOpen(false);
      }
      return;
    }
    if (confirmSwitchToTunOpen) {
      setConfirmSwitchToTunOpen(false);
      return;
    }
    if (pendingTab !== null) {
      pendingTabFocusMainRef.current = false;
      setPendingTab(null);
      return;
    }
    if (
      updatePromptOpen &&
      !updatePromptUpgrading &&
      effectiveBusyAction === null
    ) {
      setUpdatePromptFeedback(null);
      setUpdatePromptDismissed(true);
    }
  }, [
    confirmResetNetworkOpen,
    confirmSwitchToTunOpen,
    effectiveBusyAction,
    pendingTab,
    resetNetworkBusy,
    updatePromptOpen,
    updatePromptUpgrading,
  ]);

  useKeyboardShortcuts({
    onSelectTab: handleProgrammaticNavigate,
    hasOpenModal:
      pendingTab !== null ||
      confirmSwitchToTunOpen ||
      confirmResetNetworkOpen ||
      childModalOpen ||
      updatePromptOpen,
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
        message: localizeActionMessage(lang, toast.text),
      })),
    [lang, toasts],
  );

  const setBusy = useCallback((next: string | null) => {
    busyActionRef.current = next;
    if (mountedRef.current) {
      setBusyAction(next);
    }
  }, []);

  const syncAfterServiceMutation = useCallback(
    async (snapshot: DesktopStatusSnapshot | undefined) => {
      const appliedDirect = ingestActionSnapshot(snapshot);
      if (appliedDirect) {
        await onRefreshSettings();
        return;
      }
      await Promise.all([refreshStatus(), onRefreshSettings()]);
    },
    [ingestActionSnapshot, onRefreshSettings, refreshStatus],
  );

  const handleCheckUpdates = useCallback(
    async (manual = false) => {
      if (checkingUpdatesRef.current) {
        return;
      }
      checkingUpdatesRef.current = true;
      if (mountedRef.current) {
        setCheckingUpdates(true);
      }

      try {
        const payload = await checkUpdates(Boolean(manual));
        if (!mountedRef.current) {
          return;
        }
        setUpdateInfo(payload);

        if (manual) {
          const currentLang = langRef.current;
          if (payload.hasUpdate) {
            const latestLabel =
              formatVersionTag(payload.latestVersion) ?? payload.latestVersion;
            pushToast(
              "info",
              tShell(currentLang, "checkUpdatesAvailable", {
                version: latestLabel,
              }),
            );
          } else {
            const currentLabel =
              formatVersionTag(payload.currentVersion) ??
              payload.currentVersion;
            pushToast(
              "success",
              tShell(currentLang, "checkUpdatesUpToDate", {
                version: currentLabel,
              }),
            );
          }
        }
      } catch (err) {
        if (manual && mountedRef.current) {
          pushToast(
            "error",
            getLocalizedErrorMessage(
              langRef.current,
              err,
              tShell(langRef.current, "checkUpdatesFailed"),
            ),
          );
        }
      } finally {
        checkingUpdatesRef.current = false;
        if (mountedRef.current) {
          setCheckingUpdates(false);
        }
      }
    },
    [pushToast],
  );

  useEffect(() => {
    if (autoCheckedUpdatesRef.current) {
      return;
    }
    autoCheckedUpdatesRef.current = true;
    void handleCheckUpdates(false);
  }, [handleCheckUpdates]);

  const handleOpenReleaseUrl = useCallback(
    async (url: string) => {
      const currentLang = langRef.current;
      try {
        const result = await openExternalUrl(url);
        if (!mountedRef.current) {
          return;
        }
        if (!result.ok) {
          pushToast(
            "error",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "openReleaseFailed"),
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
            getLocalizedErrorMessage(
              currentLang,
              err,
              tShell(currentLang, "openReleaseFailed"),
            ),
          );
        }
      }
    },
    [pushToast],
  );

  const handleClearInstallError = useCallback(() => {
    setInstallError(null);
  }, []);

  const canAutoRouteToInstallation = useCallback((): boolean => {
    if (activeTabRef.current === "installation") {
      return false;
    }
    if (
      (activeTabRef.current === "split" && splitDirtyRef.current) ||
      (activeTabRef.current === "dns" && dnsDirtyRef.current)
    ) {
      return false;
    }
    return true;
  }, []);

  const handleToggleProtection = useCallback(
    async (connect?: boolean) => {
      if (
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
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

        if (!result.cancelled && !isCalmTransientCode(result.code)) {
          const appliedDirect = ingestActionSnapshot(result.snapshot);
          if (!appliedDirect) {
            await refreshStatus();
            if (!mountedRef.current) {
              return;
            }
          }
        } else if (result.snapshot) {
          ingestActionSnapshot(result.snapshot);
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
        } else if (!result.ok && isCalmTransientCode(result.code)) {
          pushToast(
            "info",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "actionBusy"),
            ),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "protectionUpdateFailed"),
            ),
          );
        } else if (result.needsRestart) {
          setInstallError(null);
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "protectionNeedsRestart"),
            ),
          );
        } else {
          setInstallError(null);
          if (result.message?.trim()) {
            pushToast(
              "success",
              localizeActionMessage(
                currentLang,
                scrubUrlsInText(result.message.trim()),
              ),
            );
          }
        }
      } catch (err) {
        if (mountedRef.current) {
          pushToast(
            "error",
            getLocalizedErrorMessage(
              langRef.current,
              err,
              tShell(langRef.current, "protectionToggleFailed"),
            ),
          );
        }
      } finally {
        setBusy(null);
      }
    },
    [
      ingestActionSnapshot,
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
      if (
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
        return;
      }

      if (isEngineEffective(engine)) {
        return;
      }

      setBusy(engine === "tun" ? "switch-engine:tun" : "switch-engine:proxy");
      try {
        const result = await switchEngine(engine);
        if (!mountedRef.current) {
          return;
        }

        if (!result.cancelled && !isCalmTransientCode(result.code)) {
          await syncAfterServiceMutation(result.snapshot);
          if (!mountedRef.current) {
            return;
          }
        } else if (result.snapshot) {
          ingestActionSnapshot(result.snapshot);
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
        } else if (!result.ok && isCalmTransientCode(result.code)) {
          pushToast(
            "info",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "actionBusy"),
            ),
          );
        } else if (!result.ok) {
          pushToast(
            "error",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "engineSwitchFailed", { engine: label }),
            ),
          );
        } else if (result.needsRestart) {
          setInstallError(null);
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
          setInstallError(null);
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
            getLocalizedErrorMessage(
              langRef.current,
              err,
              tShell(langRef.current, "engineSwitchGenericFailed"),
            ),
          );
        }
      } finally {
        setBusy(null);
      }
    },
    [
      ingestActionSnapshot,
      isEngineEffective,
      pushToast,
      setBusy,
      syncAfterServiceMutation,
    ],
  );

  const handleSwitchToTun = useCallback(() => {
    if (
      busyActionRef.current !== null ||
      effectiveBusyActionRef.current !== null ||
      isEngineEffective("tun")
    ) {
      return;
    }
    if (isProtectionActive) {
      setConfirmSwitchToTunOpen(true);
      return;
    }
    return handleSwitchEngine("tun");
  }, [handleSwitchEngine, isEngineEffective, isProtectionActive]);

  const handleConfirmSwitchToTun = useCallback(() => {
    if (
      busyActionRef.current !== null ||
      effectiveBusyActionRef.current !== null
    ) {
      return;
    }
    setConfirmSwitchToTunOpen(false);
    void handleSwitchEngine("tun");
  }, [handleSwitchEngine]);

  const handleInstallService = useCallback(
    async (engine?: EngineMode) => {
      if (
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
        return;
      }

      const attemptedEngine = engine ?? activeEngine;
      setInstallError(null);
      setBusy("install-service");
      try {
        const result = await installService(engine);
        if (!mountedRef.current) {
          return;
        }

        if (!result.cancelled && !isCalmTransientCode(result.code)) {
          await syncAfterServiceMutation(result.snapshot);
          if (!mountedRef.current) {
            return;
          }
        } else if (result.snapshot) {
          ingestActionSnapshot(result.snapshot);
        }

        const currentLang = langRef.current;
        if (result.cancelled) {
          const message = safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "installCancelled"),
          );
          setInstallError(
            classifyInstallError(message, {
              cancelled: true,
              code: result.code,
              attemptedEngine,
              operation: "install",
            }),
          );
          pushToast("info", message);
          if (canAutoRouteToInstallation()) {
            navigateToTab("installation", { focusMain: true });
          }
        } else if (!result.ok && isCalmTransientCode(result.code)) {
          pushToast(
            "info",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "actionBusy"),
            ),
          );
        } else if (!result.ok) {
          const message = resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "installFailed"),
          );
          setInstallError(
            classifyInstallError(message, {
              code: result.code,
              attemptedEngine,
              operation: "install",
            }),
          );
          pushToast("error", message);
          if (canAutoRouteToInstallation()) {
            navigateToTab("installation", { focusMain: true });
          }
        } else if (result.needsRestart) {
          setInstallError(null);
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "installNeedsRestart"),
            ),
          );
        } else {
          setInstallError(null);
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
          const message = getLocalizedErrorMessage(
            langRef.current,
            err,
            tShell(langRef.current, "installFailed"),
          );
          setInstallError(
            classifyInstallError(message, {
              attemptedEngine,
              operation: "install",
            }),
          );
          pushToast("error", message);
          if (canAutoRouteToInstallation()) {
            navigateToTab("installation", { focusMain: true });
          }
        }
      } finally {
        setBusy(null);
      }
    },
    [
      activeEngine,
      canAutoRouteToInstallation,
      ingestActionSnapshot,
      navigateToTab,
      pushToast,
      setBusy,
      syncAfterServiceMutation,
    ],
  );

  const runUpgradeService = useCallback(
    async (
      fromPrompt = false,
    ): Promise<{
      outcome:
        | "succeeded"
        | "already_up_to_date"
        | "downgrade_blocked"
        | "busy"
        | "cancelled"
        | "failed";
      message?: string;
    }> => {
      if (
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
        return { outcome: "busy" };
      }

      setInstallError(null);
      setBusy("upgrade-service");
      try {
        const result = await upgradeService();
        if (!mountedRef.current) {
          return { outcome: "busy" };
        }

        if (!result.cancelled && !isCalmTransientCode(result.code)) {
          await syncAfterServiceMutation(result.snapshot);
          if (!mountedRef.current) {
            return { outcome: "busy" };
          }
        } else if (result.snapshot) {
          ingestActionSnapshot(result.snapshot);
        }

        const currentLang = langRef.current;
        if (result.cancelled) {
          const message = safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "upgradeCancelled"),
          );
          setInstallError(
            classifyInstallError(message, {
              cancelled: true,
              code: result.code,
              attemptedEngine: activeEngine,
              operation: "upgrade",
            }),
          );
          pushToast("info", message);
          return { outcome: "cancelled", message };
        }
        if (!result.ok && isCalmTransientCode(result.code)) {
          const message = resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "actionBusy"),
          );
          pushToast("info", message);
          return { outcome: "busy", message };
        }
        if (!result.ok) {
          const message = resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "upgradeFailed"),
          );
          if (result.code === "downgrade_blocked") {
            setUpdatePromptFeedback(null);
            setUpdatePromptDismissed(true);
            pushToast("warn", message);
            return { outcome: "downgrade_blocked", message };
          }
          setInstallError(
            classifyInstallError(message, {
              code: result.code,
              attemptedEngine: activeEngine,
              operation: "upgrade",
            }),
          );
          pushToast("error", message);
          if (!fromPrompt && canAutoRouteToInstallation()) {
            navigateToTab("installation", { focusMain: true });
          }
          return { outcome: "failed", message };
        }
        if (result.code === "already_up_to_date") {
          setInstallError(null);
          setUpdatePromptFeedback(null);
          setUpdatePromptDismissed(true);
          pushToast("info", tShell(currentLang, "upgradeAlreadyUpToDate"));
          return { outcome: "already_up_to_date" };
        }
        if (result.needsRestart) {
          setInstallError(null);
          setUpdatePromptFeedback(null);
          setUpdatePromptDismissed(true);
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "upgradeNeedsRestart"),
            ),
          );
          return { outcome: "succeeded" };
        }
        setInstallError(null);
        setUpdatePromptFeedback(null);
        setUpdatePromptDismissed(true);
        pushToast(
          "success",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "upgradeSuccess"),
          ),
        );
        return { outcome: "succeeded" };
      } catch (err) {
        if (mountedRef.current) {
          const message = getLocalizedErrorMessage(
            langRef.current,
            err,
            tShell(langRef.current, "upgradeFailed"),
          );
          setInstallError(
            classifyInstallError(message, {
              attemptedEngine: activeEngine,
              operation: "upgrade",
            }),
          );
          pushToast("error", message);
          if (!fromPrompt && canAutoRouteToInstallation()) {
            navigateToTab("installation", { focusMain: true });
          }
          return { outcome: "failed", message };
        }
        return { outcome: "failed" };
      } finally {
        setBusy(null);
      }
    },
    [
      activeEngine,
      canAutoRouteToInstallation,
      ingestActionSnapshot,
      navigateToTab,
      pushToast,
      setBusy,
      syncAfterServiceMutation,
    ],
  );

  const handleUpgradeService = useCallback(async () => {
    await runUpgradeService(false);
  }, [runUpgradeService]);

  const handleRepairService = useCallback(
    async (engine?: EngineMode) => {
      if (
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
        return;
      }

      const attemptedEngine = engine ?? activeEngine;
      setInstallError(null);
      setBusy("repair-service");
      try {
        const result = await repairService(engine);
        if (!mountedRef.current) {
          return;
        }

        if (!result.cancelled && !isCalmTransientCode(result.code)) {
          await syncAfterServiceMutation(result.snapshot);
          if (!mountedRef.current) {
            return;
          }
        } else if (result.snapshot) {
          ingestActionSnapshot(result.snapshot);
        }

        const currentLang = langRef.current;
        if (result.cancelled) {
          const message = safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "repairCancelled"),
          );
          setInstallError(
            classifyInstallError(message, {
              cancelled: true,
              code: result.code,
              attemptedEngine,
              operation: "repair",
            }),
          );
          pushToast("info", message);
        } else if (!result.ok && isCalmTransientCode(result.code)) {
          pushToast(
            "info",
            resolveActionResultMessage(
              currentLang,
              result,
              tShell(currentLang, "actionBusy"),
            ),
          );
        } else if (!result.ok) {
          const message = resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "repairFailed"),
          );
          setInstallError(
            classifyInstallError(message, {
              code: result.code,
              attemptedEngine,
              operation: "repair",
            }),
          );
          pushToast("error", message);
        } else if (result.needsRestart) {
          setInstallError(null);
          pushToast(
            "warn",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "repairNeedsRestart"),
            ),
          );
        } else {
          setInstallError(null);
          pushToast(
            "success",
            safeActionMessage(
              currentLang,
              result.message,
              tShell(currentLang, "repairSuccess"),
            ),
          );
        }
      } catch (err) {
        if (mountedRef.current) {
          const message = getLocalizedErrorMessage(
            langRef.current,
            err,
            tShell(langRef.current, "repairFailed"),
          );
          setInstallError(
            classifyInstallError(message, {
              attemptedEngine,
              operation: "repair",
            }),
          );
          pushToast("error", message);
        }
      } finally {
        setBusy(null);
      }
    },
    [
      activeEngine,
      ingestActionSnapshot,
      pushToast,
      setBusy,
      syncAfterServiceMutation,
    ],
  );

  const handleUninstallService = useCallback(async () => {
    if (
      busyActionRef.current !== null ||
      effectiveBusyActionRef.current !== null
    ) {
      return;
    }

    setInstallError(null);
    setBusy("uninstall-service");
    try {
      const result = await uninstallService();
      if (!mountedRef.current) {
        return;
      }

      if (!result.cancelled && !isCalmTransientCode(result.code)) {
        await syncAfterServiceMutation(result.snapshot);
        if (!mountedRef.current) {
          return;
        }
      } else if (result.snapshot) {
        ingestActionSnapshot(result.snapshot);
      }

      const currentLang = langRef.current;
      if (result.cancelled) {
        pushToast(
          "info",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "uninstallCancelled"),
          ),
        );
      } else if (!result.ok && isCalmTransientCode(result.code)) {
        pushToast(
          "info",
          resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "actionBusy"),
          ),
        );
      } else if (!result.ok) {
        pushToast(
          "error",
          resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "uninstallFailed"),
          ),
        );
      } else {
        pushToast(
          "success",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "uninstallSuccess"),
          ),
        );
      }
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getLocalizedErrorMessage(
            langRef.current,
            err,
            tShell(langRef.current, "uninstallFailed"),
          ),
        );
      }
    } finally {
      setBusy(null);
    }
  }, [ingestActionSnapshot, pushToast, setBusy, syncAfterServiceMutation]);

  const handleRequestResetNetwork = useCallback(() => {
    if (
      busyActionRef.current !== null ||
      effectiveBusyActionRef.current !== null
    ) {
      return;
    }
    setConfirmResetNetworkOpen(true);
  }, []);

  const handleCancelResetNetwork = useCallback(() => {
    if (!resetNetworkBusy) {
      setConfirmResetNetworkOpen(false);
    }
  }, [resetNetworkBusy]);

  const handleConfirmResetNetwork = useCallback(async () => {
    if (
      busyActionRef.current !== null ||
      effectiveBusyActionRef.current !== null
    ) {
      return;
    }

    setBusy("reset-network");
    try {
      const result = await resetNetworkSettings();
      if (!mountedRef.current) {
        return;
      }

      if (!result.cancelled && !isCalmTransientCode(result.code)) {
        await syncAfterServiceMutation(result.snapshot);
        if (!mountedRef.current) {
          return;
        }
      } else if (result.snapshot) {
        ingestActionSnapshot(result.snapshot);
      }

      const currentLang = langRef.current;
      if (result.cancelled) {
        pushToast(
          "info",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "resetNetworkCancelled"),
          ),
        );
      } else if (!result.ok && isCalmTransientCode(result.code)) {
        pushToast(
          "info",
          resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "actionBusy"),
          ),
        );
      } else if (!result.ok) {
        pushToast(
          "error",
          resolveActionResultMessage(
            currentLang,
            result,
            tShell(currentLang, "resetNetworkFailed"),
          ),
        );
      } else {
        setInstallError(null);
        pushToast(
          "success",
          safeActionMessage(
            currentLang,
            result.message,
            tShell(currentLang, "resetNetworkSuccess"),
          ),
        );
      }
    } catch (err) {
      if (mountedRef.current) {
        pushToast(
          "error",
          getLocalizedErrorMessage(
            langRef.current,
            err,
            tShell(langRef.current, "resetNetworkFailed"),
          ),
        );
      }
    } finally {
      setBusy(null);
      if (mountedRef.current) {
        setConfirmResetNetworkOpen(false);
      }
    }
  }, [ingestActionSnapshot, pushToast, setBusy, syncAfterServiceMutation]);

  const handleUpdatePromptAction = useCallback(() => {
    if (updatePromptKind === "engine") {
      if (
        updatePromptUpgrading ||
        busyActionRef.current !== null ||
        effectiveBusyActionRef.current !== null
      ) {
        return;
      }
      setUpdatePromptFeedback(null);
      setUpdatePromptUpgrading(true);
      void runUpgradeService(true)
        .then((res) => {
          if (!mountedRef.current) {
            return;
          }
          if (res.outcome === "cancelled") {
            setUpdatePromptFeedback({
              tone: "info",
              message:
                res.message ?? tShell(langRef.current, "upgradeCancelled"),
            });
          } else if (res.outcome === "failed") {
            if (canAutoRouteToInstallation()) {
              setUpdatePromptFeedback(null);
              setUpdatePromptDismissed(true);
              navigateToTab("installation", { focusMain: true });
            } else {
              setUpdatePromptFeedback({
                tone: "error",
                message:
                  res.message ?? tShell(langRef.current, "upgradeFailed"),
              });
            }
          }
        })
        .finally(() => {
          if (mountedRef.current) {
            setUpdatePromptUpgrading(false);
          }
        });
      return;
    }

    setUpdatePromptFeedback(null);
    setUpdatePromptDismissed(true);
    const releaseUrl = updateInfo?.releaseUrl?.trim();
    if (releaseUrl) {
      void handleOpenReleaseUrl(releaseUrl);
      return;
    }
    handleProgrammaticNavigate("installation");
  }, [
    canAutoRouteToInstallation,
    handleOpenReleaseUrl,
    handleProgrammaticNavigate,
    navigateToTab,
    runUpgradeService,
    updateInfo?.releaseUrl,
    updatePromptKind,
    updatePromptUpgrading,
  ]);

  const handleViewUpdateInInstallation = useCallback(() => {
    if (updatePromptUpgrading) {
      return;
    }
    setUpdatePromptFeedback(null);
    setUpdatePromptDismissed(true);
    handleProgrammaticNavigate("installation");
  }, [handleProgrammaticNavigate, updatePromptUpgrading]);

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
            getLocalizedErrorMessage(
              currentLang,
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

  const handleRefreshInstallationStatus = useCallback(async (): Promise<void> => {
    const next = await refreshStatus(true);
    if (!next) {
      throw new Error(tShell(langRef.current, "refreshStatusFailed"));
    }
  }, [refreshStatus]);

  const handleSyncAll = useCallback(
    async (snapshot?: DesktopStatusSnapshot) => {
      const appliedDirect = ingestActionSnapshot(snapshot);
      if (appliedDirect) {
        await onRefreshSettings();
        return;
      }
      await Promise.all([refreshStatus(), onRefreshSettings()]);
    },
    [ingestActionSnapshot, onRefreshSettings, refreshStatus],
  );

  const handleRetrySync = useCallback(async () => {
    await Promise.all([refreshStatus(true), onRefreshSettings()]);
  }, [onRefreshSettings, refreshStatus]);

  const handleBoundaryReset = useCallback(() => {
    setSplitDirty(false);
    setDnsDirty(false);
    setPendingTab(null);
    setConfirmSwitchToTunOpen(false);
    setConfirmResetNetworkOpen(false);
    setChildModalOpen(false);
    setInstallError(null);
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
          getLocalizedErrorMessage(
            currentLang,
            err,
            tShell(currentLang, "activityCopyFailed"),
          ),
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
  const updatePromptFromVersion =
    updatePromptKind === "engine"
      ? formatVersionTag(status?.installedVersion)
      : formatVersionTag(updateInfo?.currentVersion ?? status?.appVersion);
  const updatePromptToVersion =
    updatePromptKind === "engine"
      ? formatVersionTag(status?.bundledEngineVersion ?? status?.appVersion)
      : formatVersionTag(updateInfo?.latestVersion);

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

      <div
        className="sr-only"
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="route-announcer"
      >
        {navAnnouncement}
      </div>

      <Sidebar
        activeTab={activeTab}
        onSelectTab={handleSelectTab}
        status={status}
        hasAppUpdate={hasAppUpdate}
        latestReleaseVersion={updateInfo?.latestVersion ?? null}
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
              description={localizeActionMessage(lang, scrubUrlsInText(error))}
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

          {status?.runningFromReadonlyDmg && activeTab !== "installation" ? (
            <InlineBanner
              tone="warn"
              title={tShell(lang, "readonlyDmgTitle")}
              description={tShell(lang, "readonlyDmgDesc")}
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
                busyAction={effectiveBusyAction}
                dismissedUpgradeKey={dismissedUpgradeKey}
                onDismissUpgrade={handleDismissUpgrade}
                onToggleProtection={handleToggleProtection}
                onSwitchEngine={handleSwitchEngine}
                onInstallService={handleInstallService}
                onUpgradeService={handleUpgradeService}
                onOpenAppFolder={handleOpenOverviewAppFolder}
                onRefreshStatus={handleRefreshStatus}
                onPushToast={handlePushToast}
                onNavigate={handleProgrammaticNavigate}
                onClearActivity={clearActivity}
                onCopyActivity={handleCopyActivity}
                onModalOpenChange={setChildModalOpen}
              />
            ) : null}

            {activeTab === "split" ? (
              <SplitTunnelView
                activeEngine={activeEngine}
                platform={status?.platform}
                serviceState={status?.serviceState}
                wintunReady={status?.wintun.ready}
                busyAction={effectiveBusyAction}
                onSaved={handleSyncAll}
                onPushToast={handlePushToast}
                onDirtyChange={setSplitDirty}
                onSwitchToTun={handleSwitchToTun}
                onNavigate={handleProgrammaticNavigate}
              />
            ) : null}

            {activeTab === "dns" ? (
              <DnsRulesView
                settings={effectiveSettings}
                status={status}
                serviceState={status?.serviceState}
                busyAction={effectiveBusyAction}
                onSaved={handleSyncAll}
                onPushToast={handlePushToast}
                onDirtyChange={setDnsDirty}
                onNavigate={handleProgrammaticNavigate}
              />
            ) : null}

            {activeTab === "diagnostics" ? (
              <DiagnosticsView
                status={status}
                serviceState={status?.serviceState}
                busyAction={effectiveBusyAction}
                onPushToast={handlePushToast}
                onNavigate={handleProgrammaticNavigate}
                onSwitchEngine={handleSwitchEngine}
                onStartProtection={handleStartProtection}
                onInstallService={handleInstallService}
                onOpenAppFolder={handleOpenAppFolder}
                onResetNetwork={handleRequestResetNetwork}
              />
            ) : null}

            {activeTab === "installation" ? (
              <InstallationView
                status={status}
                settings={effectiveSettings}
                updateInfo={updateInfo}
                checkingUpdates={checkingUpdates}
                busyAction={effectiveBusyAction}
                installError={installError}
                onInstallService={handleInstallService}
                onSwitchEngine={handleSwitchEngine}
                onUpgradeService={handleUpgradeService}
                onRepairService={handleRepairService}
                onUninstallService={handleUninstallService}
                onResetNetwork={handleRequestResetNetwork}
                onCheckUpdates={handleCheckUpdates}
                onOpenReleaseUrl={handleOpenReleaseUrl}
                onOpenAppFolder={handleOpenAppFolder}
                onRefreshStatus={handleRefreshInstallationStatus}
                onClearInstallError={handleClearInstallError}
                onNavigate={handleProgrammaticNavigate}
                onModalOpenChange={setChildModalOpen}
              />
            ) : null}

            {activeTab === "settings" ? (
              <SettingsView
                status={status}
                settings={effectiveSettings}
                updateInfo={updateInfo}
                checkingUpdates={checkingUpdates}
                busyAction={effectiveBusyAction}
                onPreferencesPreview={onPreferencesPreview}
                onPreferencesChanged={onPreferencesChanged}
                onRefreshSettings={onRefreshSettings}
                onServiceChanged={handleSyncAll}
                onInstallService={handleInstallService}
                onUpgradeService={handleUpgradeService}
                onUninstallService={handleUninstallService}
                onResetNetwork={handleRequestResetNetwork}
                onCheckUpdates={handleCheckUpdates}
                onOpenReleaseUrl={handleOpenReleaseUrl}
                onNavigate={handleProgrammaticNavigate}
                onPushToast={handlePushToast}
                onModalOpenChange={setChildModalOpen}
              />
            ) : null}
          </AppErrorBoundary>
        </div>
      </main>

      <UpdatePromptDialog
        open={updatePromptOpen}
        kind={updatePromptKind ?? "app"}
        fromVersion={updatePromptFromVersion}
        toVersion={updatePromptToVersion}
        releaseNotes={updateInfo?.releaseNotes ?? []}
        busy={updatePromptUpgrading || effectiveBusyAction !== null}
        feedback={updatePromptFeedback}
        onUpdateNow={handleUpdatePromptAction}
        onViewInstallation={handleViewUpdateInInstallation}
        onDismiss={handleDismissUpdatePrompt}
      />

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

      <ConfirmDialog
        open={confirmResetNetworkOpen}
        title={tShell(lang, "resetNetworkConfirmTitle")}
        description={tShell(lang, "resetNetworkConfirmBody")}
        confirmLabel={tShell(lang, "resetNetworkConfirmAction")}
        cancelLabel={tShell(lang, "resetNetworkCancelAction")}
        busy={resetNetworkBusy}
        onConfirm={() => {
          void handleConfirmResetNetwork();
        }}
        onCancel={handleCancelResetNetwork}
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

const PREFS_OVERRIDE_GUARD_MS = 15_000;

function AppShell() {
  const desktop = useDesktopStatus();
  const { settings, refreshSettings } = desktop;

  const [guiPrefsOverride, setGuiPrefsOverride] =
    useState<GuiPreferences | null>(null);
  const [storedLanguage, setStoredLanguage] = useState<
    LanguagePreference | undefined
  >(() => readStoredLanguage());
  const mountedRef = useRef(true);
  const settingsRef = useRef<DesktopSettingsPayload | null>(settings);
  const prefsSavePendingRef = useRef(false);
  const prefsPreviewSeqRef = useRef(0);
  const prefsGuardTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  settingsRef.current = settings;

  const clearPrefsGuardTimer = useCallback(() => {
    if (prefsGuardTimerRef.current !== null) {
      clearTimeout(prefsGuardTimerRef.current);
      prefsGuardTimerRef.current = null;
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearPrefsGuardTimer();
    };
  }, [clearPrefsGuardTimer]);

  useEffect(() => {
    if (settings !== null && !prefsSavePendingRef.current) {
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
    const seqAtStart = prefsPreviewSeqRef.current;
    const refreshed = await refreshSettings();
    if (refreshed) {
      settingsRef.current = refreshed;
    }
    if (
      mountedRef.current &&
      refreshed &&
      !prefsSavePendingRef.current &&
      seqAtStart === prefsPreviewSeqRef.current
    ) {
      setGuiPrefsOverride(null);
    }
    return refreshed;
  }, [refreshSettings]);

  const handlePreferencesPreview = useCallback(
    (nextPrefs: GuiPreferences) => {
      const seq = ++prefsPreviewSeqRef.current;
      setGuiPrefsOverride(nextPrefs);
      if (nextPrefs.language) {
        setStoredLanguage(nextPrefs.language);
        writeStoredLanguage(nextPrefs.language);
      }
      clearPrefsGuardTimer();
      const persisted = settingsRef.current?.gui;
      if (persisted && guiPrefsEqual(nextPrefs, persisted)) {
        prefsSavePendingRef.current = false;
        return;
      }
      prefsSavePendingRef.current = true;
      prefsGuardTimerRef.current = setTimeout(() => {
        prefsGuardTimerRef.current = null;
        if (prefsPreviewSeqRef.current === seq) {
          prefsSavePendingRef.current = false;
          if (mountedRef.current) {
            setGuiPrefsOverride(null);
            const persistedLang = settingsRef.current?.gui?.language;
            if (persistedLang !== undefined) {
              setStoredLanguage(persistedLang);
              writeStoredLanguage(persistedLang);
            }
            void refreshSettings();
          }
        }
      }, PREFS_OVERRIDE_GUARD_MS);
    },
    [clearPrefsGuardTimer, refreshSettings],
  );

  const handlePreferencesChanged = useCallback(
    async (nextPrefs: GuiPreferences) => {
      const seq = ++prefsPreviewSeqRef.current;
      clearPrefsGuardTimer();
      prefsSavePendingRef.current = true;
      setGuiPrefsOverride(nextPrefs);
      if (nextPrefs.language) {
        setStoredLanguage(nextPrefs.language);
        writeStoredLanguage(nextPrefs.language);
      }
      try {
        const refreshed = await refreshSettings();
        if (refreshed) {
          settingsRef.current = refreshed;
        }
        if (mountedRef.current && seq === prefsPreviewSeqRef.current) {
          prefsSavePendingRef.current = false;
          if (refreshed) {
            setGuiPrefsOverride(null);
            const nextLang = refreshed.gui.language ?? nextPrefs.language;
            if (nextLang !== undefined) {
              setStoredLanguage(nextLang);
              writeStoredLanguage(nextLang);
            }
          }
        }
      } finally {
        if (seq === prefsPreviewSeqRef.current) {
          prefsSavePendingRef.current = false;
        }
      }
    },
    [clearPrefsGuardTimer, refreshSettings],
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
