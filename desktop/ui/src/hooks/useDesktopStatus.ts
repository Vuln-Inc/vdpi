import { useCallback, useEffect, useRef, useState } from "react";
import {
  getSettings,
  getStatus,
  isTauriRuntime,
  subscribeStatus,
} from "../lib/ipc";
import type {
  ActivityEvent,
  DesktopSettingsPayload,
  DesktopStatusSnapshot,
  EngineMode,
  ServiceOperation,
  ServiceState,
  ThroughputPoint,
  VpnCoexistence,
} from "../types";

export type ToastKind = "info" | "success" | "warn" | "error";

export interface ToastMessage {
  id: string;
  kind: ToastKind;
  text: string;
}

export interface UseDesktopStatusResult {
  status: DesktopStatusSnapshot | null;
  settings: DesktopSettingsPayload | null;
  loading: boolean;
  error: string | null;
  statusError: string | null;
  settingsError: string | null;
  history: ThroughputPoint[];
  activity: ActivityEvent[];
  toasts: ToastMessage[];
  refreshStatus: (force?: boolean) => Promise<DesktopStatusSnapshot | null>;
  refreshSettings: () => Promise<DesktopSettingsPayload | null>;
  applySnapshot: (snapshot: DesktopStatusSnapshot) => boolean;
  pushToast: (kind: ToastKind, text: string, durationMs?: number) => string;
  dismissToast: (id: string) => void;
  pauseToastTimer: (id: string) => void;
  resumeToastTimer: (id: string) => void;
  clearActivity: () => void;
}

type ObservedConnectionState = ServiceState | "yielded" | "starting";

interface ObservedSnapshotState {
  connectionState: ObservedConnectionState;
  engine: EngineMode;
  vpnConflict: string | null;
  ispStage: string | null;
  liveRunning: boolean;
  bytesRx: number | null;
  bytesTx: number | null;
}

interface ActivityDraft {
  level: ActivityEvent["level"];
  category: ActivityEvent["category"];
  message: string;
}

interface ToastTimerEntry {
  timer: ReturnType<typeof setTimeout> | null;
  remainingMs: number;
  startedAtMs: number | null;
  pausedByUser: boolean;
}

function isDocumentHidden(): boolean {
  return typeof document !== "undefined" && Boolean(document.hidden);
}

const MAX_HISTORY_POINTS = 60;
const MIN_HISTORY_SAMPLE_GAP_MS = 500;
const MAX_ACTIVITY_EVENTS = 100;
const MAX_TOASTS = 4;
const FALLBACK_POLL_INTERVAL_MS = 2000;
const SETTINGS_RETRY_COOLDOWN_MS = 5000;
const DEFAULT_TOAST_DURATION_MS = 4500;
const ERROR_TOAST_DURATION_MS = 6500;

function toErrorMessage(err: unknown): string {
  if (err instanceof Error && err.message.trim().length > 0) {
    return err.message.trim();
  }
  if (typeof err === "string" && err.trim().length > 0) {
    return err.trim();
  }
  return "Unexpected IPC error";
}

function sanitizeRate(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return 0;
  }
  return value;
}

function formatEngineLabel(engine: EngineMode): string {
  return engine === "tun" ? "TUN" : "Proxy";
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

function deriveObservedConnectionState(
  serviceState: ServiceState,
  vpnConflict: string | null,
  liveRunning: boolean,
  vpnCoexistence: VpnCoexistence | null | undefined,
): ObservedConnectionState {
  if (serviceState === "not_installed") {
    return "not_installed";
  }
  if (liveRunning) {
    return "running";
  }
  if (serviceState === "running") {
    if (Boolean(vpnConflict) && vpnCoexistence === "auto_yield") {
      return "yielded";
    }
    return "starting";
  }
  return "stopped";
}

function observeSnapshot(
  snapshot: DesktopStatusSnapshot,
  vpnCoexistence?: VpnCoexistence | null,
): ObservedSnapshotState {
  const live = snapshot.live;
  const liveRunning = Boolean(live?.running);
  const vpnConflict =
    (live?.vpnConflict ?? snapshot.vpnConflict)?.trim() || null;

  const connectionState = deriveObservedConnectionState(
    snapshot.serviceState,
    vpnConflict,
    liveRunning,
    vpnCoexistence,
  );

  const engine: EngineMode = live?.engine ?? snapshot.configuredEngine;
  const ispStage = live?.ispStage?.trim() || null;
  const bytesRx =
    live && typeof live.bytesRx === "number" && Number.isFinite(live.bytesRx)
      ? live.bytesRx
      : null;
  const bytesTx =
    live && typeof live.bytesTx === "number" && Number.isFinite(live.bytesTx)
      ? live.bytesTx
      : null;

  return {
    connectionState,
    engine,
    vpnConflict,
    ispStage,
    liveRunning,
    bytesRx,
    bytesTx,
  };
}

function isLifecyclePendingOperation(
  pendingOperation: ServiceOperation | null | undefined,
): boolean {
  return (
    pendingOperation === "installing" ||
    pendingOperation === "upgrading" ||
    pendingOperation === "repairing" ||
    pendingOperation === "uninstalling"
  );
}

function deriveActivityDrafts(
  prev: ObservedSnapshotState | null,
  next: ObservedSnapshotState,
  suppressTransientStates: boolean,
): ActivityDraft[] {
  const drafts: ActivityDraft[] = [];

  if (prev === null) {
    if (next.connectionState === "not_installed") {
      if (!suppressTransientStates) {
        drafts.push({
          level: "warn",
          category: "system",
          message: "Service not installed",
        });
      }
    } else if (next.connectionState === "yielded") {
      drafts.push({
        level: "warn",
        category: "engine",
        message: "Protection yielded to VPN",
      });
    } else if (next.connectionState === "running") {
      drafts.push({
        level: "info",
        category: "engine",
        message: `Protection active (${formatEngineLabel(next.engine)})`,
      });
    } else if (next.connectionState === "stopped") {
      if (!suppressTransientStates) {
        drafts.push({
          level: "info",
          category: "engine",
          message: "Protection paused",
        });
      }
    }

    if (next.vpnConflict) {
      drafts.push({
        level: "warn",
        category: "vpn",
        message: `VPN conflict detected: ${next.vpnConflict}`,
      });
    }

    if (next.connectionState === "running" && next.ispStage) {
      drafts.push({
        level: "info",
        category: "engine",
        message: `ISP bypass stage: ${formatStageLabel(next.ispStage)}`,
      });
    }

    return drafts;
  }

  if (prev.engine !== next.engine) {
    drafts.push({
      level: "info",
      category: "engine",
      message: `Engine switched to ${formatEngineLabel(next.engine)}`,
    });
  }

  if (prev.connectionState !== next.connectionState) {
    if (next.connectionState === "yielded") {
      drafts.push({
        level: "warn",
        category: "engine",
        message: "Protection yielded to VPN",
      });
    } else if (next.connectionState === "running") {
      drafts.push({
        level: "info",
        category: "engine",
        message: `Protection active (${formatEngineLabel(next.engine)})`,
      });
    } else if (next.connectionState === "not_installed") {
      if (!suppressTransientStates) {
        drafts.push({
          level: "warn",
          category: "system",
          message: "Service not installed",
        });
      }
    } else if (next.connectionState === "stopped") {
      if (!suppressTransientStates) {
        drafts.push({
          level: "info",
          category: "engine",
          message: "Protection paused",
        });
      }
    }
  }

  if (prev.vpnConflict !== next.vpnConflict) {
    if (next.vpnConflict) {
      drafts.push({
        level: "warn",
        category: "vpn",
        message: `VPN conflict detected: ${next.vpnConflict}`,
      });
    } else if (prev.vpnConflict) {
      drafts.push({
        level: "info",
        category: "vpn",
        message: `VPN conflict cleared (${prev.vpnConflict})`,
      });
    }
  }

  if (prev.ispStage !== next.ispStage) {
    if (next.ispStage) {
      drafts.push({
        level: "info",
        category: "engine",
        message: `ISP bypass stage: ${formatStageLabel(next.ispStage)}`,
      });
    } else if (prev.ispStage && next.connectionState === "running") {
      drafts.push({
        level: "info",
        category: "engine",
        message: "ISP bypass stage reset",
      });
    }
  }

  return drafts;
}

export function useDesktopStatus(): UseDesktopStatusResult {
  const [status, setStatus] = useState<DesktopStatusSnapshot | null>(null);
  const [settings, setSettings] = useState<DesktopSettingsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [history, setHistory] = useState<ThroughputPoint[]>([]);
  const [activity, setActivity] = useState<ActivityEvent[]>([]);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const mountedRef = useRef(true);
  const prevObservedRef = useRef<ObservedSnapshotState | null>(null);
  const lastSeqRef = useRef<number | null>(null);
  const statusSeqRef = useRef(0);
  const settingsSeqRef = useRef(0);
  const statusErrorRef = useRef<string | null>(null);
  const settingsErrorRef = useRef<string | null>(null);
  const settingsRef = useRef<DesktopSettingsPayload | null>(null);
  const settingsInFlightRef = useRef(false);
  const lastSettingsRetryAtRef = useRef(0);
  const idCounterRef = useRef(0);
  const toastTimersRef = useRef<Map<string, ToastTimerEntry>>(new Map());

  const nextId = useCallback((prefix: string): string => {
    idCounterRef.current += 1;
    return `${prefix}-${Date.now()}-${idCounterRef.current}`;
  }, []);

  const refreshSettings =
    useCallback(async (): Promise<DesktopSettingsPayload | null> => {
      const seq = ++settingsSeqRef.current;
      settingsInFlightRef.current = true;
      lastSettingsRetryAtRef.current = Date.now();
      try {
        const nextSettings: DesktopSettingsPayload = await getSettings();
        if (!mountedRef.current || seq < settingsSeqRef.current) {
          return nextSettings;
        }
        settingsRef.current = nextSettings;
        settingsErrorRef.current = null;
        setSettings(nextSettings);
        setSettingsError(null);
        return nextSettings;
      } catch (err) {
        if (mountedRef.current && seq === settingsSeqRef.current) {
          const msg = toErrorMessage(err);
          settingsErrorRef.current = msg;
          setSettingsError(msg);
        }
        return null;
      } finally {
        if (seq === settingsSeqRef.current) {
          lastSettingsRetryAtRef.current = Date.now();
          settingsInFlightRef.current = false;
        }
      }
    }, []);

  const applySnapshot = useCallback(
    (snapshot: DesktopStatusSnapshot): boolean => {
      if (!mountedRef.current) {
        return false;
      }

      const hasSnapshotSeq =
        typeof snapshot.snapshotSeq === "number" &&
        Number.isFinite(snapshot.snapshotSeq);
      if (hasSnapshotSeq) {
        const seq = snapshot.snapshotSeq as number;
        if (lastSeqRef.current !== null && seq <= lastSeqRef.current) {
          if (seq === lastSeqRef.current) {
            const hadErr = statusErrorRef.current !== null;
            if (hadErr) {
              statusErrorRef.current = null;
              setStatusError(null);
            }
            if (
              !settingsInFlightRef.current &&
              settingsErrorRef.current !== null &&
              (hadErr ||
                Date.now() - lastSettingsRetryAtRef.current >=
                  SETTINGS_RETRY_COOLDOWN_MS)
            ) {
              void refreshSettings();
            }
          }
          return false;
        }
        lastSeqRef.current = seq;
      }

      const nowMs = Date.now();
      const hadStatusError = statusErrorRef.current !== null;
      statusErrorRef.current = null;
      setStatus(snapshot);
      setStatusError(null);

      // Retry getSettings() on recovery whenever settings failed or have not yet loaded.
      if (!settingsInFlightRef.current) {
        const needsInitialRecovery =
          settingsRef.current === null && hadStatusError;
        const hasRetryableSettingsError =
          settingsErrorRef.current !== null &&
          (hadStatusError ||
            nowMs - lastSettingsRetryAtRef.current >=
              SETTINGS_RETRY_COOLDOWN_MS);
        if (needsInitialRecovery || hasRetryableSettingsError) {
          void refreshSettings();
        }
      }

      const prevObserved = prevObservedRef.current;
      const observed = observeSnapshot(
        snapshot,
        settingsRef.current?.vpnCoexistence,
      );
      const isLiveRunning = observed.liveRunning;

      if (!isLiveRunning) {
        setHistory((prev) => (prev.length === 0 ? prev : []));
      } else {
        const rxBps = sanitizeRate(snapshot.live?.rxRateBps);
        const txBps = sanitizeRate(snapshot.live?.txRateBps);

        const engineSwitched =
          prevObserved !== null && prevObserved.engine !== observed.engine;
        const sessionRestarted =
          prevObserved !== null &&
          (!prevObserved.liveRunning ||
            (prevObserved.bytesRx !== null &&
              observed.bytesRx !== null &&
              observed.bytesRx < prevObserved.bytesRx) ||
            (prevObserved.bytesTx !== null &&
              observed.bytesTx !== null &&
              observed.bytesTx < prevObserved.bytesTx));

        setHistory((prev) => {
          if (engineSwitched || sessionRestarted) {
            return [{ tsMs: nowMs, rxBps, txBps }];
          }

          const last = prev[prev.length - 1];
          if (last) {
            const deltaMs = nowMs - last.tsMs;
            if (deltaMs >= 0 && deltaMs < MIN_HISTORY_SAMPLE_GAP_MS) {
              if (last.rxBps === rxBps && last.txBps === txBps) {
                return prev;
              }
              const updated = prev.slice();
              updated[updated.length - 1] = {
                tsMs: last.tsMs,
                rxBps,
                txBps,
              };
              return updated;
            }
          }

          const next: ThroughputPoint[] = [
            ...prev,
            { tsMs: nowMs, rxBps, txBps },
          ];
          return next.length > MAX_HISTORY_POINTS
            ? next.slice(next.length - MAX_HISTORY_POINTS)
            : next;
        });
      }

      const suppressTransientStates = isLifecyclePendingOperation(
        snapshot.pendingOperation,
      );
      const drafts = deriveActivityDrafts(
        prevObserved,
        observed,
        suppressTransientStates,
      );
      prevObservedRef.current =
        suppressTransientStates &&
        prevObserved !== null &&
        (observed.connectionState === "stopped" ||
          observed.connectionState === "not_installed")
          ? { ...observed, connectionState: prevObserved.connectionState }
          : observed;

      if (drafts.length > 0) {
        setActivity((prev) => {
          const next = [...prev];
          for (const draft of drafts) {
            const last = next[next.length - 1];
            if (
              last &&
              last.category === draft.category &&
              last.level === draft.level &&
              last.message === draft.message
            ) {
              continue;
            }
            next.push({
              id: nextId("evt"),
              tsMs: nowMs,
              level: draft.level,
              category: draft.category,
              message: draft.message,
            });
          }
          return next.length > MAX_ACTIVITY_EVENTS
            ? next.slice(next.length - MAX_ACTIVITY_EVENTS)
            : next;
        });
      }

      return true;
    },
    [nextId, refreshSettings],
  );

  const refreshStatus = useCallback(
    async (force?: boolean): Promise<DesktopStatusSnapshot | null> => {
      const seq = ++statusSeqRef.current;
      try {
        const snapshot: DesktopStatusSnapshot = await getStatus(force);
        if (!mountedRef.current) {
          return snapshot;
        }
        const hasSnapshotSeq =
          typeof snapshot.snapshotSeq === "number" &&
          Number.isFinite(snapshot.snapshotSeq);
        if (!hasSnapshotSeq && seq < statusSeqRef.current) {
          return snapshot;
        }
        applySnapshot(snapshot);
        return snapshot;
      } catch (err) {
        if (mountedRef.current && seq === statusSeqRef.current) {
          const msg = toErrorMessage(err);
          statusErrorRef.current = msg;
          setStatusError(msg);
        }
        return null;
      }
    },
    [applySnapshot],
  );

  const stopToastTimerEntry = useCallback((entry: ToastTimerEntry) => {
    if (entry.timer !== null) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    if (entry.startedAtMs !== null) {
      const elapsed = Math.max(0, Date.now() - entry.startedAtMs);
      entry.remainingMs = Math.max(0, entry.remainingMs - elapsed);
      entry.startedAtMs = null;
    }
  }, []);

  const startToastTimerEntry = useCallback(
    (id: string, entry: ToastTimerEntry) => {
      if (entry.timer !== null || entry.pausedByUser || isDocumentHidden()) {
        return;
      }
      if (entry.remainingMs <= 0) {
        toastTimersRef.current.delete(id);
        if (mountedRef.current) {
          setToasts((prev) => prev.filter((item) => item.id !== id));
        }
        return;
      }
      entry.startedAtMs = Date.now();
      entry.timer = setTimeout(() => {
        toastTimersRef.current.delete(id);
        if (mountedRef.current) {
          setToasts((prev) => prev.filter((item) => item.id !== id));
        }
      }, entry.remainingMs);
    },
    [],
  );

  const pauseToastTimer = useCallback(
    (id: string) => {
      const entry = toastTimersRef.current.get(id);
      if (!entry) {
        return;
      }
      entry.pausedByUser = true;
      stopToastTimerEntry(entry);
    },
    [stopToastTimerEntry],
  );

  const resumeToastTimer = useCallback(
    (id: string) => {
      const entry = toastTimersRef.current.get(id);
      if (!entry) {
        return;
      }
      entry.pausedByUser = false;
      startToastTimerEntry(id, entry);
    },
    [startToastTimerEntry],
  );

  const dismissToast = useCallback((id: string) => {
    const entry = toastTimersRef.current.get(id);
    if (entry) {
      if (entry.timer !== null) {
        clearTimeout(entry.timer);
      }
      toastTimersRef.current.delete(id);
    }
    if (!mountedRef.current) {
      return;
    }
    setToasts((prev) => prev.filter((item) => item.id !== id));
  }, []);

  const pushToast = useCallback(
    (kind: ToastKind, text: string, durationMs?: number): string => {
      const trimmed = text.trim();
      if (!trimmed || !mountedRef.current) {
        return "";
      }

      const id = nextId("toast");
      const toast: ToastMessage = { id, kind, text: trimmed };

      setToasts((prev) => {
        const next = [...prev, toast];
        return next.length > MAX_TOASTS
          ? next.slice(next.length - MAX_TOASTS)
          : next;
      });

      const resolvedDuration =
        durationMs ??
        (kind === "error"
          ? ERROR_TOAST_DURATION_MS
          : DEFAULT_TOAST_DURATION_MS);

      if (resolvedDuration > 0) {
        const entry: ToastTimerEntry = {
          timer: null,
          remainingMs: resolvedDuration,
          startedAtMs: null,
          pausedByUser: false,
        };
        toastTimersRef.current.set(id, entry);
        startToastTimerEntry(id, entry);
      }

      return id;
    },
    [nextId, startToastTimerEntry],
  );

  // Clean up timers for evicted or dismissed toasts outside state updaters
  // so React 19 StrictMode double-invocations remain pure and leak-free.
  useEffect(() => {
    const activeIds = new Set(toasts.map((item) => item.id));
    for (const [id, entry] of toastTimersRef.current.entries()) {
      if (!activeIds.has(id)) {
        if (entry.timer !== null) {
          clearTimeout(entry.timer);
        }
        toastTimersRef.current.delete(id);
      }
    }
  }, [toasts]);

  const clearActivity = useCallback(() => {
    setActivity([]);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const timers = toastTimersRef.current;

    return () => {
      mountedRef.current = false;
      for (const entry of timers.values()) {
        if (entry.timer !== null) {
          clearTimeout(entry.timer);
        }
      }
      timers.clear();
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    let unlisten: (() => void) | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let pollInFlight = false;
    let receivedPush = false;
    let fallbackPollingWanted = false;

    const stopPolling = () => {
      if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    };

    const startFallbackPolling = () => {
      fallbackPollingWanted = true;
      if (
        disposed ||
        pollTimer !== null ||
        receivedPush ||
        (typeof document !== "undefined" && document.hidden)
      ) {
        return;
      }
      pollTimer = setInterval(() => {
        if (
          disposed ||
          pollInFlight ||
          (typeof document !== "undefined" && document.hidden)
        ) {
          return;
        }
        pollInFlight = true;
        const seq = ++statusSeqRef.current;
        void getStatus()
          .then((snapshot: DesktopStatusSnapshot) => {
            if (disposed) {
              return;
            }
            const hasSnapshotSeq =
              typeof snapshot.snapshotSeq === "number" &&
              Number.isFinite(snapshot.snapshotSeq);
            if (hasSnapshotSeq || seq >= statusSeqRef.current) {
              applySnapshot(snapshot);
            }
          })
          .catch(() => {
            // Preserve last known snapshot across transient fallback poll errors.
          })
          .finally(() => {
            pollInFlight = false;
          });
      }, FALLBACK_POLL_INTERVAL_MS);
    };

    const handleVisibilityChange = () => {
      if (disposed || typeof document === "undefined") {
        return;
      }
      if (document.hidden) {
        stopPolling();
        for (const entry of toastTimersRef.current.values()) {
          stopToastTimerEntry(entry);
        }
        return;
      }
      for (const [id, entry] of Array.from(toastTimersRef.current.entries())) {
        startToastTimerEntry(id, entry);
      }
      void refreshStatus();
      if (
        (settingsRef.current === null || settingsErrorRef.current !== null) &&
        !settingsInFlightRef.current
      ) {
        void refreshSettings();
      }
      if (fallbackPollingWanted && !receivedPush) {
        startFallbackPolling();
      }
    };

    if (typeof document !== "undefined") {
      document.addEventListener("visibilitychange", handleVisibilityChange);
    }

    void Promise.allSettled([refreshStatus(), refreshSettings()]).finally(
      () => {
        if (!disposed) {
          setLoading(false);
        }
      },
    );

    const inTauri = isTauriRuntime();

    void (async () => {
      try {
        const teardown = await Promise.resolve(
          subscribeStatus((snapshot: DesktopStatusSnapshot) => {
            if (disposed) {
              return;
            }
            receivedPush = true;
            fallbackPollingWanted = false;
            stopPolling();
            if (applySnapshot(snapshot)) {
              statusSeqRef.current += 1;
            }
          }),
        );

        if (disposed) {
          if (typeof teardown === "function") {
            teardown();
          }
          return;
        }

        if (typeof teardown === "function") {
          unlisten = teardown;
        }
      } catch {
        startFallbackPolling();
        return;
      }

      if (!inTauri && !receivedPush) {
        startFallbackPolling();
      }
    })();

    return () => {
      disposed = true;
      stopPolling();
      if (typeof document !== "undefined") {
        document.removeEventListener(
          "visibilitychange",
          handleVisibilityChange,
        );
      }
      if (unlisten) {
        const teardown = unlisten;
        unlisten = null;
        try {
          teardown();
        } catch {
          // Ignore teardown errors during unmount.
        }
      }
    };
  }, [
    applySnapshot,
    refreshSettings,
    refreshStatus,
    startToastTimerEntry,
    stopToastTimerEntry,
  ]);

  const error = statusError ?? settingsError;

  return {
    status,
    settings,
    loading,
    error,
    statusError,
    settingsError,
    history,
    activity,
    toasts,
    refreshStatus,
    refreshSettings,
    applySnapshot,
    pushToast,
    dismissToast,
    pauseToastTimer,
    resumeToastTimer,
    clearActivity,
  };
}

export default useDesktopStatus;
