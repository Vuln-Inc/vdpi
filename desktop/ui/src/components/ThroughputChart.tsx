import { memo, useEffect, useMemo } from "react";
import { useLang, type ResolvedLanguage } from "../i18n/context";
import { tShell } from "../i18n/shell";
import type { ThroughputPoint } from "../types";
import { formatRate } from "../lib/format";

export interface ThroughputChartProps {
  points: ThroughputPoint[];
  running?: boolean;
  rxRateBps?: number;
  txRateBps?: number;
  title?: string;
  caption?: string;
  pausedLabel?: string;
  className?: string;
}

const WINDOW_SIZE = 60;
const SVG_WIDTH = 600;
const SVG_HEIGHT = 120;
const PAD_TOP = 6;
const PAD_BOTTOM = 6;
const PLOT_HEIGHT = SVG_HEIGHT - PAD_TOP - PAD_BOTTOM;
const MID_GRID_Y = PAD_TOP + PLOT_HEIGHT / 2;

const KB = 1024;
const MB = 1024 * KB;
const GB = 1024 * MB;
const MIN_SCALE_BPS = 128 * KB;

const NICE_STEPS_BPS: readonly number[] = [
  128 * KB,
  256 * KB,
  512 * KB,
  1 * MB,
  2 * MB,
  5 * MB,
  10 * MB,
  25 * MB,
  50 * MB,
  100 * MB,
  250 * MB,
  500 * MB,
  1 * GB,
];

const STYLE_ID = "vdpi-throughput-chart-styles";

const FALLBACK_STYLES = `
:where(.throughput-chart) {
  --_tc-ink: var(--ink-primary, var(--text-primary, #f5f5f7));
  --_tc-ink-secondary: var(--ink-secondary, var(--text-secondary, #a1a1a6));
  --_tc-ink-tertiary: var(--ink-tertiary, #7c828e);
  --_tc-accent: var(--accent-fg, var(--accent, #60a5fa));
  --_tc-border: var(--border-hairline, rgba(255, 255, 255, 0.07));
  --_tc-grid: var(--border-hairline, var(--border, rgba(255, 255, 255, 0.09)));
  --_tc-surface: var(--bg-surface-subtle, var(--surface-subtle, rgba(255, 255, 255, 0.02)));
  display: flex;
  flex-direction: column;
  gap: 8px;
  width: 100%;
  min-width: 0;
  box-sizing: border-box;
}

:where([data-theme="light"] .throughput-chart) {
  --_tc-ink: var(--ink-primary, var(--text-primary, #111317));
  --_tc-ink-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
  --_tc-ink-tertiary: var(--ink-tertiary, #6b7280);
  --_tc-accent: var(--accent-fg, var(--accent, #0066cc));
  --_tc-border: var(--border-hairline, rgba(11, 12, 14, 0.07));
  --_tc-grid: var(--border-hairline, var(--border, rgba(11, 12, 14, 0.09)));
  --_tc-surface: var(--bg-surface-subtle, var(--surface-subtle, rgba(11, 12, 14, 0.015)));
}

@media (prefers-color-scheme: light) {
  :where(:root:not([data-theme="dark"]) .throughput-chart) {
    --_tc-ink: var(--ink-primary, var(--text-primary, #111317));
    --_tc-ink-secondary: var(--ink-secondary, var(--text-secondary, #4e5460));
    --_tc-ink-tertiary: var(--ink-tertiary, #6b7280);
    --_tc-accent: var(--accent-fg, var(--accent, #0066cc));
    --_tc-border: var(--border-hairline, rgba(11, 12, 14, 0.07));
    --_tc-grid: var(--border-hairline, var(--border, rgba(11, 12, 14, 0.09)));
    --_tc-surface: var(--bg-surface-subtle, var(--surface-subtle, rgba(11, 12, 14, 0.015)));
  }
}

:where(.throughput-chart__header) {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 6px 12px;
  min-height: 20px;
  font-variant-numeric: tabular-nums;
}

:where(.throughput-chart__title-group) {
  display: inline-flex;
  align-items: baseline;
  gap: 6px;
  min-width: 0;
  white-space: nowrap;
}

:where(.throughput-chart__title) {
  margin: 0;
  font-size: var(--text-md, 14px);
  font-weight: var(--weight-semibold, 600);
  line-height: 1.3;
  letter-spacing: -0.01em;
  color: var(--_tc-ink);
}

:where(.throughput-chart__title-sep) {
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  font-size: 11.5px;
  opacity: 0.7;
}

:where(.throughput-chart__caption) {
  font-size: var(--text-sm, 12px);
  line-height: 1.3;
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
}

:where(.throughput-chart__stats) {
  display: inline-flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 12px;
  min-width: 0;
}

:where(.throughput-chart__legend) {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

:where(.throughput-chart__series) {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-size: 11.5px;
  line-height: 1.3;
  white-space: nowrap;
}

:where(.throughput-chart__swatch) {
  display: inline-block;
  width: 10px;
  height: 1.5px;
  border-radius: 1px;
  flex-shrink: 0;
}

:where(.throughput-chart__swatch--rx) {
  background: var(--accent-fg, var(--accent, var(--_tc-accent)));
}

:where(.throughput-chart__swatch--tx) {
  background: var(--ink-tertiary, var(--_tc-ink-tertiary));
}

:where(.throughput-chart__label) {
  color: var(--_tc-ink-secondary);
  font-weight: 500;
}

:where(.throughput-chart__value) {
  color: var(--_tc-ink);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

:where(.throughput-chart[data-state="paused"] .throughput-chart__value) {
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  font-weight: 500;
}

:where(.throughput-chart__peaks) {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  line-height: 1.3;
  color: var(--_tc-ink-secondary);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

:where(.throughput-chart__peak-label) {
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  text-transform: uppercase;
  letter-spacing: 0.04em;
  font-size: 10px;
  font-weight: 600;
}

:where(.throughput-chart__peak-sep) {
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  opacity: 0.7;
}

:where(.throughput-chart__body) {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: stretch;
  gap: 10px;
  width: 100%;
  min-width: 0;
}

:where(.throughput-chart__plot) {
  position: relative;
  width: 100%;
  height: 120px;
  min-width: 0;
  background: var(--_tc-surface);
  border: 1px solid var(--border-hairline, var(--_tc-border));
  border-radius: 6px;
  box-sizing: border-box;
  overflow: hidden;
}

:where(.throughput-chart__svg) {
  display: block;
  width: 100%;
  height: 100%;
  overflow: visible;
}

:where(.throughput-chart__axis) {
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  align-items: flex-end;
  height: 120px;
  padding: 6px 0;
  box-sizing: border-box;
  flex-shrink: 0;
  font-size: 10.5px;
  line-height: 1;
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  font-variant-numeric: tabular-nums;
  text-align: right;
  user-select: none;
}

:where(.throughput-chart__tick) {
  display: block;
  white-space: nowrap;
}

:where(.throughput-chart__overlay) {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  padding: 8px 12px;
  text-align: center;
  pointer-events: none;
}

:where(.throughput-chart__overlay-title) {
  margin: 0;
  font-size: 12.5px;
  font-weight: 500;
  color: var(--_tc-ink-secondary);
  line-height: 1.35;
}

:where(.throughput-chart__overlay-sub) {
  margin: 0;
  font-size: 11.5px;
  color: var(--ink-tertiary, var(--_tc-ink-tertiary));
  line-height: 1.35;
}

:where(.throughput-chart .sr-only) {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
`;

function ensureStyles(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById(STYLE_ID)) return;
  const style = document.createElement("style");
  style.id = STYLE_ID;
  style.textContent = FALLBACK_STYLES;
  document.head.appendChild(style);
}

function sanitizeRate(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return 0;
  }
  return value;
}

export function computeNiceUpperBound(maxBps: number): number {
  const safeMax = sanitizeRate(maxBps);
  if (safeMax <= 0) return MIN_SCALE_BPS;

  const target = safeMax * 1.08;
  for (const step of NICE_STEPS_BPS) {
    if (target <= step) {
      return step;
    }
  }

  const gbTarget = target / GB;
  const magnitude = Math.pow(10, Math.floor(Math.log10(gbTarget)));
  const normalized = gbTarget / magnitude;
  const factor =
    normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return factor * magnitude * GB;
}

function buildPolylinePoints(
  samples: readonly ThroughputPoint[],
  pick: (point: ThroughputPoint) => number,
  upperBound: number,
): string {
  const count = samples.length;
  if (count === 0) return "";

  const slotStep = SVG_WIDTH / (WINDOW_SIZE - 1);
  const startSlot = WINDOW_SIZE - count;

  const mapY = (bps: number): string => {
    const clamped = Math.min(Math.max(sanitizeRate(bps), 0), upperBound);
    const ratio = upperBound > 0 ? clamped / upperBound : 0;
    const y = PAD_TOP + PLOT_HEIGHT * (1 - ratio);
    return y.toFixed(2);
  };

  if (count === 1) {
    const y = mapY(pick(samples[0]));
    const xEnd = SVG_WIDTH;
    const xStart = Math.max(0, xEnd - slotStep);
    return `${xStart.toFixed(2)},${y} ${xEnd.toFixed(2)},${y}`;
  }

  const coords: string[] = new Array(count);
  for (let i = 0; i < count; i += 1) {
    const x = (startSlot + i) * slotStep;
    const y = mapY(pick(samples[i]));
    coords[i] = `${x.toFixed(2)},${y}`;
  }
  return coords.join(" ");
}

function getPausedSubtitle(
  pausedLabel: string,
  lang: ResolvedLanguage,
): string {
  switch (pausedLabel.trim()) {
    case "Checking status...":
    case "Durum kontrol ediliyor...":
      return tShell(lang, "chartSubChecking");
    case "Setup required":
    case "Kurulum gerekli":
      return tShell(lang, "chartSubSetup");
    case "Starting...":
    case "Başlatılıyor...":
      return tShell(lang, "chartSubStarting");
    default:
      return tShell(lang, "chartSubPaused");
  }
}

function ThroughputChartComponent({
  points,
  running = true,
  rxRateBps,
  txRateBps,
  title,
  caption,
  pausedLabel,
  className,
}: ThroughputChartProps) {
  const { lang } = useLang();
  const resolvedTitle = title ?? tShell(lang, "chartDefaultTitle");
  const resolvedCaption = caption ?? tShell(lang, "chartDefaultCaption");
  const resolvedPausedLabel =
    pausedLabel ?? tShell(lang, "chartDefaultPausedLabel");

  useEffect(() => {
    ensureStyles();
  }, []);

  const windowPoints = useMemo(
    () => (points.length > WINDOW_SIZE ? points.slice(-WINDOW_SIZE) : points),
    [points],
  );

  const latestPoint =
    windowPoints.length > 0 ? windowPoints[windowPoints.length - 1] : undefined;

  const currentRx = running
    ? sanitizeRate(rxRateBps ?? latestPoint?.rxBps)
    : 0;
  const currentTx = running
    ? sanitizeRate(txRateBps ?? latestPoint?.txBps)
    : 0;

  const { peakRx, peakTx, upperBound, rxPolyline, txPolyline } = useMemo(() => {
    if (!running) {
      return {
        peakRx: 0,
        peakTx: 0,
        upperBound: MIN_SCALE_BPS,
        rxPolyline: "",
        txPolyline: "",
      };
    }

    let maxRx = currentRx;
    let maxTx = currentTx;
    for (let i = 0; i < windowPoints.length; i += 1) {
      const rx = sanitizeRate(windowPoints[i].rxBps);
      const tx = sanitizeRate(windowPoints[i].txBps);
      if (rx > maxRx) maxRx = rx;
      if (tx > maxTx) maxTx = tx;
    }

    const bound = computeNiceUpperBound(Math.max(maxRx, maxTx));
    const rxLine = buildPolylinePoints(windowPoints, (p) => p.rxBps, bound);
    const txLine = buildPolylinePoints(windowPoints, (p) => p.txBps, bound);

    return {
      peakRx: maxRx,
      peakTx: maxTx,
      upperBound: bound,
      rxPolyline: rxLine,
      txPolyline: txLine,
    };
  }, [windowPoints, running, currentRx, currentTx]);

  const classes = [
    "throughput-chart",
    running ? "throughput-chart--running" : "throughput-chart--paused",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  const svgAriaLabel = running
    ? tShell(lang, "chartSvgAriaRunning", {
        rx: formatRate(currentRx),
        tx: formatRate(currentTx),
        peakRx: formatRate(peakRx),
        peakTx: formatRate(peakTx),
        bound: formatRate(upperBound),
      })
    : tShell(lang, "chartSvgAriaPaused", { label: resolvedPausedLabel });

  return (
    <div
      className={classes}
      data-state={running ? "running" : "paused"}
      data-scale-bps={upperBound}
    >
      <div className="throughput-chart__header">
        <div className="throughput-chart__title-group">
          {resolvedTitle ? (
            <h2 className="card-title throughput-chart__title">
              {resolvedTitle}
            </h2>
          ) : null}
          {resolvedTitle && resolvedCaption ? (
            <span className="throughput-chart__title-sep" aria-hidden="true">
              ·
            </span>
          ) : null}
          {resolvedCaption ? (
            <span className="card-caption throughput-chart__caption tabular-nums">
              {resolvedCaption}
            </span>
          ) : null}
        </div>

        <div className="throughput-chart__stats">
          <div className="throughput-chart__legend">
            <span
              className="throughput-chart__series"
              title={tShell(lang, "chartDownloadTitle")}
            >
              <span
                className="throughput-chart__swatch throughput-chart__swatch--rx"
                aria-hidden="true"
              />
              <span className="sr-only">{tShell(lang, "chartDownloadSr")}</span>
              <span className="throughput-chart__value">
                ↓ {formatRate(currentRx)}
              </span>
            </span>

            <span
              className="throughput-chart__series"
              title={tShell(lang, "chartUploadTitle")}
            >
              <span
                className="throughput-chart__swatch throughput-chart__swatch--tx"
                aria-hidden="true"
              />
              <span className="sr-only">{tShell(lang, "chartUploadSr")}</span>
              <span className="throughput-chart__value">
                ↑ {formatRate(currentTx)}
              </span>
            </span>
          </div>

          <div className="throughput-chart__peaks">
            <span className="throughput-chart__peak-label">
              {tShell(lang, "chartPeak")}
            </span>
            <span>↓ {formatRate(peakRx)}</span>
            <span className="throughput-chart__peak-sep" aria-hidden="true">
              ·
            </span>
            <span>↑ {formatRate(peakTx)}</span>
          </div>
        </div>
      </div>

      <div className="throughput-chart__body">
        <div className="throughput-chart__plot">
          <svg
            className="throughput-chart__svg"
            viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
            preserveAspectRatio="none"
            role="img"
            aria-label={svgAriaLabel}
          >
            <line
              x1={0}
              y1={MID_GRID_Y}
              x2={SVG_WIDTH}
              y2={MID_GRID_Y}
              stroke="var(--border-subtle)"
              strokeWidth={1}
              vectorEffect="non-scaling-stroke"
              shapeRendering="crispEdges"
            />

            {running && txPolyline && (
              <polyline
                data-series="upload"
                fill="none"
                stroke="var(--ink-tertiary)"
                strokeWidth={1.5}
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
                points={txPolyline}
              />
            )}

            {running && rxPolyline && (
              <polyline
                data-series="download"
                fill="none"
                stroke="var(--accent-fg, var(--accent))"
                strokeWidth={1.5}
                strokeLinecap="round"
                strokeLinejoin="round"
                vectorEffect="non-scaling-stroke"
                points={rxPolyline}
              />
            )}
          </svg>

          {!running ? (
            <div className="throughput-chart__overlay" role="status">
              <p className="throughput-chart__overlay-title">
                {resolvedPausedLabel}
              </p>
              <p className="throughput-chart__overlay-sub">
                {getPausedSubtitle(resolvedPausedLabel, lang)}
              </p>
            </div>
          ) : windowPoints.length === 0 ? (
            <div className="throughput-chart__overlay" role="status">
              <p className="throughput-chart__overlay-sub">
                {tShell(lang, "chartWaitingSamples")}
              </p>
            </div>
          ) : null}
        </div>

        <div className="throughput-chart__axis" aria-hidden="true">
          <span className="throughput-chart__tick throughput-chart__tick--top">
            {formatRate(upperBound)}
          </span>
          <span className="throughput-chart__tick throughput-chart__tick--mid">
            {formatRate(upperBound / 2)}
          </span>
          <span className="throughput-chart__tick throughput-chart__tick--bottom">
            {formatRate(0)}
          </span>
        </div>
      </div>
    </div>
  );
}

export const ThroughputChart = memo(ThroughputChartComponent);
ThroughputChart.displayName = "ThroughputChart";

export default ThroughputChart;
