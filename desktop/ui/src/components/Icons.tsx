import type { ReactNode, SVGProps } from "react";

export interface IconProps
  extends Omit<SVGProps<SVGSVGElement>, "width" | "height" | "children"> {
  size?: number;
  className?: string;
}

export interface IconChevronProps extends IconProps {
  direction?: "right" | "down" | "left" | "up";
}

interface StrokeIconProps extends IconProps {
  children: ReactNode;
}

function StrokeIcon({
  size = 16,
  strokeWidth,
  className,
  children,
  ...rest
}: StrokeIconProps) {
  const adaptiveStrokeWidth = strokeWidth ?? (size <= 14 ? 1.85 : 1.6);

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={adaptiveStrokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...rest}
    >
      {children}
    </svg>
  );
}

/** vdpi split rounded diamond brand mark (monochrome, inherits currentColor). */
export function BrandMark({ size = 24, className, ...rest }: IconProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
      className={className}
      {...rest}
    >
      <path
        fillOpacity={0.55}
        d="M13.27 4.8Q13.27 2.7 14.76 4.18L20.06 9.48Q21.53 10.96 20.06 12.43L14.76 17.73Q13.27 19.22 13.27 17.12Z"
      />
      <path
        fillOpacity={1}
        d="M9.24 6.27Q10.73 4.78 10.73 6.88L10.73 19.2Q10.73 21.3 9.24 19.82L3.94 14.52Q2.47 13.04 3.94 11.57Z"
      />
    </svg>
  );
}

export function IconOverview(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <rect x="3" y="3" width="7.5" height="9" rx="1.75" />
      <rect x="13.5" y="3" width="7.5" height="5.5" rx="1.75" />
      <rect x="13.5" y="11.5" width="7.5" height="9.5" rx="1.75" />
      <rect x="3" y="15" width="7.5" height="6" rx="1.75" />
    </StrokeIcon>
  );
}

export function IconSplitTunnel(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M3 8V3h5" />
      <path d="M21 8V3h-5" />
      <path d="M12 21v-6.5Q12 12 10.2 10.2L3 3" />
      <path d="M12 14.5Q12 12 13.8 10.2L21 3" />
    </StrokeIcon>
  );
}

export function IconDns(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <circle cx="12" cy="12" r="9" />
      <ellipse cx="12" cy="12" rx="4" ry="9" />
      <path d="M3 12h18" />
    </StrokeIcon>
  );
}

export function IconDiagnostics(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M2.5 12H7l2.5-7.5 5 15L17 12h4.5" />
    </StrokeIcon>
  );
}

export function IconSettings(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2Z" />
      <circle cx="12" cy="12" r="3" />
    </StrokeIcon>
  );
}

export function IconPower(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M12 2.5v9" />
      <path d="M17.66 6.34a8 8 0 1 1-11.32 0" />
    </StrokeIcon>
  );
}

export function IconSearch(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <circle cx="11" cy="11" r="7.5" />
      <path d="m20.5 20.5-4.2-4.2" />
    </StrokeIcon>
  );
}

export function IconRefresh(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M4.3 9.8A8 8 0 0 1 18.6 7.5L20 9" />
      <path d="M20 4.5V9h-4.5" />
      <path d="M19.7 14.2A8 8 0 0 1 5.4 16.5L4 15" />
      <path d="M4 19.5V15h4.5" />
    </StrokeIcon>
  );
}

export function IconCopy(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <rect x="9" y="9" width="12" height="12" rx="2" />
      <path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1" />
    </StrokeIcon>
  );
}

export function IconCheck(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="m4.5 12.75 5 5 10-11" />
    </StrokeIcon>
  );
}

export function IconPlus(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M12 5v14" />
      <path d="M5 12h14" />
    </StrokeIcon>
  );
}

export function IconFolder(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M3 6.5a2 2 0 0 1 2-2h4.17a2 2 0 0 1 1.6.8l1.06 1.4a2 2 0 0 0 1.6.8H19a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-11Z" />
    </StrokeIcon>
  );
}

export function IconClose(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="m6 6 12 12" />
      <path d="M18 6 6 18" />
    </StrokeIcon>
  );
}

export function IconAlert(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M10.29 3.86 2.82 17a2 2 0 0 0 1.71 3h14.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" />
      <path d="M12 9v4" />
      <path d="M12 16.5h.01" />
    </StrokeIcon>
  );
}

export function IconShield(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M12 2.5 4.5 5.75v5.5c0 4.9 3.2 8.75 7.5 10.25 4.3-1.5 7.5-5.35 7.5-10.25v-5.5L12 2.5Z" />
    </StrokeIcon>
  );
}

export function IconEye(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M2.5 12C5 7.2 8.2 5.5 12 5.5c3.8 0 7 1.7 9.5 6.5-2.5 4.8-5.7 6.5-9.5 6.5-3.8 0-7-1.7-9.5-6.5Z" />
      <circle cx="12" cy="12" r="3" />
    </StrokeIcon>
  );
}

export function IconEyeOff(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M10.6 5.65A10.7 10.7 0 0 1 12 5.5c3.8 0 7 1.7 9.5 6.5a15.3 15.3 0 0 1-2.55 3.45" />
      <path d="M16.1 17.55A10.1 10.1 0 0 1 12 18.5c-3.8 0-7-1.7-9.5-6.5a15.3 15.3 0 0 1 3.7-4.5" />
      <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
      <path d="m3 3 18 18" />
    </StrokeIcon>
  );
}

export function IconTray(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <rect x="3" y="3" width="18" height="18" rx="2.5" />
      <path d="M3 15h18" />
      <path d="m9 8 3 3 3-3" />
    </StrokeIcon>
  );
}

export function IconExternal(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M14 4h6v6" />
      <path d="M10 14 20 4" />
      <path d="M18 13v5a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5" />
    </StrokeIcon>
  );
}

const CHEVRON_PATHS: Record<NonNullable<IconChevronProps["direction"]>, string> =
  {
    right: "m9 6 6 6-6 6",
    down: "m6 9 6 6 6-6",
    left: "m15 6-6 6 6 6",
    up: "m6 15 6-6 6 6",
  };

export function IconChevron({
  direction = "right",
  ...props
}: IconChevronProps) {
  return (
    <StrokeIcon {...props}>
      <path d={CHEVRON_PATHS[direction]} />
    </StrokeIcon>
  );
}

export function IconTrash(props: IconProps) {
  return (
    <StrokeIcon {...props}>
      <path d="M4 6.5h16" />
      <path d="M9 6.5v-2A1.5 1.5 0 0 1 10.5 3h3A1.5 1.5 0 0 1 15 4.5v2" />
      <path d="m6 6.5.85 12.1a2 2 0 0 0 2 1.9h6.3a2 2 0 0 0 2-1.9L18 6.5" />
      <path d="M10 11v5.5" />
      <path d="M14 11v5.5" />
    </StrokeIcon>
  );
}
