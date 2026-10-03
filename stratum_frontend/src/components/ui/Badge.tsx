import type { ReactNode } from "react";
import { Tooltip } from "./Tooltip";

export type Tone = "neutral" | "info" | "success" | "warning" | "danger";

export function Badge({
  tone = "neutral",
  outline,
  icon,
  title,
  children,
}: {
  tone?: Tone;
  outline?: boolean;
  icon?: ReactNode;
  title?: string;
  children: ReactNode;
}) {
  const badge = (
    <span className={["badge", tone !== "neutral" && `tone-${tone}`, outline && "badge-outline"].filter(Boolean).join(" ")}>
      {icon}
      {children}
    </span>
  );
  return title ? <Tooltip text={title}>{badge}</Tooltip> : badge;
}

/** Status mit Punkt und Text, nie nur über die Farbe. */
export function StatusBadge({
  tone,
  label,
  pulse,
  title,
}: {
  tone: Tone;
  label: string;
  pulse?: boolean;
  title?: string;
}) {
  return (
    <Badge tone={tone} title={title} icon={<span className={pulse ? "status-dot pulse" : "status-dot"} />}>
      {label}
    </Badge>
  );
}
