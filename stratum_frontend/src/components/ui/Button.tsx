import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Tooltip } from "./Tooltip";

type Variant = "primary" | "secondary" | "ghost" | "danger";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "sm" | "md";
  icon?: ReactNode;
}

export function Button({ variant = "secondary", size = "md", icon, children, className, type, ...rest }: ButtonProps) {
  const cls = ["btn", variant !== "secondary" && `btn-${variant}`, size === "sm" && "btn-sm", className]
    .filter(Boolean)
    .join(" ");
  return (
    <button type={type ?? "button"} className={cls} {...rest}>
      {icon}
      {children}
    </button>
  );
}

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Beschriftung für Screenreader und Tooltip. */
  label: string;
  icon: ReactNode;
  size?: "sm" | "md";
  tip?: "above" | "below" | "right" | false;
}

export function IconButton({ label, icon, size = "md", tip = "above", className, type, ...rest }: IconButtonProps) {
  const button = (
    <button
      type={type ?? "button"}
      aria-label={label}
      className={["icon-btn", size === "sm" && "icon-btn-sm", className].filter(Boolean).join(" ")}
      {...rest}
    >
      {icon}
    </button>
  );
  return tip ? (
    <Tooltip text={label} side={tip}>
      {button}
    </Tooltip>
  ) : (
    button
  );
}
