import type { ReactNode } from "react";

/** Tooltip über CSS (`data-tip`), erscheint bei Hover und Tastaturfokus. */
export function Tooltip({
  text,
  side = "above",
  children,
}: {
  text: string;
  side?: "above" | "below" | "right";
  children: ReactNode;
}) {
  const cls = ["tip", side === "below" && "tip-below", side === "right" && "tip-right"].filter(Boolean).join(" ");
  return (
    <span className={cls} data-tip={text}>
      {children}
    </span>
  );
}
