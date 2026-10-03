// Anzeige-Bausteine: Tabs, Property List, Zeit, Hash, Code, Kopieren,
// Leer-, Fehler- und Ladezustand.

import { useState, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { Check, Copy, TriangleAlert } from "lucide-react";
import { shortHash, utc } from "../../lib/format";
import { IconButton } from "./Button";
import { Tooltip } from "./Tooltip";

export interface TabItem {
  id: string;
  label: string;
  to?: string;
  count?: number;
  icon?: ReactNode;
}

/** Reiter als Links (mit `to`) oder als Schalter (`onSelect`). */
export function Tabs({ items, active, onSelect }: { items: TabItem[]; active?: string; onSelect?: (id: string) => void }) {
  return (
    <nav className="tabs" role="tablist">
      {items.map((t) => {
        const inner = (
          <>
            {t.icon}
            {t.label}
            {t.count !== undefined && <span className="count">{t.count}</span>}
          </>
        );
        return t.to ? (
          <NavLink key={t.id} to={t.to} end className={({ isActive }) => (isActive ? "tab active" : "tab")} role="tab">
            {inner}
          </NavLink>
        ) : (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={active === t.id}
            className={active === t.id ? "tab active" : "tab"}
            onClick={() => onSelect?.(t.id)}
          >
            {inner}
          </button>
        );
      })}
    </nav>
  );
}

export function PropertyList({ items }: { items: [string, ReactNode][] }) {
  return (
    <dl className="props">
      {items.map(([k, v]) => (
        <div key={k} className="contents">
          <dt>{k}</dt>
          <dd>{v ?? <span className="muted">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Zeitpunkt in UTC; der volle Wert steht im Tooltip. */
export function Timestamp({ value, precise }: { value: string | null | undefined; precise?: boolean }) {
  if (!value) {
    return <span className="muted">—</span>;
  }
  return (
    <time dateTime={value} title={value} className="mono">
      {utc(value, precise)}
    </time>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <IconButton
      size="sm"
      label={done ? "Copied" : label}
      icon={done ? <Check /> : <Copy />}
      onClick={(e) => {
        e.stopPropagation();
        void navigator.clipboard?.writeText(value).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    />
  );
}

/** Hash gekürzt mit Kopieren; der volle Wert steht im Tooltip. */
export function HashValue({ value, algo, full }: { value: string; algo?: string; full?: boolean }) {
  return (
    <span className="hash">
      {algo && <span className="hash-algo">{algo}</span>}
      <Tooltip text={value}>
        <span>{full ? value : shortHash(value)}</span>
      </Tooltip>
      <CopyButton value={value} label={`Copy ${algo ?? "value"}`} />
    </span>
  );
}

export function CodeBlock({ children }: { children: string }) {
  return <pre className="code-block">{children}</pre>;
}

export function EmptyState({ title, text, action }: { title: string; text?: string; action?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {text && <span>{text}</span>}
      {action}
    </div>
  );
}

export function ErrorState({
  title,
  reason,
  hint,
  action,
}: {
  title: string;
  reason?: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="error-state" role="alert">
      <strong className="row">
        <TriangleAlert size={15} aria-hidden />
        {title}
      </strong>
      {reason && (
        <span>
          <span className="section-label">Reason</span>
          <br />
          {reason}
        </span>
      )}
      {hint && <span>{hint}</span>}
      {action}
    </div>
  );
}

export function Skeleton({ lines = 3, width }: { lines?: number; width?: number }) {
  return (
    <div className="stack" aria-busy="true" aria-label="Loading">
      {Array.from({ length: lines }, (_, i) => (
        <span key={i} className="skeleton" style={{ width: width ? `${width}%` : `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}
