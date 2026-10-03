// Überlagernde Bausteine: Popover, Menü, Kontextmenü, Command Palette.

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { Search } from "lucide-react";
import { Kbd } from "./Kbd";

/** Schließt bei Klick außerhalb und bei Escape. */
function useDismiss(open: boolean, close: () => void, ref: React.RefObject<HTMLElement | null>) {
  useEffect(() => {
    if (!open) {
      return;
    }
    const down = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        close();
      }
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        close();
      }
    };
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key, true);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key, true);
    };
  }, [open, close, ref]);
}

/** Auslöser mit aufklappendem Inhalt unterhalb (rechts oder links bündig). */
export function Popover({
  trigger,
  children,
  align = "left",
}: {
  trigger: (props: { open: boolean; toggle: () => void }) => ReactNode;
  children: (close: () => void) => ReactNode;
  align?: "left" | "right";
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const close = useMemo(() => () => setOpen(false), []);
  useDismiss(open, close, ref);
  return (
    <div ref={ref} className="popover-anchor">
      {trigger({ open, toggle: () => setOpen((o) => !o) })}
      {open && (
        <div className={align === "right" ? "popover popover-right" : "popover"} role="menu">
          {children(close)}
        </div>
      )}
    </div>
  );
}

export interface MenuAction {
  label: string;
  icon?: ReactNode;
  shortcut?: string;
  disabled?: boolean;
  /** Grund, warum die Aktion nicht verfügbar ist. */
  reason?: string;
  onSelect?: () => void;
}

export type MenuEntry = MenuAction | "separator" | { section: string };

export function Menu({ entries, close }: { entries: MenuEntry[]; close: () => void }) {
  return (
    <>
      {entries.map((e, i) => {
        if (e === "separator") {
          return <div key={i} className="menu-sep" />;
        }
        if ("section" in e) {
          return (
            <div key={i} className="menu-label section-label">
              {e.section}
            </div>
          );
        }
        return (
          <button
            key={i}
            type="button"
            role="menuitem"
            className="menu-item"
            disabled={e.disabled}
            title={e.disabled ? e.reason : undefined}
            onClick={() => {
              close();
              e.onSelect?.();
            }}
          >
            {e.icon}
            {e.label}
            {e.shortcut && <Kbd>{e.shortcut}</Kbd>}
          </button>
        );
      })}
    </>
  );
}

/** Kontextmenü an der Mausposition. `open` aus onContextMenu aufrufen. */
export function useContextMenu() {
  const [state, setState] = useState<{ x: number; y: number; entries: MenuEntry[] } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const close = useMemo(() => () => setState(null), []);
  useDismiss(state !== null, close, ref);
  const open = (e: React.MouseEvent, entries: MenuEntry[]) => {
    e.preventDefault();
    const x = Math.min(e.clientX, window.innerWidth - 240);
    const y = Math.min(e.clientY, window.innerHeight - 40 - entries.length * 30);
    setState({ x, y, entries });
  };
  const menu = state
    ? createPortal(
        <div ref={ref} className="popover context-menu" role="menu" style={{ left: state.x, top: state.y }}>
          <Menu entries={state.entries} close={close} />
        </div>,
        document.body,
      )
    : null;
  return { open, menu };
}

export interface PaletteItem {
  id: string;
  group: string;
  label: string;
  hint?: string;
  icon?: ReactNode;
  keywords?: string;
  disabled?: boolean;
  run: () => void;
}

/** Command Palette: Suche über Befehle, Ziele und zuletzt Geöffnetes. */
export function CommandPalette({ items, onClose }: { items: PaletteItem[]; onClose: () => void }) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const list = useRef<HTMLDivElement>(null);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase().replace(/^>\s*/, "");
    const words = q.split(/\s+/).filter(Boolean);
    return items.filter((i) => {
      const text = `${i.group} ${i.label} ${i.hint ?? ""} ${i.keywords ?? ""}`.toLowerCase();
      return words.every((w) => text.includes(w));
    });
  }, [items, query]);

  useEffect(() => setActive(0), [query]);
  useEffect(() => {
    list.current?.querySelector(".active")?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const run = (i: PaletteItem | undefined) => {
    if (i && !i.disabled) {
      onClose();
      i.run();
    }
  };

  let lastGroup = "";
  return createPortal(
    <div className="palette-backdrop" onMouseDown={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-label="Command palette"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(a + 1, shown.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(a - 1, 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            run(shown[active]);
          } else if (e.key === "Escape") {
            e.preventDefault();
            onClose();
          }
        }}
      >
        <div className="palette-input">
          <Search aria-hidden />
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search…"
            aria-label="Command"
          />
          <Kbd>Esc</Kbd>
        </div>
        <div className="palette-list" ref={list} role="listbox">
          {shown.length === 0 && <div className="menu-label muted">No matches.</div>}
          {shown.map((i, n) => {
            const head = i.group !== lastGroup;
            lastGroup = i.group;
            return (
              <div key={i.id}>
                {head && <div className="menu-label section-label">{i.group}</div>}
                <button
                  type="button"
                  role="option"
                  aria-selected={n === active}
                  disabled={i.disabled}
                  className={n === active ? "menu-item palette-item active" : "menu-item palette-item"}
                  onMouseEnter={() => setActive(n)}
                  onClick={() => run(i)}
                >
                  {i.icon}
                  {i.label}
                  {i.hint && <small>{i.hint}</small>}
                </button>
              </div>
            );
          })}
        </div>
        <div className="palette-foot">
          <span>
            <Kbd>↑</Kbd> <Kbd>↓</Kbd> navigate
          </span>
          <span>
            <Kbd>↵</Kbd> open
          </span>
          <span>
            <Kbd>Esc</Kbd> close
          </span>
        </div>
      </div>
    </div>,
    document.body,
  );
}
