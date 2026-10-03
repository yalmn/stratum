// Aufteilende Bausteine: Split Pane, Tree, Drawer, Panel.

import { useRef, useState, type ReactNode } from "react";
import { ChevronDown, ChevronRight, X } from "lucide-react";
import { useWorkspace } from "../../app/store";
import { IconButton } from "./Button";

/**
 * Zwei Bereiche mit verschiebbarer Grenze. Die Breite des linken Bereichs
 * (Prozent) bleibt unter `id` gespeichert.
 */
export function SplitPane({
  id,
  initial = 30,
  min = 15,
  max = 70,
  left,
  right,
}: {
  id: string;
  initial?: number;
  min?: number;
  max?: number;
  left: ReactNode;
  right: ReactNode;
}) {
  const size = useWorkspace((s) => s.paneSizes[id] ?? initial);
  const setSize = useWorkspace((s) => s.setPaneSize);
  const box = useRef<HTMLDivElement>(null);
  const clamp = (v: number) => Math.min(max, Math.max(min, v));
  return (
    <div className="split" ref={box}>
      <div className="split-pane" style={{ width: `${size}%` }}>
        {left}
      </div>
      <button
        type="button"
        className="split-handle"
        aria-label="Resize"
        onPointerDown={(e) => {
          const el = box.current;
          if (!el) {
            return;
          }
          e.currentTarget.setPointerCapture(e.pointerId);
          const rect = el.getBoundingClientRect();
          const move = (ev: PointerEvent) => setSize(id, clamp(((ev.clientX - rect.left) / rect.width) * 100));
          const up = () => {
            window.removeEventListener("pointermove", move);
            window.removeEventListener("pointerup", up);
          };
          window.addEventListener("pointermove", move);
          window.addEventListener("pointerup", up);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowLeft") {
            setSize(id, clamp(size - 2));
          } else if (e.key === "ArrowRight") {
            setSize(id, clamp(size + 2));
          }
        }}
      />
      <div className="split-pane" style={{ flex: 1 }}>
        {right}
      </div>
    </div>
  );
}

export interface TreeNode {
  id: string;
  label: string;
  icon?: ReactNode;
  children?: TreeNode[];
  /** Kinder werden erst beim Aufklappen geladen. */
  hasChildren?: boolean;
}

export function Tree({
  nodes,
  selected,
  onSelect,
  onExpand,
}: {
  nodes: TreeNode[];
  selected?: string;
  onSelect?: (n: TreeNode) => void;
  onExpand?: (n: TreeNode) => void;
}) {
  return (
    <ul className="tree" role="tree">
      {nodes.map((n) => (
        <TreeItem key={n.id} node={n} selected={selected} onSelect={onSelect} onExpand={onExpand} />
      ))}
    </ul>
  );
}

function TreeItem({
  node,
  selected,
  onSelect,
  onExpand,
}: {
  node: TreeNode;
  selected?: string;
  onSelect?: (n: TreeNode) => void;
  onExpand?: (n: TreeNode) => void;
}) {
  const [open, setOpen] = useState(false);
  const expandable = node.hasChildren || (node.children?.length ?? 0) > 0;
  const toggle = () => {
    if (!open) {
      onExpand?.(node);
    }
    setOpen(!open);
  };
  return (
    <li role="treeitem" aria-expanded={expandable ? open : undefined} aria-selected={selected === node.id}>
      <div
        className={selected === node.id ? "tree-node selected" : "tree-node"}
        tabIndex={0}
        onClick={() => onSelect?.(node)}
        onDoubleClick={toggle}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight" && !open) {
            toggle();
          } else if (e.key === "ArrowLeft" && open) {
            setOpen(false);
          } else if (e.key === "Enter") {
            onSelect?.(node);
          }
        }}
      >
        <span
          className="tree-toggle"
          onClick={(e) => {
            e.stopPropagation();
            if (expandable) {
              toggle();
            }
          }}
        >
          {expandable ? open ? <ChevronDown /> : <ChevronRight /> : <span className="tree-spacer" />}
        </span>
        {node.icon}
        <span>{node.label}</span>
      </div>
      {open && node.children && node.children.length > 0 && (
        <Tree nodes={node.children} selected={selected} onSelect={onSelect} onExpand={onExpand} />
      )}
    </li>
  );
}

/** Rahmen des Context Drawers: Kopf mit Art und Titel, Inhalt, Aktionen. */
export function DrawerFrame({
  kind,
  title,
  badges,
  onClose,
  children,
}: {
  kind: string;
  title: ReactNode;
  badges?: ReactNode;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <aside className="drawer" aria-label={`${kind} details`}>
      <header className="drawer-head">
        <div className="drawer-title">
          <span className="section-label">{kind}</span>
          <h2>{title}</h2>
          {badges && <div className="row wrap">{badges}</div>}
        </div>
        <IconButton label="Close (Esc)" icon={<X />} onClick={onClose} tip="below" />
      </header>
      <div className="drawer-body">{children}</div>
    </aside>
  );
}

export function DrawerSection({ title, children, actions }: { title: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="drawer-section">
      <div className="drawer-section-head">
        <span className="section-label">{title}</span>
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Panel({ title, actions, children }: { title?: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="panel">
      {title && (
        <header className="panel-head">
          <h3>{title}</h3>
          <span className="spacer" />
          {actions}
        </header>
      )}
      <div className="panel-body">{children}</div>
    </section>
  );
}
