import { create } from "zustand";
import type { GraphEdge, GraphNode, GraphPage } from "../../lib/api/types";

export interface GraphState {
  nodes: (GraphNode & { slot: number })[];
  edges: GraphEdge[];
  pages: Record<string, string | null>;
  pinned: string[];
}
const empty = (): GraphState => ({ nodes: [], edges: [], pages: {}, pinned: [] });
const MAX_NODES = 120;
const MAX_EDGES = 240;

/** Übernimmt nur Kanten, deren beide Endpunkte sichtbar sind. */
export function mergeGraph(current: GraphState, page: GraphPage): { state: GraphState; limited: boolean } {
  const nodes = new Map(current.nodes.map((n) => [n.id, n]));
  const edges = new Map(current.edges.map((e) => [e.id, e]));
  let limited = false;
  const incoming = current.nodes.length === 0 ? [...page.knoten.filter((n) => n.id === page.wurzel), ...page.knoten.filter((n) => n.id !== page.wurzel)] : page.knoten;
  for (const n of incoming) {
    if (nodes.has(n.id) || nodes.size < MAX_NODES) {
      const used = new Set([...nodes.values()].map((v) => v.slot));
      let slot = nodes.get(n.id)?.slot ?? 0;
      if (!nodes.has(n.id)) while (used.has(slot)) slot++;
      nodes.set(n.id, { ...n, slot });
    }
    else limited = true;
  }
  for (const e of page.kanten) {
    if (!nodes.has(e.source) || !nodes.has(e.target)) { limited = true; continue; }
    if (edges.has(e.id) || edges.size < MAX_EDGES) edges.set(e.id, e);
    else limited = true;
  }
  return { state: { ...current, nodes: [...nodes.values()], edges: [...edges.values()], pages: { ...current.pages, [page.wurzel]: limited ? current.pages[page.wurzel] ?? null : page.naechste } }, limited };
}

interface Workspace {
  number: string; graph: GraphState; history: GraphState[]; limited: boolean;
  enter: (number: string) => void;
  merge: (page: GraphPage) => void;
  hide: (id: string) => void;
  pin: (id: string) => void;
  undo: () => void;
  reset: () => void;
}
export const useGraphWorkspace = create<Workspace>((set) => ({
  number: "", graph: empty(), history: [], limited: false,
  enter: (number) => set((s) => s.number === number ? s : { number, graph: empty(), history: [], limited: false }),
  merge: (p) => set((s) => { const result = mergeGraph(s.graph, p); return { graph: result.state, limited: result.limited, history: [...s.history.slice(-9), s.graph] }; }),
  hide: (id) => set((s) => s.graph.pinned.includes(id) ? s : { history: [...s.history.slice(-9), s.graph], graph: { ...s.graph, nodes: s.graph.nodes.filter((n) => n.id !== id), edges: s.graph.edges.filter((e) => e.source !== id && e.target !== id), pages: {}, pinned: s.graph.pinned } }),
  pin: (id) => set((s) => ({ graph: { ...s.graph, pinned: s.graph.pinned.includes(id) ? s.graph.pinned.filter((v) => v !== id) : [...s.graph.pinned, id] } })),
  undo: () => set((s) => s.history.length ? { graph: s.history[s.history.length - 1], history: s.history.slice(0, -1), limited: false } : s),
  reset: () => set({ graph: empty(), history: [], limited: false }),
}));
