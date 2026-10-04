import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Activity, Expand, EyeOff, Pin, RotateCcw, Undo2 } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useEntities, useGraphExpand } from "../../lib/api/queries";
import { useDetail } from "../../app/detail";
import { useSession } from "../../lib/permissions";
import { label } from "../../lib/format";
import { useGraphWorkspace } from "./graphState";

const groups: Record<string, string[]> = {
  network: ["ip_address", "network_endpoint", "domain_name", "url", "network_share", "mac_address", "network_interface"],
  processes: ["process", "service", "scheduled_task"], files: ["file", "file_stream", "directory", "volume"], users: ["user_account", "user_group", "credential"],
};

export function GraphPage({ number }: { number: string }) {
  const [params, setParams] = useSearchParams();
  const { me, can } = useSession();
  const scope = `${me.konto.id}|${number}`;
  const focus = params.get("entity") ?? "";
  const mode = params.get("mode") ?? "all";
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [zoom, setZoom] = useState(1);
  const list = useEntities(number, "", search);
  const expand = useGraphExpand(number);
  const workspace = useGraphWorkspace();
  const { graph } = workspace;
  const { detail, open } = useDetail();
  const navigate = useNavigate();
  useEffect(() => { workspace.enter(scope); }, [scope, workspace.enter]);
  useEffect(() => {
    if (focus && workspace.number === scope && !graph.nodes.some((n) => n.id === focus)) {
      expand.mutate({ id: focus }, { onSuccess: (p) => { if (useGraphWorkspace.getState().number === scope) workspace.merge(p); } });
    }
    // Eine neue URL-Wurzel löst genau eine Abfrage aus; Fehler werden manuell wiederholt.
  }, [focus, scope, workspace.number]);
  const selected = graph.nodes.find((n) => n.id === (detail?.kind === "entity" ? detail.id : focus));
  const positions = useMemo(() => {
    return new Map(graph.nodes.map((n) => {
      const i = n.slot;
      if (i === 0) return [n.id, { x: 0, y: 0 }];
      let slot = i - 1, ring = 1;
      while (slot >= ring * 8) { slot -= ring * 8; ring++; }
      const angle = slot / (ring * 8) * Math.PI * 2;
      return [n.id, { x: Math.cos(angle) * ring * 340, y: Math.sin(angle) * ring * 340 }];
    }));
  }, [graph.nodes]);
  const edgeBends = useMemo(() => {
    const groups = new Map<string, string[]>();
    for (const e of graph.edges) { const key = [e.source, e.target].sort().join("|"); groups.set(key, [...(groups.get(key) ?? []), e.id]); }
    const result = new Map<string, number>();
    for (const ids of groups.values()) ids.forEach((id, i) => result.set(id, (i - (ids.length - 1) / 2) * 70));
    return result;
  }, [graph.edges]);
  const points = [...positions.values()];
  const minX = Math.min(0, ...points.map((p) => p.x)) - 150;
  const minY = Math.min(0, ...points.map((p) => p.y)) - 80;
  const width = Math.max(700, Math.max(0, ...points.map((p) => p.x)) - minX + 150);
  const height = Math.max(480, Math.max(0, ...points.map((p) => p.y)) - minY + 80);
  const visible = new Set(graph.nodes.filter((n) => mode === "all" || n.id === selected?.id || groups[mode]?.includes(n.kind)).map((n) => n.id));
  function load(id: string, more = false) {
    expand.mutate({ id, nach: more ? graph.pages[id] ?? undefined : undefined }, { onSuccess: (p) => { if (useGraphWorkspace.getState().number === scope) workspace.merge(p); } });
  }
  function choose(id: string) {
    setParams((p) => { const n = new URLSearchParams(p); n.set("entity", id); n.set("detail", `entity:${id}`); return n; });
    if (focus === id || graph.nodes.some((n) => n.id === id)) load(id);
  }
  if (!can("case.view") || !can("file.view")) return <EmptyState title="Graph permission required" text="Your role needs case.view and file.view to inspect relationships." />;
  if (workspace.number !== scope) return <p role="status">Loading graph workspace…</p>;
  return <div className="graph-workspace">
    <div className="filter-bar">
      <form className="filter-search" onSubmit={(e) => { e.preventDefault(); setSearch(query.trim()); }}><Input aria-label="Find graph entity" placeholder="Find entity by name (Enter)" value={query} onChange={(e) => setQuery(e.target.value)} /></form>
      <Select aria-label="Graph mode" value={mode} onChange={(e) => setParams((p) => { const n = new URLSearchParams(p); n.set("mode", e.target.value); return n; })}>
        <option value="all">All relationships</option>{Object.keys(groups).map((g) => <option key={g} value={g}>{label(g)}</option>)}
      </Select>
      <Button size="sm" icon={<Undo2 />} disabled={!workspace.history.length || expand.isPending} onClick={workspace.undo}>Undo expansion</Button>
      <Button size="sm" icon={<RotateCcw />} disabled={expand.isPending} onClick={workspace.reset}>Clear graph</Button>
    </div>
    <div className="graph-body">
      <aside className="graph-roots">
        <p className="muted">Choose a starting entity</p>
        {list.error && <ErrorState title="Entities unavailable" reason={list.error.message} />}
        {list.isPending && <p role="status">Loading entities…</p>}
        {list.data?.pages.flatMap((p) => p.eintraege).slice(0, 300).map((n) => <button type="button" className="list-row" key={n.id} disabled={expand.isPending} onClick={() => choose(n.id)}><span className="list-main">{n.display_name}</span><small className="muted">{label(n.kind)}</small></button>)}
        {list.data && (list.data.pages[0]?.eintraege.length ?? 0) === 0 && <p>No entities found. Run an analysis or change the search.</p>}
        {list.hasNextPage && <p className="muted">First 300 entities shown. Narrow the search to find others.</p>}
      </aside>
      <div className="graph-main">
        <div className="graph-toolbar">
          <strong>{selected?.name ?? "Investigation graph"}</strong>
          <span className="muted">{graph.nodes.length} nodes · {graph.edges.length} relationships loaded</span>
          {selected && <>
            <Button size="sm" icon={<Expand />} disabled={expand.isPending} onClick={() => load(selected.id)}>Expand 1 hop</Button>
            {graph.pages[selected.id] && <Button size="sm" disabled={expand.isPending} onClick={() => load(selected.id, true)}>More relationships</Button>}
            <Button size="sm" icon={<Pin />} onClick={() => workspace.pin(selected.id)}>{graph.pinned.includes(selected.id) ? "Unpin" : "Pin"}</Button>
            <Button size="sm" icon={<EyeOff />} disabled={graph.pinned.includes(selected.id)} onClick={() => workspace.hide(selected.id)}>Hide</Button>
            <Button size="sm" icon={<Activity />} onClick={() => navigate(`/cases/${encodeURIComponent(number)}/timeline?ent=${selected.id}&entname=${encodeURIComponent(selected.name)}`)}>Timeline</Button>
          </>}
          <label className="row">Zoom <input aria-label="Graph zoom" type="range" min="0.5" max="4" step="0.1" value={zoom} onChange={(e) => setZoom(Number(e.target.value))} /></label>
        </div>
        {expand.isPending && <p role="status" className="graph-message">Loading direct relationships…</p>}
        {expand.error && <div className="graph-message"><ErrorState title="Graph expansion failed" reason={expand.error.message} />{focus && <Button onClick={() => load(focus)}>Retry</Button>}</div>}
        {workspace.limited && <p className="graph-message" role="status">Display limit reached (120 nodes / 240 relationships). Hide nodes or clear the graph before expanding further.</p>}
        {graph.nodes.length === 0 ? <EmptyState title="Start with an entity" text="Choose a user, process, file or address on the left. Only stored relationships are shown." /> : <div className="graph-canvas">
          <svg style={{ width: `${zoom * 100}%`, height: `${zoom * 100}%`, minHeight: 350 }} viewBox={`${minX} ${minY} ${width} ${height}`} role="group" aria-label="Investigation relationships">
            <defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor" /></marker></defs>
            {graph.edges.filter((e) => visible.has(e.source) && visible.has(e.target)).map((e) => {
              const a = positions.get(e.source)!, b = positions.get(e.target)!;
              const dx = b.x - a.x, dy = b.y - a.y;
              const scale = Math.max(Math.abs(dx) / 112, Math.abs(dy) / 34, 1);
              const ax = a.x + dx / scale, ay = a.y + dy / scale, bx = b.x - dx / scale, by = b.y - dy / scale;
              const distance = Math.hypot(dx, dy) || 1;
              const bend = (edgeBends.get(e.id) ?? 0) * (e.source < e.target ? 1 : -1);
              const cx = (a.x + b.x) / 2 - dy / distance * bend;
              const cy = (a.y + b.y) / 2 + dx / distance * bend;
              const inferred = !["observed", "parsed", "derived"].includes(e.derivation);
              return <g key={e.id} className={`graph-edge ${inferred ? "inferred" : ""} ${detail?.id === e.id ? "selected" : ""}`} role="button" tabIndex={0} aria-label={`${e.kind}, ${e.derivation}`} onClick={() => open("relationship", e.id)} onKeyDown={(v) => { if (v.key === "Enter" || v.key === " ") { v.preventDefault(); open("relationship", e.id); } }}>
                <title>{e.kind}: {e.derivation}. Open relationship and provenance.</title>
                {e.source === e.target ? <path d={`M ${a.x} ${a.y - 32} C ${a.x - 90} ${a.y - 150}, ${a.x + 90} ${a.y - 150}, ${a.x + 20} ${a.y - 32}`} markerEnd="url(#graph-arrow)" /> : <path d={`M ${ax} ${ay} Q ${cx} ${cy} ${bx} ${by}`} markerEnd="url(#graph-arrow)" />}
                <text x={(a.x + b.x + 2 * cx) / 4} y={(a.y + b.y + 2 * cy) / 4 - (e.source === e.target ? 90 : 8)}>{e.kind}</text>
              </g>;
            })}
            {graph.nodes.filter((n) => visible.has(n.id)).map((n) => { const p = positions.get(n.id)!; return <g key={n.id} transform={`translate(${p.x},${p.y})`} className={`graph-node ${selected?.id === n.id ? "selected" : ""}`} role="button" tabIndex={0} aria-label={`${n.name}, ${label(n.kind)}`} onClick={() => open("entity", n.id)} onDoubleClick={() => load(n.id)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open("entity", n.id); } }}>
              <title>{n.name} ({label(n.kind)}). Double-click to expand.</title><rect x="-112" y="-32" width="224" height="64" rx="6" /><text textAnchor="middle" y="-4">{n.name.length > 28 ? `${n.name.slice(0, 27)}…` : n.name}</text><text textAnchor="middle" y="18" className="graph-node-kind">{label(n.kind)}{graph.pinned.includes(n.id) ? " · Pinned" : ""}</text>
            </g>; })}
          </svg>
        </div>}
        <div className="graph-legend"><span>Stored relationships only. Arrow indicates direction.</span><span>Solid: <DerivationBadge kind="parsed" /> / observed / derived</span><span>Dashed: interpretation or other derivation. Select an edge to inspect its source.</span></div>
      </div>
    </div>
  </div>;
}
