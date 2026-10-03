// Timeline (Vorgabe Abschnitt 16, Tabellenmodus): Ereignisse nach Zeit,
// filterbar nach Evidence, Zeitraum, Ereignisart, Entität und Text; Details
// im Drawer. Filter stehen in der Adresse und sind teilbar.

import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { X } from "lucide-react";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { Popover } from "../../components/ui/Overlay";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useCase, useEventKinds, useTimeline } from "../../lib/api/queries";
import type { TimelineEvent } from "../../lib/api/types";
import { count, label } from "../../lib/format";
import { useDetail } from "../../app/detail";

/** Kurzbeschreibung: Beteiligte nach Rolle, sonst wichtige Attribute. */
function summary(e: TimelineEvent): string {
  const parts = e.participants.slice(0, 4).map((p) => p.name);
  if (parts.length > 0) {
    return parts.join(" · ");
  }
  const a = e.attributes;
  return ["name", "pfad", "path", "url", "programm", "wert"]
    .map((k) => a[k])
    .filter((v) => typeof v === "string" && v)
    .slice(0, 2)
    .join(" · ");
}

const h = columnHelper<TimelineEvent>();
const columns = [
  h.accessor("occurred_utc", {
    header: "Time (UTC)",
    size: 220,
    enableSorting: false,
    cell: (c) => <Timestamp value={c.getValue()} precise />,
  }),
  h.accessor("kind", { header: "Event", size: 200, enableSorting: false, cell: (c) => label(c.getValue()) }),
  h.display({ id: "summary", header: "Summary", size: 360, cell: (c) => summary(c.row.original) }),
  h.accessor("derivation", {
    header: "Derivation",
    size: 130,
    enableSorting: false,
    cell: (c) => <DerivationBadge kind={c.getValue()} />,
  }),
];

/** `datetime-local` gilt hier als UTC, nie als Zeit des Rechners. */
function toUtcIso(local: string): string | undefined {
  return local ? new Date(`${local}:00Z`).toISOString() : undefined;
}

function fromIso(iso: string | null): string {
  return iso ? iso.slice(0, 16) : "";
}

export function TimelinePage({ number }: { number: string }) {
  const [params, setParams] = useSearchParams();
  const c = useCase(number);
  const kinds = useEventKinds(number);
  const { detail, open } = useDetail();
  const filter = {
    evidence: params.get("ev") ?? undefined,
    von: params.get("von") ?? undefined,
    bis: params.get("bis") ?? undefined,
    arten: params.get("art")?.split(",").filter(Boolean) ?? [],
    entitaet: params.get("ent") ?? undefined,
    suche: params.get("q") ?? undefined,
  };
  const [text, setText] = useState(filter.suche ?? "");
  const tl = useTimeline(number, filter);
  const rows = useMemo(() => tl.data?.pages.flatMap((p) => p.eintraege) ?? [], [tl.data]);
  const loadMore = useCallback(() => {
    if (tl.hasNextPage && !tl.isFetchingNextPage) {
      void tl.fetchNextPage();
    }
  }, [tl]);

  const set = (changes: Record<string, string | null | undefined>) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      for (const [k, v] of Object.entries(changes)) {
        if (v) n.set(k, v);
        else n.delete(k);
      }
      return n;
    });
  const toggleKind = (k: string) => {
    const next = filter.arten.includes(k) ? filter.arten.filter((x) => x !== k) : [...filter.arten, k];
    set({ art: next.join(",") || null });
  };
  const total = (kinds.data ?? []).reduce((s, k) => s + k.anzahl, 0);
  const active = !!(filter.evidence || filter.von || filter.bis || filter.arten.length || filter.entitaet || filter.suche);

  return (
    <div className="timeline">
      <div className="filter-bar">
        <Select value={filter.evidence ?? ""} onChange={(e) => set({ ev: e.target.value || null })} aria-label="Evidence" className="filter-select">
          <option value="">All evidence</option>
          {(c.data?.evidence ?? []).map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </Select>
        <label className="filter-field">
          <span className="muted">From (UTC)</span>
          <Input type="datetime-local" value={fromIso(filter.von ?? null)} onChange={(e) => set({ von: toUtcIso(e.target.value) })} />
        </label>
        <label className="filter-field">
          <span className="muted">To (UTC)</span>
          <Input type="datetime-local" value={fromIso(filter.bis ?? null)} onChange={(e) => set({ bis: toUtcIso(e.target.value) })} />
        </label>
        <Popover
          trigger={({ toggle }) => (
            <Button onClick={toggle}>
              Event types {filter.arten.length > 0 ? `(${filter.arten.length})` : `(all ${count(total)})`}
            </Button>
          )}
        >
          {() => (
            <div className="kind-picker">
              {(kinds.data ?? [])
                .slice()
                .sort((a, b) => b.anzahl - a.anzahl)
                .map((k) => (
                  <label key={k.art} className="checkbox">
                    <input type="checkbox" checked={filter.arten.includes(k.art)} onChange={() => toggleKind(k.art)} />
                    <span className="list-main">{label(k.art)}</span>
                    <span className="muted mono">{count(k.anzahl)}</span>
                  </label>
                ))}
              {kinds.data?.length === 0 && <span className="muted">No events in this case.</span>}
            </div>
          )}
        </Popover>
        <form
          className="filter-search"
          onSubmit={(e) => {
            e.preventDefault();
            set({ q: text.trim() || null });
          }}
        >
          <Input placeholder="Text in event (Enter)" value={text} onChange={(e) => setText(e.target.value)} />
        </form>
        {filter.entitaet && (
          <Badge tone="info">
            Entity: {params.get("entname") ?? filter.entitaet.slice(0, 8)}
            <button type="button" className="badge-x" aria-label="Remove entity filter" onClick={() => set({ ent: null, entname: null })}>
              <X size={11} />
            </button>
          </Badge>
        )}
        {active && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setText("");
              set({ ev: null, von: null, bis: null, art: null, ent: null, entname: null, q: null });
            }}
          >
            Clear filters
          </Button>
        )}
      </div>
      <div className="timeline-body">
        {tl.isPending && <Skeleton lines={10} />}
        {tl.error && <ErrorState title="Timeline could not be loaded." reason={tl.error.message} />}
        {tl.data && rows.length === 0 && (
          <EmptyState
            title={active ? "No events match the filters." : "No events in this case yet."}
            text={active ? "Widen the time range or clear filters." : "Run an analysis; parsed artifacts become events here."}
          />
        )}
        {rows.length > 0 && (
          <DataTable
            label="Timeline"
            data={rows}
            columns={columns}
            rowId={(e) => e.id}
            grow={["summary"]}
            selected={detail?.kind === "event" ? detail.id : null}
            onSelect={(e) => open("event", e.id)}
            onEndReached={loadMore}
            footer={
              <>
                {count(rows.length)} events loaded{tl.hasNextPage ? ", scroll for more" : ""}
                {tl.isFetching && <span className="muted"> · loading…</span>}
                <span className="spacer" />
                Times in UTC as recorded; original precision in the details
              </>
            }
          />
        )}
      </div>
    </div>
  );
}
