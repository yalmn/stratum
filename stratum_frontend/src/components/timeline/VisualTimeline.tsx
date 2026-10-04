import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Button } from "../ui/Button";
import { Timestamp } from "../ui/Display";
import { DerivationBadge } from "../forensic/Badges";
import type { TimelineEvent } from "../../lib/api/types";
import { count, label } from "../../lib/format";

/** Visueller Verlauf der geladenen Seite; Herkunft und Originalzeit bleiben im Drawer. */
export function VisualTimeline({ events, selected, onSelect, onRange, onMore, hasMore, loading }: {
  events: TimelineEvent[]; selected?: string | null; onSelect: (event: TimelineEvent) => void;
  onRange: (from: string, to: string) => void; onMore: () => void; hasMore: boolean; loading: boolean;
}) {
  const scroll = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({ count: events.length, getScrollElement: () => scroll.current,
    estimateSize: () => 100, overscan: 6, getItemKey: (i) => events[i]!.id });
  const times = events.map((e) => Date.parse(e.occurred_utc));
  const first = times[0] ?? 0;
  const last = times[times.length - 1] ?? first;
  const width = Math.max(1, last - first + 1);
  const bins = Array.from({ length: 32 }, () => 0);
  for (const time of times) bins[Math.min(31, Math.floor((time - first) / width * 32))]!++;
  const peak = Math.max(1, ...bins);
  return <div className="visual-timeline">
    <div className="timeline-density">
      <div className="row"><strong>Activity in loaded events</strong><span className="spacer" /><span className="muted">{count(events.length)} events{hasMore ? "; more available" : ""}</span></div>
      <div className="density-bars" aria-label="Time distribution of loaded events">
        {bins.map((n, i) => {
          const from = new Date(Math.floor(first + width * i / 32)).toISOString();
          const to = new Date(Math.ceil(Math.min(last + 1, first + width * (i + 1) / 32))).toISOString();
          return <button type="button" key={i} disabled={!n} aria-label={`${n} loaded events from ${from} to ${to}`} title={`${n} loaded events; click to investigate this range`} onClick={() => onRange(from, to)}><span style={{ height: `${Math.max(3, n / peak * 100)}%` }} /></button>;
        })}
      </div>
      <div className="row"><Timestamp value={events[0]?.occurred_utc} /><span className="spacer" /><Timestamp value={events.at(-1)?.occurred_utc} /></div>
      <p className="muted">Select a time segment to narrow the investigation. Distribution covers loaded events only.</p>
    </div>
    <div className="timeline-scroll" ref={scroll}>
      <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
        {virtual.getVirtualItems().map((item) => {
          const e = events[item.index]!;
          const text = e.participants.map((p) => `${label(p.role)}: ${p.name}`).slice(0, 4).join(" · ");
          const fallback = Object.entries(e.attributes).filter(([, v]) => typeof v === "string").slice(0, 2).map(([k, v]) => `${label(k)}: ${v}`).join(" · ");
          return <button type="button" key={e.id} className={`timeline-event${selected === e.id ? " selected" : ""}`} style={{ position: "absolute", top: item.start, height: item.size, width: "100%" }} onClick={() => onSelect(e)} aria-label={`${label(e.kind)} at ${e.occurred_utc}`}>
            <span className="timeline-time"><Timestamp value={e.occurred_utc} precise /></span>
            <span className="timeline-track" aria-hidden><span /></span>
            <span className="timeline-event-main"><span className="row"><strong>{label(e.kind)}</strong><DerivationBadge kind={e.derivation} /></span><span className="timeline-event-summary">{text || fallback || "Open event for source details"}</span><span className="muted">Open evidence and related entities</span></span>
          </button>;
        })}
      </div>
    </div>
    <div className="row timeline-load"><span className="muted">Original timestamps and provenance are available in each event.</span><span className="spacer" />{hasMore && <Button size="sm" onClick={onMore} disabled={loading}>{loading ? "Loading…" : "Load more events"}</Button>}</div>
  </div>;
}
