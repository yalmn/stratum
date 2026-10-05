// War Room (Vorgabe Abschnitt 20): operativer Verlauf des Falls, älteste
// oben, neueste unten, Eingabe darunter. Getrennt von Timeline (was auf dem
// System geschah) und Audit (was Benutzer in stratum taten).

import { useEffect, useMemo, useRef, useState } from "react";
import { CornerDownRight, Download, MessageSquare, Server } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, HashValue, Skeleton, Timestamp } from "../../components/ui/Display";
import { Textarea } from "../../components/ui/Input";
import { Kbd, MOD } from "../../components/ui/Kbd";
import { JobStatusBadge } from "../../components/forensic/Badges";
import { usePostNote, useWarRoom } from "../../lib/api/queries";
import type { JobStatus, WarRoomItem } from "../../lib/api/types";
import { count } from "../../lib/format";
import { useDetail } from "../../app/detail";

type Filter = "all" | "analyst" | "system";

const kindOf = (e: WarRoomItem): Filter =>
  e.kind === "analyst_note" || e.kind === "analyst_message" ? "analyst" : "system";

function SystemBody({ e }: { e: WarRoomItem }) {
  const p = e.payload as Record<string, unknown>;
  const { open } = useDetail();
  const job = typeof p.job_id === "string" ? p.job_id : null;
  const what = p.job_kind === "network_enrichment" ? "DNS / WHOIS" : p.job_kind === "yara_scan" ? "YARA scan" : p.job_kind === "evidence_import" ? "Evidence import" : "Analysis";
  const evidence = e.object_refs.find((r) => r.type === "evidence");
  if (e.kind === "search") {
    return <div className="wr-body">
      <span>Artifact search: <span className="mono">{String(p.suche ?? "")}</span></span>
      <span className="muted">{count(Number(p.anzahl ?? 0))} results on this page · Stored artifact fields{typeof p.typ === "string" ? ` · ${p.typ}` : ""}</span>
    </div>;
  }
  if (e.kind === "file_extracted") {
    return (
      <div className="wr-body">
        <div className="row">
          <Download size={14} />
          <span>
            Exported <span className="mono">{String(p.pfad ?? p.name ?? "")}</span> ({count(Number(p.bytes ?? 0))} bytes)
          </span>
        </div>
        {typeof p.sha256 === "string" && <HashValue algo="SHA256" value={p.sha256} />}
      </div>
    );
  }
  if (p.event === "job_queued") {
    return (
      <div className="wr-body row">
        <span>{what} queued</span>
        {typeof p.datei === "string" && <span className="mono muted">{p.datei}</span>}
        {evidence && (
          <button type="button" className="link" onClick={() => open("evidence", evidence.id)}>
            evidence
          </button>
        )}
        {job && (
          <button type="button" className="link" onClick={() => open("job", job)}>
            job
          </button>
        )}
      </div>
    );
  }
  if (p.event === "job_finished") {
    const r = (p.result ?? {}) as Record<string, unknown>;
    const facts = [
      typeof r.funde === "number" ? `${count(r.funde)} findings` : null,
      typeof r.zeitstrahl === "number" ? `${count(r.zeitstrahl)} timeline entries` : null,
      typeof r.warnungen === "number" && r.warnungen > 0 ? `${count(r.warnungen)} warnings` : null,
      typeof r.name === "string" ? `${r.name} ${r.neu ? "registered" : "hash confirmed"}` : null,
    ].filter(Boolean);
    return (
      <div className="wr-body">
        <div className="row">
          <span>{what} finished</span>
          <JobStatusBadge status={p.status as JobStatus} />
          {job && (
            <button type="button" className="link" onClick={() => open("job", job)}>
              details
            </button>
          )}
        </div>
        {facts.length > 0 && <span className="muted">{facts.join(" · ")}</span>}
        {typeof p.error === "string" && p.error && <span className="form-error">{p.error}</span>}
      </div>
    );
  }
  return (
    <div className="wr-body">
      <code className="muted">{JSON.stringify(p)}</code>
    </div>
  );
}

function Entry({ e, parent }: { e: WarRoomItem; parent?: WarRoomItem }) {
  const analyst = kindOf(e) === "analyst";
  const text = (e.payload as { text?: string }).text ?? "";
  return (
    <article className={analyst ? "wr-entry analyst" : "wr-entry system"}>
      <div className="wr-icon">{analyst ? <MessageSquare /> : <Server />}</div>
      <div className="wr-main">
        <header className="wr-head">
          <strong>{analyst ? (e.actor_name ?? "Analyst") : "Stratum"}</strong>
          {!analyst && e.actor_name && <span className="muted">for {e.actor_name}</span>}
          <Timestamp value={e.timestamp} />
        </header>
        {parent && (
          <div className="wr-reply muted">
            <CornerDownRight size={12} />
            {((parent.payload as { text?: string }).text ?? "").slice(0, 120)}
          </div>
        )}
        {analyst ? <div className="wr-text">{text}</div> : <SystemBody e={e} />}
      </div>
    </article>
  );
}

export function WarRoomPage({ number }: { number: string }) {
  const wr = useWarRoom(number);
  const post = usePostNote(number);
  const [filter, setFilter] = useState<Filter>("all");
  const [text, setText] = useState("");
  const end = useRef<HTMLDivElement>(null);
  // Älteste oben: Seiten kommen neueste zuerst und werden umgedreht.
  const all = useMemo(() => (wr.data?.pages.flatMap((p) => p.eintraege) ?? []).slice().reverse(), [wr.data]);
  const byId = useMemo(() => new Map(all.map((e) => [e.id, e])), [all]);
  const shown = all.filter((e) => filter === "all" || kindOf(e) === filter);
  const newest = all[all.length - 1]?.id;

  useEffect(() => {
    end.current?.scrollIntoView({ block: "end" });
  }, [newest]);

  const send = () => {
    const t = text.trim();
    if (t) {
      post.mutate({ text: t }, { onSuccess: () => setText("") });
    }
  };

  return (
    <div className="war-room">
      <div className="filter-bar">
        {(["all", "analyst", "system"] as const).map((f) => (
          <Button key={f} size="sm" variant={filter === f ? "primary" : "secondary"} onClick={() => setFilter(f)}>
            {f === "all" ? "All" : f === "analyst" ? "Analyst" : "System"}
          </Button>
        ))}
        <span className="spacer" />
        <span className="muted">Investigation log. The forensic timeline and the audit log are separate.</span>
      </div>
      <div className="wr-stream">
        {wr.hasNextPage && (
          <Button size="sm" variant="ghost" onClick={() => void wr.fetchNextPage()} disabled={wr.isFetchingNextPage}>
            Load older entries
          </Button>
        )}
        {wr.isPending && <Skeleton lines={6} />}
        {wr.error && <ErrorState title="War Room could not be loaded." reason={wr.error.message} />}
        {wr.data && shown.length === 0 && (
          <EmptyState title="Nothing here yet." text="Notes, analyses, imports and exports of this case appear here." />
        )}
        {shown.map((e) => (
          <Entry key={e.id} e={e} parent={e.parent_entry_id ? byId.get(e.parent_entry_id) : undefined} />
        ))}
        <div ref={end} />
      </div>
      <form
        className="wr-input"
        onSubmit={(e) => {
          e.preventDefault();
          send();
        }}
      >
        <Textarea
          rows={3}
          placeholder="Note for the investigation log…"
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              send();
            }
          }}
        />
        <div className="row">
          {post.error && <span className="form-error">{post.error.message}</span>}
          <span className="spacer" />
          <span className="muted">
            <Kbd>{MOD}↵</Kbd> to post · notes cannot be edited later
          </span>
          <Button type="submit" variant="primary" disabled={post.isPending || !text.trim()}>
            Post note
          </Button>
        </div>
      </form>
    </div>
  );
}
