import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { EmptyState, ErrorState, Skeleton } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { Button } from "../../components/ui/Button";
import { useArtifacts, useCase } from "../../lib/api/queries";
import type { ArtifactRow } from "../../lib/api/types";
import { label, count } from "../../lib/format";
import { useDetail } from "../../app/detail";
import { useSession } from "../../lib/permissions";

const KINDS = [
  "ntfs_mft_record", "ntfs_stream", "usn_record", "registry_key", "registry_value", "evtx_record",
  "prefetch_record", "lnk_record", "jump_list_entry", "shell_item", "recycle_bin_record",
  "browser_history_row", "browser_login_row", "powershell_history_line", "ese_record",
  "pcap_packet", "network_flow", "log_line", "sqlite_row", "mobile_record", "unknown",
];
function sourceLabel(source: Record<string, unknown>): string {
  if (typeof source.path === "string") return source.path;
  if (typeof source.key_path === "string") return `${source.hive ?? "Registry"}\\${source.key_path}`;
  if (source.type === "ntfs") return `MFT ${source.mft_record} · Volume offset ${source.volume_offset}`;
  if (source.type === "byte_range") return `Image offset ${source.offset}`;
  if (source.type === "pcap") return `Packet ${source.packet_number}`;
  return JSON.stringify(source);
}
const h = columnHelper<ArtifactRow>();
const columns = [
  h.accessor("kind", { header: "Type", size: 160, cell: c => <span className="badge">{label(c.getValue())}</span> }),
  h.accessor("evidence_name", { header: "Evidence", size: 180 }),
  h.accessor("source_locator", { header: "Source", size: 260, cell: c => <span className="mono" title={JSON.stringify(c.getValue())}>{sourceLabel(c.getValue())}</span> }),
  h.accessor("preview", { header: "Stored fields", size: 350 }),
  h.accessor("observations", { header: "Observations", size: 110 }),
];

export function ArtifactsPage({ number, searchMode = false }: { number: string; searchMode?: boolean }) {
  const [params, setParams] = useSearchParams();
  const kind = params.get("art") ?? "";
  const evidence = params.get("evidence") ?? "";
  const search = params.get("q") ?? "";
  const [text, setText] = useState(search);
  useEffect(() => setText(search), [search]);
  const { can } = useSession();
  const allowed = can("search.run");
  const enabled = (!searchMode || !!search) && (!search || allowed);
  const list = useArtifacts(number, kind, evidence, search, enabled);
  const c = useCase(number);
  const { detail, open } = useDetail();
  const rows = useMemo(() => list.data?.pages.flatMap(p => p.eintraege) ?? [], [list.data]);
  const loadMore = useCallback(() => {
    if (list.hasNextPage && !list.isFetchingNextPage) void list.fetchNextPage();
  }, [list]);
  const set = (k: string, v: string) => setParams(p => {
    const n = new URLSearchParams(p);
    if (v) n.set(k, v);
    else n.delete(k);
    return n;
  });

  return (
    <div className="timeline">
      <p className="muted" style={{ padding: "12px 20px", margin: 0 }}>
        Search stored artifact and observation fields, including IPs, URLs and source locations. Literal text, case insensitive.
        File contents outside the case model are searched in Explorer. Secrets stay masked.
      </p>
      <div className="filter-bar">
        <Select value={kind} onChange={e => set("art", e.target.value)} aria-label="Artifact type" className="filter-select">
          <option value="">All artifact types</option>
          {KINDS.map(k => <option key={k} value={k}>{label(k)}</option>)}
        </Select>
        <Select value={evidence} onChange={e => set("evidence", e.target.value)} aria-label="Evidence" className="filter-select">
          <option value="">All evidence</option>
          {c.data?.evidence.map(e => <option key={e.id} value={e.id}>{e.name}</option>)}
        </Select>
        <form className="filter-search row" onSubmit={e => {
          e.preventDefault();
          const next = text.trim();
          if (!allowed || (searchMode && !next)) return;
          if (next === search && enabled) void list.refetch();
          else set("q", next);
        }}>
          <Input aria-label="Search stored artifact fields" placeholder="Word, IP, URL or source path" value={text}
            onChange={e => setText(e.target.value)} disabled={!allowed} maxLength={512} />
          <Button type="submit" disabled={!allowed || (searchMode && !text.trim()) || list.isFetching}>Search</Button>
        </form>
        {search && <Button onClick={() => { setText(""); set("q", ""); }}>Clear</Button>}
      </div>
      <div className="timeline-body">
        {!allowed && <p className="muted">Searching requires the search.run permission.</p>}
        {searchMode && !search && <EmptyState title="Search this case" text="Enter a word, IP address or URL. Select a result to inspect its source and add it to Investigation selection." />}
        {enabled && list.isPending && <Skeleton lines={10} />}
        {list.error && <ErrorState title="Artifacts could not be loaded" reason={list.error.message} />}
        {enabled && list.data && rows.length === 0 && <EmptyState title="No stored artifacts found"
          text={search || kind || evidence ? "Change the search or filters. This does not prove absence from the original evidence." : "Run an analysis to populate the case model."} />}
        {enabled && rows.length > 0 && <DataTable label={searchMode ? "Artifact search results" : "Artifacts"}
          data={rows} columns={columns} rowId={r => r.id} grow={["preview"]} numeric={["observations"]}
          selected={detail?.kind === "artifact" ? detail.id : null} onSelect={r => open("artifact", r.id)}
          onEndReached={loadMore} footer={`${count(rows.length)} artifacts loaded${list.hasNextPage ? ", scroll for more" : ""}`} />}
      </div>
    </div>
  );
}
