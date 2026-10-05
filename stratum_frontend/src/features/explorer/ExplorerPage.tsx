// File Explorer (Vorgabe Abschnitt 13): Verzeichnisbaum links, Inhalt des
// gewählten Verzeichnisses in der Mitte, Datei-Details im Context Drawer.
// Zustand in der Adresse: Evidence, Volume, Verzeichnis und Pfad dorthin.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Activity,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  File,
  Fingerprint,
  Folder,
  FolderOpen,
  HardDrive,
  Info,
} from "lucide-react";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { SplitPane } from "../../components/ui/Layout";
import { useContextMenu } from "../../components/ui/Overlay";
import { fileExportUrl, useCase, useDirectory, useSubdirs, useVolumes, useCatalogSearch } from "../../lib/api/queries";
import type { Evidence, FileEntry } from "../../lib/api/types";
import { bytes, count, fileAttributes } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";
import { catalogRows, catalogRowId } from "./catalogRows";

const ROOT = 5;

interface Crumb {
  record: number;
  name: string;
}

function parseTrail(v: string | null): Crumb[] {
  if (!v) {
    return [];
  }
  return v.split("/").flatMap((p) => {
    const i = p.indexOf(":");
    const record = Number(p.slice(0, i));
    return i > 0 && Number.isFinite(record) ? [{ record, name: decodeURIComponent(p.slice(i + 1)) }] : [];
  });
}

function formatTrail(t: Crumb[]): string {
  return t.map((c) => `${c.record}:${encodeURIComponent(c.name)}`).join("/");
}

export function fileDetailId(evidence: string, volume: number, record: number): string {
  return `${evidence}|${volume}|${record}`;
}

const h = columnHelper<FileEntry>();
const nameColumn = (showSource = false) =>
  h.accessor("name", {
    header: showSource ? "Name / source path" : "Name",
    size: showSource ? 480 : 280,
    cell: (c) => {
      const e = c.row.original;
      const ads = (e.streams ?? []).filter((s) => s.name && s.name !== "WofCompressedData").length;
      return (
        <span className={showSource ? "file-source" : undefined}>
          <span className="file-name">
            {e.is_directory ? <Folder className="ico-dir" /> : <File className="ico-file" />}
            <span>{e.name}</span>
            {showSource && <span className="file-record mono">MFT {e.mft_record}</span>}
            {ads > 0 && <Badge tone="warning">ADS {ads}</Badge>}
            {e.error && <Badge tone="danger">Error</Badge>}
          </span>
          {showSource && <span className="file-source-path mono" title={e.path}>{e.path}</span>}
        </span>
      );
    },
  });
const columns = [
  nameColumn(),
  h.accessor("size", {
    header: "Size",
    size: 110,
    cell: (c) => (c.row.original.is_directory || c.getValue() === null ? "" : bytes(c.getValue() ?? 0)),
  }),
  h.accessor("si_modified", { header: "Modified (SI, UTC)", size: 200, cell: (c) => <Timestamp value={c.getValue()} /> }),
  h.accessor("si_created", { header: "Created (SI, UTC)", size: 200, cell: (c) => <Timestamp value={c.getValue()} /> }),
  h.accessor("mft_record", { header: "MFT #", size: 90, cell: (c) => <span className="mono">{c.getValue()}</span> }),
  h.accessor("attributes", {
    header: "Attributes",
    size: 150,
    enableSorting: false,
    cell: (c) => <span className="muted">{fileAttributes(c.getValue())}</span>,
  }),
];

const searchColumns = [nameColumn(true), ...columns.slice(1)];

function DirNode({
  evidence,
  volume,
  entry,
  trail,
  current,
  onOpen,
}: {
  evidence: string;
  volume: number;
  entry: FileEntry;
  trail: Crumb[];
  current: number;
  onOpen: (trail: Crumb[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const sub = useSubdirs(evidence, volume, entry.mft_record, open);
  const mine = [...trail, { record: entry.mft_record, name: entry.name }];
  return (
    <li role="treeitem" aria-expanded={entry.hat_kinder ? open : undefined}>
      <div
        className={current === entry.mft_record ? "tree-node selected" : "tree-node"}
        tabIndex={0}
        onClick={() => onOpen(mine)}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") setOpen(true);
          else if (e.key === "ArrowLeft") setOpen(false);
          else if (e.key === "Enter") onOpen(mine);
        }}
      >
        <span
          className="tree-toggle"
          onClick={(e) => {
            e.stopPropagation();
            if (entry.hat_kinder) setOpen(!open);
          }}
        >
          {entry.hat_kinder ? open ? <ChevronDown /> : <ChevronRight /> : <span className="tree-spacer" />}
        </span>
        {open ? <FolderOpen className="ico-dir" /> : <Folder className="ico-dir" />}
        <span>{entry.name}</span>
      </div>
      {open && (
        <ul className="tree" role="group">
          {sub.isPending && <li className="tree-note muted">Loading…</li>}
          {sub.data?.dirs.map((d) => (
            <DirNode
              key={d.mft_record}
              evidence={evidence}
              volume={volume}
              entry={d}
              trail={mine}
              current={current}
              onOpen={onOpen}
            />
          ))}
          {sub.data?.more && <li className="tree-note muted">More folders: open this folder</li>}
        </ul>
      )}
    </li>
  );
}

function Tree({
  evidence,
  volume,
  current,
  label,
  onOpen,
}: {
  evidence: string;
  volume: number;
  current: number;
  label: string;
  onOpen: (trail: Crumb[]) => void;
}) {
  const root = useSubdirs(evidence, volume, ROOT, true);
  return (
    <div className="explorer-tree">
      <ul className="tree" role="tree">
        <li role="treeitem" aria-expanded>
          <div className={current === ROOT ? "tree-node selected" : "tree-node"} tabIndex={0} onClick={() => onOpen([])}>
            <span className="tree-toggle">
              <ChevronDown />
            </span>
            <HardDrive />
            <span>{label}</span>
          </div>
          <ul className="tree" role="group">
            {root.isPending && <li className="tree-note muted">Loading…</li>}
            {root.data?.dirs.map((d) => (
              <DirNode key={d.mft_record} evidence={evidence} volume={volume} entry={d} trail={[]} current={current} onOpen={onOpen} />
            ))}
          </ul>
        </li>
      </ul>
    </div>
  );
}

function Listing({
  evidence,
  volume,
  dir,
  trail,
  onEnter,
  base,
  filter,
}: {
  evidence: string;
  volume: number;
  dir: number;
  trail: Crumb[];
  onEnter: (trail: Crumb[]) => void;
  base: string;
  filter: { suche: string; endung: string; format: string };
}) {
  const searching = !!(filter.suche || filter.endung || filter.format);
  const directory = useDirectory(evidence, volume, dir, !searching);
  const found = useCatalogSearch(evidence, volume, filter, searching);
  const list = searching ? found : directory;
  const { detail, open } = useDetail();
  const [params] = useSearchParams();
  const { can } = useSession();
  const navigate = useNavigate();
  const menu = useContextMenu();
  const rows = useMemo(() => catalogRows(list.data?.pages ?? []), [list.data]);
  const loadMore = useCallback(() => {
    if (list.hasNextPage && !list.isFetching) {
      void list.fetchNextPage({ cancelRefetch: false });
    }
  }, [list]);
  const id = (e: FileEntry) => fileDetailId(evidence, volume, e.mft_record);
  const rowId = catalogRowId;
  const selected = rows.find((e) => detail?.kind === "file" && detail.id === id(e) && (!params.get("file_path") || params.get("file_path") === e.path));
  const enter = (e: FileEntry) => (e.is_directory ? onEnter([...trail, { record: e.mft_record, name: e.name }]) : open("file", id(e), e.path));

  if (list.isPending) {
    return <Skeleton lines={10} />;
  }
  if (list.error) {
    return <ErrorState title="Folder could not be read." reason={list.error.message} />;
  }
  if (rows.length === 0) {
    return <EmptyState title={searching ? "No matching files in this volume." : "This folder is empty."} />;
  }
  return (
    <>
      <DataTable
        label={searching ? "Files matching catalog filters" : "Folder content"}
        data={rows}
        columns={searching ? searchColumns : columns}
        rowHeight={searching ? 64 : 36}
        rowId={rowId}
        grow={["name"]}
        numeric={["size"]}
        selected={selected ? rowId(selected) : null}
        onSelect={(e) => open("file", id(e), e.path)}
        onOpen={enter}
        onEndReached={loadMore}
        onContextMenu={(ev, e) =>
          menu.open(ev, [
            ...(e.is_directory ? [{ label: "Open folder", icon: <FolderOpen />, onSelect: () => enter(e) }] : []),
            { label: "Open details", icon: <Info />, onSelect: () => open("file", id(e), e.path) },
            ...(e.is_directory
              ? []
              : [
                  { label: "View hex and strings", icon: <Fingerprint />, onSelect: () => open("file", id(e), e.path) },
                  {
                    label: "Export file",
                    icon: <Download />,
                    disabled: !can("file.extract"),
                    reason: "Missing permission file.extract",
                    onSelect: () => window.open(fileExportUrl(evidence, volume, e.mft_record), "_blank"),
                  },
                ]),
            "separator" as const,
            {
              label: "Show in timeline",
              icon: <Activity />,
              onSelect: () => navigate(`${base}/timeline?ev=${evidence}&q=${encodeURIComponent(e.name)}`),
            },
            { label: "Copy path", icon: <Copy />, onSelect: () => void navigator.clipboard?.writeText(e.path) },
          ])
        }
        footer={
          <>
            {count(rows.length)} {searching ? "source paths" : "entries"}{list.hasNextPage ? " loaded, scroll for more" : ""}
            <span className="spacer" />
            {searching ? "Several paths can refer to the same MFT record (hardlinks)." : "Double-click or Enter opens a folder · J/K to move"}
          </>
        }
      />
      {menu.menu}
    </>
  );
}

export function ExplorerPage({ number }: { number: string }) {
  const c = useCase(number);
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const evidenceList: Evidence[] = c.data?.evidence ?? [];
  const evidence = params.get("ev") ?? evidenceList.find((e) => e.kind === "raw_disk_image" || e.kind === "e01_image")?.id;
  const volumes = useVolumes(evidence);
  const volume = params.get("vol") !== null ? Number(params.get("vol")) : volumes.data?.[0]?.volume_offset;
  const trail = parseTrail(params.get("pfad"));
  const filter = { suche: params.get("q") ?? "", endung: params.get("ext") ?? "", format: params.get("fmt") ?? "" };
  const [searchText, setSearchText] = useState(filter.suche);
  useEffect(() => setSearchText(filter.suche), [filter.suche]);
  const { can } = useSession();
  const changeFilter = (k: string, v: string) => setParams((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); n.delete("detail"); return n; });
  const dir = trail.length > 0 ? trail[trail.length - 1]!.record : ROOT;

  const go = (t: Crumb[], changes: Record<string, string | null> = {}) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      if (t.length > 0) n.set("pfad", formatTrail(t));
      else n.delete("pfad");
      n.delete("detail");
      for (const [k, v] of Object.entries(changes)) {
        if (v === null) n.delete(k);
        else n.set(k, v);
      }
      return n;
    });

  if (c.isPending) {
    return (
      <div className="page">
        <Skeleton lines={6} />
      </div>
    );
  }
  if (evidenceList.length === 0) {
    return (
      <div className="page">
        <EmptyState title="No evidence in this case yet." text="Add evidence first, then run an analysis with the file catalog." />
      </div>
    );
  }
  const volLabel = (v: number) => `Volume @ ${v.toLocaleString("en-US")}`;

  return (
    <div className="explorer">
      <div className="explorer-bar">
        <Select
          value={evidence ?? ""}
          onChange={(e) => go([], { ev: e.target.value, vol: null })}
          aria-label="Evidence"
          className="explorer-select"
        >
          {evidenceList.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </Select>
        {volumes.data && volumes.data.length > 0 && (
          <Select
            value={String(volume ?? "")}
            onChange={(e) => go([], { vol: e.target.value })}
            aria-label="Volume"
            className="explorer-select"
          >
            {volumes.data.map((v) => (
              <option key={v.volume_offset} value={v.volume_offset}>
                {volLabel(v.volume_offset)} · {count(v.eintraege)} entries
              </option>
            ))}
          </Select>
        )}
        <nav className="crumbs" aria-label="Path">
          <button type="button" onClick={() => go([])}>
            {volume !== undefined ? volLabel(volume) : "Volume"}
          </button>
          {trail.map((t, i) => (
            <span key={`${t.record}-${i}`}>
              <span className="crumb-sep">\</span>
              <button type="button" onClick={() => go(trail.slice(0, i + 1))}>
                {t.name}
              </button>
            </span>
          ))}
        </nav>
      </div>
      {can("search.run") && <form className="filter-bar" onSubmit={(e) => { e.preventDefault(); changeFilter("q", searchText.trim()); }}>
        <Input aria-label="Find file path in the whole volume" placeholder="Find file name or path across this volume" value={searchText} onChange={(e) => setSearchText(e.target.value)} />
        <Button type="submit" size="sm">Find files</Button>
        <Input aria-label="File extension" placeholder="Extension, e.g. png" value={filter.endung} onChange={(e) => changeFilter("ext", e.target.value.trim())} />
        <Select aria-label="Detected format" value={filter.format} onChange={(e) => changeFilter("fmt", e.target.value)}>
          <option value="">All detected formats</option>
          {["png", "jpeg", "gif", "pdf", "pe", "elf", "zip", "sqlite3"].map((f) => <option key={f} value={f}>{f.toUpperCase()} (signature)</option>)}
        </Select>
        {(filter.suche || filter.endung || filter.format) && <Button size="sm" variant="ghost" onClick={() => { setSearchText(""); setParams((p) => { const n = new URLSearchParams(p); for (const k of ["q", "ext", "fmt"]) n.delete(k); return n; }); }}>Clear filters</Button>}
        <span className="muted">Search scope: whole volume. Detected formats require content identification during analysis.</span>
      </form>}
      {volumes.isPending && evidence && <Skeleton lines={6} />}
      {volumes.data && volumes.data.length === 0 && (
        <div className="page">
          <EmptyState
            title="No file catalog for this evidence."
            text="Run an analysis with the option File catalog; afterwards the folder tree appears here."
            action={
              <Button onClick={() => navigate(`/cases/${encodeURIComponent(number)}/evidence?analyze=${evidence}`)}>
                Analyze with file catalog
              </Button>
            }
          />
        </div>
      )}
      {evidence && volume !== undefined && volumes.data && volumes.data.length > 0 && (
        <div className="explorer-split">
          <SplitPane
            id="explorer"
            initial={26}
            min={14}
            max={50}
            left={<Tree evidence={evidence} volume={volume} current={dir} label={volLabel(volume)} onOpen={(t) => go(t)} />}
            right={
              <div className="explorer-list">
                <Listing key={`${evidence}-${volume}-${dir}`} evidence={evidence} volume={volume} dir={dir} filter={filter} trail={trail} onEnter={(t) => go(t)} base={`/cases/${encodeURIComponent(number)}`} />
              </div>
            }
          />
        </div>
      )}
    </div>
  );
}
