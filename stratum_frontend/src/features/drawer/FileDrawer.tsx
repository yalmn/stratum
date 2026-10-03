// Datei im Context Drawer: Überblick, Zeitstempel (SI und FN), NTFS,
// Hashes, Inhalt als Hex und Strings. Lesen des Inhalts steht im Audit.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, ChevronLeft, ChevronRight, Download, Fingerprint } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { CodeBlock, CopyButton, ErrorState, HashValue, PropertyList, Skeleton, Tabs, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { HexViewer, strings } from "../../components/forensic/HexViewer";
import { fileExportUrl, useFileEntry, useHashFile, useHexWindow } from "../../lib/api/queries";
import { bytes, count, fileAttributes } from "../../lib/format";
import { useSession } from "../../lib/permissions";

const WINDOW = 4096;

function parse(id: string): [string, number, number] | null {
  const [ev, vol, rec] = id.split("|");
  const v = Number(vol);
  const r = Number(rec);
  return ev && Number.isFinite(v) && Number.isFinite(r) ? [ev, v, r] : null;
}

export function FileDrawer({ id, caseNumber, onClose }: { id: string; caseNumber: string; onClose: () => void }) {
  const p = parse(id);
  if (!p) {
    return (
      <DrawerFrame kind="File" title="Invalid reference" onClose={onClose}>
        <ErrorState title="The file reference in the address is not valid." />
      </DrawerFrame>
    );
  }
  return <FileView evidence={p[0]} volume={p[1]} record={p[2]} caseNumber={caseNumber} onClose={onClose} />;
}

function FileView({
  evidence,
  volume,
  record,
  caseNumber,
  onClose,
}: {
  evidence: string;
  volume: number;
  record: number;
  caseNumber: string;
  onClose: () => void;
}) {
  const entry = useFileEntry(evidence, volume, record);
  const { can } = useSession();
  const navigate = useNavigate();
  const hash = useHashFile(evidence, volume, record);
  const [view, setView] = useState<"hex" | "strings" | null>(null);
  const [offset, setOffset] = useState(0);

  if (entry.isPending) {
    return (
      <DrawerFrame kind="File" title="…" onClose={onClose}>
        <Skeleton lines={8} />
      </DrawerFrame>
    );
  }
  const f = entry.data?.[0];
  if (!f) {
    return (
      <DrawerFrame kind="File" title="Not found" onClose={onClose}>
        <ErrorState title="Not in the file catalog." reason={entry.error?.message} />
      </DrawerFrame>
    );
  }
  const others = (entry.data ?? []).slice(1);
  const size = f.size ?? 0;
  const ads = (f.streams ?? []).filter((s) => s.name);
  const hashes = hash.data;

  return (
    <DrawerFrame kind={f.is_directory ? "Folder" : "File"} title={f.name || "(root)"} onClose={onClose}>
      <div className="drawer-actions">
        {!f.is_directory && (
          <>
            <Button size="sm" icon={<Fingerprint />} onClick={() => setView(view ? null : "hex")}>
              {view ? "Hide content" : "View content"}
            </Button>
            <Button size="sm" icon={<Fingerprint />} disabled={hash.isPending} onClick={() => hash.mutate()}>
              {hash.isPending ? "Hashing…" : "Calculate hash"}
            </Button>
            {can("file.extract") && (
              <a className="btn btn-sm" href={fileExportUrl(evidence, volume, record)} download>
                <Download />
                Export
              </a>
            )}
          </>
        )}
        <Button
          size="sm"
          icon={<Activity />}
          onClick={() => navigate(`/cases/${encodeURIComponent(caseNumber)}/timeline?ev=${evidence}&q=${encodeURIComponent(f.name)}`)}
        >
          Show in timeline
        </Button>
      </div>
      <DrawerSection title="Overview">
        <PropertyList
          items={[
            [
              "Path",
              <span className="row">
                <span className="mono">{f.path || "\\"}</span>
                <CopyButton value={f.path} label="Copy path" />
              </span>,
            ],
            ["Size", f.is_directory ? null : <span className="mono" title={`${count(size)} bytes`}>{bytes(size)}</span>],
            ["Valid length", f.valid_length !== null ? <span className="mono">{count(f.valid_length)}</span> : null],
            ["Type", f.file_type ?? f.mime],
            ["Other names", others.length > 0 ? others.map((o) => o.path).join(", ") : null],
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Timestamps (UTC)">
        <table className="ts-table">
          <thead>
            <tr>
              <th />
              <th>$STANDARD_INFORMATION</th>
              <th>$FILE_NAME</th>
            </tr>
          </thead>
          <tbody>
            {(
              [
                ["Created", f.si_created, f.fn_created],
                ["Modified", f.si_modified, f.fn_modified],
                ["MFT modified", f.si_mft_modified, f.fn_mft_modified],
                ["Accessed", f.si_accessed, f.fn_accessed],
              ] as const
            ).map(([k, si, fn]) => (
              <tr key={k}>
                <td className="muted">{k}</td>
                <td>
                  <Timestamp value={si} precise bare />
                </td>
                <td>
                  <Timestamp value={fn} precise bare />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </DrawerSection>
      <DrawerSection title="NTFS">
        <PropertyList
          items={[
            ["MFT record", <span className="mono">{f.mft_record}</span>],
            ["Sequence", f.sequence !== null ? <span className="mono">{f.sequence}</span> : null],
            ["Parent record", f.parent_record !== undefined ? <span className="mono">{f.parent_record}</span> : null],
            ["Record offset", f.mft_record_offset !== null ? <span className="mono">{f.mft_record_offset}</span> : null],
            ["Volume offset", <span className="mono">{volume}</span>],
            ["Attributes", f.attributes.length > 0 ? fileAttributes(f.attributes) : null],
            ["Hard links", f.hardlinks],
            ["Reparse tag", f.reparse_tag && <span className="mono">{f.reparse_tag}</span>],
            ["WOF", f.wof],
            [
              "Streams",
              ads.length > 0 ? (
                <span className="stack">
                  {ads.map((s) => (
                    <span key={s.name} className="mono">
                      :{s.name} {s.groesse !== undefined ? `(${bytes(s.groesse)})` : ""}
                    </span>
                  ))}
                </span>
              ) : null,
            ],
          ]}
        />
        {(f.error || f.content_error) && <ErrorState title="Read problems" reason={[f.error, f.content_error].filter(Boolean).join("; ")} />}
      </DrawerSection>
      {!f.is_directory && (
        <DrawerSection title="Hashes">
          {hashes ? (
            <div className="stack">
              <HashValue algo="SHA256" value={hashes.sha256} />
              <HashValue algo="BLAKE3" value={hashes.blake3} />
              <span className="muted">
                {count(hashes.bytes)} bytes read{hashes.wof ? `, unpacked from ${hashes.wof}` : ""}.{" "}
                {hashes.im_katalog_vermerkt ? "SHA-256 recorded in the catalog." : ""}
              </span>
            </div>
          ) : f.sha256 ? (
            <HashValue algo="SHA256" value={f.sha256} />
          ) : (
            <span className="muted">Not hashed yet. Calculating reads the whole file from the image.</span>
          )}
          {hash.error && <ErrorState title="Hash failed." reason={hash.error.message} />}
        </DrawerSection>
      )}
      {!f.is_directory && view && (
        <ContentSection
          evidence={evidence}
          volume={volume}
          record={record}
          size={size}
          offset={offset}
          setOffset={setOffset}
          view={view}
          setView={setView}
        />
      )}
    </DrawerFrame>
  );
}

function ContentSection({
  evidence,
  volume,
  record,
  size,
  offset,
  setOffset,
  view,
  setView,
}: {
  evidence: string;
  volume: number;
  record: number;
  size: number;
  offset: number;
  setOffset: (o: number) => void;
  view: "hex" | "strings";
  setView: (v: "hex" | "strings") => void;
}) {
  const win = useHexWindow(evidence, volume, record, offset, true);
  const end = Math.min(size, offset + WINDOW);
  return (
    <DrawerSection
      title="Content"
      actions={
        <span className="row">
          <span className="muted mono">
            {count(offset)}–{count(end)} / {count(size)}
          </span>
          <Button size="sm" variant="ghost" icon={<ChevronLeft />} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - WINDOW))} aria-label="Previous block" />
          <Button size="sm" variant="ghost" icon={<ChevronRight />} disabled={end >= size} onClick={() => setOffset(offset + WINDOW)} aria-label="Next block" />
        </span>
      }
    >
      <Tabs
        active={view}
        onSelect={(v) => setView(v as "hex" | "strings")}
        items={[
          { id: "hex", label: "Hex" },
          { id: "strings", label: "Strings" },
        ]}
      />
      {win.isPending && <Skeleton lines={8} />}
      {win.error && <ErrorState title="Content could not be read." reason={win.error.message} />}
      {win.data &&
        (view === "hex" ? (
          <HexViewer bytes={win.data.bytes} offset={offset} />
        ) : (
          <CodeBlock>{strings(win.data.bytes).join("\n") || "(no strings of 4 or more characters in this block)"}</CodeBlock>
        ))}
    </DrawerSection>
  );
}
