// Datei im Context Drawer: Überblick, Zeitstempel (SI und FN), NTFS,
// Hashes, Inhalt als Hex und Strings. Lesen des Inhalts steht im Audit.

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, ChevronLeft, ChevronRight, Download, Fingerprint } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { CodeBlock, CopyButton, ErrorState, HashValue, PropertyList, Skeleton, Tabs, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { HexViewer, strings } from "../../components/forensic/HexViewer";
import { fileExportUrl, useFileEntry, useHashFile, useHexWindow, useFileSearch, useFilePreview, useFileIps } from "../../lib/api/queries";
import { Input, Select } from "../../components/ui/Input";
import { bytes, count, fileAttributes } from "../../lib/format";
import { useSession } from "../../lib/permissions";

const WINDOW = 4096;

function parse(id: string): [string, number, number] | null {
  const parts = id.split("|");
  if (parts.length !== 3) return null;
  const [ev, vol, rec] = parts;
  const v = Number(vol);
  const r = Number(rec);
  return ev && vol && rec && Number.isSafeInteger(v) && v >= 0 && Number.isSafeInteger(r) && r >= 0 ? [ev, v, r] : null;
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
  return <FileView key={id} evidence={p[0]} volume={p[1]} record={p[2]} caseNumber={caseNumber} onClose={onClose} />;
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
  const [view, setView] = useState<"hex" | "strings" | "text" | "preview" | null>("hex");
  const search = useFileSearch(evidence, volume, record);
  const ips = useFileIps(evidence, volume, record);
  const [word, setWord] = useState("");
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
      {!f.is_directory && can("search.run") && (
        <DrawerSection title="Find words in this file">
          <form className="row" onSubmit={(e) => { e.preventDefault(); if (word) search.mutate(word); }}>
            <Input aria-label="Word to find" placeholder="Word or phrase" value={word} onChange={(e) => setWord(e.target.value)} maxLength={1024} />
            <Button type="submit" size="sm" disabled={!word || search.isPending}>{search.isPending ? "Searching…" : "Search"}</Button>
          </form>
          <p className="muted">Literal, case-sensitive UTF-8 and UTF-16LE. Up to 256 MiB and 500 matches. Offsets refer to the logical file content.</p>
          {search.error && <ErrorState title="Search failed" reason={search.error.message} />}
          {search.data && <>
            <p role="status">Search for “{search.variables}”: {count(search.data.treffer.length)} matches in {bytes(search.data.gelesen)}. {search.data.vollstaendig ? "Whole file searched." : "Search limit reached; results are incomplete."}</p>
            <div className="file-matches">{search.data.treffer.map((t) => <Button key={`${t.offset}-${t.kodierung}`} size="sm" variant="ghost" onClick={() => { setOffset(Math.floor(t.offset / WINDOW) * WINDOW); setView("hex"); }}>0x{t.offset.toString(16).toUpperCase()} · {t.kodierung}</Button>)}</div>
          </>}
        </DrawerSection>
      )}
      {!f.is_directory && can("search.run") && (
        <DrawerSection title="IP address occurrences">
          <Button size="sm" disabled={ips.isPending} onClick={() => ips.mutate()}>{ips.isPending ? "Scanning…" : "Find IP addresses"}</Button>
          <p className="muted">ASCII and UTF-16LE literals, up to 256 MiB and 500 occurrences. Logical file offsets. Text occurrences do not establish network activity.</p>
          {ips.error && <ErrorState title="IP search failed" reason={ips.error.message} />}
          {ips.data && <>
            <p role="status">{count(ips.data.ergebnis.treffer.length)} occurrences in {bytes(ips.data.ergebnis.gelesen)}. {ips.data.ergebnis.vollstaendig ? "Whole file searched." : "Search limit reached; results are incomplete."}</p>
            <div className="file-matches">{ips.data.ergebnis.treffer.map((t) => (
              <div className="row" key={`${t.offset}-${t.kodierung}`}>
                <Button size="sm" variant="ghost" title={`Original: ${t.original}. Show surrounding logical bytes.`} onClick={() => { setOffset(Math.max(0, t.offset - 64)); setView("hex"); }}>
                  {t.art} {t.adresse} · 0x{t.offset.toString(16).toUpperCase()} · {t.kodierung}
                </Button>
                <CopyButton value={t.adresse} label="Copy IP address" />
              </div>
            ))}</div>
          </>}
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
            ["Detected format", f.file_type ?? "Not identified; extension is not proof of format"],
            ["MIME", f.mime],
            ["Signature bytes", f.signature ? <span className="mono">{f.signature.bytes} at logical offset 0x{f.signature.offset.toString(16)}</span> : null],
            ["Evidence", <span className="mono">{evidence}</span>],
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
  view: "hex" | "strings" | "text" | "preview";
  setView: (v: "hex" | "strings" | "text" | "preview") => void;
}) {
  const win = useHexWindow(evidence, volume, record, offset, view !== "preview");
  const preview = useFilePreview(evidence, volume, record, view === "preview" && size <= 8 * 1024 * 1024);
  const [jump, setJump] = useState(String(offset));
  const [encoding, setEncoding] = useState("utf-8");
  useEffect(() => setJump(String(offset)), [offset]);
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
        onSelect={(v) => setView(v as "hex" | "strings" | "text" | "preview")}
        items={[
          { id: "hex", label: "Raw / Hex" },
          { id: "text", label: "Text" },
          { id: "preview", label: "Image preview" },
          { id: "strings", label: "Strings" },
        ]}
      />
      <p className="muted">Logical file bytes. NTFS compression and WOF are decoded; the displayed offset is not a physical image offset.</p>
      {view === "text" && <Select value={encoding} onChange={(e) => setEncoding(e.target.value)} aria-label="Text encoding"><option value="utf-8">UTF-8</option><option value="utf-16le">UTF-16LE</option><option value="utf-16be">UTF-16BE</option></Select>}
      {view !== "preview" && <form className="row" onSubmit={(e) => { e.preventDefault(); const n = Number(jump); if (Number.isSafeInteger(n) && n >= 0 && n <= size) setOffset(n); }}>
        <Input aria-label="Logical byte offset, decimal or hexadecimal" value={jump} onChange={(e) => setJump(e.target.value)} placeholder="Byte offset or 0x…" />
        <Button size="sm" type="submit">Go to offset</Button>
      </form>}
      {view === "preview" && <>
        <p className="muted">PNG, JPEG and GIF only, up to 8 MiB. Preview is decoded from file content.</p>
        {size > 8 * 1024 * 1024 && <ErrorState title="File exceeds the 8 MiB preview limit." />}
        {preview.isFetching && <Skeleton lines={6} />}
        {preview.error && <ErrorState title="Preview could not be read." reason={preview.error.message} />}
        {preview.data && <ImagePreview data={preview.data.bytes} />}
      </>}
      {view !== "preview" && win.isPending && <Skeleton lines={8} />}
      {view !== "preview" && win.error && <ErrorState title="Content could not be read." reason={win.error.message} />}
      {view !== "preview" && win.data &&
        (view === "hex" ? (
          <HexViewer bytes={win.data.bytes} offset={offset} />
        ) : view === "text" ? (
          <CodeBlock>{new TextDecoder(encoding).decode(win.data.bytes).replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "·") || "(empty)"}</CodeBlock>
        ) : (
          <CodeBlock>{strings(win.data.bytes).join("\n") || "(no strings of 4 or more characters in this block)"}</CodeBlock>
        ))}
    </DrawerSection>
  );
}

function ImagePreview({ data }: { data: Uint8Array }) {
  const png = [137, 80, 78, 71, 13, 10, 26, 10].every((v, i) => data[i] === v);
  const jpeg = data[0] === 255 && data[1] === 216 && data[2] === 255;
  const gif = ["GIF87a", "GIF89a"].includes(new TextDecoder().decode(data.subarray(0, 6)));
  const mime = png ? "image/png" : jpeg ? "image/jpeg" : gif ? "image/gif" : null;
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    setFailed(false);
    if (!mime) { setUrl(null); return; }
    const u = URL.createObjectURL(new Blob([new Uint8Array(data)], { type: mime }));
    setUrl(u);
    return () => URL.revokeObjectURL(u);
  }, [data, mime]);
  if (!mime) return <ErrorState title="No supported raster image signature." reason="Use Raw / Hex or export the file for another viewer." />;
  if (failed) return <ErrorState title="The browser could not decode this image." />;
  return url ? <img className="file-preview" src={url} alt="Preview of evidence file" onError={() => setFailed(true)} /> : null;
}
