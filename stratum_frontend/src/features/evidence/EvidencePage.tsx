// Evidence Sources: je Quelle eine kompakte Zeile mit Art, Größe,
// Integrität und Aktionen. Details im Drawer, Analyse und Import inline im
// Workspace statt in Dialogen.

import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Activity, File, Folder, FolderTree, HardDrive, Info, Play, Upload } from "lucide-react";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, HashValue, Skeleton, Timestamp } from "../../components/ui/Display";
import { Checkbox, Field, Input } from "../../components/ui/Input";
import { useContextMenu } from "../../components/ui/Overlay";
import { evidenceKind, IntegrityBadge, SupportBadge } from "../../components/forensic/Badges";
import { useCase, useCaseFolder, useImportEvidence, useStartAnalysis } from "../../lib/api/queries";
import type { AnalysisOptions, Evidence } from "../../lib/api/types";
import { bytes, count } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

const analyzable = (e: Evidence) => e.kind === "raw_disk_image" || e.kind === "e01_image";

export function EvidencePage({ number }: { number: string }) {
  const c = useCase(number);
  const { can } = useSession();
  const [params, setParams] = useSearchParams();
  const { detail, open } = useDetail();
  const menu = useContextMenu();
  const navigate = useNavigate();
  const base = `/cases/${encodeURIComponent(number)}`;
  const adding = params.get("add") === "1";
  const analyzing = params.get("analyze");
  // Mehrere Schlüssel in einer Änderung, sonst überschreibt die zweite die erste.
  const update = (changes: Record<string, string | null>) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      for (const [k, v] of Object.entries(changes)) {
        if (v === null) {
          n.delete(k);
        } else {
          n.set(k, v);
        }
      }
      return n;
    });
  const set = (k: string, v: string | null) => update({ [k]: v });
  const showJob = (panel: string) => (job: string) => update({ [panel]: null, detail: `job:${job}` });

  if (c.isPending) {
    return (
      <div className="page">
        <Skeleton lines={6} />
      </div>
    );
  }
  if (c.error || !c.data) {
    return (
      <div className="page">
        <ErrorState title="Evidence could not be loaded." reason={c.error?.message} />
      </div>
    );
  }
  const f = c.data.fall;
  const ev = c.data.evidence;

  return (
    <div className="page">
      <div className="page-head">
        <h2>Evidence Sources</h2>
        <span className="muted">{ev.length}</span>
        <span className="spacer" />
        {can("evidence.import") && !adding && (
          <Button icon={<Upload />} disabled={!f.case_folder} onClick={() => set("add", "1")}>
            Add Evidence
          </Button>
        )}
      </div>

      {adding && f.case_folder && <ImportPanel number={number} folder={f.case_folder} onDone={() => set("add", null)} onQueued={showJob("add")} />}

      {ev.length === 0 && !adding && (
        <EmptyState
          title="No evidence yet."
          text={
            f.case_folder
              ? `Import an image or capture from ${f.case_folder}. It is opened read-only and hashed (SHA-256, BLAKE3).`
              : "This case has no case folder. Evidence can be registered with the command line (stratum evidence hinzu)."
          }
          action={
            can("evidence.import") && f.case_folder ? (
              <Button icon={<Upload />} onClick={() => set("add", "1")}>
                Add Evidence
              </Button>
            ) : undefined
          }
        />
      )}

      <div className="evidence-list">
        {ev.map((e) => (
          <div key={e.id} className="evidence-block">
            <div
              className={detail?.kind === "evidence" && detail.id === e.id ? "evidence-item selected" : "evidence-item"}
              onClick={() => open("evidence", e.id)}
              onContextMenu={(m) =>
                menu.open(m, [
                  { label: "Open details", icon: <Info />, onSelect: () => open("evidence", e.id) },
                  {
                    label: "Analyze…",
                    icon: <Play />,
                    disabled: !can("analysis.start") || !analyzable(e),
                    reason: analyzable(e) ? "Missing permission analysis.start" : "No analyzer for this format yet",
                    onSelect: () => set("analyze", e.id),
                  },
                  "separator",
                  { label: "Copy SHA-256", onSelect: () => void navigator.clipboard?.writeText(e.sha256) },
                  { label: "Copy path", onSelect: () => void navigator.clipboard?.writeText(e.source_uri) },
                ])
              }
            >
              <HardDrive className="evidence-icon" aria-hidden />
              <div className="evidence-main">
                <div className="row">
                  <strong className="evidence-name">{e.name}</strong>
                  {e.role && <span className="muted">· {e.role}</span>}
                </div>
                <div className="evidence-meta">
                  <span className="section-label">{evidenceKind(e.kind)}</span>
                  <span className="mono" title={`${count(e.size)} bytes`}>
                    {bytes(e.size)}
                  </span>
                  <span className="muted">
                    Imported <Timestamp value={e.imported_at} />
                  </span>
                </div>
              </div>
              <div className="evidence-hash" onClick={(x) => x.stopPropagation()}>
                <HashValue algo="SHA256" value={e.sha256} />
              </div>
              <div className="evidence-badges">
                <SupportBadge support={e.support} />
                <IntegrityBadge evidence={e} />
              </div>
              <div className="evidence-actions" onClick={(x) => x.stopPropagation()}>
                <Button size="sm" onClick={() => open("evidence", e.id)}>
                  Open
                </Button>
                {can("analysis.start") && analyzable(e) && (
                  <Button size="sm" variant="primary" icon={<Play />} onClick={() => set("analyze", e.id)}>
                    Analyze
                  </Button>
                )}
                <Button size="sm" icon={<FolderTree />} onClick={() => navigate(`${base}/explorer?ev=${e.id}`)}>
                  Files
                </Button>
                <Button size="sm" icon={<Activity />} onClick={() => navigate(`${base}/timeline?ev=${e.id}`)}>
                  Timeline
                </Button>
              </div>
            </div>
            {analyzing === e.id && <AnalyzePanel number={number} evidence={e} onDone={() => set("analyze", null)} onQueued={showJob("analyze")} />}
          </div>
        ))}
      </div>
      {menu.menu}
    </div>
  );
}

const OPTIONS: [keyof AnalysisOptions, string, string][] = [
  ["katalog", "File catalog", "Directory tree for the explorer, written to the database."],
  ["mft_timeline", "MFT timeline", "SI and FN timestamps of all MFT records."],
  ["usn_journal", "USN journal", "Create, rename and delete records from $UsnJrnl:$J."],
  ["datei_hashes", "File hashes", "SHA-256 and signature of every file. Reads all content; slow."],
  ["raw_sweep", "Raw keyword sweep", "Search the whole image, including unallocated space."],
  ["ohne_begriffe", "Skip bundled keyword list", "Only analyzers, no keyword search."],
  ["bdp", "Use recorded bdp.info", "Only the partition described by the bdp.info next to the image."],
];

function AnalyzePanel({
  number,
  evidence,
  onDone,
  onQueued,
}: {
  number: string;
  evidence: Evidence;
  onDone: () => void;
  onQueued: (job: string) => void;
}) {
  const start = useStartAnalysis(number);
  const hasBdp = typeof (evidence.metadata as Record<string, unknown> | null)?.bdp_info === "string";
  return (
    <form
      className="inline-panel"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const optionen: Partial<AnalysisOptions> = {};
        for (const [k] of OPTIONS) {
          optionen[k] = f.get(k) === "on";
        }
        start.mutate(
          { evidence: evidence.id, optionen },
          { onSuccess: (r) => onQueued(r.job) },
        );
      }}
    >
      <div>
        <h2>Analyze {evidence.name}</h2>
        <span className="muted">
          The image is opened read-only and fully re-hashed first; the analysis only starts if the SHA-256 matches.
        </span>
      </div>
      <div className="form-grid">
        {OPTIONS.filter(([k]) => k !== "bdp" || hasBdp).map(([k, text, hint]) => (
          <Checkbox key={k} name={k} label={text} hint={hint} defaultChecked={k === "katalog"} />
        ))}
      </div>
      {start.error && <div className="form-error">{start.error.message}</div>}
      <div className="form-actions">
        <Button type="submit" variant="primary" icon={<Play />} disabled={start.isPending}>
          Queue analysis
        </Button>
        <Button variant="ghost" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function FolderBrowser({ number, value, onPick }: { number: string; value: string; onPick: (rel: string) => void }) {
  const [path, setPath] = useState("");
  const listing = useCaseFolder(number, path, true);
  const parts = path ? path.split("/") : [];
  const join = (name: string) => (path ? `${path}/${name}` : name);
  return (
    <div className="stack">
      <nav className="crumbs" aria-label="Folder">
        <button type="button" onClick={() => setPath("")}>
          {listing.data?.ordner ?? "Case folder"}
        </button>
        {parts.map((p, i) => (
          <span key={i}>
            <span className="crumb-sep">/</span>
            <button type="button" onClick={() => setPath(parts.slice(0, i + 1).join("/"))}>
              {p}
            </button>
          </span>
        ))}
      </nav>
      <div className="folder-browser">
        {listing.isPending && <div className="menu-label muted">Loading…</div>}
        {listing.error && <div className="menu-label form-error">{listing.error.message}</div>}
        {listing.data?.eintraege.length === 0 && <div className="menu-label muted">This folder is empty.</div>}
        {listing.data?.eintraege.map((e) => {
          const rel = join(e.name);
          return (
            <button
              key={e.name}
              type="button"
              className={value === rel ? "folder-row selected" : "folder-row"}
              onClick={() => (e.typ === "dir" ? setPath(rel) : onPick(rel))}
              onDoubleClick={() => e.typ === "file" && onPick(rel)}
            >
              {e.typ === "dir" ? <Folder className="ico-dir" /> : <File className="ico-file" />}
              <span>{e.name}</span>
              {e.registriert && <Badge tone="success">registered</Badge>}
              {e.typ === "link" && <Badge outline>link</Badge>}
              {e.groesse !== null && <span className="size">{bytes(e.groesse)}</span>}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ImportPanel({
  number,
  folder,
  onDone,
  onQueued,
}: {
  number: string;
  folder: string;
  onDone: () => void;
  onQueued: (job: string) => void;
}) {
  const importEvidence = useImportEvidence(number);
  const [file, setFile] = useState("");
  return (
    <form
      className="inline-panel"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const d: Record<string, string> = {};
        for (const k of ["datei", "name", "rolle"]) {
          const v = String(f.get(k) ?? "").trim();
          if (v) {
            d[k] = v;
          }
        }
        importEvidence.mutate(d, { onSuccess: (r) => onQueued(r.job) });
      }}
    >
      <div>
        <h2>Add Evidence</h2>
        <span className="muted">
          From the case folder <span className="mono">{folder}</span>. The file is opened read-only, its type is detected
          and it is hashed as a background job.
        </span>
      </div>
      <FolderBrowser number={number} value={file} onPick={setFile} />
      <div className="form-grid">
        <Field label="Selected file" hint="Pick it above, or type a path relative to the case folder.">
          <Input name="datei" required placeholder="images/workstation.E01" mono value={file} onChange={(e) => setFile(e.target.value)} />
        </Field>
        <Field label="Display name" hint="Defaults to the file name.">
          <Input name="name" />
        </Field>
        <Field label="System or role">
          <Input name="rolle" placeholder="Webserver" />
        </Field>
      </div>
      {importEvidence.error && <div className="form-error">{importEvidence.error.message}</div>}
      <div className="form-actions">
        <Button type="submit" variant="primary" icon={<Upload />} disabled={importEvidence.isPending}>
          Import
        </Button>
        <Button variant="ghost" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
