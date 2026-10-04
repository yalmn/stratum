// Universal Context Drawer: zeigt das in der URL gewählte Objekt rechts
// neben dem Workspace. Jede Art hat einen Inhalt, der Rahmen ist gleich.

import { useNavigate } from "react-router-dom";
import { Activity, ArrowRight, Ban, Copy, FolderTree, Play } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { CodeBlock, CopyButton, ErrorState, HashValue, PropertyList, Skeleton, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import {
  CaseStatusBadge,
  ClassificationBadge,
  evidenceKind,
  IntegrityBadge,
  integrity,
  JobStatusBadge,
  SupportBadge,
} from "../../components/forensic/Badges";
import { JobProgress, phaseLabel } from "../../components/forensic/JobProgress";
import { useCancelJob, useCase, useCases, useJobs } from "../../lib/api/queries";
import { isFinished, type Evidence, type Job } from "../../lib/api/types";
import { bytes, count, duration } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail, type Detail } from "../../app/detail";
import { jobTitle } from "../jobs/JobsCenter";
import { useLiveJob } from "../jobs/live";
import { RelationshipDrawer } from "./RelationshipDrawer";
import { EntityDrawer } from "./EntityDrawer";
import { EventDrawer } from "./EventDrawer";
import { NetworkResult } from "./NetworkResult";
import { YaraResult } from "./YaraResult";
import { FileDrawer } from "./FileDrawer";

export function ContextDrawer({ detail, caseNumber }: { detail: Detail; caseNumber?: string }) {
  const { close } = useDetail();
  if (detail.kind === "case") {
    return <CaseDetailView number={detail.id} onClose={close} />;
  }
  if (!caseNumber) {
    return null;
  }
  switch (detail.kind) {
    case "evidence":
      return <EvidenceDetail number={caseNumber} id={detail.id} onClose={close} />;
    case "job":
      return <JobDetail number={caseNumber} id={detail.id} onClose={close} />;
    case "file":
      return <FileDrawer key={detail.id} id={detail.id} caseNumber={caseNumber} onClose={close} />;
    case "event":
      return <EventDrawer key={detail.id} id={detail.id} caseNumber={caseNumber} onClose={close} />;
    case "relationship":
      return <RelationshipDrawer key={detail.id} id={detail.id} caseNumber={caseNumber} onClose={close} />;
    case "entity":
      return <EntityDrawer key={detail.id} id={detail.id} caseNumber={caseNumber} onClose={close} />;
  }
}

function Loading({ kind, onClose }: { kind: string; onClose: () => void }) {
  return (
    <DrawerFrame kind={kind} title={<span className="skeleton" style={{ width: 160 }} />} onClose={onClose}>
      <Skeleton lines={6} />
    </DrawerFrame>
  );
}

function NotFound({ kind, onClose }: { kind: string; onClose: () => void }) {
  return (
    <DrawerFrame kind={kind} title="Not found" onClose={onClose}>
      <ErrorState title={`This ${kind.toLowerCase()} is not part of the case or no longer visible.`} />
    </DrawerFrame>
  );
}

const analyzable = (e: Evidence) => e.kind === "raw_disk_image" || e.kind === "e01_image";

function EvidenceDetail({ number, id, onClose }: { number: string; id: string; onClose: () => void }) {
  const c = useCase(number);
  const jobs = useJobs(number);
  const { can } = useSession();
  const navigate = useNavigate();
  const { open } = useDetail();
  if (c.isPending) {
    return <Loading kind="Evidence" onClose={onClose} />;
  }
  const e = c.data?.evidence.find((x) => x.id === id);
  if (!e) {
    return <NotFound kind="Evidence" onClose={onClose} />;
  }
  const m = (e.metadata ?? {}) as Record<string, unknown>;
  const runs = (jobs.data ?? []).filter((j) => (j.parameters as Record<string, unknown> | null)?.evidence_id === e.id);
  const ewf = m.ewf as Record<string, unknown> | null | undefined;
  const i = integrity(e);
  return (
    <DrawerFrame
      kind="Evidence"
      title={e.name}
      onClose={onClose}
      badges={
        <>
          <span className="badge">{evidenceKind(e.kind)}</span>
          <SupportBadge support={e.support} />
          <IntegrityBadge evidence={e} />
        </>
      }
    >
      <div className="drawer-actions">
        {can("analysis.start") && analyzable(e) && (
          <Button
            variant="primary"
            size="sm"
            icon={<Play />}
            onClick={() => navigate(`/cases/${encodeURIComponent(number)}/evidence?analyze=${e.id}`)}
          >
            Analyze
          </Button>
        )}
        <Button size="sm" icon={<FolderTree />} onClick={() => navigate(`/cases/${encodeURIComponent(number)}/explorer?ev=${e.id}`)}>
          Explore files
        </Button>
        <Button size="sm" icon={<Activity />} onClick={() => navigate(`/cases/${encodeURIComponent(number)}/timeline?ev=${e.id}`)}>
          Timeline
        </Button>
        <Button size="sm" icon={<Copy />} onClick={() => void navigator.clipboard?.writeText(e.id)}>
          Copy reference
        </Button>
      </div>
      <DrawerSection title="General">
        <PropertyList
          items={[
            ["Type", evidenceKind(e.kind)],
            ["Size", <span className="mono" title={`${count(e.size)} bytes`}>{bytes(e.size)}</span>],
            ["Role", e.role],
            ["Original name", e.original_name && <span className="mono">{e.original_name}</span>],
            [
              "Source",
              <span className="row">
                <span className="mono">{e.source_uri}</span>
                <CopyButton value={e.source_uri} label="Copy path" />
              </span>,
            ],
            ["Registered", <Timestamp value={e.imported_at} />],
            ["Acquired", <Timestamp value={e.acquired_at} />],
            ["ID", <span className="mono">{e.id}</span>],
          ]}
        />
      </DrawerSection>
      <DrawerSection title="Integrity">
        <div className="stack">
          <span className="muted">{i.tip}</span>
          <HashValue algo="SHA256" value={e.sha256} />
          <HashValue algo="BLAKE3" value={e.blake3} />
          {typeof m.md5 === "string" && <HashValue algo="MD5" value={m.md5} />}
          {typeof m.sha1 === "string" && <HashValue algo="SHA1" value={m.sha1} />}
        </div>
      </DrawerSection>
      {ewf && (
        <DrawerSection title="Acquisition">
          <CodeBlock>{JSON.stringify(ewf, null, 2)}</CodeBlock>
        </DrawerSection>
      )}
      <DrawerSection title={`Analysis runs (${runs.length})`}>
        {runs.length === 0 ? (
          <span className="muted">No analysis yet.</span>
        ) : (
          <div className="list">
            {runs.map((j) => (
              <button key={j.id} type="button" className="list-row" onClick={() => open("job", j.id)}>
                <JobStatusBadge status={j.status} />
                <Timestamp value={j.created_at} />
                <ArrowRight size={14} className="muted" />
              </button>
            ))}
          </div>
        )}
      </DrawerSection>
    </DrawerFrame>
  );
}

function JobDetail({ number, id, onClose }: { number: string; id: string; onClose: () => void }) {
  const jobs = useJobs(number);
  if (jobs.isPending) {
    return <Loading kind="Job" onClose={onClose} />;
  }
  const job = jobs.data?.find((j) => j.id === id);
  return job ? <JobView job={job} number={number} onClose={onClose} /> : <NotFound kind="Job" onClose={onClose} />;
}

function JobView({ job, number, onClose }: { job: Job; number: string; onClose: () => void }) {
  const u = useLiveJob(job);
  const c = useCase(number);
  const { can } = useSession();
  const cancel = useCancelJob();
  const { open } = useDetail();
  const p = (job.parameters ?? {}) as Record<string, unknown>;
  const r = (u.result ?? {}) as Record<string, unknown>;
  const ev = c.data?.evidence.find((e) => e.id === p.evidence_id || e.id === r.evidence_id);
  const timings = Object.entries(u.progress.phasen ?? {}).filter(
    ([, phase]) => phase.abgeschlossen && typeof phase.dauer_ms === "number",
  );
  return (
    <DrawerFrame
      kind={job.kind === "evidence_import" ? "Import job" : "Analysis job"}
      title={jobTitle(job)}
      onClose={onClose}
      badges={<JobStatusBadge status={u.status} />}
    >
      {!isFinished(u.status) && (
        <div className="stack">
          <JobProgress update={u} />
          {can("analysis.cancel") && (
            <div className="drawer-actions">
              <Button
                size="sm"
                variant="danger"
                icon={<Ban />}
                disabled={cancel.isPending || job.cancel_requested}
                onClick={() => cancel.mutate(job.id)}
              >
                {job.cancel_requested ? "Cancel requested" : "Cancel job"}
              </Button>
            </div>
          )}
        </div>
      )}
      {u.status === "failed" && <ErrorState title="Job failed." reason={u.error ?? undefined} />}
      {u.status === "cancelled" && <ErrorState title="Job cancelled." reason={u.error ?? undefined} />}
      <DrawerSection title="General">
        <PropertyList
          items={[
            [
              "Evidence",
              ev ? (
                <button type="button" className="link" onClick={() => open("evidence", ev.id)}>
                  {ev.name}
                </button>
              ) : (
                typeof p.datei === "string" && <span className="mono">{p.datei}</span>
              ),
            ],
            ["Created", <Timestamp value={job.created_at} />],
            ["Started", <Timestamp value={job.started_at} />],
            ["Finished", <Timestamp value={job.finished_at} />],
            ["Duration", job.started_at && <span className="mono">{duration(job.started_at, job.finished_at)}</span>],
            ["Worker", job.worker && <span className="mono">{job.worker}</span>],
            ["Analysis run", u.analysis_run_id && <span className="mono">{u.analysis_run_id}</span>],
            ["Job ID", <span className="mono">{job.id}</span>],
          ]}
        />
      </DrawerSection>
      {timings.length > 0 && (
        <DrawerSection title="Phase timings">
          <PropertyList
            items={timings.map(([name, phase]) => [
              phaseLabel(name),
              <span className="mono">{((phase.dauer_ms ?? 0) / 1000).toLocaleString("en-US", { maximumFractionDigits: 3 })} s</span>,
            ])}
          />
          <p className="muted">Completed phases only. Overlapping phases cannot be added to get the total duration.</p>
        </DrawerSection>
      )}
      {u.status === "completed" && (
        <DrawerSection title="Result">
          <PropertyList
            items={[
              ...(typeof r.funde === "number" ? [["Findings", count(r.funde)] as [string, string]] : []),
              ...(typeof r.zeitstrahl === "number" ? [["Timeline entries", count(r.zeitstrahl)] as [string, string]] : []),
              ...(typeof r.warnungen === "number" ? [["Warnings", count(r.warnungen)] as [string, string]] : []),
              ...(typeof r.report === "string"
                ? [["Report", <span className="mono">{r.report}</span>] as [string, React.ReactNode]]
                : []),
              ...(typeof r.report_sha256 === "string"
                ? [["Report SHA256", <HashValue value={r.report_sha256} />] as [string, React.ReactNode]]
                : []),
              ...(typeof r.sha256 === "string"
                ? [["SHA256", <HashValue value={r.sha256} />] as [string, React.ReactNode]]
                : []),
              ...(typeof r.neu === "boolean"
                ? [["Registration", r.neu ? "New evidence" : "Already registered, hash confirmed"] as [string, string]]
                : []),
            ]}
          />
        </DrawerSection>
      )}
      {u.status === "completed" && <NetworkResult value={r} />}
      {u.status === "completed" && <YaraResult value={r} caseNumber={number} />}
      <DrawerSection title="Parameters">
        <CodeBlock>{JSON.stringify(job.parameters, null, 2)}</CodeBlock>
      </DrawerSection>
    </DrawerFrame>
  );
}

function CaseDetailView({ number, onClose }: { number: string; onClose: () => void }) {
  const cases = useCases();
  const navigate = useNavigate();
  const c = cases.data?.find((x) => x.case_number === number);
  if (cases.isPending) {
    return <Loading kind="Case" onClose={onClose} />;
  }
  if (!c) {
    return <NotFound kind="Case" onClose={onClose} />;
  }
  return (
    <DrawerFrame
      kind="Case"
      title={c.title}
      onClose={onClose}
      badges={
        <>
          <CaseStatusBadge status={c.status} />
          <ClassificationBadge value={c.classification} />
        </>
      }
    >
      <div className="drawer-actions">
        <Button
          variant="primary"
          size="sm"
          icon={<ArrowRight />}
          onClick={() => navigate(`/cases/${encodeURIComponent(c.case_number)}/overview`)}
        >
          Open case
        </Button>
      </div>
      <DrawerSection title="General">
        <PropertyList
          items={[
            ["Number", <span className="mono">{c.case_number}</span>],
            ["Evidence", count(c.evidence)],
            ["Case folder", c.case_folder && <span className="mono">{c.case_folder}</span>],
            ["Time zone", c.timezone ?? <span className="muted">not set</span>],
            ["Opened", <Timestamp value={c.opened_at} />],
            ["Created", <Timestamp value={c.created_at} />],
          ]}
        />
      </DrawerSection>
      {c.description && (
        <DrawerSection title="Description">
          <p className="secondary">{c.description}</p>
        </DrawerSection>
      )}
    </DrawerFrame>
  );
}
