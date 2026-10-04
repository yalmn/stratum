import { useNavigate } from "react-router-dom";
import { Activity, Bell } from "lucide-react";
import { Badge } from "../../components/ui/Badge";
import { Popover } from "../../components/ui/Overlay";
import { JobProgress } from "../../components/forensic/JobProgress";
import { JobStatusBadge } from "../../components/forensic/Badges";
import { useCases, useJobs } from "../../lib/api/queries";
import { isFinished, type Job } from "../../lib/api/types";
import { ago } from "../../lib/format";
import { useWorkspace } from "../../app/store";
import { useLiveJob } from "./live";

export function jobTitle(job: Job): string {
  const p = job.parameters as Record<string, unknown> | null;
  if (job.kind === "network_enrichment") return "DNS / WHOIS";
  if (job.kind === "yara_scan") return "YARA scan";
  if (job.kind === "evidence_import") {
    const datei = typeof p?.datei === "string" ? p.datei.split("/").pop() : "";
    return `Import ${datei}`;
  }
  return "Analysis";
}

function Row({ job, caseNumber, onOpen }: { job: Job; caseNumber?: string; onOpen: () => void }) {
  const u = useLiveJob(job);
  return (
    <button type="button" className="jobs-row" onClick={onOpen}>
      <div className="row">
        <strong>{jobTitle(job)}</strong>
        <span className="muted">{caseNumber}</span>
        <span className="spacer" />
        {isFinished(u.status) ? (
          <span className="muted">{ago(job.finished_at)}</span>
        ) : (
          <JobStatusBadge status={u.status} />
        )}
      </div>
      {!isFinished(u.status) && <JobProgress update={u} compact />}
      {isFinished(u.status) && u.status !== "completed" && <JobStatusBadge status={u.status} />}
    </button>
  );
}

export function JobsCenter() {
  const jobs = useJobs();
  const cases = useCases();
  const navigate = useNavigate();
  const number = new Map((cases.data ?? []).map((c) => [c.id, c.case_number]));
  const list = jobs.data ?? [];
  const running = list.filter((j) => !isFinished(j.status));
  const done = list.filter((j) => isFinished(j.status)).slice(0, 6);
  const open = (j: Job, close: () => void) => {
    close();
    const n = number.get(j.case_id);
    if (n) {
      navigate(`/cases/${encodeURIComponent(n)}/overview?detail=job:${j.id}`);
    }
  };
  return (
    <Popover
      align="right"
      trigger={({ toggle, open }) => (
        <button type="button" className={open ? "top-btn active" : "top-btn"} onClick={toggle} aria-label="Jobs">
          <Activity />
          <span>Jobs</span>
          {running.length > 0 && <Badge tone="info">{running.length}</Badge>}
        </button>
      )}
    >
      {(close) => (
        <div className="jobs-center">
          <div className="section-label menu-label">Running</div>
          {running.length === 0 && <div className="menu-label muted">No running jobs.</div>}
          {running.map((j) => (
            <Row key={j.id} job={j} caseNumber={number.get(j.case_id)} onOpen={() => open(j, close)} />
          ))}
          <div className="menu-sep" />
          <div className="section-label menu-label">Completed</div>
          {done.length === 0 && <div className="menu-label muted">Nothing yet.</div>}
          {done.map((j) => (
            <Row key={j.id} job={j} caseNumber={number.get(j.case_id)} onOpen={() => open(j, close)} />
          ))}
        </div>
      )}
    </Popover>
  );
}

export function Notifications() {
  const items = useWorkspace((s) => s.notifications);
  const markRead = useWorkspace((s) => s.markRead);
  const navigate = useNavigate();
  const unread = items.filter((n) => !n.read).length;
  return (
    <Popover
      align="right"
      trigger={({ toggle, open }) => (
        <button
          type="button"
          className={open ? "top-btn active" : "top-btn"}
          aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`}
          onClick={() => {
            toggle();
            markRead();
          }}
        >
          <Bell />
          {unread > 0 && <Badge tone="info">{unread}</Badge>}
        </button>
      )}
    >
      {(close) => (
        <div className="jobs-center">
          <div className="section-label menu-label">Notifications</div>
          {items.length === 0 && (
            <div className="menu-label muted">Completed analyses and imports of this session appear here.</div>
          )}
          {items.map((n) => (
            <button
              key={n.id}
              type="button"
              className="jobs-row"
              onClick={() => {
                close();
                if (n.link) {
                  navigate(n.link);
                }
              }}
            >
              <div className="row">
                <span className={`status-dot tone-text-${n.tone}`} />
                <strong>{n.title}</strong>
                <span className="spacer" />
                <span className="muted">{ago(n.at)}</span>
              </div>
              <span className="muted">{n.text}</span>
            </button>
          ))}
        </div>
      )}
    </Popover>
  );
}
