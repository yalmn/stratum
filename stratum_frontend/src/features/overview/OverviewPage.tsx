// Case Overview: was wissen wir aktuell über diesen Fall? Wenige, ruhige
// Flächen statt KPI-Karten; alles Weitere über den Drawer.

import { useNavigate } from "react-router-dom";
import { ArrowRight, Play } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Panel } from "../../components/ui/Layout";
import { integrity, JobStatusBadge } from "../../components/forensic/Badges";
import { JobProgress } from "../../components/forensic/JobProgress";
import { useCase, useEventKinds, useJobs } from "../../lib/api/queries";
import { isFinished, type Job } from "../../lib/api/types";
import { count, label } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";
import { jobTitle } from "../jobs/JobsCenter";
import { useLiveJob } from "../jobs/live";

function Summary({ title, value, lines, onOpen }: { title: string; value: string; lines: string[]; onOpen?: () => void }) {
  return (
    <button type="button" className="summary" onClick={onOpen} disabled={!onOpen}>
      <span className="section-label">{title}</span>
      <span className="summary-value">{value}</span>
      {lines.map((l) => (
        <span key={l} className="muted">
          {l}
        </span>
      ))}
    </button>
  );
}

function JobLine({ job }: { job: Job }) {
  const u = useLiveJob(job);
  const { open } = useDetail();
  return (
    <button type="button" className="list-row" onClick={() => open("job", job.id)}>
      <span className="list-main">{jobTitle(job)}</span>
      {isFinished(u.status) ? <Timestamp value={job.finished_at} /> : <JobProgress update={u} compact />}
      <JobStatusBadge status={u.status} />
    </button>
  );
}

export function OverviewPage({ number }: { number: string }) {
  const c = useCase(number);
  const jobs = useJobs(number);
  const kinds = useEventKinds(number);
  const { can } = useSession();
  const navigate = useNavigate();
  const base = `/cases/${encodeURIComponent(number)}`;

  if (c.isPending) {
    return (
      <div className="page">
        <Skeleton lines={8} />
      </div>
    );
  }
  if (!c.data) {
    return null;
  }
  const ev = c.data.evidence;
  const verified = ev.filter((e) => integrity(e).verified).length;
  const list = jobs.data ?? [];
  const running = list.filter((j) => !isFinished(j.status));
  const analyses = list.filter((j) => j.kind === "analysis");
  const completed = analyses.filter((j) => j.status === "completed").length;
  const failed = list.filter((j) => j.status === "failed").length;
  const eventKinds = [...(kinds.data ?? [])].sort((a, b) => b.anzahl - a.anzahl);
  const total = eventKinds.reduce((s, k) => s + k.anzahl, 0);

  return (
    <div className="page">
      <div className="summary-grid">
        <Summary
          title="Evidence"
          value={`${ev.length} ${ev.length === 1 ? "source" : "sources"}`}
          lines={[ev.length === 0 ? "Nothing imported yet" : `${verified} of ${ev.length} verified at analysis`]}
          onOpen={() => navigate(`${base}/evidence`)}
        />
        <Summary
          title="Analysis"
          value={running.length > 0 ? `${running.length} running` : `${completed} completed`}
          lines={[`${analyses.length} analysis ${analyses.length === 1 ? "run" : "runs"}`, ...(failed ? [`${failed} failed`] : [])]}
        />
        <Summary title="Findings" value="—" lines={["Planned: Investigation Core"]} />
        <Summary title="Threat Intel" value="—" lines={["Planned: Intelligence"]} />
      </div>

      <div className="overview-columns">
        <Panel
          title="Activity in the case model"
          actions={<span className="muted">{kinds.data ? `${count(total)} events` : ""}</span>}
        >
          {kinds.error && <ErrorState title="Event types could not be loaded." reason={kinds.error.message} />}
          {kinds.isPending && <Skeleton lines={5} />}
          {kinds.data && eventKinds.length === 0 && (
            <EmptyState
              title="No events yet."
              text="Run an analysis to fill the case model."
              action={
                can("analysis.start") && ev.length > 0 ? (
                  <Button size="sm" icon={<Play />} onClick={() => navigate(`${base}/evidence`)}>
                    Run Analysis
                  </Button>
                ) : undefined
              }
            />
          )}
          {eventKinds.length > 0 && (
            <div className="bars">
              {eventKinds.slice(0, 12).map((k) => (
                <div key={k.art} className="bar-row" title={`${count(k.anzahl)} ${k.art}`}>
                  <span className="bar-label">{label(k.art)}</span>
                  <span className="bar-track">
                    <span className="bar-fill" style={{ width: `${(k.anzahl / eventKinds[0]!.anzahl) * 100}%` }} />
                  </span>
                  <span className="mono bar-value">{count(k.anzahl)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel
          title="Jobs"
          actions={
            <Button size="sm" variant="ghost" icon={<ArrowRight />} onClick={() => navigate(`${base}/evidence`)}>
              Evidence
            </Button>
          }
        >
          {jobs.isPending && <Skeleton lines={4} />}
          {jobs.data && list.length === 0 && <span className="muted">No jobs in this case yet.</span>}
          <div className="list">
            {list.slice(0, 10).map((j) => (
              <JobLine key={j.id} job={j} />
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
