// Laufende Jobs: genau eine SSE-Verbindung je laufendem Job für die ganze
// Oberfläche. Der Stand liegt in einem kleinen Store; Jobs Center,
// Übersicht und Drawer lesen ihn. Endet ein Job, entsteht eine
// Benachrichtigung.

import { useEffect } from "react";
import { create } from "zustand";
import { useJobStream, useJobs, useCases } from "../../lib/api/queries";
import { isFinished, type Job, type JobUpdate } from "../../lib/api/types";
import { useWorkspace } from "../../app/store";

interface LiveState {
  updates: Record<string, JobUpdate>;
  set: (id: string, u: JobUpdate) => void;
}

const useLive = create<LiveState>((set) => ({
  updates: {},
  set: (id, u) => set((s) => ({ updates: { ...s.updates, [id]: u } })),
}));

/** Aktueller Stand eines Jobs: live, falls verbunden, sonst aus der Liste. */
export function useLiveJob(job: Job): JobUpdate {
  const live = useLive((s) => s.updates[job.id]);
  return (
    (!isFinished(job.status) && live) || {
      status: job.status,
      progress: (job.progress ?? {}) as JobUpdate["progress"],
      error: job.error,
      result: (job.result ?? null) as JobUpdate["result"],
      analysis_run_id: job.analysis_run_id,
    }
  );
}

function Stream({ job, caseNumber }: { job: Job; caseNumber?: string }) {
  const store = useLive((s) => s.set);
  const notify = useWorkspace((s) => s.notify);
  const u = useJobStream(job, (fin) => {
    const what = job.kind === "evidence_import" ? "Import" : job.kind === "http_replay" ? "HTTP reconstruction" : "Analysis";
    notify({
      title: `${what} ${fin.status === "completed" ? "completed" : fin.status}`,
      text: caseNumber ?? job.case_id,
      tone: fin.status === "completed" ? "success" : fin.status === "failed" ? "danger" : "warning",
      link: caseNumber ? `/cases/${encodeURIComponent(caseNumber)}/overview?detail=job:${job.id}` : undefined,
    });
  });
  useEffect(() => store(job.id, u), [store, job.id, u]);
  return null;
}

/** Unsichtbar in der Shell: verbindet alle laufenden Jobs. */
export function JobWatcher() {
  const jobs = useJobs();
  const cases = useCases();
  const number = new Map((cases.data ?? []).map((c) => [c.id, c.case_number]));
  return (
    <>
      {(jobs.data ?? [])
        .filter((j) => !isFinished(j.status))
        .map((j) => (
          <Stream key={j.id} job={j} caseNumber={number.get(j.case_id)} />
        ))}
    </>
  );
}
