// Abfragen und Änderungen als Hooks. Seiten rufen nur diese auf, nie fetch
// direkt; Schlüssel und Pfade stehen an einer Stelle.

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "./client";
import {
  isFinished,
  type AnalysisOptions,
  type Case,
  type CaseDetail,
  type CaseRow,
  type EventKindCount,
  type Job,
  type JobUpdate,
  type Me,
} from "./types";

const enc = encodeURIComponent;

export const keys = {
  me: ["me"] as const,
  cases: ["cases"] as const,
  case: (n: string) => ["case", n] as const,
  jobs: (n?: string) => (n ? (["jobs", n] as const) : (["jobs"] as const)),
  eventKinds: (n: string) => ["event-kinds", n] as const,
};

export function useMe() {
  return useQuery({ queryKey: keys.me, queryFn: () => api<Me>("/ich"), retry: false, staleTime: 60_000 });
}

export function useLogin() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (d: { name: string; passwort: string }) => api<unknown>("/sitzung", { method: "POST", body: d }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.me }),
  });
}

export function useLogout() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api<void>("/sitzung", { method: "DELETE" }),
    onSettled: () => client.clear(),
  });
}

export function useCases() {
  return useQuery({ queryKey: keys.cases, queryFn: () => api<CaseRow[]>("/faelle") });
}

export function useCase(number: string) {
  return useQuery({ queryKey: keys.case(number), queryFn: () => api<CaseDetail>(`/faelle/${enc(number)}`) });
}

export function useCreateCase() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (d: Record<string, string>) => api<Case>("/faelle", { method: "POST", body: d }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.cases }),
  });
}

/** Jobs eines Falls oder (ohne Nummer) alle sichtbaren. */
export function useJobs(number?: string) {
  const path = number ? `/jobs?fall=${enc(number)}&anzahl=100` : "/jobs?anzahl=100";
  return useQuery({ queryKey: keys.jobs(number), queryFn: () => api<Job[]>(path), refetchInterval: 15_000 });
}

export function useEventKinds(number: string) {
  return useQuery({
    queryKey: keys.eventKinds(number),
    queryFn: () => api<EventKindCount[]>(`/faelle/${enc(number)}/zeitachse/arten`),
  });
}

function useJobInvalidation(number: string) {
  const client = useQueryClient();
  return () => {
    void client.invalidateQueries({ queryKey: keys.jobs() });
    void client.invalidateQueries({ queryKey: keys.case(number) });
  };
}

export function useStartAnalysis(number: string) {
  const done = useJobInvalidation(number);
  return useMutation({
    mutationFn: (d: { evidence: string; optionen: Partial<AnalysisOptions> }) =>
      api<{ job: string }>(`/faelle/${enc(number)}/analysen`, { method: "POST", body: d }),
    onSuccess: done,
  });
}

export function useImportEvidence(number: string) {
  const done = useJobInvalidation(number);
  return useMutation({
    mutationFn: (d: Record<string, string>) =>
      api<{ job: string }>(`/faelle/${enc(number)}/evidence`, { method: "POST", body: d }),
    onSuccess: done,
  });
}

export function useCancelJob() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api<unknown>(`/jobs/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: keys.jobs() }),
  });
}

/**
 * Laufender Stand eines Jobs über Server-Sent Events. Endet der Job, werden
 * Jobs und Fall neu geladen. Für beendete Jobs öffnet sich keine Verbindung.
 */
export function useJobStream(job: Job, onFinished?: (u: JobUpdate) => void): JobUpdate {
  const client = useQueryClient();
  const [update, setUpdate] = useState<JobUpdate>(() => ({
    status: job.status,
    progress: (job.progress ?? {}) as JobUpdate["progress"],
    error: job.error,
    result: (job.result ?? null) as JobUpdate["result"],
    analysis_run_id: job.analysis_run_id,
  }));

  useEffect(() => {
    if (isFinished(job.status)) {
      return;
    }
    const source = new EventSource(`/api/v1/jobs/${job.id}/fortschritt`);
    source.addEventListener("stand", (e) => {
      const u = JSON.parse((e as MessageEvent<string>).data) as JobUpdate;
      setUpdate(u);
      if (isFinished(u.status)) {
        source.close();
        void client.invalidateQueries({ queryKey: keys.jobs() });
        void client.invalidateQueries({ queryKey: ["case"] });
        void client.invalidateQueries({ queryKey: ["event-kinds"] });
        onFinished?.(u);
      }
    });
    // Nach dem Ende verbände EventSource sonst immer wieder neu.
    source.addEventListener("fehler", () => source.close());
    source.onerror = () => {
      if (source.readyState === EventSource.CLOSED) {
        source.close();
      }
    };
    return () => source.close();
    // onFinished bewusst nicht als Abhängigkeit: sonst neue Verbindung je Render.
  }, [job.id, job.status, client]);

  return update;
}
