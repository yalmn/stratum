// Abfragen und Änderungen als Hooks. Seiten rufen nur diese auf, nie fetch
// direkt; Schlüssel und Pfade stehen an einer Stelle.

import { useEffect, useState } from "react";
import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, apiBytes } from "./client";
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
  type EntityDetail,
  type EntityRow,
  type EventDetail,
  type FileEntry,
  type FileHashes,
  type Page,
  type RawFinding,
  type TimelineEvent,
  type VolumeInfo,
  type WarRoomItem,
  type WarRoomPage,
  type FolderListing,
  type Role,
  type User,
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
    onSettled: () => client.resetQueries(),
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

// Explorer

export function useVolumes(evidence: string | undefined) {
  return useQuery({
    queryKey: ["volumes", evidence],
    queryFn: () => api<VolumeInfo[]>(`/evidence/${evidence}/volumes`),
    enabled: !!evidence,
    staleTime: 60_000,
  });
}

const PAGE = 500;

/** Inhalt eines Verzeichnisses, seitenweise nachgeladen. */
export function useDirectory(evidence: string | undefined, volume: number | undefined, dir: number) {
  return useInfiniteQuery({
    queryKey: ["dir", evidence, volume, dir],
    queryFn: ({ pageParam }) =>
      api<Page<FileEntry>>(
        `/evidence/${evidence}/dateien?volume=${volume}&verzeichnis=${dir}&anzahl=${PAGE}${
          pageParam ? `&nach=${enc(pageParam)}` : ""
        }`,
      ),
    initialPageParam: "",
    getNextPageParam: (last) => last.naechste ?? undefined,
    enabled: !!evidence && volume !== undefined,
    staleTime: 60_000,
  });
}

/** Nur die Unterverzeichnisse (für den Baum); erste Seite genügt meist. */
export function useSubdirs(evidence: string, volume: number, dir: number, enabled: boolean) {
  return useQuery({
    queryKey: ["subdirs", evidence, volume, dir],
    queryFn: async () => {
      const p = await api<Page<FileEntry>>(`/evidence/${evidence}/dateien?volume=${volume}&verzeichnis=${dir}&anzahl=1000`);
      return { dirs: p.eintraege.filter((e) => e.is_directory), more: p.naechste !== null && p.eintraege.every((e) => e.is_directory) };
    },
    enabled,
    staleTime: 60_000,
  });
}

export function useFileEntry(evidence: string, volume: number, record: number) {
  return useQuery({
    queryKey: ["file", evidence, volume, record],
    queryFn: () => api<FileEntry[]>(`/evidence/${evidence}/dateien/${volume}/${record}`),
  });
}

export function useHexWindow(evidence: string, volume: number, record: number, offset: number, enabled: boolean) {
  return useQuery({
    queryKey: ["hex", evidence, volume, record, offset],
    queryFn: () => apiBytes(`/evidence/${evidence}/dateien/${volume}/${record}/inhalt?offset=${offset}&laenge=4096`),
    enabled,
    placeholderData: keepPreviousData,
    staleTime: Infinity,
  });
}

export function useHashFile(evidence: string, volume: number, record: number) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: () => api<FileHashes>(`/evidence/${evidence}/dateien/${volume}/${record}/hash`, { method: "POST" }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["file", evidence, volume, record] });
      void client.invalidateQueries({ queryKey: ["dir", evidence, volume] });
    },
  });
}

export function fileExportUrl(evidence: string, volume: number, record: number): string {
  return `/api/v1/evidence/${evidence}/dateien/${volume}/${record}/export`;
}

// Timeline

export interface TimelineFilter {
  evidence?: string;
  von?: string;
  bis?: string;
  arten?: string[];
  entitaet?: string;
  suche?: string;
}

export function useTimeline(number: string, f: TimelineFilter) {
  const q = new URLSearchParams({ anzahl: "300" });
  if (f.evidence) q.set("evidence", f.evidence);
  if (f.von) q.set("von", f.von);
  if (f.bis) q.set("bis", f.bis);
  if (f.arten && f.arten.length > 0) q.set("art", f.arten.join(","));
  if (f.entitaet) q.set("entitaet", f.entitaet);
  if (f.suche) q.set("suche", f.suche);
  const base = `/faelle/${enc(number)}/zeitachse?${q.toString()}`;
  return useInfiniteQuery({
    queryKey: ["timeline", number, base],
    queryFn: ({ pageParam }) => api<Page<TimelineEvent>>(pageParam ? `${base}&nach=${enc(pageParam)}` : base),
    initialPageParam: "",
    getNextPageParam: (last) => last.naechste ?? undefined,
    placeholderData: keepPreviousData,
  });
}

export function useEventDetail(id: string) {
  return useQuery({ queryKey: ["event", id], queryFn: () => api<EventDetail>(`/ereignisse/${id}`) });
}

export function useRawFinding(artifact: string | null, cleartext: boolean, enabled: boolean) {
  return useQuery({
    queryKey: ["raw", artifact, cleartext],
    queryFn: () => api<RawFinding>(`/artefakte/${artifact}/rohfund${cleartext ? "?klartext=true" : ""}`),
    enabled: enabled && !!artifact,
    retry: false,
  });
}

// Entitäten

export function useEntities(number: string, kind: string, search: string) {
  const q = new URLSearchParams({ anzahl: "300" });
  if (kind) q.set("art", kind);
  if (search) q.set("suche", search);
  const base = `/faelle/${enc(number)}/entitaeten?${q.toString()}`;
  return useInfiniteQuery({
    queryKey: ["entities", number, base],
    queryFn: ({ pageParam }) => api<Page<EntityRow>>(pageParam ? `${base}&nach=${enc(pageParam)}` : base),
    initialPageParam: "",
    getNextPageParam: (last) => last.naechste ?? undefined,
    placeholderData: keepPreviousData,
  });
}

export function useEntity(id: string, cleartext: boolean) {
  return useQuery({
    queryKey: ["entity", id, cleartext],
    queryFn: () => api<EntityDetail>(`/entitaeten/${id}${cleartext ? "?klartext=true" : ""}`),
    retry: false,
  });
}

// War Room

export function useWarRoom(number: string) {
  return useInfiniteQuery({
    queryKey: ["war-room", number],
    queryFn: ({ pageParam }) =>
      api<WarRoomPage>(`/faelle/${enc(number)}/warroom?anzahl=100${pageParam ? `&vor=${pageParam}` : ""}`),
    initialPageParam: "",
    getNextPageParam: (last) => last.naechste ?? undefined,
    refetchInterval: 10_000,
  });
}

export function usePostNote(number: string) {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (d: { text: string; parent?: string }) =>
      api<WarRoomItem>(`/faelle/${enc(number)}/warroom`, { method: "POST", body: d }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["war-room", number] }),
  });
}

// Konten

export function useRegister() {
  return useMutation({
    mutationFn: (d: { name: string; anzeigename: string; passwort: string }) =>
      api<{ username: string; status: string }>("/registrierung", { method: "POST", body: d }),
  });
}

export function useChangeOwnPassword() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (d: { bisher: string; neu: string }) => api<void>("/ich/passwort", { method: "POST", body: d }),
    // Alle Sitzungen enden; neu laden führt zur Anmeldung.
    onSuccess: () => client.resetQueries(),
  });
}

export function useAccounts() {
  return useQuery({ queryKey: ["accounts"], queryFn: () => api<User[]>("/konten") });
}

export function useRoles() {
  return useQuery({ queryKey: ["roles"], queryFn: () => api<Role[]>("/rollen"), staleTime: 60_000 });
}

export function useAccountAction() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: (d: { id: string; action: "freigeben" | "ablehnen" | "sperren" | "rollen" | "passwort" | "superadmin"; body?: unknown }) =>
      api<void>(`/konten/${d.id}/${d.action}`, { method: d.action === "rollen" ? "PUT" : "POST", body: d.body }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["accounts"] });
      void client.invalidateQueries({ queryKey: keys.me });
    },
  });
}

export function useCaseFolder(number: string, path: string, enabled: boolean) {
  return useQuery({
    queryKey: ["case-folder", number, path],
    queryFn: () => api<FolderListing>(`/faelle/${enc(number)}/ordner?pfad=${enc(path)}`),
    enabled,
    retry: false,
  });
}
