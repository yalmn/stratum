// Typen der API. Modellobjekte kommen aus stratum_model (erzeugt mit
// `npm run typen`, Ordner model/). Hier stehen nur die Hüllen, die der
// Server um sie legt, und die Form des Job-Fortschritts aus stratum-jobs.

import type { Case } from "./model/Case";
import type { Evidence } from "./model/Evidence";
import type { Job } from "./model/Job";
import type { JobStatus } from "./model/JobStatus";
import type { Permission } from "./model/Permission";
import type { User } from "./model/User";

export type { Case } from "./model/Case";
export type { CaseClassification } from "./model/CaseClassification";
export type { CaseStatus } from "./model/CaseStatus";
export type { DerivationKind } from "./model/DerivationKind";
export type { Evidence } from "./model/Evidence";
export type { EvidenceKind } from "./model/EvidenceKind";
export type { EvidenceSupport } from "./model/EvidenceSupport";
export type { Job } from "./model/Job";
export type { JobKind } from "./model/JobKind";
export type { JobStatus } from "./model/JobStatus";
export type { Permission } from "./model/Permission";
export type { User } from "./model/User";

/** GET /ich */
export interface Me {
  konto: User;
  rechte: Permission[];
}

/** GET /faelle: Fall mit Zahl seiner Evidence (FallZeile im Store). */
export type CaseRow = Case & { evidence: number };

/** GET /faelle/{nummer} */
export interface CaseDetail {
  fall: Case;
  evidence: Evidence[];
}

/** GET /faelle/{nummer}/zeitachse/arten */
export interface EventKindCount {
  art: string;
  anzahl: number;
}

/** Stand einer Phase, wie der Worker ihn in job.progress schreibt. */
export interface PhaseProgress {
  erledigt: number;
  gesamt: number;
}

/** job.progress (stratum-jobs, JobRueckmeldung). */
export interface JobProgress {
  phase?: string;
  phasen?: Record<string, PhaseProgress>;
  meldung?: string;
}

/** Ereignis `stand` aus GET /jobs/{id}/fortschritt. */
export interface JobUpdate {
  status: JobStatus;
  progress: JobProgress;
  error: string | null;
  result: Record<string, unknown> | null;
  analysis_run_id: string | null;
}

/** Optionen eines Analyse-Jobs (stratum_jobs::AnalyseOptionen). */
export interface AnalysisOptions {
  katalog: boolean;
  datei_hashes: boolean;
  mft_timeline: boolean;
  usn_journal: boolean;
  raw_sweep: boolean;
  ohne_begriffe: boolean;
  bdp: boolean;
}

export function jobProgress(job: Pick<Job, "progress">): JobProgress {
  const p = job.progress;
  return p && typeof p === "object" && !Array.isArray(p) ? (p as JobProgress) : {};
}

export function isFinished(s: JobStatus): boolean {
  return s === "completed" || s === "failed" || s === "cancelled";
}
