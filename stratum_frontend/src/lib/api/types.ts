// Typen der API. Modellobjekte kommen aus stratum_model (erzeugt mit
// `npm run typen`, Ordner model/). Hier stehen nur die Hüllen, die der
// Server um sie legt, und die Form des Job-Fortschritts aus stratum-jobs.

import type { Case } from "./model/Case";
import type { Evidence } from "./model/Evidence";
import type { Job } from "./model/Job";
import type { JobStatus } from "./model/JobStatus";
import type { Permission } from "./model/Permission";
import type { User } from "./model/User";
import type { WarRoomEntry } from "./model/WarRoomEntry";
import type { DerivationKind } from "./model/DerivationKind";

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
export type { WarRoomEntry } from "./model/WarRoomEntry";
export type { WarRoomEntryKind } from "./model/WarRoomEntryKind";
export type { ObjectRef } from "./model/ObjectRef";

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

/** Seite einer Liste mit Marke für die nächste (Keyset). */
export interface Page<T> {
  eintraege: T[];
  naechste: string | null;
}

/** GET /evidence/{id}/volumes */
export interface VolumeInfo {
  volume_offset: number;
  eintraege: number;
  verzeichnisse: number;
  wurzel: number;
}

/** Katalogeintrag (store/dateien.rs, datei_json). Zeiten als Text in voller FILETIME-Auflösung. */
export interface FileEntry {
  mft_record: number;
  parent_record?: number;
  name: string;
  path: string;
  is_directory: boolean;
  sequence: number | null;
  size: number | null;
  valid_length: number | null;
  si_created: string | null;
  si_modified: string | null;
  si_mft_modified: string | null;
  si_accessed: string | null;
  fn_created: string | null;
  fn_modified: string | null;
  fn_mft_modified: string | null;
  fn_accessed: string | null;
  attributes: string[];
  streams: { name: string; groesse?: number }[] | null;
  hardlinks: number | null;
  reparse_tag: string | null;
  wof: string | null;
  mft_record_offset: number | null;
  sha256: string | null;
  file_type: string | null;
  mime: string | null;
  hash_error: string | null;
  error: string | null;
  content_error: string | null;
  hat_kinder: boolean;
}

/** POST .../hash */
export interface FileHashes {
  bytes: number;
  sha256: string;
  blake3: string;
  groesse: number;
  gueltige_laenge: number | null;
  wof: string | null;
  im_katalog_vermerkt: boolean;
}

export interface Participant {
  entity_id: string;
  role: string;
  kind: string;
  name: string;
}

/** Eintrag der Zeitachse (store/daten.rs, zeitachse). */
export interface TimelineEvent {
  id: string;
  kind: string;
  occurred_utc: string;
  occurred_at: Record<string, unknown> | null;
  ended_at: Record<string, unknown> | null;
  attributes: Record<string, unknown>;
  derivation: DerivationKind;
  participants: Participant[];
}

export interface EventProvenance {
  role: string;
  evidence_id: string;
  evidence_name: string | null;
  artifact_id: string | null;
  artifact_kind: string | null;
  source_locator: Record<string, unknown> | null;
  parser: Record<string, unknown> | null;
  analysis_run_id: string | null;
  rohfund_id: string | null;
}

/** GET /ereignisse/{id} */
export interface EventDetail {
  ereignis: TimelineEvent;
  herkunft: EventProvenance[];
}

/** Entität in Listen (store/daten.rs, entitaeten). */
export interface EntityRow {
  id: string;
  kind: string;
  canonical_key: string;
  display_name: string;
  attributes: Record<string, unknown>;
  first_seen: string | null;
  last_seen: string | null;
  ereignisse: number;
  beziehungen: number;
}

/** GET /entitaeten/{id} */
export interface EntityDetail {
  entitaet: {
    id: string;
    case_id: string;
    kind: string;
    canonical_key: string;
    display_name: string;
    attributes: Record<string, unknown>;
    first_seen: string | null;
    last_seen: string | null;
    klartext: boolean;
  };
  beziehungen: {
    id: string;
    kind: string;
    derivation: DerivationKind;
    richtung: "aus" | "ein";
    gegenueber: { id: string; kind: string; name: string };
    valid_from: string | null;
    valid_until: string | null;
    attributes: Record<string, unknown>;
  }[];
  ereignisse: { id: string; kind: string; occurred_utc: string | null; role: string; derivation: DerivationKind }[];
}

/** GET /artefakte/{id}/rohfund */
export interface RawFinding {
  artefakt: string;
  rohfund_id: string | null;
  fund: Record<string, unknown>;
  maskiert: boolean;
  klartext: boolean;
  report: { analysis_run_id: string; pfad: string; sha256: string; geprueft: boolean } | null;
}

/** War-Room-Eintrag mit Anzeigename des Handelnden. */
export type WarRoomItem = WarRoomEntry & { actor_name: string | null };

export interface WarRoomPage {
  eintraege: WarRoomItem[];
  naechste: string | null;
}
