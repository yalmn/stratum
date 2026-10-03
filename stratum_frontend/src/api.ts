// Zugriff auf die stratum-API (/api/v1). Die Sitzung steckt im
// HttpOnly-Cookie, das der Server bei der Anmeldung setzt; das Token
// selbst sieht die Oberfläche nie.

export class ApiFehler extends Error {
  constructor(
    public status: number,
    text: string,
  ) {
    super(text);
  }
}

export async function api<T>(pfad: string, optionen: { methode?: string; daten?: unknown } = {}): Promise<T> {
  const antwort = await fetch(`/api/v1${pfad}`, {
    method: optionen.methode ?? "GET",
    credentials: "same-origin",
    headers: optionen.daten === undefined ? undefined : { "Content-Type": "application/json" },
    body: optionen.daten === undefined ? undefined : JSON.stringify(optionen.daten),
  });
  if (antwort.status === 204) {
    return undefined as T;
  }
  const text = await antwort.text();
  let inhalt: unknown = null;
  try {
    inhalt = text ? JSON.parse(text) : null;
  } catch {
    inhalt = null;
  }
  if (!antwort.ok) {
    const meldung =
      inhalt && typeof inhalt === "object" && "fehler" in inhalt
        ? String((inhalt as { fehler: unknown }).fehler)
        : `HTTP ${antwort.status}`;
    throw new ApiFehler(antwort.status, meldung);
  }
  return inhalt as T;
}

export interface Konto {
  id: string;
  username: string;
  display_name: string;
  kind: string;
  status: string;
  superadmin: boolean;
}

export interface Ich {
  konto: Konto;
  rechte: string[];
}

export interface Fall {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  status: string;
  classification: string;
  created_at: string;
  opened_at: string | null;
  closed_at: string | null;
  timezone: string | null;
  case_folder: string | null;
}

export interface FallZeile extends Fall {
  evidence: number;
}

export interface Evidence {
  id: string;
  case_id: string;
  kind: string;
  name: string;
  role: string | null;
  original_name: string | null;
  source_uri: string;
  size: number;
  sha256: string;
  blake3: string;
  acquired_at: string | null;
  imported_at: string;
  support: string;
  metadata: Record<string, unknown>;
}

export interface FallDetail {
  fall: Fall;
  evidence: Evidence[];
}

export type JobStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface PhasenStand {
  erledigt: number;
  gesamt: number;
}

export interface Fortschritt {
  phase?: string;
  phasen?: Record<string, PhasenStand>;
  meldung?: string;
}

export interface Job {
  id: string;
  case_id: string;
  kind: "analysis" | "evidence_import";
  status: JobStatus;
  parameters: Record<string, unknown>;
  progress: Fortschritt;
  created_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  worker: string | null;
  cancel_requested: boolean;
  error: string | null;
  analysis_run_id: string | null;
  result: Record<string, unknown> | null;
}

export interface AnalyseOptionen {
  katalog: boolean;
  datei_hashes: boolean;
  mft_timeline: boolean;
  usn_journal: boolean;
  raw_sweep: boolean;
  ohne_begriffe: boolean;
  bdp: boolean;
}

export function beendet(s: JobStatus): boolean {
  return s === "completed" || s === "failed" || s === "cancelled";
}
