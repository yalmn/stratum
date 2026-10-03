// Fachliche Kennzeichnungen. Herkunft (Derivation) ist Pflicht überall, wo
// abgeleitete Objekte erscheinen: Beobachtetes und Gefolgertes sehen nie
// gleich aus.

import { HardDrive, ShieldAlert, ShieldCheck } from "lucide-react";
import type {
  CaseClassification,
  CaseStatus,
  DerivationKind,
  Evidence,
  EvidenceKind,
  EvidenceSupport,
  JobStatus,
} from "../../lib/api/types";
import { label } from "../../lib/format";
import { Badge, StatusBadge, type Tone } from "../ui/Badge";

const DERIVATION: Record<DerivationKind, { text: string; tone: Tone; tip: string }> = {
  observed: { text: "Observed", tone: "success", tip: "Directly observed in the evidence." },
  parsed: { text: "Parsed", tone: "success", tip: "Extracted deterministically by a parser." },
  derived: { text: "Derived", tone: "info", tip: "Computed from several fields of the same source." },
  correlated: { text: "Correlated", tone: "warning", tip: "Joined across artifacts by a rule. Interpretation, not fact." },
  reconstructed: { text: "Reconstructed", tone: "warning", tip: "Produced by replay or a reconstructed environment." },
  simulated: { text: "Simulated", tone: "warning", tip: "Produced inside a simulation." },
  analyst_asserted: { text: "Analyst", tone: "info", tip: "Added deliberately by an analyst." },
  external_intel: { text: "External Intel", tone: "info", tip: "From an external threat intelligence source." },
  ai_suggested: { text: "AI Suggested", tone: "danger", tip: "Suggested by a language model. Never a finding by itself." },
};

export function DerivationBadge({ kind }: { kind: DerivationKind }) {
  const d = DERIVATION[kind];
  return (
    <Badge tone={d.tone} outline title={d.tip}>
      {d.text}
    </Badge>
  );
}

export const DERIVATION_KINDS = Object.keys(DERIVATION) as DerivationKind[];

const CASE_STATUS: Record<CaseStatus, Tone> = {
  new: "info",
  active: "success",
  review: "warning",
  suspended: "neutral",
  closed: "neutral",
  archived: "neutral",
};

export function CaseStatusBadge({ status }: { status: CaseStatus }) {
  return <StatusBadge tone={CASE_STATUS[status]} label={label(status)} />;
}

const CLASSIFICATION: Record<CaseClassification, Tone> = {
  open: "neutral",
  internal: "neutral",
  confidential: "warning",
  strictly_confidential: "danger",
};

export function ClassificationBadge({ value }: { value: CaseClassification }) {
  return (
    <Badge tone={CLASSIFICATION[value]} outline>
      {label(value)}
    </Badge>
  );
}

const JOB: Record<JobStatus, { tone: Tone; text: string }> = {
  queued: { tone: "neutral", text: "Queued" },
  running: { tone: "info", text: "Running" },
  completed: { tone: "success", text: "Completed" },
  failed: { tone: "danger", text: "Failed" },
  cancelled: { tone: "warning", text: "Cancelled" },
};

export function JobStatusBadge({ status }: { status: JobStatus }) {
  const j = JOB[status];
  return <StatusBadge tone={j.tone} label={j.text} pulse={status === "running"} />;
}

const KIND: Partial<Record<EvidenceKind, string>> = {
  raw_disk_image: "Raw Disk Image",
  e01_image: "E01 Image",
  vhd_image: "VHD Image",
  pcap: "Packet Capture",
};

export function evidenceKind(kind: EvidenceKind): string {
  return KIND[kind] ?? label(kind);
}

const SUPPORT: Record<EvidenceSupport, { tone: Tone; text: string; tip: string }> = {
  recognized: { tone: "info", text: "Recognized", tip: "Format recognized; not analyzed yet." },
  analyzed: { tone: "success", text: "Analyzed", tip: "At least one completed analysis run." },
  unsupported_format: {
    tone: "neutral",
    text: "Unsupported",
    tip: "Registered and hashed; no analyzer for this format yet.",
  },
  key_missing: { tone: "warning", text: "Key missing", tip: "Recognized, but a decryption key is missing." },
};

export function SupportBadge({ support }: { support: EvidenceSupport }) {
  const s = SUPPORT[support];
  return <StatusBadge tone={s.tone} label={s.text} title={s.tip} />;
}

/**
 * Stand der Integrität: der SHA-256 steht seit dem Import fest; eine
 * abgeschlossene Analyse hat das Image vorher vollständig dagegen geprüft.
 */
export function integrity(e: Evidence): { verified: boolean; text: string; tip: string } {
  return e.support === "analyzed"
    ? {
        verified: true,
        text: "SHA-256 verified",
        tip: "Recomputed and matched before a completed analysis run.",
      }
    : {
        verified: false,
        text: "SHA-256 recorded",
        tip: "Computed at import. Verified again before every analysis.",
      };
}

export function IntegrityBadge({ evidence }: { evidence: Evidence }) {
  const i = integrity(evidence);
  return (
    <Badge
      tone={i.verified ? "success" : "neutral"}
      title={i.tip}
      icon={i.verified ? <ShieldCheck /> : <ShieldAlert />}
    >
      {i.text}
    </Badge>
  );
}

export function EvidenceReference({ evidence, onOpen }: { evidence: Evidence; onOpen?: () => void }) {
  return (
    <button type="button" className="evidence-ref" onClick={onOpen} title={evidence.source_uri}>
      <HardDrive aria-hidden />
      <span>{evidence.name}</span>
    </button>
  );
}
