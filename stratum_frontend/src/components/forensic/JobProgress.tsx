import type { JobUpdate } from "../../lib/api/types";
import { bytes, count, label } from "../../lib/format";

const PHASE: Record<string, { text: string; unit: "bytes" | "items" }> = {
  hashing: { text: "Integrity hash", unit: "bytes" },
  katalog: { text: "File catalog", unit: "items" },
  analyzer: { text: "Analyzers", unit: "items" },
  suche: { text: "Keyword search", unit: "bytes" },
};

export function phaseLabel(p: string): string {
  return PHASE[p]?.text ?? label(p);
}

/** Fortschritt der laufenden Phase mit Balken und Mengenangabe. */
export function JobProgress({ update, compact }: { update: JobUpdate; compact?: boolean }) {
  const p = update.progress ?? {};
  const phase = p.phase;
  const stand = phase ? p.phasen?.[phase] : undefined;
  const share = stand && stand.gesamt > 0 ? Math.min(1, stand.erledigt / stand.gesamt) : null;
  const unit = phase ? PHASE[phase]?.unit : undefined;
  const amount =
    stand && stand.gesamt > 0
      ? unit === "bytes"
        ? `${bytes(stand.erledigt)} / ${bytes(stand.gesamt)}`
        : `${count(stand.erledigt)} / ${count(stand.gesamt)}`
      : null;

  if (update.status === "queued") {
    return <span className="muted">Waiting for a worker</span>;
  }
  return (
    <div className="progress" aria-label="Progress">
      <div className="progress-head">
        <span>{phase ? phaseLabel(phase) : "Starting"}</span>
        {share !== null && <span className="mono">{Math.round(share * 100)}%</span>}
      </div>
      <div className="progress-track" role="progressbar" aria-valuenow={share !== null ? Math.round(share * 100) : undefined}>
        <div
          className={share === null ? "progress-fill indeterminate" : "progress-fill"}
          style={share === null ? undefined : { width: `${share * 100}%` }}
        />
      </div>
      {!compact && (amount || p.meldung) && (
        <div className="progress-head muted">
          <span className="mono">{amount}</span>
          <span>{p.meldung}</span>
        </div>
      )}
    </div>
  );
}
