// Anzeige von Größen und Zeiten. Zeiten immer in UTC und so gekennzeichnet:
// die Oberfläche nimmt keine Zeitzone des Rechners an.

export function groesse(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const einheiten = ["KiB", "MiB", "GiB", "TiB"];
  let wert = bytes / 1024;
  let i = 0;
  while (wert >= 1024 && i < einheiten.length - 1) {
    wert /= 1024;
    i += 1;
  }
  return `${wert.toLocaleString("de-DE", { maximumFractionDigits: 1 })} ${einheiten[i]}`;
}

export function zeit(iso: string | null | undefined): string {
  if (!iso) {
    return "";
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  return `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

export function zahl(n: number): string {
  return n.toLocaleString("de-DE");
}

export function kurz(hash: string, laenge = 12): string {
  return hash.length > laenge ? `${hash.slice(0, laenge)}…` : hash;
}

const STATUS: Record<string, string> = {
  queued: "wartet",
  running: "läuft",
  completed: "fertig",
  failed: "fehlgeschlagen",
  cancelled: "abgebrochen",
};

export function jobStatus(s: string): string {
  return STATUS[s] ?? s;
}

const ART: Record<string, string> = {
  analysis: "Analyse",
  evidence_import: "Import",
};

export function jobArt(s: string): string {
  return ART[s] ?? s;
}

const PHASE: Record<string, string> = {
  hashing: "Hash",
  katalog: "Katalog",
  analyzer: "Analyzer",
  suche: "Suche",
};

export function phase(s: string): string {
  return PHASE[s] ?? s;
}
