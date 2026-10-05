import type { FileEntry } from "../../lib/api/types";

/** Vollständiger Katalogschlüssel innerhalb einer Evidence und eines Volumes. */
export function catalogRowId(entry: FileEntry): string {
  return JSON.stringify([entry.mft_record, entry.parent_record, entry.name]);
}

/** Überlappende Seiten dürfen denselben Eintrag nur einmal darstellen. */
export function catalogRows(pages: { eintraege: FileEntry[] }[]): FileEntry[] {
  const rows = new Map<string, FileEntry>();
  for (const page of pages) {
    for (const entry of page.eintraege) rows.set(catalogRowId(entry), entry);
  }
  return [...rows.values()];
}

/** Wählt genau den angeklickten Quellpfad; unbekannte Pfade werden nicht ersetzt. */
export function catalogEntry(entries: FileEntry[], path: string | null): FileEntry | undefined {
  return path === null ? entries[0] : entries.find(entry => entry.path === path);
}
