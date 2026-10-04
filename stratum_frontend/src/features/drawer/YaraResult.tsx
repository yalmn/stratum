import { useNavigate } from "react-router-dom";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { HashValue, PropertyList } from "../../components/ui/Display";
import { DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";

interface Occurrence { id: string; rule: string; string: string; offset: number | null; length: number | null }
const h = columnHelper<Occurrence>();
const columns = [
  h.accessor("rule", { header: "Rule", size: 170 }), h.accessor("string", { header: "String", size: 80 }),
  h.accessor("offset", { header: "Logical offset", size: 140, cell: (c) => c.getValue() === null ? "Condition only" : `0x${c.getValue()!.toString(16).toUpperCase()}` }),
  h.accessor("length", { header: "Stored bytes", size: 100 }),
];
interface ScanResult {
  regel_sha256: string; bytes: number;
  quelle: { evidence: string; volume: number; mft: number; pfad: string };
  ergebnis: { version: string; vollstaendig: boolean; treffer: { regel: string; strings: { string: string; offset: number; gespeicherte_laenge: number }[] }[] };
}
export function YaraResult({ value, caseNumber }: { value: Record<string, unknown>; caseNumber: string }) {
  const navigate = useNavigate();
  if (value.werkzeug !== "YARA") return null;
  const r = value as unknown as ScanResult;
  const rows: Occurrence[] = r.ergebnis.treffer.flatMap<Occurrence>((t, i) => t.strings.length ? t.strings.map((s, j) => ({ id: `${i}-${j}`, rule: t.regel, string: s.string, offset: s.offset, length: s.gespeicherte_laenge })) : [{ id: `${i}`, rule: t.regel, string: "", offset: null, length: null }]);
  return <DrawerSection title="YARA matches">
    <PropertyList items={[["Version", r.ergebnis.version], ["File", r.quelle.pfad], ["Bytes scanned", r.bytes], ["Matching rules", r.ergebnis.treffer.length], ["Complete", r.ergebnis.vollstaendig ? "Yes" : "Rule limit reached; incomplete"]]} />
    <HashValue algo="Rules SHA256" value={r.regel_sha256} /><p><DerivationBadge kind="derived" /></p>
    <p className="muted">Rule conditions matched. This does not establish malware or execution. Stored bytes may be shorter than the complete string match. Select a string occurrence to inspect its logical bytes.</p>
    {rows.length === 0 ? <p>No matching rules in the scanned file.</p> : <div style={{ height: 320 }}><DataTable label="YARA matches" data={rows} columns={columns} rowId={(v) => v.id} grow={["rule"]} onSelect={(s) => { if (s.offset !== null) navigate(`/cases/${encodeURIComponent(caseNumber)}/explorer?ev=${r.quelle.evidence}&detail=file:${r.quelle.evidence}|${r.quelle.volume}|${r.quelle.mft}&pos=${Math.max(0, s.offset - 64)}`); }} footer={`${rows.length} rule / string rows`} /></div>}
  </DrawerSection>;
}
