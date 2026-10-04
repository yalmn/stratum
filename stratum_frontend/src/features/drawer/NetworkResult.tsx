import { CodeBlock, PropertyList, Timestamp } from "../../components/ui/Display";
import { DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";
interface Result {
  host: string; abgefragt_am: string; beendet_am: string; alle_erfolgreich: boolean;
  antworten: { art: string; version: string; erfolgreich: boolean; text: string; abgefragt_am: string | null; beendet_am: string }[];
}
export function NetworkResult({ value }: { value: Record<string, unknown> }) {
  if (value.werkzeug !== "DNS/WHOIS") return null;
  const r = value as unknown as Result;
  return <DrawerSection title="External network answers">
    <PropertyList items={[["Host", r.host], ["Requested", <Timestamp value={r.abgefragt_am} />], ["Finished", <Timestamp value={r.beendet_am} />], ["Queries", r.alle_erfolgreich ? "All succeeded" : "Some queries failed; inspect individual results"]]} />
    <p><DerivationBadge kind="external_intel" /></p>
    <p className="muted">Current external answers. No historical DNS, ownership or network activity is established by this lookup. DNS output separates the resolver from the answer.</p>
    {r.antworten.map((a, i) => <div className="graph-source" key={i}><h3>{a.art}: {a.erfolgreich ? "Response" : "Failed"}</h3><p className="muted">{a.version}</p><PropertyList items={[["Queried", <Timestamp value={a.abgefragt_am} />], ["Finished", <Timestamp value={a.beendet_am} />]]} /><CodeBlock>{a.text}</CodeBlock></div>)}
  </DrawerSection>;
}
