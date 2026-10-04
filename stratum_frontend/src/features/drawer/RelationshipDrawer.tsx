import { Button } from "../../components/ui/Button";
import { CodeBlock, ErrorState, PropertyList, Skeleton, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useRelationship } from "../../lib/api/queries";
import { useDetail } from "../../app/detail";

export function RelationshipDrawer({ id, caseNumber, onClose }: { id: string; caseNumber: string; onClose: () => void }) {
  const query = useRelationship(caseNumber, id);
  const { open } = useDetail();
  const r = query.data?.beziehung;
  return <DrawerFrame kind="Relationship" title={r?.kind ?? "Relationship"} onClose={onClose}>
    {query.isPending && <Skeleton lines={6} />}
    {query.error && <ErrorState title="Relationship could not be loaded" reason={query.error.message} />}
    {r && <>
      <DrawerSection title="Direction and derivation">
        <Button onClick={() => open("entity", r.source.id)}>{r.source.name}</Button><p className="muted">{r.kind} →</p><Button onClick={() => open("entity", r.target.id)}>{r.target.name}</Button>
        <p><DerivationBadge kind={r.derivation} /></p>
        <PropertyList items={[["ID", <span className="mono">{r.id}</span>], ["Valid from", <Timestamp value={r.valid_from} />], ["Valid until", <Timestamp value={r.valid_until} />]]} />
      </DrawerSection>
      <DrawerSection title="Provenance">
        {!query.data!.herkunft.length && <p className="muted">No provenance recorded for this relationship. Do not treat it as a verified source fact.</p>}
        {!query.data!.herkunft_vollstaendig && <p className="muted">First 100 source references shown.</p>}
        {query.data!.herkunft.map((p, i) => <div className="graph-source" key={i}>
          <Button size="sm" onClick={() => open("evidence", p.evidence_id)}>Open evidence</Button>
          <PropertyList items={[["Role", p.role], ["Evidence", <span className="mono">{p.evidence_id}</span>], ["Artifact", p.artifact_id], ["Observation", p.observation_id], ["Analysis run", p.analysis_run_id]]} />
          {p.source_locator && <CodeBlock>{JSON.stringify(p.source_locator, null, 2)}</CodeBlock>}
          {p.parser && <CodeBlock>{JSON.stringify(p.parser, null, 2)}</CodeBlock>}
        </div>)}
      </DrawerSection>
    </>}
  </DrawerFrame>;
}
