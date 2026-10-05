import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/Button";
import { CodeBlock, EmptyState, ErrorState, PropertyList, Skeleton } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { useArtifact, useRawFinding } from "../../lib/api/queries";
import { label } from "../../lib/format";
import { useDetail } from "../../app/detail";
import { BookmarkButton } from "../bookmarks/BookmarkButton";

const SOURCE_LABELS: Record<string, string> = {
  byte_offset: "File offset (bytes)",
  image_offset: "Image offset (bytes)",
  record_offset: "MFT record image offset (bytes)",
  volume_offset: "Volume image offset (bytes)",
  cell_offset: "Hive cell offset (bytes)",
  offset: "Image offset (bytes)",
};
function observedFields(value: unknown): [string, string][] {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    return Object.entries(value).map(([k, v]) => [label(k), valueText(v)]);
  }
  return [["Value", valueText(value)]];
}
function valueText(value: unknown): string {
  if (value === null) return "not recorded";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
}

export function ArtifactDrawer({ id, caseNumber, onClose }: { id: string; caseNumber: string; onClose: () => void }) {
  const navigate = useNavigate();
  const { open } = useDetail();
  const [raw, setRaw] = useState(false);
  useEffect(() => setRaw(false), [id]);
  const query = useArtifact(caseNumber, id);
  const source = useRawFinding(id, false, raw);
  const a = query.data;

  return (
    <DrawerFrame kind="Artifact" title={a ? label(a.kind) : "Source artifact"} onClose={onClose}>
      {query.isPending && <Skeleton lines={8} />}
      {query.error && <ErrorState title="Source artifact unavailable" reason={query.error.message} />}
      {a && <>
        <BookmarkButton number={caseNumber} kind="artifact" target={id} />
        <Button size="sm" onClick={() => navigate(`/cases/${encodeURIComponent(caseNumber)}/reconstruction?source_kind=artifact&source_id=${id}`)}>
          Reconstruct HTTP request
        </Button>
        <DrawerSection title="Source and parser">
          <PropertyList items={[
            ["Artifact ID", id],
            ["Evidence", a.evidence_name ?? a.evidence_id],
            ...Object.entries(a.source_locator).map(([k, v]) => [SOURCE_LABELS[k] ?? label(k), valueText(v)] as [string, string]),
            ...Object.entries(a.parser).map(([k, v]) => [`Parser ${label(k)}`, valueText(v)] as [string, string]),
          ]} />
          <Button size="sm" onClick={() => open("evidence", a.evidence_id)}>Open evidence</Button>
        </DrawerSection>
        <DrawerSection title="Observed fields">
          <p className="muted">Source output, with credential secrets masked. Showing {a.felder.length} of {a.observations} observations.</p>
          {a.felder.map(o => <div key={o.id}>
            <h4>{label(o.kind)}</h4>
            <PropertyList items={observedFields(o.fields)} />
          </div>)}
        </DrawerSection>
        <DrawerSection title="Linked objects and analysis runs">
          <p className="muted">Up to 100 provenance links. Event times are shown in the linked event.</p>
          {a.herkunft.length === 0 && <EmptyState title="No linked objects recorded" text="The source location above remains available." />}
          {a.herkunft.map((p, i) => <div key={i}>
            <p className="muted">{label(p.role)} · {label(p.object_type)} · Run {p.analysis_run_id ?? "not recorded"}</p>
            {p.source_locator && JSON.stringify(p.source_locator) !== JSON.stringify(a.source_locator) && <PropertyList items={Object.entries(p.source_locator).map(([k, v]) => [SOURCE_LABELS[k] ?? label(k), valueText(v)])} />}
            {p.observation_id && <p className="muted mono">Observation {p.observation_id}</p>}
            {p.object_type === "entity" || p.object_type === "event"
              ? <Button size="sm" onClick={() => open(p.object_type as "entity" | "event", p.object_id)}>Open {label(p.object_type)}</Button>
              : <span className="mono">{p.object_id}</span>}
          </div>)}
        </DrawerSection>
        <DrawerSection title="Original raw finding">
          <Button size="sm" onClick={() => setRaw(!raw)}>{raw ? "Hide raw finding" : "Load raw finding"}</Button>
          {raw && source.isPending && <Skeleton lines={4} />}
          {raw && source.error && <ErrorState title="Raw finding unavailable" reason={source.error.message} />}
          {raw && source.data && <CodeBlock>{JSON.stringify(source.data.fund, null, 2)}</CodeBlock>}
        </DrawerSection>
      </>}
    </DrawerFrame>
  );
}
