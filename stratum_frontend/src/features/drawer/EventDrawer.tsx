// Ereignis im Context Drawer: Zeit, Art, Herkunftsstatus, Beteiligte,
// Attribute und Herkunft bis zur Fundstelle (Vorgabe Abschnitt 41), auf
// Wunsch mit dem Rohfund aus dem geprüften Report.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, FileSearch } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { CodeBlock, ErrorState, PropertyList, Skeleton, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useEventDetail, useRawFinding } from "../../lib/api/queries";
import type { EventProvenance } from "../../lib/api/types";
import { label } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

function Value({ v }: { v: unknown }) {
  if (v === null || v === undefined || v === "") {
    return <span className="muted">—</span>;
  }
  if (typeof v === "object") {
    return <span className="mono">{JSON.stringify(v)}</span>;
  }
  return <span className="mono">{String(v)}</span>;
}

function Source({ p }: { p: EventProvenance }) {
  const [show, setShow] = useState(false);
  const [clear, setClear] = useState(false);
  const { can } = useSession();
  const { open } = useDetail();
  const raw = useRawFinding(p.artifact_id, clear, show);
  const loc = p.source_locator ?? {};
  const parser = p.parser ?? {};
  return (
    <div className="provenance">
      <PropertyList
        items={[
          ["Role", label(p.role)],
          [
            "Source",
            <button type="button" className="link" onClick={() => open("evidence", p.evidence_id)}>
              {p.evidence_name ?? p.evidence_id}
            </button>,
          ],
          ["Artifact", p.artifact_kind && label(p.artifact_kind)],
          ...Object.entries(loc).map(([k, v]) => [label(k), <Value v={v} />] as [string, React.ReactNode]),
          ["Parser", parser.name ? <span className="mono">{`${String(parser.name)} ${String(parser.version ?? "")}`}</span> : null],
          ["Analysis run", p.analysis_run_id && <span className="mono">{p.analysis_run_id}</span>],
        ]}
      />
      {p.artifact_id && (
        <div className="drawer-actions">
          <Button size="sm" icon={<FileSearch />} onClick={() => setShow(!show)}>
            {show ? "Hide raw finding" : "Show raw finding"}
          </Button>
          {show && raw.data?.maskiert && can("credential.view_sensitive") && (
            <Button size="sm" variant="danger" onClick={() => setClear(true)}>
              Reveal secrets (audited)
            </Button>
          )}
        </div>
      )}
      {show && raw.isPending && <Skeleton lines={4} />}
      {show && raw.error && <ErrorState title="Raw finding not available." reason={raw.error.message} />}
      {show && raw.data && (
        <>
          {raw.data.report && (
            <span className="muted">
              From report {raw.data.report.pfad}, SHA-256 checked{raw.data.maskiert ? ", secrets masked" : ""}.
            </span>
          )}
          <CodeBlock>{JSON.stringify(raw.data.fund, null, 2)}</CodeBlock>
        </>
      )}
    </div>
  );
}

export function EventDrawer({ id, caseNumber, onClose }: { id: string; caseNumber: string; onClose: () => void }) {
  const d = useEventDetail(id);
  const navigate = useNavigate();
  const { open } = useDetail();
  if (d.isPending) {
    return (
      <DrawerFrame kind="Event" title="…" onClose={onClose}>
        <Skeleton lines={8} />
      </DrawerFrame>
    );
  }
  if (!d.data) {
    return (
      <DrawerFrame kind="Event" title="Not found" onClose={onClose}>
        <ErrorState title="Event could not be loaded." reason={d.error?.message} />
      </DrawerFrame>
    );
  }
  const e = d.data.ereignis;
  return (
    <DrawerFrame kind="Event" title={label(e.kind)} onClose={onClose} badges={<DerivationBadge kind={e.derivation} />}>
      <div className="drawer-actions">
        <Button
          size="sm"
          icon={<Activity />}
          onClick={() =>
            navigate(
              `/cases/${encodeURIComponent(caseNumber)}/timeline?von=${encodeURIComponent(
                new Date(new Date(e.occurred_utc).getTime() - 5 * 60_000).toISOString(),
              )}&detail=event:${e.id}`,
            )
          }
        >
          Timeline around this event
        </Button>
      </div>
      <DrawerSection title="When">
        <PropertyList
          items={[
            ["UTC", <Timestamp value={e.occurred_utc} precise />],
            ...(e.occurred_at
              ? Object.entries(e.occurred_at).map(([k, v]) => [label(k), <Value v={v} />] as [string, React.ReactNode])
              : []),
          ]}
        />
      </DrawerSection>
      <DrawerSection title={`Involved (${e.participants.length})`}>
        <div className="list">
          {e.participants.map((p) => (
            <button key={`${p.entity_id}-${p.role}`} type="button" className="list-row" onClick={() => open("entity", p.entity_id)}>
              <span className="badge">{label(p.kind)}</span>
              <span className="list-main">{p.name}</span>
              <span className="muted">{label(p.role)}</span>
            </button>
          ))}
          {e.participants.length === 0 && <span className="muted">No entities linked.</span>}
        </div>
      </DrawerSection>
      <DrawerSection title="Attributes">
        <PropertyList items={Object.entries(e.attributes).map(([k, v]) => [label(k), <Value v={v} />] as [string, React.ReactNode])} />
      </DrawerSection>
      <DrawerSection title={`Evidence provenance (${d.data.herkunft.length})`}>
        {d.data.herkunft.map((p, i) => (
          <Source key={i} p={p} />
        ))}
        {d.data.herkunft.length === 0 && <span className="muted">No provenance recorded.</span>}
      </DrawerSection>
    </DrawerFrame>
  );
}
