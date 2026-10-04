import { BookmarkButton } from "../bookmarks/BookmarkButton";
// Entität im Context Drawer: Attribute (Geheimwerte maskiert), Beziehungen,
// letzte Ereignisse; Klartext nur mit credential.view_sensitive.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Activity, ArrowLeft, ArrowRight, Eye, Globe, Waypoints } from "lucide-react";
import { Button } from "../../components/ui/Button";
import { ErrorState, PropertyList, Skeleton, Timestamp } from "../../components/ui/Display";
import { DrawerFrame, DrawerSection } from "../../components/ui/Layout";
import { DerivationBadge } from "../../components/forensic/Badges";
import { useEntity } from "../../lib/api/queries";
import { label } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

export function EntityDrawer({ id, caseNumber, onClose }: { id: string; caseNumber: string; onClose: () => void }) {
  const [clear, setClear] = useState(false);
  const d = useEntity(id, clear);
  const { can } = useSession();
  const { open } = useDetail();
  const navigate = useNavigate();
  if (d.isPending) {
    return (
      <DrawerFrame kind="Entity" title="…" onClose={onClose}>
        <Skeleton lines={8} />
      </DrawerFrame>
    );
  }
  if (!d.data) {
    return (
      <DrawerFrame kind="Entity" title="Not available" onClose={onClose}>
        <ErrorState title="Entity could not be loaded." reason={d.error?.message} />
      </DrawerFrame>
    );
  }
  const e = d.data.entitaet;
  const attrs = Object.entries(e.attributes).filter(([k]) => k !== "sensibel");
  const masked = attrs.some(([, v]) => v === "[maskiert]");
  return (
    <DrawerFrame kind={label(e.kind)} title={e.display_name} onClose={onClose}>
      <div className="drawer-actions">
        {e.kind==="url"&&can("connector.use")&&<Button size="sm" onClick={()=>navigate(`/cases/${encodeURIComponent(caseNumber)}/reconstruction?target=${encodeURIComponent(e.canonical_key.replace(/^url:/,""))}&direction=outgoing&source_kind=entity&source_id=${e.id}`)}>Reconstruct HTTP request</Button>}<BookmarkButton number={caseNumber} kind="entity" target={e.id} />
        {["ip_address", "domain_name", "url"].includes(e.kind) && can("connector.use") && <Button size="sm" icon={<Globe />} onClick={() => navigate(`/cases/${encodeURIComponent(caseNumber)}/network?target=${encodeURIComponent(e.canonical_key.replace(/^(ip|domain|url):/, ""))}`)}>DNS / WHOIS</Button>}
        <Button size="sm" icon={<Waypoints />} onClick={() => navigate(`/cases/${encodeURIComponent(caseNumber)}/graph?entity=${e.id}&detail=entity:${e.id}`)}>Show in graph</Button>
        <Button
          size="sm"
          icon={<Activity />}
          onClick={() => navigate(`/cases/${encodeURIComponent(caseNumber)}/timeline?ent=${e.id}&entname=${encodeURIComponent(e.display_name)}`)}
        >
          Show in timeline
        </Button>
        {masked && can("credential.view_sensitive") && (
          <Button size="sm" variant="danger" icon={<Eye />} onClick={() => setClear(true)}>
            Reveal secrets (audited)
          </Button>
        )}
      </div>
      <DrawerSection title="Overview">
        <PropertyList
          items={[
            ["Key", <span className="mono">{e.canonical_key}</span>],
            ["First seen", <Timestamp value={e.first_seen} />],
            ["Last seen", <Timestamp value={e.last_seen} />],
            ...attrs.map(([k, v]) => [label(k), <span className="mono">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>] as [string, React.ReactNode]),
          ]}
        />
        {e.klartext && <span className="form-error">Secrets shown in clear text. This access is in the audit log.</span>}
      </DrawerSection>
      <DrawerSection title={`Relationships (${d.data.beziehungen.length})`}>
        <div className="list">
          {d.data.beziehungen.map((b) => (
            <button key={b.id} type="button" className="list-row" onClick={() => open("entity", b.gegenueber.id)}>
              {b.richtung === "aus" ? <ArrowRight size={14} /> : <ArrowLeft size={14} />}
              <span className="mono rel-kind">{b.kind}</span>
              <span className="list-main">{b.gegenueber.name}</span>
              <DerivationBadge kind={b.derivation} />
            </button>
          ))}
          {d.data.beziehungen.length === 0 && <span className="muted">No relationships.</span>}
        </div>
      </DrawerSection>
      <DrawerSection title={`Recent events (${d.data.ereignisse.length})`}>
        <div className="list">
          {d.data.ereignisse.map((ev) => (
            <button key={`${ev.id}-${ev.role}`} type="button" className="list-row" onClick={() => open("event", ev.id)}>
              <Timestamp value={ev.occurred_utc} />
              <span className="list-main">{label(ev.kind)}</span>
              <span className="muted">{label(ev.role)}</span>
            </button>
          ))}
          {d.data.ereignisse.length === 0 && <span className="muted">No events.</span>}
        </div>
      </DrawerSection>
    </DrawerFrame>
  );
}
