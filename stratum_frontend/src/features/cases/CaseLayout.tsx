import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { Copy, Ellipsis, Link2, Pencil, Play, Upload, Workflow } from "lucide-react";
import { Button, IconButton } from "../../components/ui/Button";
import { ErrorState, Skeleton, Tabs } from "../../components/ui/Display";
import { Menu, Popover } from "../../components/ui/Overlay";
import { Tooltip } from "../../components/ui/Tooltip";
import { CaseStatusBadge, ClassificationBadge } from "../../components/forensic/Badges";
import { useCase, useEventKinds, useJobs } from "../../lib/api/queries";
import { isFinished } from "../../lib/api/types";
import { count } from "../../lib/format";
import { useSession } from "../../lib/permissions";
import { CASE_ITEMS } from "../../app/navigation";
import { useWorkspace } from "../../app/store";
import { EvidencePage } from "../evidence/EvidencePage";
import { OverviewPage } from "../overview/OverviewPage";
import { PlannedView } from "./PlannedView";
import { EntitiesPage } from "../entities/EntitiesPage";
import { ExplorerPage } from "../explorer/ExplorerPage";
import { TimelinePage } from "../timeline/TimelinePage";
import { WarRoomPage } from "../war-room/WarRoomPage";
import { NetworkPage } from "../network/NetworkPage";
import { GraphPage } from "../graph/GraphPage";
import { AuditPage } from "../audit/AuditPage";
import { EditCase } from "./EditCase";

function Metric({ label, value, tip }: { label: string; value: string; tip?: string }) {
  const m = (
    <span className="metric">
      <span className="metric-label">{label}</span>
      <span className="metric-value">{value}</span>
    </span>
  );
  return tip ? <Tooltip text={tip}>{m}</Tooltip> : m;
}

function CaseHeader({ number }: { number: string }) {
  const [editing, setEditing] = useState(false);
  const c = useCase(number);
  const kinds = useEventKinds(number);
  const jobs = useJobs(number);
  const { can } = useSession();
  const navigate = useNavigate();
  const base = `/cases/${encodeURIComponent(number)}`;
  const f = c.data?.fall;
  const events = (kinds.data ?? []).reduce((s, k) => s + k.anzahl, 0);
  const running = (jobs.data ?? []).filter((j) => !isFinished(j.status)).length;
  const runs = (jobs.data ?? []).filter((j) => j.kind === "analysis").length;

  if (!f) {
    return (
      <div className="case-header">
        <Skeleton lines={2} width={40} />
      </div>
    );
  }
  return (
    <div className="case-header">
      <div className="case-title-row">
        <h1>
          <span className="mono case-number">{f.case_number}</span>
          <span className="case-title">{f.title}</span>
        </h1>
        <div className="row">
          <CaseStatusBadge status={f.status} />
          <ClassificationBadge value={f.classification} />
        </div>
        <span className="spacer" />
        {can("case.edit") && <Button icon={<Pencil />} onClick={() => setEditing(!editing)}>Edit case</Button>}
        {can("analysis.start") && (
          <Popover
            align="right"
            trigger={({ toggle }) => (
              <Button variant="primary" icon={<Play />} onClick={toggle}>
                Analyze
              </Button>
            )}
          >
            {(close) => {
              const images = (c.data?.evidence ?? []).filter((e) => e.kind === "raw_disk_image" || e.kind === "e01_image");
              return (
                <Menu
                  close={close}
                  entries={
                    images.length > 0
                      ? [
                          { section: "Analyze evidence" },
                          ...images.map((e) => ({
                            label: e.name,
                            icon: <Play />,
                            onSelect: () => navigate(`${base}/evidence?analyze=${e.id}`),
                          })),
                        ]
                      : [{ label: "No disk image in this case yet", disabled: true }]
                  }
                />
              );
            }}
          </Popover>
        )}
        <Tooltip text="Planned: Operational Layer">
          <Button icon={<Workflow />} disabled>
            Run Playbook
          </Button>
        </Tooltip>
        {can("evidence.import") && (
          <Button
            icon={<Upload />}
            disabled={!f.case_folder}
            title={f.case_folder ? undefined : "The case has no case folder; import is only possible from there."}
            onClick={() => navigate(`${base}/evidence?add=1`)}
          >
            Add Evidence
          </Button>
        )}
        <Popover
          align="right"
          trigger={({ toggle }) => <IconButton label="Actions" icon={<Ellipsis />} onClick={toggle} />}
        >
          {(close) => (
            <Menu
              close={close}
              entries={[
                {
                  label: "Run analysis…",
                  icon: <Play />,
                  disabled: !can("analysis.start"),
                  onSelect: () => navigate(`${base}/evidence`),
                },
                "separator",
                {
                  label: "Copy case number",
                  icon: <Copy />,
                  onSelect: () => void navigator.clipboard?.writeText(f.case_number),
                },
                {
                  label: "Copy link",
                  icon: <Link2 />,
                  onSelect: () => void navigator.clipboard?.writeText(window.location.href),
                },
              ]}
            />
          )}
        </Popover>
      </div>
      {editing && can("case.edit") && <EditCase key={f.id} value={f} onClose={() => setEditing(false)} />}
      <div className="case-metrics">
        <Metric label="Evidence" value={count(c.data?.evidence.length ?? 0)} />
        <Metric label="Analysis runs" value={count(runs)} tip="Analysis jobs in this case" />
        <Metric label="Events" value={kinds.data ? count(events) : "…"} tip="Normalized events in the case model" />
        <Metric label="Running jobs" value={count(running)} />
      </div>
      <Tabs
        items={CASE_ITEMS.filter((i) => !i.planned).map((i) => ({
          id: i.id,
          label: i.label,
          icon: i.icon,
          to: `${base}/${i.path}`,
        }))}
      />
    </div>
  );
}

export function CaseLayout() {
  const number = useParams().number ?? "";
  const c = useCase(number);
  const remember = useWorkspace((s) => s.remember);
  useEffect(() => {
    if (c.data) {
      remember({ kind: "case", id: c.data.fall.case_number, label: c.data.fall.case_number, hint: c.data.fall.title });
    }
  }, [c.data, remember]);

  if (c.error) {
    return (
      <div className="page">
        <ErrorState title={`Case ${number} could not be opened.`} reason={c.error.message} />
      </div>
    );
  }
  return (
    <div className="case-layout">
      <CaseHeader number={number} />
      <div className="case-body">
        <Routes>
          <Route index element={<Navigate to="overview" replace />} />
          <Route path="overview" element={<OverviewPage number={number} />} />
          <Route path="evidence" element={<EvidencePage number={number} />} />
          <Route path="explorer" element={<ExplorerPage number={number} />} />
          <Route path="timeline" element={<TimelinePage number={number} />} />
          <Route path="network" element={<NetworkPage key={number} number={number} />} />
          <Route path="graph" element={<GraphPage key={number} number={number} />} />
          <Route path="audit" element={<AuditPage key={number} number={number} />} />
          <Route path="entities" element={<EntitiesPage number={number} />} />
          <Route path="war-room" element={<WarRoomPage number={number} />} />
          <Route path=":view" element={<PlannedView />} />
        </Routes>
      </div>
    </div>
  );
}
