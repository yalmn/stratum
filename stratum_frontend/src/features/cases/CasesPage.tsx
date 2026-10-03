import { useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, Copy, Plus } from "lucide-react";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Button } from "../../components/ui/Button";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Field, Input, Select, Textarea } from "../../components/ui/Input";
import { useContextMenu } from "../../components/ui/Overlay";
import { CaseStatusBadge, ClassificationBadge } from "../../components/forensic/Badges";
import { useCases, useCreateCase } from "../../lib/api/queries";
import type { CaseRow } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";
import { useDetail } from "../../app/detail";

const h = columnHelper<CaseRow>();
const columns = [
  h.accessor("case_number", {
    header: "Case",
    size: 200,
    cell: (c) => <span className="mono">{c.getValue()}</span>,
  }),
  h.accessor("title", { header: "Title", size: 260 }),
  h.accessor("status", { header: "Status", size: 120, cell: (c) => <CaseStatusBadge status={c.getValue()} /> }),
  h.accessor("classification", {
    header: "Classification",
    size: 170,
    cell: (c) => <ClassificationBadge value={c.getValue()} />,
  }),
  h.accessor("evidence", { header: "Evidence", size: 100 }),
  h.accessor("created_at", { header: "Created (UTC)", size: 200, cell: (c) => <Timestamp value={c.getValue()} /> }),
];

export function CasesPage() {
  const cases = useCases();
  const { can } = useSession();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const { detail, open } = useDetail();
  const menu = useContextMenu();
  const creating = params.get("new") === "1";
  const openCase = (c: CaseRow) => navigate(`/cases/${encodeURIComponent(c.case_number)}/overview`);
  const data = useMemo(() => cases.data ?? [], [cases.data]);

  return (
    <div className="page page-fill">
      <div className="page-head">
        <div>
          <h1>Cases</h1>
          <span className="muted">Select a case to see its summary, double-click or press Enter to open it.</span>
        </div>
        <span className="spacer" />
        {can("case.create") && !creating && (
          <Button variant="primary" icon={<Plus />} onClick={() => setParams({ new: "1" })}>
            New Case
          </Button>
        )}
      </div>
      {creating && <NewCase onDone={() => setParams({})} />}
      {cases.isPending && <Skeleton lines={6} />}
      {cases.error && <ErrorState title="Cases could not be loaded." reason={cases.error.message} />}
      {cases.data && data.length === 0 && (
        <EmptyState
          title="No cases yet."
          text={can("case.create") ? "Create the first case to start an investigation." : "Ask an administrator to create a case."}
        />
      )}
      {data.length > 0 && (
        <DataTable
          label="Cases"
          data={data}
          columns={columns}
          rowId={(c) => c.case_number}
          grow={["title"]}
          numeric={["evidence"]}
          selected={detail?.kind === "case" ? detail.id : null}
          onSelect={(c) => open("case", c.case_number)}
          onOpen={openCase}
          onContextMenu={(e, c) =>
            menu.open(e, [
              { label: "Open case", icon: <ArrowRight />, onSelect: () => openCase(c) },
              { label: "Copy case number", icon: <Copy />, onSelect: () => void navigator.clipboard?.writeText(c.case_number) },
            ])
          }
          footer={`${data.length} cases`}
        />
      )}
      {menu.menu}
    </div>
  );
}

function NewCase({ onDone }: { onDone: () => void }) {
  const create = useCreateCase();
  const navigate = useNavigate();
  return (
    <form
      className="inline-panel"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        const d: Record<string, string> = {};
        for (const k of ["nummer", "titel", "ordner", "beschreibung", "zeitzone", "einstufung"]) {
          const v = String(f.get(k) ?? "").trim();
          if (v) {
            d[k] = v;
          }
        }
        create.mutate(d, {
          onSuccess: (c) => {
            onDone();
            navigate(`/cases/${encodeURIComponent(c.case_number)}/overview`);
          },
        });
      }}
    >
      <h2>New Case</h2>
      <div className="form-grid">
        <Field label="Case number">
          <Input name="nummer" required placeholder="DFIR-2026-0002" mono autoFocus />
        </Field>
        <Field label="Title">
          <Input name="titel" required placeholder="Compromised Webserver" />
        </Field>
        <Field label="Classification">
          <Select name="einstufung" defaultValue="internal">
            <option value="open">Open</option>
            <option value="internal">Internal</option>
            <option value="confidential">Confidential</option>
            <option value="strictly_confidential">Strictly Confidential</option>
          </Select>
        </Field>
        <Field label="Case folder on the server" hint="Evidence can only be imported from inside this folder.">
          <Input name="ordner" placeholder="/mnt/evidence/dfir-2026-0002" mono />
        </Field>
        <Field label="Time zone" hint="Only if known from the registry; never assumed.">
          <Input name="zeitzone" placeholder="Europe/Berlin" />
        </Field>
        <Field label="Description" wide>
          <Textarea name="beschreibung" rows={2} />
        </Field>
      </div>
      {create.error && <div className="form-error">{create.error.message}</div>}
      <div className="form-actions">
        <Button type="submit" variant="primary" disabled={create.isPending}>
          Create case
        </Button>
        <Button variant="ghost" onClick={onDone}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
