import { useMemo, useState } from "react";
import { RefreshCw, ShieldCheck } from "lucide-react";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { Button } from "../../components/ui/Button";
import { CodeBlock, EmptyState, ErrorState, HashValue, PropertyList, Skeleton, Timestamp } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { useAudit, useVerifyAudit } from "../../lib/api/queries";
import type { AuditRow } from "../../lib/api/types";
import { useSession } from "../../lib/permissions";

const h = columnHelper<AuditRow>();
const columns = [
  h.accessor("sequence", { header: "Sequence", size: 90 }),
  h.accessor("timestamp", { header: "Investigation time", size: 210, cell: (c) => <Timestamp value={c.getValue()} /> }),
  h.accessor("akteur", { header: "Analyst", size: 150 }),
  h.accessor("action", { header: "Action", size: 190 }),
  h.accessor("result", { header: "Result", size: 90 }),
  h.accessor("object_type", { header: "Object", size: 130 }),
];
export function AuditPage({ number }: { number: string }) {
  const { can } = useSession();
  const list = useAudit(number, can("audit.view"));
  const verify = useVerifyAudit();
  const [text, setText] = useState("");
  const [result, setResult] = useState("");
  const [selected, setSelected] = useState<AuditRow | null>(null);
  const loaded = useMemo(() => list.data?.pages.flat() ?? [], [list.data]);
  const rows = loaded.filter((r) => (!result || r.result === result) && `${r.action} ${r.akteur} ${r.object_type} ${r.object_id ?? ""}`.toLocaleLowerCase().includes(text.toLocaleLowerCase()));
  if (!can("audit.view")) return <EmptyState title="Audit permission required" text="Your role needs audit.view to inspect the investigation log." />;
  return <div className="audit-workspace">
    <div className="filter-bar">
      <Input aria-label="Filter loaded audit entries" placeholder="Filter loaded actions, analysts, objects" value={text} onChange={(e) => setText(e.target.value)} />
      <Select aria-label="Audit result" value={result} onChange={(e) => setResult(e.target.value)}><option value="">All results</option><option value="success">Success</option><option value="denied">Denied</option><option value="failure">Failure</option></Select>
      <Button icon={<RefreshCw />} disabled={list.isFetching} onClick={() => { setSelected(null); void list.refetch(); }}>Refresh</Button>
      {can("audit.verify") && <Button icon={<ShieldCheck />} disabled={verify.isPending} onClick={() => verify.mutate()}>{verify.isPending ? "Checking…" : "Verify entire audit chain"}</Button>}
    </div>
    <p className="audit-notice">Analyst actions and investigation time. Separate from artifact timestamps and War Room notes. Filters apply to {loaded.length} loaded entries.</p>
    {verify.error && <ErrorState title="Audit verification failed" reason={verify.error.message} />}
    {verify.data && <div className="audit-notice" role="status"><strong>{verify.data.fehler_gesamt === 0 ? "Audit chain intact" : "Audit chain has errors"}</strong> · {verify.data.ereignisse} entries checked across all cases.<HashValue value={verify.data.letzter_hash} />{verify.data.fehler.map((f) => <p key={f} className="form-error">{f}</p>)}</div>}
    <div className="audit-body">
      <div className="audit-table">
        {list.isPending && <Skeleton lines={8} />}
        {list.error && <ErrorState title="Audit could not be loaded" reason={list.error.message} />}
        {list.data && rows.length === 0 && <EmptyState title="No matching loaded entries" text="Change the filter or load older entries." />}
        {rows.length > 0 && <DataTable label="Investigation audit" data={rows} columns={columns} rowId={(r) => r.id} grow={["action"]} selected={selected?.id} onSelect={setSelected} footer={`${rows.length} matching entries`} />}
        {list.hasNextPage && <Button disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>Load older entries</Button>}
      </div>
      {selected && <aside className="audit-detail">
        <h3>{selected.action}</h3>
        <PropertyList items={[["Sequence", selected.sequence], ["Analyst", selected.akteur], ["Time", <Timestamp value={selected.timestamp} />], ["Result", selected.result], ["Object", selected.object_type], ["Reference", selected.object_id]]} />
        <HashValue algo="SHA256" value={selected.hash} /><HashValue algo="Previous SHA256" value={selected.previous_hash ?? ""} />
        <CodeBlock>{JSON.stringify(selected.details, null, 2)}</CodeBlock>
      </aside>}
    </div>
  </div>;
}
