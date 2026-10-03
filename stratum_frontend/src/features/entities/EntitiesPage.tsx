// Entitäten (Vorgabe Abschnitt 18): Benutzer, Rechner, Prozesse, Dateien,
// Adressen … mit Zahl der Ereignisse und Beziehungen; Details im Drawer.

import { useCallback, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { DataTable, columnHelper } from "../../components/data-table/DataTable";
import { EmptyState, ErrorState, Skeleton, Timestamp } from "../../components/ui/Display";
import { Input, Select } from "../../components/ui/Input";
import { useEntities } from "../../lib/api/queries";
import type { EntityRow } from "../../lib/api/types";
import type { EntityKind } from "../../lib/api/model/EntityKind";
import { count, label } from "../../lib/format";
import { useDetail } from "../../app/detail";

// Alle Arten aus dem Modell; der Typ prüft die Namen gegen stratum_model.
const KINDS: EntityKind[] = [
  "host",
  "user_account",
  "user_group",
  "file",
  "file_stream",
  "directory",
  "volume",
  "network_share",
  "process",
  "service",
  "scheduled_task",
  "registry_key",
  "registry_value",
  "ip_address",
  "network_endpoint",
  "domain_name",
  "url",
  "mac_address",
  "network_interface",
  "email_address",
  "browser_profile",
  "usb_device",
  "certificate",
  "credential",
  "hash",
  "software",
  "package",
  "container",
  "virtual_machine",
  "database",
  "database_account",
  "cloud_account",
  "cloud_resource",
  "mobile_device",
  "application",
  "malware",
  "tool",
  "other",
];

const h = columnHelper<EntityRow>();
const columns = [
  h.accessor("kind", { header: "Type", size: 140, cell: (c) => <span className="badge">{label(c.getValue())}</span> }),
  h.accessor("display_name", { header: "Name", size: 220 }),
  h.accessor("ereignisse", { header: "Events", size: 90 }),
  h.accessor("beziehungen", { header: "Relations", size: 100 }),
  h.accessor("first_seen", { header: "First seen", size: 180, cell: (c) => <Timestamp value={c.getValue()} /> }),
  h.accessor("last_seen", { header: "Last seen", size: 180, cell: (c) => <Timestamp value={c.getValue()} /> }),
];

export function EntitiesPage({ number }: { number: string }) {
  const [params, setParams] = useSearchParams();
  const kind = params.get("art") ?? "";
  const search = params.get("q") ?? "";
  const [text, setText] = useState(search);
  const list = useEntities(number, kind, search);
  const { detail, open } = useDetail();
  const rows = useMemo(() => list.data?.pages.flatMap((p) => p.eintraege) ?? [], [list.data]);
  const loadMore = useCallback(() => {
    if (list.hasNextPage && !list.isFetchingNextPage) {
      void list.fetchNextPage();
    }
  }, [list]);
  const set = (k: string, v: string) =>
    setParams((p) => {
      const n = new URLSearchParams(p);
      if (v) n.set(k, v);
      else n.delete(k);
      return n;
    });

  return (
    <div className="timeline">
      <div className="filter-bar">
        <Select value={kind} onChange={(e) => set("art", e.target.value)} aria-label="Type" className="filter-select">
          <option value="">All types</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {label(k)}
            </option>
          ))}
        </Select>
        <form
          className="filter-search"
          onSubmit={(e) => {
            e.preventDefault();
            set("q", text.trim());
          }}
        >
          <Input placeholder="Name or key (Enter)" value={text} onChange={(e) => setText(e.target.value)} />
        </form>
      </div>
      <div className="timeline-body">
        {list.isPending && <Skeleton lines={10} />}
        {list.error && <ErrorState title="Entities could not be loaded." reason={list.error.message} />}
        {list.data && rows.length === 0 && (
          <EmptyState title="No entities found." text={kind || search ? "Change the type or search." : "Run an analysis to fill the case model."} />
        )}
        {rows.length > 0 && (
          <DataTable
            label="Entities"
            data={rows}
            columns={columns}
            rowId={(e) => e.id}
            grow={["display_name"]}
            numeric={["ereignisse", "beziehungen"]}
            selected={detail?.kind === "entity" ? detail.id : null}
            onSelect={(e) => open("entity", e.id)}
            onEndReached={loadMore}
            footer={`${count(rows.length)} entities loaded${list.hasNextPage ? ", scroll for more" : ""}`}
          />
        )}
      </div>
    </div>
  );
}
