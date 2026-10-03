// /dev/design-system: alle Bausteine an einer Stelle, mit festen
// Beispielwerten. Diese Werte sind keine Falldaten.

import { useState } from "react";
import { Copy, FileText, Folder, HardDrive, Play, Plus, Search, Trash2 } from "lucide-react";
import { DataTable, columnHelper } from "../components/data-table/DataTable";
import { Badge, StatusBadge } from "../components/ui/Badge";
import { Button, IconButton } from "../components/ui/Button";
import { CodeBlock, EmptyState, ErrorState, HashValue, PropertyList, Skeleton, Tabs, Timestamp } from "../components/ui/Display";
import { Checkbox, Field, Input, SearchInput, Select } from "../components/ui/Input";
import { Kbd, MOD } from "../components/ui/Kbd";
import { DrawerFrame, DrawerSection, Panel, SplitPane, Tree, type TreeNode } from "../components/ui/Layout";
import { Menu, Popover, useContextMenu } from "../components/ui/Overlay";
import { Tooltip } from "../components/ui/Tooltip";
import { DERIVATION_KINDS, DerivationBadge, JobStatusBadge } from "../components/forensic/Badges";
import { JobProgress } from "../components/forensic/JobProgress";
import { useWorkspace } from "../app/store";

interface SampleRow {
  id: string;
  name: string;
  size: number;
  modified: string;
  mft: number;
}

const rows: SampleRow[] = Array.from({ length: 5000 }, (_, i) => ({
  id: String(i),
  name: `sample-${String(i).padStart(4, "0")}.bin`,
  size: (i * 7919) % 1_000_000,
  modified: new Date(Date.UTC(2026, 0, 1, 0, 0, i)).toISOString(),
  mft: 1000 + i,
}));

const h = columnHelper<SampleRow>();
const columns = [
  h.accessor("name", { header: "Name", size: 240, cell: (c) => <span className="mono">{c.getValue()}</span> }),
  h.accessor("size", { header: "Size", size: 110 }),
  h.accessor("modified", { header: "Modified (UTC)", size: 220, cell: (c) => <Timestamp value={c.getValue()} /> }),
  h.accessor("mft", { header: "MFT #", size: 100 }),
];

const tree: TreeNode[] = [
  {
    id: "c",
    label: "C:",
    icon: <HardDrive />,
    children: [
      { id: "w", label: "Windows", icon: <Folder />, children: [{ id: "s", label: "System32", icon: <Folder /> }] },
      { id: "u", label: "Users", icon: <Folder />, children: [{ id: "f", label: "notes.txt", icon: <FileText /> }] },
    ],
  },
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="ds-section">
      <h2>{title}</h2>
      <div className="ds-body">{children}</div>
    </section>
  );
}

export function DesignSystemPage() {
  const [tab, setTab] = useState("overview");
  const [selected, setSelected] = useState<string | null>(null);
  const [treeSel, setTreeSel] = useState<string>();
  const menu = useContextMenu();
  const setPalette = useWorkspace((s) => s.setPalette);

  return (
    <div className="page ds">
      <div className="page-head">
        <div>
          <h1>Design System</h1>
          <span className="muted">Building blocks of the workspace. Sample values only, not case data.</span>
        </div>
      </div>

      <Section title="Typography and colour">
        <div className="ds-swatches">
          {["bg-root", "bg-sidebar", "bg-surface", "bg-elevated", "bg-hover", "border", "text-primary", "text-secondary", "text-muted", "accent", "info", "success", "warning", "danger"].map(
            (t) => (
              <div key={t} className="ds-swatch">
                <span className={`ds-chip ds-${t}`} />
                <span className="mono">--{t}</span>
              </div>
            ),
          )}
        </div>
        <div className="stack">
          <h1>Heading 18 / 600</h1>
          <h2>Heading 15 / 600</h2>
          <span>Body 13 Inter. The analyst should never lose the investigation context.</span>
          <span className="mono">JetBrains Mono · 0x91822A3F · MFT #81923 · HKLM\SYSTEM\Select</span>
          <span className="section-label">Section label</span>
        </div>
      </Section>

      <Section title="Buttons">
        <div className="row wrap">
          <Button variant="primary" icon={<Play />}>
            Primary
          </Button>
          <Button icon={<Plus />}>Secondary</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="danger" icon={<Trash2 />}>
            Danger
          </Button>
          <Button size="sm">Small</Button>
          <Button disabled>Disabled</Button>
          <IconButton label="Search" icon={<Search />} />
          <IconButton label="Copy" icon={<Copy />} size="sm" />
        </div>
      </Section>

      <Section title="Inputs">
        <div className="form-grid">
          <Field label="Input" hint="Hint text">
            <Input placeholder="Placeholder" />
          </Field>
          <Field label="Monospace input">
            <Input mono defaultValue="C:\Users\alice\Downloads" />
          </Field>
          <Field label="Select">
            <Select defaultValue="b">
              <option value="a">Option A</option>
              <option value="b">Option B</option>
            </Select>
          </Field>
          <Field label="Search input">
            <SearchInput placeholder="Search evidence, entities, events…" shortcut="/" />
          </Field>
          <Checkbox label="Checkbox" hint="With a short explanation" defaultChecked />
        </div>
      </Section>

      <Section title="Badges">
        <div className="row wrap">
          <Badge>Neutral</Badge>
          <Badge tone="info">Info</Badge>
          <Badge tone="success">Success</Badge>
          <Badge tone="warning">Warning</Badge>
          <Badge tone="danger">Danger</Badge>
          <StatusBadge tone="success" label="Active" />
          <JobStatusBadge status="running" />
          <JobStatusBadge status="failed" />
        </div>
        <div className="row wrap">
          {DERIVATION_KINDS.map((k) => (
            <DerivationBadge key={k} kind={k} />
          ))}
        </div>
      </Section>

      <Section title="Tabs, tooltip, keys">
        <Tabs
          active={tab}
          onSelect={setTab}
          items={[
            { id: "overview", label: "Overview" },
            { id: "timeline", label: "Timeline", count: 2509 },
            { id: "graph", label: "Graph" },
          ]}
        />
        <div className="row">
          <Tooltip text="Tooltips explain without hiding information.">
            <Button size="sm">Hover me</Button>
          </Tooltip>
          <span>
            <Kbd>{MOD}K</Kbd> command palette · <Kbd>G</Kbd> <Kbd>E</Kbd> evidence · <Kbd>Esc</Kbd> close drawer
          </span>
          <Button size="sm" onClick={() => setPalette(true)}>
            Open command palette
          </Button>
        </div>
      </Section>

      <Section title="Popover and context menu">
        <div className="row">
          <Popover trigger={({ toggle }) => <Button onClick={toggle}>Actions ⋯</Button>}>
            {(close) => (
              <Menu
                close={close}
                entries={[
                  { section: "Investigate" },
                  { label: "Show Timeline", shortcut: "G T" },
                  { label: "Show Graph", disabled: true, reason: "Planned" },
                  "separator",
                  { label: "Copy Reference", icon: <Copy /> },
                ]}
              />
            )}
          </Popover>
          <div
            className="ds-context"
            onContextMenu={(e) =>
              menu.open(e, [
                { label: "Open Details" },
                { label: "View Hex", disabled: true, reason: "Planned" },
                { label: "Search Related" },
                "separator",
                { label: "Create Finding", disabled: true, reason: "Planned" },
              ])
            }
          >
            Right-click here
          </div>
          {menu.menu}
        </div>
      </Section>

      <Section title="Property list, hash, timestamp, code">
        <div className="ds-two">
          <PropertyList
            items={[
              ["Path", <span className="mono">C:\Users\alice\AppData\Local\Temp</span>],
              ["SHA256", <HashValue value="82ac39f1d0e7c5a1b2f4e6d8c0a1b3c5d7e9f1a3b5c7d9e1f3a5b7c9d1e3ff00" />],
              ["Size", "291 KiB"],
              ["Modified", <Timestamp value="2026-04-01T07:22:16.3722754Z" precise />],
              ["Empty", null],
            ]}
          />
          <CodeBlock>{`stratum evidence hinzu DFIR-2026-0001 /mnt/evidence/disk01.dd\nSHA-256 8a11329d…11fa`}</CodeBlock>
        </div>
      </Section>

      <Section title="Progress, empty, error, skeleton">
        <div className="ds-two">
          <div className="stack">
            <JobProgress
              update={{
                status: "running",
                progress: { phase: "analyzer", phasen: { analyzer: { erledigt: 8291, gesamt: 10184 } }, meldung: "Browser" },
                error: null,
                result: null,
                analysis_run_id: null,
              }}
            />
            <JobProgress
              update={{ status: "running", progress: { phase: "hashing" }, error: null, result: null, analysis_run_id: null }}
            />
            <Skeleton lines={3} />
          </div>
          <div className="stack">
            <EmptyState
              title="No findings yet."
              text="Run an analysis or create a finding manually."
              action={<Button size="sm">Run Analysis</Button>}
            />
            <ErrorState
              title="NTFS catalog could not be completed."
              reason="Invalid attribute at MFT #91821"
              hint="Analysis continues with remaining records."
            />
          </div>
        </div>
      </Section>

      <Section title="Split pane and tree">
        <div className="ds-split">
          <SplitPane
            id="ds-split"
            initial={30}
            left={
              <div className="ds-pad">
                <Tree nodes={tree} selected={treeSel} onSelect={(n) => setTreeSel(n.id)} />
              </div>
            }
            right={<div className="ds-pad muted">Drag the handle or focus it and use the arrow keys.</div>}
          />
        </div>
      </Section>

      <Section title="Data table (5,000 rows, virtualized)">
        <DataTable
          label="Sample rows"
          data={rows}
          columns={columns}
          rowId={(r) => r.id}
          grow={["name"]}
          numeric={["size", "mft"]}
          height={320}
          selected={selected}
          onSelect={(r) => setSelected(r.id)}
          footer={`${rows.length.toLocaleString("en-US")} rows · J/K to move · Enter to open`}
        />
      </Section>

      <Section title="Drawer">
        <div className="ds-drawer">
          <DrawerFrame kind="File" title="payload.exe" badges={<DerivationBadge kind="parsed" />} onClose={() => undefined}>
            <DrawerSection title="Overview">
              <PropertyList items={[["Size", "291 KiB"], ["First seen", <Timestamp value="2026-04-01T14:03:17Z" />]]} />
            </DrawerSection>
            <DrawerSection title="Evidence">
              <PropertyList items={[["Source", "disk01.dd"], ["MFT #", <span className="mono">81923</span>]]} />
            </DrawerSection>
          </DrawerFrame>
        </div>
      </Section>

      <Panel title="Panel">
        <span className="muted">Compact surface for grouped content. No oversized cards.</span>
      </Panel>
    </div>
  );
}
