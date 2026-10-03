// Datentabelle: TanStack Table (Modell, Sortierung, Spaltenbreiten) und
// TanStack Virtual (nur sichtbare Zeilen im DOM). Tastatur: J/K bzw.
// Pfeiltasten wählen, Enter öffnet. Ausgewählte Zeile wird hervorgehoben,
// das Öffnen zeigt sie im Context Drawer.

import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  columnSizingFeature,
  createColumnHelper,
  createSortedRowModel,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type ColumnDef,
  type RowData,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp } from "lucide-react";

export const dataTableFeatures = tableFeatures({
  rowSortingFeature,
  columnSizingFeature,
  sortedRowModel: createSortedRowModel(),
});

export type DataColumn<T extends RowData> = ColumnDef<typeof dataTableFeatures, T, any>;

export function columnHelper<T extends RowData>() {
  return createColumnHelper<typeof dataTableFeatures, T>();
}

const ROW = 36;

export function DataTable<T extends RowData>({
  data,
  columns,
  rowId,
  selected,
  onSelect,
  onOpen,
  onContextMenu,
  grow = [],
  numeric = [],
  height,
  footer,
  label,
}: {
  data: T[];
  columns: DataColumn<T>[];
  rowId: (row: T) => string;
  selected?: string | null;
  onSelect?: (row: T) => void;
  onOpen?: (row: T) => void;
  onContextMenu?: (e: React.MouseEvent, row: T) => void;
  /** Spalten, die den Rest der Breite teilen. */
  grow?: string[];
  /** Rechtsbündige Zahlenspalten. */
  numeric?: string[];
  height?: number | string;
  footer?: ReactNode;
  label: string;
}) {
  const table = useTable({
    features: dataTableFeatures,
    columns,
    data,
    getRowId: (row: T) => rowId(row),
  });
  const rows = table.getRowModel().rows;
  const scroll = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scroll.current,
    estimateSize: () => ROW,
    getItemKey: (i) => rows[i]?.id ?? i,
    overscan: 12,
  });
  const [cursor, setCursor] = useState<number>(-1);

  // Auswahl von außen (etwa aus dem Drawer per Deep Link) übernehmen.
  useEffect(() => {
    if (selected) {
      const i = rows.findIndex((r) => r.id === selected);
      if (i >= 0) {
        setCursor(i);
      }
    }
  }, [selected, rows]);

  const headers = table.getHeaderGroups()[0]?.headers ?? [];
  const template = headers
    .map((h) => (grow.includes(h.column.id) ? `minmax(${h.getSize()}px, 1fr)` : `${h.getSize()}px`))
    .join(" ");

  const move = (to: number) => {
    const i = Math.max(0, Math.min(rows.length - 1, to));
    const row = rows[i];
    if (row) {
      setCursor(i);
      virtualizer.scrollToIndex(i, { align: "auto" });
      onSelect?.(row.original);
    }
  };

  return (
    <div className="dt" style={height ? { height } : undefined}>
      <div
        className="dt-scroll"
        ref={scroll}
        tabIndex={0}
        role="grid"
        aria-label={label}
        aria-rowcount={rows.length}
        onKeyDown={(e) => {
          if (e.key === "j" || e.key === "ArrowDown") {
            e.preventDefault();
            move(cursor + 1);
          } else if (e.key === "k" || e.key === "ArrowUp") {
            e.preventDefault();
            move(cursor - 1);
          } else if (e.key === "Enter" && cursor >= 0) {
            const row = rows[cursor];
            if (row) {
              (onOpen ?? onSelect)?.(row.original);
            }
          }
        }}
      >
        <div className="dt-head" role="row" style={{ gridTemplateColumns: template }}>
          {headers.map((h) => {
            const sorted = h.column.getIsSorted();
            return (
              <div
                key={h.id}
                role="columnheader"
                aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                className={numeric.includes(h.column.id) ? "dt-cell num dt-sort" : "dt-cell dt-sort"}
                onClick={h.column.getCanSort() ? h.column.getToggleSortingHandler() : undefined}
              >
                {h.isPlaceholder ? null : <table.FlexRender header={h} />}
                {sorted === "asc" && <ArrowUp size={12} aria-hidden />}
                {sorted === "desc" && <ArrowDown size={12} aria-hidden />}
              </div>
            );
          })}
        </div>
        <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
          {virtualizer.getVirtualItems().map((item) => {
            const row = rows[item.index];
            if (!row) {
              return null;
            }
            const isSelected = selected === row.id;
            return (
              <div
                key={row.id}
                role="row"
                aria-selected={isSelected}
                className={[
                  "dt-row",
                  isSelected && "selected",
                  cursor === item.index && "cursor",
                ]
                  .filter(Boolean)
                  .join(" ")}
                style={{
                  gridTemplateColumns: template,
                  position: "absolute",
                  top: 0,
                  left: 0,
                  right: 0,
                  transform: `translateY(${item.start}px)`,
                }}
                onClick={() => {
                  setCursor(item.index);
                  onSelect?.(row.original);
                }}
                onDoubleClick={() => onOpen?.(row.original)}
                onContextMenu={onContextMenu ? (e) => onContextMenu(e, row.original) : undefined}
              >
                {row.getAllCells().map((cell) => (
                  <div
                    key={cell.id}
                    role="gridcell"
                    className={numeric.includes(cell.column.id) ? "dt-cell num" : "dt-cell"}
                  >
                    <table.FlexRender cell={cell} />
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
      {footer !== undefined && <div className="dt-foot">{footer}</div>}
    </div>
  );
}
