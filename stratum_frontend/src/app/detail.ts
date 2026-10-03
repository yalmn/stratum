// Context Drawer über die URL (`?detail=art:id`): teilbar, Zurück-Taste
// schließt ihn, der Workspace bleibt dabei stehen.

import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

export type DetailKind = "evidence" | "job" | "case";

export interface Detail {
  kind: DetailKind;
  id: string;
}

export function parseDetail(v: string | null): Detail | null {
  if (!v) {
    return null;
  }
  const i = v.indexOf(":");
  if (i <= 0) {
    return null;
  }
  const kind = v.slice(0, i) as DetailKind;
  return ["evidence", "job", "case"].includes(kind) ? { kind, id: v.slice(i + 1) } : null;
}

export function useDetail() {
  const [params, setParams] = useSearchParams();
  const detail = parseDetail(params.get("detail"));
  const open = useCallback(
    (kind: DetailKind, id: string) =>
      setParams(
        (p) => {
          const n = new URLSearchParams(p);
          n.set("detail", `${kind}:${id}`);
          return n;
        },
        { replace: false },
      ),
    [setParams],
  );
  const close = useCallback(
    () =>
      setParams((p) => {
        const n = new URLSearchParams(p);
        n.delete("detail");
        return n;
      }),
    [setParams],
  );
  return { detail, open, close };
}
