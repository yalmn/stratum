// Darstellung von Größen, Zeiten und Codes. Zeiten immer in UTC und so
// gekennzeichnet; die Oberfläche nimmt keine Zeitzone des Rechners an.

export function bytes(n: number): string {
  if (n < 1024) {
    return `${n} B`;
  }
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
}

export function count(n: number): string {
  return n.toLocaleString("en-US");
}

/** `2026-10-03 13:08:27 UTC`; Bruchteile nur mit `precise`. */
export function utc(iso: string | null | undefined, precise = false): string {
  if (!iso) {
    return "";
  }
  const m = /^(\d{4,}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/.exec(iso);
  if (m && (m[4] === "Z" || m[4] === "+00:00" || m[4] === undefined)) {
    return `${m[1]} ${m[2]}${precise && m[3] ? m[3] : ""} UTC`;
  }
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/** Abstand zu jetzt, grob: `2m ago`, `3h ago`. */
export function ago(iso: string | null | undefined): string {
  if (!iso) {
    return "";
  }
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(s)) {
    return "";
  }
  if (s < 60) {
    return "just now";
  }
  if (s < 3600) {
    return `${Math.floor(s / 60)}m ago`;
  }
  if (s < 86400) {
    return `${Math.floor(s / 3600)}h ago`;
  }
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(fromIso: string | null, toIso: string | null): string {
  if (!fromIso) {
    return "";
  }
  const end = toIso ? new Date(toIso).getTime() : Date.now();
  let s = Math.max(0, Math.round((end - new Date(fromIso).getTime()) / 1000));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  const pad = (x: number) => String(x).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/** `snake_case` zu `Snake Case` für Anzeigen technischer Codes. */
export function label(code: string): string {
  return code
    .split("_")
    .map((w) => (w ? w[0]!.toUpperCase() + w.slice(1) : w))
    .join(" ");
}

// NTFS-Dateiattribute, wie der Katalog sie benennt.
const FILE_ATTRIBUTES: Record<string, string> = {
  schreibgeschuetzt: "read-only",
  versteckt: "hidden",
  system: "system",
  archiv: "archive",
  temporaer: "temporary",
  sparse: "sparse",
  reparse_point: "reparse point",
  komprimiert: "compressed",
  offline: "offline",
  nicht_indiziert: "not indexed",
  verschluesselt: "encrypted",
};

export function fileAttributes(a: string[] | null | undefined): string {
  return (a ?? []).map((x) => FILE_ATTRIBUTES[x] ?? x).join(", ");
}

export function shortHash(h: string, head = 8, tail = 4): string {
  return h.length > head + tail + 1 ? `${h.slice(0, head)}…${h.slice(-tail)}` : h;
}
