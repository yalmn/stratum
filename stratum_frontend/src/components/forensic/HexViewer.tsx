// Hex-Ansicht eines Ausschnitts: Offset, 16 Bytes je Zeile, ASCII.

const hex = (n: number, w: number) => n.toString(16).toUpperCase().padStart(w, "0");

export function HexViewer({ bytes, offset }: { bytes: Uint8Array; offset: number }) {
  const lines: string[] = [];
  const width = Math.max(8, hex(offset + bytes.length, 1).length);
  for (let i = 0; i < bytes.length; i += 16) {
    const row = bytes.subarray(i, i + 16);
    let h = "";
    let a = "";
    for (let j = 0; j < 16; j++) {
      const b = row[j];
      h += b === undefined ? "   " : `${hex(b, 2)} `;
      if (j === 7) {
        h += " ";
      }
      a += b === undefined ? "" : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·";
    }
    lines.push(`${hex(offset + i, width)}  ${h} ${a}`);
  }
  return <pre className="hex-view">{lines.join("\n") || "(empty)"}</pre>;
}

/** Druckbare ASCII- und UTF-16LE-Folgen ab `min` Zeichen. */
export function strings(bytes: Uint8Array, min = 4): string[] {
  const out: string[] = [];
  let cur = "";
  for (const b of bytes) {
    if (b >= 0x20 && b < 0x7f) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= min) {
        out.push(cur);
      }
      cur = "";
    }
  }
  if (cur.length >= min) {
    out.push(cur);
  }
  // UTF-16LE: druckbares Zeichen gefolgt von 0x00.
  cur = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const b = bytes[i]!;
    if (bytes[i + 1] === 0 && b >= 0x20 && b < 0x7f) {
      cur += String.fromCharCode(b);
    } else {
      if (cur.length >= min) {
        out.push(`${cur}  [UTF-16LE]`);
      }
      cur = "";
    }
  }
  if (cur.length >= min) {
    out.push(`${cur}  [UTF-16LE]`);
  }
  return out;
}
