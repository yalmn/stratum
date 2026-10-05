import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import assert from "node:assert/strict";
const project = fileURLToPath(new URL("..", import.meta.url));
const output = mkdtempSync(join(tmpdir(), "stratum-catalog-test-"));
let compiled;
try {
  execFileSync(join(project, "node_modules/.bin/tsc"), ["--ignoreConfig", "--outDir", output, "--module", "ESNext", "--target", "ES2022", "--moduleResolution", "bundler", "--skipLibCheck", "src/features/explorer/catalogRows.ts"], { cwd: project, stdio: "pipe" });
  compiled = readFileSync(join(output, "features/explorer/catalogRows.js"), "utf8");
} finally {
  rmSync(output, { recursive: true, force: true });
}
const { catalogRows, catalogEntry } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);

test("überlappende Seiten zeigen jeden Katalogeintrag einmal", () => {
  const image = { mft_record: 101, parent_record: 5, name: "bild.jpg", path: "bild.jpg", size: 10 };
  const other = { ...image, mft_record: 102 };
  const rows = catalogRows([{ eintraege: [image, other] }, { eintraege: [{ ...image, size: 11 }] }]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].size, 11);
  assert.equal(rows[1].mft_record, 102);
});

test("Hardlinks mit anderem Namen oder Elternverzeichnis bleiben sichtbar", () => {
  const image = { mft_record: 101, parent_record: 5, name: "bild.jpg" };
  const rows = catalogRows([{ eintraege: [image, { ...image, name: "kopie.jpg" }, { ...image, parent_record: 100 }] }]);
  assert.equal(rows.length, 3);
  assert.deepEqual(catalogRows([]), []);
});

test("zwei Dateien mit je zwei Hardlink-Pfaden ergeben vier Quellen", () => {
  const entries = [
    { mft_record: 27596, parent_record: 3333, name: "DMR_120.jpg", path: "Program Files (x86)\\Media\\DMR_120.jpg" },
    { mft_record: 27596, parent_record: 24532, name: "DMR_120.jpg", path: "Windows\\WinSxS\\wow64\\DMR_120.jpg" },
    { mft_record: 27597, parent_record: 1327, name: "DMR_120.jpg", path: "Program Files\\Media\\DMR_120.jpg" },
    { mft_record: 27597, parent_record: 15139, name: "DMR_120.jpg", path: "Windows\\WinSxS\\amd64\\DMR_120.jpg" },
  ];
  const rows = catalogRows([{ eintraege: entries }]);
  assert.equal(rows.length, 4);
  assert.equal(new Set(rows.map(r => r.mft_record)).size, 2);
  assert.deepEqual(rows.map(r => r.path), entries.map(r => r.path));
});

test("Detailansicht verwendet den gewählten Hardlink statt immer des ersten Pfads", () => {
  const first = { mft_record: 27596, parent_record: 3333, name: "DMR_120.jpg", path: "Program Files (x86)\\Media\\DMR_120.jpg" };
  const second = { ...first, parent_record: 24532, path: "Windows\\WinSxS\\wow64\\DMR_120.jpg" };
  assert.equal(catalogEntry([first, second], second.path), second);
  assert.equal(catalogEntry([first, second], null), first);
  assert.equal(catalogEntry([first, second], "unknown.jpg"), undefined);
});
