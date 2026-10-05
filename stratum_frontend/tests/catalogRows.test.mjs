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
const { catalogRows } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`);

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
