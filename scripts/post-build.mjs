// Post-build: rename dist/cjs/**/*.js -> *.cjs and rewrite require() paths.
import { readdir, rename, readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";

async function* walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(p);
    else yield p;
  }
}

const cjsDir = path.resolve("dist/cjs");
const renames = [];
for await (const f of walk(cjsDir)) {
  if (f.endsWith(".js")) renames.push(f);
}

// Rewrite relative require() calls before renaming to keep links consistent.
for (const f of renames) {
  let src = await readFile(f, "utf8");
  // require("./foo") and require("../foo") -> add .cjs extension if missing
  src = src.replace(/require\(("|')(\.{1,2}\/[^"']+?)\1\)/g, (m, q, p) => {
    if (/\.[a-zA-Z0-9]+$/.test(p)) return m;
    return `require(${q}${p}.cjs${q})`;
  });
  await writeFile(f, src);
}
for (const f of renames) {
  await rename(f, f.replace(/\.js$/, ".cjs"));
}
console.log(`[post-build] renamed ${renames.length} files to .cjs`);
