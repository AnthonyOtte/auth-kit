import { defineConfig } from "tsup";

  export default defineConfig({
    entry: {
      index: "src/index.ts",
      "server/index": "src/server/index.ts",
      "shared/index": "src/shared/index.ts",
      "client/index": "src/client/index.ts",
    },
    format: ["esm"],
    dts: true,
    sourcemap: false,
    clean: true,
    splitting: false,
    target: "node20",
    shims: false,
    treeshake: true,
  });
  