import { build } from "esbuild";
import { copyFile, mkdir, rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });
await mkdir("dist", { recursive: true });

const common = { bundle: true, minify: true, target: "es2020", format: "iife", legalComments: "none", logLevel: "info" };
await build({ ...common, entryPoints: ["src/web/app.ts"], outfile: "dist/app.js" });
await build({ ...common, entryPoints: ["src/sw.ts"], outfile: "dist/sw.js" });

for (const f of ["index.html", "style.css", "favicon.svg"]) await copyFile(`src/web/${f}`, `dist/${f}`);
