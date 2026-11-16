// Runs the same API as a real HTTP server, so you can attack it with curl,
// Burp Suite or Postman. Binds to localhost only: never expose it.
import { createServer } from "node:http";
import { createRange } from "./core/api.ts";

const port = Number(process.env.PORT ?? 8787);
const range = createRange();

createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", async () => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k] = v;
    const out = await range.handle({
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers,
      body: chunks.length ? Buffer.concat(chunks).toString("utf8") : undefined,
    });
    res.writeHead(out.status, { ...out.headers, "x-served-by": "node" });
    res.end(out.status === 204 ? undefined : out.body);
  });
}).listen(port, "127.0.0.1", () => {
  console.log(`API attack range listening on http://127.0.0.1:${port}`);
  console.log(`Switch flaws on per request with the header  x-range-vulns: bola,jwt-none,...`);
});
