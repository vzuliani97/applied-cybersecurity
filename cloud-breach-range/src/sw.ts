// The service worker plays all of "AWS" for the public demo: the shop's
// preview endpoint, the metadata service behind it and S3. It answers inside
// the visitor's own browser, so nothing misconfigured runs on the internet.
import { createCloud } from "./core/cloud.ts";

interface FetchEventLike {
  request: Request;
  clientId: string;
  respondWith(r: Promise<Response>): void;
}
interface ExtendableEventLike {
  waitUntil(p: Promise<unknown>): void;
}
const sw = self as unknown as {
  location: Location;
  registration: { scope: string };
  skipWaiting(): Promise<void>;
  clients: { claim(): Promise<void>; get(id: string): Promise<{ postMessage(m: unknown): void } | undefined> };
  addEventListener(type: "install" | "activate", fn: (e: ExtendableEventLike) => void): void;
  addEventListener(type: "fetch", fn: (e: FetchEventLike) => void): void;
};

const cloud = createCloud();

sw.addEventListener("install", (e) => e.waitUntil(sw.skipWaiting()));
sw.addEventListener("activate", (e) => e.waitUntil(sw.clients.claim()));

sw.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  const scope = new URL(sw.registration.scope).pathname;
  const rel = url.pathname.slice(scope.length - 1);
  if (url.origin !== sw.location.origin || !/^\/(shop\/api\/|aws\/s3|_reset)/.test(rel)) return;

  e.respondWith(
    (async () => {
      const headers: Record<string, string> = {};
      e.request.headers.forEach((v, k) => (headers[k] = v));
      const client = e.clientId ? await sw.clients.get(e.clientId) : undefined;
      const out = await cloud.handle({ method: e.request.method, path: rel + url.search, headers }, (ev) => client?.postMessage({ type: "cloud-event", ev }));
      return new Response(out.status === 204 ? null : out.body, { status: out.status, headers: { ...out.headers, "x-served-by": "service-worker" } });
    })(),
  );
});
