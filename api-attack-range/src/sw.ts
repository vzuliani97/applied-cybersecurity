// The service worker is the "server" of the public demo: it answers every
// request to ./api/* inside the visitor's own browser. Nothing vulnerable
// runs on the internet, and each visitor gets their own fresh data.
import { createRange } from "./core/api.ts";

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

const range = createRange();

sw.addEventListener("install", (e) => e.waitUntil(sw.skipWaiting()));
sw.addEventListener("activate", (e) => e.waitUntil(sw.clients.claim()));

sw.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  const scope = new URL(sw.registration.scope).pathname;
  if (url.origin !== sw.location.origin || !url.pathname.startsWith(scope + "api/")) return;

  e.respondWith(
    (async () => {
      const headers: Record<string, string> = {};
      e.request.headers.forEach((v, k) => (headers[k] = v));
      const body = e.request.method === "GET" || e.request.method === "HEAD" ? undefined : await e.request.text();
      // Every decision the server makes is streamed to the page that sent the request.
      const client = e.clientId ? await sw.clients.get(e.clientId) : undefined;
      const out = await range.handle(
        { method: e.request.method, path: url.pathname.slice(scope.length - 1) + url.search, headers, body },
        (ev) => client?.postMessage({ type: "range-event", ev }),
      );
      return new Response(out.status === 204 ? null : out.body, {
        status: out.status,
        headers: { ...out.headers, "x-served-by": "service-worker" },
      });
    })(),
  );
});
