import { VULNS, VULN_HEADER, ACCOUNTS, createRange, type RangeEvent, type Req, type Res, type Snapshot, type Vuln } from "../core/api.ts";
import { SCENARIOS, type L, type Scenario } from "../core/scenarios.ts";

type Lang = "es" | "en";
type Mode = "vulnerable" | "fixed";
interface Exchange {
  req: Req;
  res: Res;
  ms: number;
  key: boolean;
}

const UI = {
  back: { es: "← valterzuliani.com", en: "← valterzuliani.com" },
  title: { es: "Campo de tiro de APIs", en: "API attack range" },
  lede: {
    es: "Seis fallas del OWASP API Security Top 10, cada una con un interruptor. Atácala vulnerable, cámbiala a corregida y vuelve a atacar.",
    en: "Six flaws from the OWASP API Security Top 10, each with a switch. Attack it vulnerable, flip it to fixed and attack again.",
  },
  where: {
    es: "Todo corre en tu navegador: un service worker hace de servidor y los datos son ficticios. Nada vulnerable queda expuesto en internet.",
    en: "Everything runs in your browser: a service worker plays the server and the data is fictional. Nothing vulnerable is exposed on the internet.",
  },
  whereFallback: {
    es: "Tu navegador no permite service workers aquí, así que la API corre dentro de la página. Las peticiones no aparecerán en la pestaña Red.",
    en: "Your browser does not allow service workers here, so the API runs inside the page. Requests will not show in the Network tab.",
  },
  devtools: {
    es: "Abre las herramientas de desarrollador, pestaña Red: cada petición es real.",
    en: "Open developer tools, Network tab: every request is real.",
  },
  scenarios: { es: "Ataques", en: "Attacks" },
  console: { es: "Consola libre", en: "Free console" },
  vulnerable: { es: "Vulnerable", en: "Vulnerable" },
  fixed: { es: "Corregido", en: "Fixed" },
  launch: { es: "Lanzar ataque", en: "Launch attack" },
  running: { es: "Atacando…", en: "Attacking…" },
  theFix: { es: "El arreglo", en: "The fix" },
  codeVuln: { es: "Vulnerable", en: "Vulnerable" },
  codeFixed: { es: "Corregido", en: "Fixed" },
  requests: { es: "peticiones", en: "requests" },
  request: { es: "Petición", en: "Request" },
  response: { es: "Respuesta", en: "Response" },
  send: { es: "Enviar", en: "Send" },
  reset: { es: "Reiniciar datos", en: "Reset data" },
  resetDone: { es: "Datos reiniciados.", en: "Data reset." },
  consoleHelp: {
    es: "Escribe una petición HTTP cruda. {{token}} se reemplaza por un token de Lucía recién emitido. Marca qué fallas quieres encendidas.",
    en: "Write a raw HTTP request. {{token}} is replaced with a freshly issued token for Lucía. Tick the flaws you want switched on.",
  },
  flaws: { es: "Fallas encendidas", en: "Flaws switched on" },
  parseError: {
    es: "No pude leer la petición. La primera línea debe ser como: GET /api/orders HTTP/1.1",
    en: "Could not read the request. The first line should look like: GET /api/orders HTTP/1.1",
  },
  pathError: { es: "La ruta debe empezar por /api/", en: "The path must start with /api/" },
  error: { es: "Algo falló al lanzar el ataque:", en: "Something failed while launching the attack:" },
  showMore: { es: "Ver las otras {n} peticiones", en: "Show the other {n} requests" },
  hint: { es: "Prueba primero en Vulnerable y luego en Corregido.", en: "Try Vulnerable first, then Fixed." },
  source: { es: "Código en GitHub", en: "Code on GitHub" },
  attacker: { es: "Atacante", en: "Attacker" },
  server: { es: "Servidor", en: "Server" },
  slow: { es: "Cámara lenta", en: "Slow motion" },
  users: { es: "Usuarios", en: "Users" },
  role: { es: "rol", en: "role" },
  deleted: { es: "eliminado", en: "deleted" },
  balance: { es: "Saldo de Lucía", en: "Lucía's balance" },
  credits: { es: "canjes del cupón", en: "coupon credits" },
  failures: { es: "Fallos de login de Mateo", en: "Mateo's failed logins" },
  locked: { es: "bloqueada {s} s", en: "locked {s} s" },
  waiting: { es: "Esperando la primera petición…", en: "Waiting for the first request…" },
  credit: {
    es: "Inspirado en OWASP crAPI, VAmPI y la PortSwigger Web Security Academy. Código propio.",
    en: "Inspired by OWASP crAPI, VAmPI and the PortSwigger Web Security Academy. Original code.",
  },
} satisfies Record<string, L>;

const REPO = "https://github.com/vzuliani97/applied-cybersecurity/tree/main/api-attack-range";

// ---------- state ----------
let lang: Lang = initialLang();
let current = SCENARIOS[0]!.id as string; // scenario id or "console"
const modes = new Map<string, Mode>(SCENARIOS.map((s) => [s.id, "vulnerable"]));
const results = new Map<string, { outcome: Awaited<ReturnType<Scenario["run"]>> | null; log: Exchange[]; error?: string; mode: Mode }>();
let running = false;
let progress = "";
let consoleText = "GET /api/orders/1003 HTTP/1.1\nAuthorization: Bearer {{token}}\n";
const consoleVulns = new Set<Vuln>(["bola"]);
let consoleResult: { log: Exchange[]; error?: string } | null = null;
let consoleNote = "";

let transportKind: "sw" | "page" | "pending" = "pending";

// ---------- live view ----------
let slow = true;
const SLOW_MS = 260;
let liveOn = false;
let liveStart = 0;
let liveEvents: RangeEvent[] = [];
let liveStream: Exchange[] = [];
let snap: Snapshot | null = null;
let prevSnap: Snapshot | null = null;
let roster: Snapshot["users"] = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function startLive(log: Exchange[]): void {
  liveOn = true;
  liveStart = performance.now();
  liveEvents = [];
  liveStream = log;
  snap = prevSnap = null;
  roster = [];
}

function onEvent(ev: RangeEvent): void {
  if (!liveOn) return;
  // The reset that opens each run sets the roster everything else is compared with.
  if (!roster.length || /reinici/i.test(ev.msg.es)) roster = ev.snapshot.users.map((u) => ({ ...u }));
  if (/reinici/i.test(ev.msg.es)) return;
  liveEvents.push({ ...ev, at: Math.round(performance.now() - liveStart) });
  if (liveEvents.length > 300) liveEvents.shift();
  prevSnap = snap;
  snap = ev.snapshot;
  renderLive();
}
let pageRange: ReturnType<typeof createRange> | null = null;

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem("vz-lang");
    if (saved === "es" || saved === "en") return saved;
  } catch {
    /* storage may be unavailable */
  }
  return (navigator.language || "es").toLowerCase().startsWith("es") ? "es" : "en";
}

const t = (l: L) => l[lang];

// ---------- transport ----------
async function startTransport(): Promise<void> {
  if ("serviceWorker" in navigator && window.isSecureContext) {
    try {
      await navigator.serviceWorker.register("sw.js", { scope: "./" });
      if (!navigator.serviceWorker.controller) {
        await new Promise<void>((resolve) => {
          const done = () => resolve();
          navigator.serviceWorker.addEventListener("controllerchange", done, { once: true });
          setTimeout(done, 4000);
        });
      }
      if (navigator.serviceWorker.controller) {
        transportKind = "sw";
        return;
      }
    } catch {
      /* fall through to the in-page API */
    }
  }
  pageRange = createRange();
  transportKind = "page";
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.addEventListener("message", (e: MessageEvent) => {
    const d = e.data as { type?: string; ev?: RangeEvent };
    if (d?.type === "range-event" && d.ev) onEvent(d.ev);
  });
  navigator.serviceWorker.startMessages();
}

async function transport(req: Req): Promise<Res> {
  await transportReady;
  if (transportKind === "page" && pageRange) return pageRange.handle(req, onEvent);
  const r = await fetch(req.path.replace(/^\//, ""), { method: req.method, headers: req.headers, body: req.body, cache: "no-store" });
  const headers: Record<string, string> = {};
  r.headers.forEach((v, k) => (headers[k] = v));
  return { status: r.status, headers, body: await r.text() };
}

function sender(vulns: Vuln[], log: Exchange[]) {
  return async (req: Req, opts?: { key?: boolean }): Promise<Res> => {
    const full: Req = { ...req, headers: { ...req.headers, [VULN_HEADER]: vulns.join(",") } };
    if (slow) await sleep(SLOW_MS);
    const t0 = performance.now();
    const res = await transport(full);
    log.push({ req: full, res, ms: Math.round(performance.now() - t0), key: !!opts?.key });
    renderLive();
    return res;
  };
}

// ---------- actions ----------
async function launch(s: Scenario): Promise<void> {
  if (running) return;
  running = true;
  progress = "";
  const mode = modes.get(s.id)!;
  const log: Exchange[] = [];
  results.set(s.id, { outcome: null, log, mode });
  startLive(log);
  render();
  try {
    await transport({ method: "POST", path: "/api/_reset", headers: {} });
    const outcome = await s.run({
      send: sender(mode === "vulnerable" ? [s.vuln] : [], log),
      progress: (d, n) => {
        progress = `${d}/${n}`;
        const btn = document.querySelector<HTMLButtonElement>("#launch");
        if (btn) btn.textContent = `${t(UI.running)} ${progress}`;
      },
    });
    await sleep(200); // let the last server events arrive
    results.set(s.id, { outcome, log, mode });
  } catch (e) {
    results.set(s.id, { outcome: null, log, mode, error: e instanceof Error ? e.message : String(e) });
  } finally {
    running = false;
    render();
    document.querySelector("#verdict")?.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
  }
}

function parseRaw(text: string): Req | null {
  const norm = text.replace(/\r\n/g, "\n").replace(/^\s+/, "");
  const sep = norm.indexOf("\n\n");
  const head = sep >= 0 ? norm.slice(0, sep) : norm;
  const body = sep >= 0 ? norm.slice(sep + 2).trim() : "";
  const lines = head.split("\n").filter((l) => l.trim());
  const m = /^([A-Za-z]+)\s+(\S+)(?:\s+HTTP\/[\d.]+)?\s*$/.exec(lines.shift() ?? "");
  if (!m) return null;
  const headers: Record<string, string> = {};
  for (const line of lines) {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  if (body && !Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) headers["Content-Type"] = "application/json";
  return { method: m[1]!.toUpperCase(), path: m[2]!, headers, body: body || undefined };
}

async function sendConsole(): Promise<void> {
  if (running) return;
  consoleNote = "";
  let text = consoleText;
  const log: Exchange[] = [];
  running = true;
  startLive(log);
  render();
  try {
    if (text.includes("{{token}}")) {
      const r = await transport({
        method: "POST",
        path: "/api/login",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: "lucia", password: ACCOUNTS.lucia.password }),
      });
      const token = r.status === 200 ? (JSON.parse(r.body) as { token: string }).token : "";
      text = text.split("{{token}}").join(token);
    }
    const req = parseRaw(text);
    if (!req) consoleResult = { log, error: t(UI.parseError) };
    else if (!req.path.startsWith("/api/")) consoleResult = { log, error: t(UI.pathError) };
    else {
      await sender([...consoleVulns], log)(req, { key: true });
      await sleep(150);
      consoleResult = { log };
    }
  } catch (e) {
    consoleResult = { log, error: e instanceof Error ? e.message : String(e) };
  } finally {
    running = false;
    render();
  }
}

async function resetData(): Promise<void> {
  await transport({ method: "POST", path: "/api/_reset", headers: {} });
  consoleNote = t(UI.resetDone);
  render();
}

// ---------- rendering ----------
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const STATUS_TEXT: Record<number, string> = { 200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 409: "Conflict", 429: "Too Many Requests", 500: "Internal Server Error" };

function rawRequest(r: Req): string {
  const lines = [`${r.method} ${r.path} HTTP/1.1`];
  for (const [k, v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  let out = esc(lines.join("\n")).replace(new RegExp(`^(${VULN_HEADER}: .*)$`, "mi"), '<span class="lab">$1</span>');
  if (r.body) out += "\n\n" + esc(pretty(r.body));
  return out;
}

function rawResponse(r: Res): string {
  const lines = [`HTTP/1.1 ${r.status} ${STATUS_TEXT[r.status] ?? ""}`];
  for (const k of ["content-type", "retry-after", "x-served-by"]) if (r.headers[k]) lines.push(`${k}: ${r.headers[k]}`);
  let out = lines.join("\n");
  if (r.body) out += "\n\n" + pretty(r.body);
  return esc(out);
}

function pretty(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

function statusClass(s: number): string {
  return s < 300 ? "s2" : s < 500 ? "s4" : "s5";
}

function exchangeHtml(x: Exchange, i: number, total: number): string {
  const open = x.key || total <= 3;
  return `<details class="ex${x.key ? " key" : ""}"${open ? " open" : ""}>
    <summary><span class="num">${i + 1}</span><span class="m">${esc(x.req.method)}</span><span class="p">${esc(x.req.path)}</span><span class="st ${statusClass(x.res.status)}">${x.res.status}</span><span class="ms">${x.ms} ms</span></summary>
    <div class="pair"><div><h4>${t(UI.request)}</h4><pre>${rawRequest(x.req)}</pre></div><div><h4>${t(UI.response)}</h4><pre>${rawResponse(x.res)}</pre></div></div>
  </details>`;
}

function logHtml(log: Exchange[]): string {
  if (!log.length) return "";
  const rows = log.map((x, i) => ({ x, i }));
  // Long attacks (brute force, race) keep the first rows and the decisive one in view.
  const shown = log.length > 8 ? rows.filter(({ x, i }) => i < 3 || x.key || i === log.length - 1) : rows;
  const hidden = rows.filter((r) => !shown.includes(r));
  const more = hidden.length
    ? `<details class="more"><summary>${t(UI.showMore).replace("{n}", String(hidden.length))}</summary>${hidden.map(({ x, i }) => exchangeHtml(x, i, log.length)).join("")}</details>`
    : "";
  const head = shown.filter(({ i }) => i < 3);
  const tail = shown.filter(({ i }) => i >= 3);
  return `<div class="log"><p class="count">${log.length} ${t(UI.requests)}</p>${head.map(({ x, i }) => exchangeHtml(x, i, log.length)).join("")}${more}${tail.map(({ x, i }) => exchangeHtml(x, i, log.length)).join("")}</div>`;
}

function liveHtml(): string {
  if (!liveOn) return "";
  return `<section class="live" id="live">${liveInner()}</section>`;
}

const money = (n: number) => "$" + n.toLocaleString("es-CO");

function liveInner(): string {
  const rows = liveStream
    .map((x, i) => `<li class="${i === liveStream.length - 1 ? "new" : ""}"><span class="m">${esc(x.req.method)}</span><span class="p">${esc(x.req.path)}</span><span class="st ${statusClass(x.res.status)}">${x.res.status}</span></li>`)
    .join("");
  const events = liveEvents
    .map((e, i) => `<li class="lv-${e.level}${i === liveEvents.length - 1 ? " new" : ""}"><span class="tm">+${(e.at / 1000).toFixed(2)}s</span><span>${esc(t(e.msg))}</span></li>`)
    .join("");
  const s = snap;
  const p = prevSnap;
  const users = (roster.length ? roster : s?.users ?? [])
    .map((u) => {
      const now = s?.users.find((x) => x.id === u.id);
      const before = p?.users.find((x) => x.id === u.id);
      const gone = s && !now;
      const roleChanged = now && now.role !== u.role;
      const flash = (p && before && !now) || (now && before && now.role !== before.role) ? " chg" : "";
      return `<tr class="${gone ? "gone" : ""}${flash}"><td>${u.id}</td><td>${esc(u.username)}</td><td class="${roleChanged ? "hot" : ""}">${gone ? t(UI.deleted) : esc(now?.role ?? u.role)}</td></tr>`;
    })
    .join("");
  const bal = s?.wallets[2] ?? 0;
  const balChg = p && (p.wallets[2] ?? 0) !== bal ? " chg" : "";
  const lg = s?.logins.mateo;
  const lgChg = p && JSON.stringify(p.logins.mateo) !== JSON.stringify(lg) ? " chg" : "";
  const segs = Array.from({ length: 5 }, (_, i) => `<i class="${(lg?.failures ?? 0) > i ? "on" : ""}"></i>`).join("");
  return `<div class="lv-col atk"><h3>${t(UI.attacker)}</h3>${rows ? `<ol class="stream">${rows}</ol>` : `<p class="wait">${t(UI.waiting)}</p>`}</div>
  <div class="lv-col srv"><h3>${t(UI.server)}</h3>
    <div class="db">
      <table class="tbl"><caption>${t(UI.users)}</caption><tbody>${users}</tbody></table>
      <div class="tiles">
        <div class="tile${balChg}"><span>${t(UI.balance)}</span><b class="${(s?.couponCredits ?? 0) > 1 ? "hot" : ""}">${money(bal)}</b><small>${s?.couponCredits ?? 0} ${t(UI.credits)}</small></div>
        <div class="tile${lgChg}"><span>${t(UI.failures)}</span><b class="${(lg?.failures ?? 0) > 5 ? "hot" : ""}">${lg?.failures ?? 0}</b><small class="segs">${segs}${lg?.lockedSeconds ? ` ${t(UI.locked).replace("{s}", String(lg.lockedSeconds))}` : ""}</small></div>
      </div>
    </div>
    ${events ? `<ol class="slog">${events}</ol>` : ""}
  </div>`;
}

function renderLive(): void {
  const el = document.getElementById("live");
  if (!el) return;
  el.innerHTML = liveInner();
  for (const box of el.querySelectorAll<HTMLElement>(".slog, .stream")) box.scrollTop = box.scrollHeight;
}

function navHtml(): string {
  const items = SCENARIOS.map((s) => {
    const r = results.get(s.id);
    const mark = r?.outcome ? (r.outcome.breached ? '<i class="dot br" aria-hidden="true"></i>' : '<i class="dot ok" aria-hidden="true"></i>') : "";
    return `<button class="tab${current === s.id ? " on" : ""}" data-tab="${s.id}" aria-current="${current === s.id}"><span class="code">${s.owasp.replace(":2023", "")}</span><span class="name">${esc(t(s.title))}</span>${mark}</button>`;
  }).join("");
  return `<nav class="tabs" aria-label="${t(UI.scenarios)}">${items}<button class="tab con${current === "console" ? " on" : ""}" data-tab="console" aria-current="${current === "console"}"><span class="code">&gt;_</span><span class="name">${t(UI.console)}</span></button></nav>`;
}

function scenarioHtml(s: Scenario): string {
  const mode = modes.get(s.id)!;
  const r = results.get(s.id);
  let verdict = `<p class="hint">${t(UI.hint)}</p>`;
  if (r?.error) verdict = `<div id="verdict" class="verdict err" role="status"><strong>${t(UI.error)}</strong> ${esc(r.error)}</div>`;
  else if (r?.outcome) {
    const o = r.outcome;
    verdict = `<div id="verdict" class="verdict ${o.breached ? "br" : "ok"}" role="status"><span class="badge">${r.mode === "vulnerable" ? t(UI.vulnerable) : t(UI.fixed)}</span><strong>${esc(t(o.headline))}</strong><p>${esc(t(o.detail))}</p></div>`;
  }
  return `<article class="scn">
    <p class="ow">${s.owasp} · ${esc(t(s.tagline))}</p>
    <h2>${esc(t(s.title))}</h2>
    <p class="story">${esc(t(s.story))}</p>
    <div class="controls">
      <div class="switch" role="radiogroup" aria-label="Modo / Mode">
        <button role="radio" data-mode="vulnerable" aria-checked="${mode === "vulnerable"}">${t(UI.vulnerable)}</button>
        <button role="radio" data-mode="fixed" aria-checked="${mode === "fixed"}">${t(UI.fixed)}</button>
      </div>
      <button id="launch" class="launch ${mode}"${running ? " disabled" : ""}>${running ? `${t(UI.running)} ${progress}` : t(UI.launch)}</button>
      ${slowHtml()}
    </div>
    ${verdict}
    ${liveHtml()}
    ${r ? logHtml(r.log) : ""}
    <section class="fix">
      <h3>${t(UI.theFix)}</h3>
      <p>${esc(t(s.fix))}</p>
      <div class="code2">
        <figure class="cv"><figcaption>${t(UI.codeVuln)}</figcaption><pre>${esc(s.code.vulnerable)}</pre></figure>
        <figure class="cf"><figcaption>${t(UI.codeFixed)}</figcaption><pre>${esc(s.code.fixed)}</pre></figure>
      </div>
    </section>
  </article>`;
}

function slowHtml(): string {
  return `<label class="slow"><input type="checkbox" id="slow"${slow ? " checked" : ""}><span>${t(UI.slow)}</span></label>`;
}

function consoleHtml(): string {
  const boxes = VULNS.map((v) => {
    const s = SCENARIOS.find((x) => x.vuln === v)!;
    return `<label class="chk"><input type="checkbox" data-vuln="${v}"${consoleVulns.has(v) ? " checked" : ""}><span>${s.owasp.replace(":2023", "")} ${esc(t(s.title))}</span></label>`;
  }).join("");
  const res = consoleResult;
  return `<article class="scn">
    <p class="ow">HTTP</p>
    <h2>${t(UI.console)}</h2>
    <p class="story">${t(UI.consoleHelp)}</p>
    <label class="sr" for="raw">${t(UI.request)}</label>
    <textarea id="raw" spellcheck="false" rows="8">${esc(consoleText)}</textarea>
    <fieldset class="flaws"><legend>${t(UI.flaws)}</legend>${boxes}</fieldset>
    <div class="controls"><button id="send" class="launch vulnerable"${running ? " disabled" : ""}>${t(UI.send)}</button><button id="reset" class="ghost">${t(UI.reset)}</button>${slowHtml()}<span class="note" role="status">${esc(consoleNote)}</span></div>
    ${res?.error ? `<div class="verdict err" role="status">${esc(res.error)}</div>` : ""}
    ${liveHtml()}
    ${res ? logHtml(res.log) : ""}
  </article>`;
}

function render(): void {
  document.documentElement.lang = lang;
  document.title = `${t(UI.title)} · Valter Zuliani`;
  const s = SCENARIOS.find((x) => x.id === current);
  const where = transportKind === "page" ? t(UI.whereFallback) : `${t(UI.where)} ${t(UI.devtools)}`;
  const app = document.getElementById("app")!;
  const scrollY = window.scrollY;
  const focusId = (document.activeElement as HTMLElement | null)?.id;
  app.innerHTML = `
  <header class="top"><div class="wrap">
    <a class="back" href="../">${t(UI.back)}</a>
    <div class="lang" role="group" aria-label="Idioma / Language"><button data-lang="es" aria-pressed="${lang === "es"}">ES</button><button data-lang="en" aria-pressed="${lang === "en"}">EN</button></div>
  </div></header>
  <header class="hero"><div class="wrap">
    <h1>${t(UI.title)}</h1>
    <p class="lede">${t(UI.lede)}</p>
    <p class="where">${where}</p>
  </div></header>
  <main class="wrap grid">
    ${navHtml()}
    <div class="stage">${s ? scenarioHtml(s) : consoleHtml()}</div>
  </main>
  <footer class="foot"><div class="wrap"><p>${t(UI.credit)}</p><p><a href="${REPO}" rel="noopener">${t(UI.source)}</a></p></div></footer>`;
  window.scrollTo(0, scrollY);
  for (const box of app.querySelectorAll<HTMLElement>(".slog, .stream")) box.scrollTop = box.scrollHeight;
  const on = app.querySelector<HTMLElement>(".tab.on");
  const strip = app.querySelector<HTMLElement>(".tabs");
  if (on && strip && strip.scrollWidth > strip.clientWidth) strip.scrollLeft = on.offsetLeft - 16;
  if (focusId) document.getElementById(focusId)?.focus();
}

// ---------- events ----------
document.addEventListener("click", (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>("button");
  if (!el) return;
  if (el.dataset.lang) {
    lang = el.dataset.lang as Lang;
    try {
      localStorage.setItem("vz-lang", lang);
    } catch {
      /* ignore */
    }
    render();
  } else if (el.dataset.tab) {
    if (running) return;
    current = el.dataset.tab;
    liveOn = false;
    render();
    document.querySelector(".stage")?.scrollIntoView({ block: "nearest" });
  } else if (el.dataset.mode) {
    if (running) return;
    modes.set(current, el.dataset.mode as Mode);
    render();
  } else if (el.id === "launch") {
    const s = SCENARIOS.find((x) => x.id === current);
    if (s) void launch(s);
  } else if (el.id === "send") void sendConsole();
  else if (el.id === "reset") void resetData();
});

document.addEventListener("input", (e) => {
  const el = e.target as HTMLElement;
  if (el.id === "raw") consoleText = (el as HTMLTextAreaElement).value;
});

document.addEventListener("change", (e) => {
  const el = e.target as HTMLInputElement;
  if (el.id === "slow") {
    slow = el.checked;
    return;
  }
  const v = el.dataset.vuln as Vuln | undefined;
  if (!v) return;
  if (el.checked) consoleVulns.add(v);
  else consoleVulns.delete(v);
});

document.addEventListener("keydown", (e) => {
  const el = e.target as HTMLElement;
  if (el.getAttribute("role") !== "radio" || (e.key !== "ArrowLeft" && e.key !== "ArrowRight")) return;
  e.preventDefault();
  modes.set(current, modes.get(current) === "vulnerable" ? "fixed" : "vulnerable");
  render();
  document.querySelector<HTMLElement>(`[data-mode="${modes.get(current)}"]`)?.focus();
});

const transportReady = startTransport();
render();
void transportReady.then(render);
