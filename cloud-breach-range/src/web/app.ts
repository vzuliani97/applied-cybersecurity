import { CONTROL_HEADER, CONTROLS, createCloud, type CloudEvent, type Control, type Req, type Res, type Snapshot } from "../core/cloud.ts";
import { STAGES, runChain, type Outcome, type Stage, type Step } from "../core/chain.ts";
import { CONTROL_TEXT, STAGE_TEXT, UI } from "./content.ts";
import type { L } from "../core/cloud.ts";

type Lang = "es" | "en";
interface Exchange {
  req: Req;
  res: Res;
  ms: number;
  step: Step & { key?: boolean };
}

const REPO = "https://github.com/vzuliani97/applied-cybersecurity/tree/main/cloud-breach-range";

// ---------- state ----------
let lang: Lang = initialLang();
const on = new Set<Control>();
let running = false;
let progressStage: Stage | null = null;
let log: Exchange[] = [];
let outcome: Outcome | null = null;
let ranWith: Set<Control> | null = null;
let error = "";
let events: CloudEvent[] = [];
let snap: Snapshot | null = null;
let slow = true;
const SLOW_MS = 420;
let transportKind: "sw" | "page" | "pending" = "pending";
let pageCloud: ReturnType<typeof createCloud> | null = null;
let runStart = 0;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const t = (l: L) => l[lang];

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem("vz-lang-choice");
    if (saved === "es" || saved === "en") return saved;
  } catch {
    /* storage may be unavailable */
  }
  return "en";
}

// ---------- transport ----------
async function startTransport(): Promise<void> {
  if ("serviceWorker" in navigator && window.isSecureContext) {
    try {
      await navigator.serviceWorker.register("sw.js", { scope: "./" });
      if (!navigator.serviceWorker.controller) {
        await new Promise<void>((resolve) => {
          navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true });
          setTimeout(resolve, 4000);
        });
      }
      if (navigator.serviceWorker.controller) {
        transportKind = "sw";
        return;
      }
    } catch {
      /* fall back to the in-page cloud */
    }
  }
  pageCloud = createCloud();
  transportKind = "page";
}

function onEvent(ev: CloudEvent): void {
  if (!running && !outcome) return;
  events.push({ ...ev, at: Math.round(performance.now() - runStart) });
  snap = ev.snapshot;
  renderLive();
}

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.addEventListener("message", (e: MessageEvent) => {
    const d = e.data as { type?: string; ev?: CloudEvent };
    if (d?.type === "cloud-event" && d.ev) onEvent(d.ev);
  });
  navigator.serviceWorker.startMessages();
}

async function transport(req: Req): Promise<Res> {
  await transportReady;
  if (transportKind === "page" && pageCloud) return pageCloud.handle(req, onEvent);
  const r = await fetch(req.path.replace(/^\//, ""), { method: req.method, headers: req.headers, cache: "no-store" });
  const headers: Record<string, string> = {};
  r.headers.forEach((v, k) => (headers[k] = v));
  return { status: r.status, headers, body: await r.text() };
}

// ---------- the run ----------
async function launch(): Promise<void> {
  if (running) return;
  running = true;
  outcome = null;
  error = "";
  log = [];
  events = [];
  snap = null;
  progressStage = null;
  ranWith = new Set(on);
  runStart = performance.now();
  render();
  try {
    await transport({ method: "POST", path: "/_reset", headers: {} });
    const controls = [...on].join(",");
    outcome = await runChain(async (req, step) => {
      if (slow) await sleep(SLOW_MS);
      progressStage = step.stage;
      const full: Req = { ...req, headers: { ...req.headers, [CONTROL_HEADER]: controls } };
      const t0 = performance.now();
      const res = await transport(full);
      log.push({ req: full, res, ms: Math.round(performance.now() - t0), step });
      renderLive();
      renderChain();
      return res;
    }, ranWith);
    await sleep(200);
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  } finally {
    running = false;
    render();
    document.querySelector("#verdict")?.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "nearest" });
  }
}

// ---------- rendering ----------
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const STATUS: Record<number, string> = { 200: "OK", 204: "No Content", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 502: "Bad Gateway" };
const sc = (s: number) => (s < 300 ? "s2" : s < 500 ? "s4" : "s5");

function pretty(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}

/** One short line of what came back, as a terminal would show it. */
function shortResponse(x: Exchange): string {
  const b = x.res.body;
  if (x.req.path.startsWith("/shop/")) {
    try {
      const j = JSON.parse(b) as { status?: number; body?: string; error?: string; title?: string };
      if (j.error) return `${x.res.status} ${j.error}`;
      if (j.title) return `${j.status} "${j.title}"`;
      const inner = (j.body ?? "").replace(/\s+/g, " ").trim();
      return `${j.status} ${inner.length > 110 ? inner.slice(0, 110) + "…" : inner || "(empty)"}`;
    } catch {
      return String(x.res.status);
    }
  }
  const code = /<Code>(\w+)<\/Code>/.exec(b)?.[1];
  if (code) return `An error occurred (${code})`;
  const names = [...b.matchAll(/<(?:Name|Key)>([^<]+)<\/(?:Name|Key)>/g)].map((m) => m[1]).filter((n, i, a) => a.indexOf(n) === i);
  if (names.length && b.includes("ListAllMyBuckets")) return names.join("   ");
  if (names.length && b.includes("ListBucketResult")) return names.slice(1).join("   ");
  const lines = b.trim().split("\n");
  return lines.slice(0, 3).join("\n") + (lines.length > 3 ? `\n… ${lines.length - 3} more rows` : "");
}

function chainHtml(): string {
  const reached = outcome ? outcome.reached : running && progressStage ? STAGES.indexOf(progressStage) : -1;
  const ctrl = ranWith ?? on;
  const nodes = STAGES.map((s, i) => {
    const owned = outcome ? i < outcome.reached : running && i < reached;
    const live = running && progressStage === s;
    const guards = CONTROLS.filter((c) => CONTROL_TEXT[c].guards === s && ctrl.has(c));
    const blocked = outcome && !outcome.breached && i === outcome.reached;
    const shield = guards.length ? `<span class="shield${blocked ? " held" : ""}" title="${esc(guards.map((g) => t(CONTROL_TEXT[g].name)).join(", "))}">${blocked ? "✕" : "◆"} ${guards.length}</span>` : "";
    return `<li class="node${owned ? " owned" : ""}${live ? " live" : ""}${blocked ? " stop" : ""}">${shield}<b>${esc(t(STAGE_TEXT[s].name))}</b><small>${esc(t(STAGE_TEXT[s].sub))}</small></li>`;
  }).join('<li class="arrow" aria-hidden="true"></li>');
  return `<ol class="chain" aria-label="${t(UI.chain)}">${nodes}</ol>`;
}

function controlsHtml(): string {
  const rows = CONTROLS.map((c) => {
    const x = CONTROL_TEXT[c];
    return `<label class="ctl${on.has(c) ? " on" : ""}"><input type="checkbox" data-ctl="${c}"${on.has(c) ? " checked" : ""}${running ? " disabled" : ""}><span class="tg" aria-hidden="true"></span><span class="tx"><b>${esc(t(x.name))}</b><small class="ly">${esc(t(x.layer))}</small><span>${esc(t(x.what))}</span></span></label>`;
  }).join("");
  return `<section class="defs"><div class="defs-h"><h2>${t(UI.defences)}</h2><div class="presets"><button class="ghost" data-preset="off"${running ? " disabled" : ""}>${t(UI.allOff)}</button><button class="ghost" data-preset="on"${running ? " disabled" : ""}>${t(UI.allOn)}</button></div></div><div class="ctls">${rows}</div>
  <div class="controls"><button id="launch" class="launch"${running ? " disabled" : ""}>${running ? t(UI.running) : t(UI.launch)}</button><label class="slow"><input type="checkbox" id="slow"${slow ? " checked" : ""}><span>${t(UI.slow)}</span></label></div></section>`;
}

function verdictHtml(): string {
  if (error) return `<div id="verdict" class="verdict err" role="status"><strong>${t(UI.error)}</strong> ${esc(error)}</div>`;
  if (!outcome) return running ? "" : `<p class="hint">${t(UI.hint)}</p>`;
  const o = outcome;
  const badges = `<span class="badge ${o.breached ? "br" : "ok"}">${o.breached ? t(UI.breached) : t(UI.held)}</span><span class="badge ${o.detected ? "ok" : "mute"}">${o.detected ? t(UI.detected) : t(UI.unseen)}</span>`;
  return `<div id="verdict" class="verdict ${o.breached ? "br" : "ok"}" role="status">${badges}<strong>${esc(t(o.headline))}</strong><p>${esc(t(o.detail))}</p></div>`;
}

function liveInner(): string {
  const term = log
    .map((x, i) => `<li class="${i === log.length - 1 ? "new" : ""}${x.step.key ? " key" : ""}"><code class="cmd"><span class="ps">$</span> ${esc(x.step.cmd)}</code><pre class="out ${sc(x.res.status)}">${esc(shortResponse(x))}</pre></li>`)
    .join("");
  const evs = events
    .map((e, i) => `<li class="lv-${e.level}${i === events.length - 1 ? " new" : ""}"><span class="tag t-${e.layer}">${e.layer === "trail" ? "CloudTrail" : e.layer === "guardduty" ? "GuardDuty" : e.layer.toUpperCase()}</span><span>${esc(t(e.msg))}</span></li>`)
    .join("");
  const s = snap;
  const tiles = `<div class="tiles">
    <div class="tile${s?.credentialsLeaked ? " hot" : ""}"><span>${t(UI.leaked)}</span><b>${s?.credentialsLeaked ? esc(s.credentialsLeaked.slice(0, 12)) + "…" : t(UI.none)}</b>${s?.revoked ? `<small class="okc">${t(UI.revoked)}</small>` : ""}</div>
    <div class="tile"><span>${t(UI.trail)}</span><b>${s?.trail.length ?? 0}</b></div>
    <div class="tile${s?.findings.length ? " good" : ""}"><span>${t(UI.findings)}</span><b>${s?.findings.length ?? 0}</b></div>
    <div class="tile${s?.exfiltrated.length ? " hot" : ""}"><span>${t(UI.exfil)}</span><b>${s?.exfiltrated.length ?? 0}</b></div>
  </div>`;
  return `<div class="lv-col atk"><h3>${t(UI.attacker)}</h3>${term ? `<ol class="term">${term}</ol>` : `<p class="wait">${t(UI.waiting)}</p>`}</div>
  <div class="lv-col srv"><h3>${t(UI.cloud)}</h3>${tiles}${evs ? `<ol class="slog">${evs}</ol>` : ""}${(ranWith ?? on).has("detect-respond") ? `<p class="note2">${t(UI.timing)}</p>` : ""}</div>`;
}

function logHtml(): string {
  if (!log.length || running) return "";
  const rows = log
    .map((x, i) => {
      const lines = [`${x.req.method} ${x.req.path} HTTP/1.1`, ...Object.entries(x.req.headers).map(([k, v]) => `${k}: ${v}`)];
      const reqTxt = esc(lines.join("\n")).replace(new RegExp(`^(${CONTROL_HEADER}: .*)$`, "mi"), '<span class="lab">$1</span>');
      const resTxt = esc([`HTTP/1.1 ${x.res.status} ${STATUS[x.res.status] ?? ""}`, ...["content-type", "x-served-by"].filter((k) => x.res.headers[k]).map((k) => `${k}: ${x.res.headers[k]}`)].join("\n") + (x.res.body ? "\n\n" + pretty(x.res.body) : ""));
      return `<details class="ex${x.step.key ? " key" : ""}"><summary><span class="num">${i + 1}</span><span class="m">${x.req.method}</span><span class="p">${esc(x.req.path)}</span><span class="st ${sc(x.res.status)}">${x.res.status}</span><span class="ms">${x.ms} ms</span></summary><div class="pair"><div><h4>${t(UI.request)}</h4><pre>${reqTxt}</pre></div><div><h4>${t(UI.response)}</h4><pre>${resTxt}</pre></div></div></details>`;
    })
    .join("");
  return `<div class="log"><p class="count">${log.length} ${t(UI.requests)}</p>${rows}</div>`;
}

function fixesHtml(): string {
  const cards = CONTROLS.map((c) => {
    const x = CONTROL_TEXT[c];
    return `<article class="fx"><h3>${esc(t(x.name))} <small>${esc(t(x.layer))}</small></h3><p>${esc(t(x.what))}</p><div class="code2"><figure class="cv"><figcaption>${t(UI.before)}</figcaption><pre>${esc(x.vulnerable)}</pre></figure><figure class="cf"><figcaption>${t(UI.after)}</figcaption><pre>${esc(x.fixed)}</pre></figure></div></article>`;
  }).join("");
  return `<section class="fixes wrap"><h2>${t(UI.fixes)}</h2><p class="fl">${t(UI.fixesLede)}</p>${cards}</section>`;
}

function renderLive(): void {
  const el = document.getElementById("live");
  if (!el) return;
  el.innerHTML = liveInner();
  for (const box of el.querySelectorAll<HTMLElement>(".slog, .term")) box.scrollTop = box.scrollHeight;
}

function renderChain(): void {
  const el = document.getElementById("chainbox");
  if (el) el.innerHTML = chainHtml();
}

function render(): void {
  document.documentElement.lang = lang;
  document.title = `${t(UI.title)} · Valter Zuliani`;
  const where = transportKind === "page" ? t(UI.whereFallback) : `${t(UI.where)} ${t(UI.devtools)}`;
  const app = document.getElementById("app")!;
  const y = window.scrollY;
  const focusId = (document.activeElement as HTMLElement | null)?.id;
  const focusCtl = (document.activeElement as HTMLElement | null)?.dataset?.ctl;
  const showLive = running || outcome || error;
  app.innerHTML = `
  <header class="top"><div class="wrap"><a class="back" href="../">${t(UI.back)}</a>
    <div class="lang" role="group" aria-label="Idioma / Language"><button data-lang="es" aria-pressed="${lang === "es"}">ES</button><button data-lang="en" aria-pressed="${lang === "en"}">EN</button></div></div></header>
  <header class="hero"><div class="wrap"><h1>${t(UI.title)}</h1><p class="lede">${t(UI.lede)}</p><p class="where">${where}</p></div></header>
  <main class="wrap">
    <div id="chainbox">${chainHtml()}</div>
    ${controlsHtml()}
    ${verdictHtml()}
    ${showLive ? `<section class="live" id="live">${liveInner()}</section>` : ""}
    ${logHtml()}
  </main>
  ${fixesHtml()}
  <footer class="foot"><div class="wrap"><p>${t(UI.credit)}</p><p><a href="${REPO}" rel="noopener">${t(UI.source)}</a></p></div></footer>`;
  window.scrollTo(0, y);
  for (const box of app.querySelectorAll<HTMLElement>(".slog, .term")) box.scrollTop = box.scrollHeight;
  if (focusCtl) app.querySelector<HTMLElement>(`[data-ctl="${focusCtl}"]`)?.focus();
  else if (focusId) document.getElementById(focusId)?.focus();
}

// ---------- events ----------
document.addEventListener("click", (e) => {
  const el = (e.target as HTMLElement).closest<HTMLElement>("button");
  if (!el) return;
  if (el.dataset.lang) {
    lang = el.dataset.lang as Lang;
    try {
      localStorage.setItem("vz-lang-choice", lang);
    } catch {
      /* ignore */
    }
    render();
  } else if (el.dataset.preset && !running) {
    on.clear();
    if (el.dataset.preset === "on") CONTROLS.forEach((c) => on.add(c));
    render();
  } else if (el.id === "launch") void launch();
});

document.addEventListener("change", (e) => {
  const el = e.target as HTMLInputElement;
  if (el.id === "slow") slow = el.checked;
  const c = el.dataset.ctl as Control | undefined;
  if (!c || running) return;
  if (el.checked) on.add(c);
  else on.delete(c);
  render();
});

const transportReady = startTransport();
render();
void transportReady.then(render);
