"use strict";
// All log-derived text goes through textContent / createTextNode, never HTML strings.
const SEVS = ["critical", "high", "medium", "low"];
const NS = "http://www.w3.org/2000/svg";

function el(tag, attrs, text) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}
function svg(tag, attrs, text) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
  if (text !== undefined) n.textContent = text;
  return n;
}
async function get(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + " -> " + r.status);
  return r.json();
}
function badge(sev) {
  const b = el("span", { class: "badge" });
  b.append(el("span", { class: "dot sev-" + sev }), document.createTextNode(sev));
  return b;
}

function drawSeverity(box, by) {
  box.replaceChildren();
  const max = Math.max(1, ...SEVS.map((s) => by[s]));
  const W = 320, rowH = 36, label = 70;
  const root = svg("svg", { viewBox: `0 0 ${W} ${rowH * SEVS.length}`, width: "100%", role: "img", "aria-label": "Alerts by severity" });
  SEVS.forEach((s, i) => {
    const w = Math.max(by[s] ? 4 : 0, ((W - label - 40) * by[s]) / max);
    const y = i * rowH;
    root.append(svg("text", { x: 0, y: y + 22 }, s));
    root.append(svg("rect", { x: label, y: y + 6, width: w, height: 22, rx: 4, class: "fill-" + s }));
    root.append(svg("text", { x: label + w + 6, y: y + 22, class: "val" }, String(by[s])));
  });
  box.append(root);
}

function drawTimeline(box, rows) {
  box.replaceChildren();
  if (!rows.length) { box.append(el("p", { class: "muted" }, "No alerts yet.")); return; }
  const W = 640, H = 200, left = 28, bottom = 24, top = 8;
  const totals = rows.map((r) => SEVS.reduce((a, s) => a + r[s], 0));
  const max = Math.max(...totals);
  const slot = (W - left) / rows.length, bw = Math.min(28, slot - 4);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": "Alerts per hour by severity" });
  root.append(svg("line", { x1: left, x2: W, y1: H - bottom, y2: H - bottom, class: "axis" }));
  root.append(svg("text", { x: 0, y: top + 8 }, String(max)));
  rows.forEach((r, i) => {
    const x = left + i * slot + (slot - bw) / 2;
    let y = H - bottom;
    // stack low (bottom) to critical (top); 2px gap between segments
    [...SEVS].reverse().forEach((s) => {
      if (!r[s]) return;
      const h = ((H - bottom - top) * r[s]) / max;
      y -= h;
      const rect = svg("rect", { x, y: y + 1, width: bw, height: Math.max(1, h - 2), rx: 3, class: "fill-" + s });
      rect.append(svg("title", {}, `${r.bucket} ${s}: ${r[s]}`));
      root.append(rect);
    });
    if (rows.length <= 14 || i % 2 === 0) root.append(svg("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" }, r.bucket.slice(11, 13) + "h"));
  });
  box.append(root);
}

function drawLegend() {
  const ul = document.getElementById("legend");
  ul.replaceChildren();
  [...SEVS].reverse().forEach((s) => {
    const li = el("li");
    li.append(el("span", { class: "dot sev-" + s }), document.createTextNode(s));
    ul.append(li);
  });
}

function detailRow(a) {
  const tr = el("tr", { class: "detail" });
  const td = el("td", { colspan: "5" });
  const text = [
    a.title,
    "group: " + JSON.stringify(a.details.group),
    "window: " + a.first_ts + " to " + a.last_ts,
    a.tags.length ? "tags: " + a.tags.join(", ") : "",
    "",
    ...(a.details.sample || []),
  ].filter((x, i) => x !== "" || i === 4).join("\n");
  td.append(el("pre", {}, text));
  tr.append(td);
  return tr;
}

function drawAlerts(list) {
  const body = document.querySelector("#alerts tbody");
  body.replaceChildren();
  document.getElementById("empty").hidden = list.length > 0;
  for (const a of list) {
    const tr = el("tr");
    const sev = el("td"); sev.append(badge(a.severity));
    tr.append(sev, el("td", {}, a.title), el("td", {}, a.group_key.replace(/^event:\d+$/, "single event")), el("td", {}, a.first_ts), el("td", {}, String(a.event_count)));
    let open = null;
    tr.addEventListener("click", () => {
      if (open) { open.remove(); open = null; return; }
      open = detailRow(a);
      tr.after(open);
    });
    body.append(tr);
  }
}

async function refresh() {
  const sev = document.getElementById("sev-filter").value;
  const [s, list] = await Promise.all([get("/api/summary"), get("/api/alerts?limit=200" + (sev ? "&severity=" + encodeURIComponent(sev) : ""))]);
  document.getElementById("totals").textContent = `${s.alerts_total} alerts from ${s.events_total} events`;
  drawSeverity(document.getElementById("by-severity"), s.by_severity);
  drawTimeline(document.getElementById("timeline"), s.timeline);
  drawAlerts(list);
}

drawLegend();
document.getElementById("sev-filter").addEventListener("change", refresh);
refresh().catch((e) => { document.getElementById("totals").textContent = String(e); });
setInterval(() => refresh().catch(() => {}), 15000);
