"use strict";
const $ = (s) => document.querySelector(s);

function show(id) {
  for (const s of ["upload", "running", "report"]) $("#" + s).hidden = (s !== id);
}
function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text != null) e.textContent = text;   // textContent only — never innerHTML
  if (cls) e.className = cls;
  return e;
}
// Class names a cell may carry; must match rules in web_app.css.
const CELL_CLASSES = ["admin", "flowerr", "warn"];
function cellText(c) {
  if (c == null) return "";
  if (typeof c === "object") return c.text != null ? String(c.text) : JSON.stringify(c);
  return String(c);
}
// rowClass(row, index) -> class name or null; cells are strings or {text, cls}.
function table(headers, rows, rowClass) {
  const t = el("table"), thead = el("thead"), tr = el("tr");
  for (const h of headers) tr.appendChild(el("th", h));
  thead.appendChild(tr); t.appendChild(thead);
  const tb = el("tbody");
  rows.forEach((r, i) => {
    const row = el("tr");
    if (rowClass) { const c = rowClass(r, i); if (c) row.className = c; }
    for (const cell of r) {
      const td = el("td", cellText(cell));
      if (cell && typeof cell === "object" && CELL_CLASSES.includes(cell.cls)) td.className = cell.cls;
      row.appendChild(td);
    }
    tb.appendChild(row);
  });
  t.appendChild(tb);
  return t;
}
function isAdmin(roles) {
  return (Array.isArray(roles) ? roles : []).some(x => String(x).toLowerCase() === "administrator");
}
function setStatus(msg) { $("#status").textContent = msg; }

$("#run-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const res = await fetch("/run", { method: "POST", body: new FormData(ev.target) });
    if (!res.ok) { const j = await res.json().catch(() => ({error: res.status})); alert("Error: " + (j.error || res.status)); return; }
    const { job_id } = await res.json();
    setStatus("Running…");
    show("running");
    poll(job_id);
  } catch (e) {
    alert("Error: " + e);
  }
});

async function poll(id) {
  try {
    const res = await fetch("/status/" + encodeURIComponent(id));
    if (!res.ok) throw new Error("status HTTP " + res.status);
    const j = await res.json();
    $("#log").textContent = (j.phase_lines || []).join("\n");
    $("#log").scrollTop = $("#log").scrollHeight;
    if (j.state === "running") { setTimeout(() => poll(id), 1000); return; }
    if (j.state === "error") { setStatus("Failed"); $("#log").textContent += "\n\nERROR:\n" + (j.error || ""); return; }
    await renderReport(id);
  } catch (e) {
    show("running");
    setStatus("Error while polling: " + e);
  }
}

async function renderReport(id) {
  try {
    const res = await fetch("/report/" + encodeURIComponent(id));
    if (!res.ok) throw new Error("report HTTP " + res.status);
    const { summary, iocs, verdict, report_dir } = await res.json();
    drawReport(id, summary || {}, iocs || {}, verdict || {level: "amber", reasons: ["no verdict"]}, report_dir);
  } catch (e) {
    show("running");
    setStatus("Error rendering report: " + e);
  }
}

function drawReport(id, summary, iocs, verdict, report_dir) {
  const r = $("#report"); r.textContent = "";

  const reasons = verdict.reasons || [];
  const level = String(verdict.level || "amber");
  const v = el("div", reasons.length ? reasons.join("; ") : "nothing notable",
               "verdict " + (["red", "amber", "green"].includes(level) ? level : "amber"));
  v.prepend(el("strong", level.toUpperCase() + " — "));
  r.appendChild(v);

  const run = summary.run || {};
  r.appendChild(el("h3", "Run"));
  r.appendChild(table(["check", "value"], [
    ["login_ok", run.login_ok === false ? { text: "false", cls: "warn" } : (run.login_ok == null ? "n/a" : String(run.login_ok))],
    ["wp_restarted", run.wp_restarted ? { text: "true", cls: "warn" } : String(!!run.wp_restarted)],
    ["fatal", run.fatal ? { text: String(run.fatal), cls: "warn" } : String(!!run.fatal)],
  ]));
  const warnings = Array.isArray(summary.warnings) ? summary.warnings : [];
  if (warnings.length) {
    r.appendChild(el("h3", "Warnings"));
    const ul = el("ul");
    for (const w of warnings) ul.appendChild(el("li", String(w)));
    r.appendChild(ul);
  }

  const db = summary.db_diff || {}, net = summary.network || {}, arts = summary.artifacts || {};
  r.appendChild(el("h3", "Users added"));
  r.appendChild(table(["login", "email", "roles"],
    (db.users_added || []).map(u => [u.login, u.email || "",
      { text: (Array.isArray(u.roles) ? u.roles : []).join(", "), cls: isAdmin(u.roles) ? "admin" : "" }])));

  r.appendChild(el("h3", "Call chain (sample's own functions)"));
  r.appendChild(table(["function", "location"],
    (summary.callchain || []).map(c => [c.function, c.file + ":" + c.line])));

  r.appendChild(el("h3", "Network — flows"));
  const flows = net.flows || [];
  r.appendChild(table(["host", "method", "path", "status"],
    flows.map(f => [
      f.host_spoofed ? { text: f.host + " (spoofed Host; dst " + (f.dst || "?") + ")", cls: "flowerr" } : f.host,
      f.method, f.path,
      // no response: show why instead of a blank cell (textContent via el())
      f.status == null && f.error ? { text: "error: " + f.error, cls: "flowerr" } : f.status]),
    (_, i) => (flows[i].wp_core ? "wpcore" : null)));

  r.appendChild(el("h3", "Network — dropped"));
  r.appendChild(table(["dst", "port"], (net.dropped || []).map(d => [d.dst, d.port])));

  r.appendChild(el("h3", "IOCs"));
  r.appendChild(table(["type", "value", "notes"],
    (iocs.indicators || []).map(i => [i.type, i.value, i.notes || ""])));

  r.appendChild(el("h3", "Artifacts"));
  const bundle = arts.bundle;
  const useBundle = Array.isArray(bundle) && bundle.length > 0;
  const files = (useBundle ? bundle
    : [].concat(arts.traces || [], arts.sp_dumps || [], arts.pcaps || []))
    .concat(["summary.json", "iocs.json"]);
  const links = el("p");
  for (const a of files) {
    const base = String(a).split("/").pop();
    const link = el("a", base, "dl");
    link.href = "/artifact/" + encodeURIComponent(id) + "/" + encodeURIComponent(base);
    links.appendChild(link);
  }
  r.appendChild(links);
  if (useBundle) r.appendChild(el("p", "Artifacts are this run's bundle under the report dir.", "note"));
  r.appendChild(el("p", "Report dir: " + report_dir, "note"));
  show("report");
}
