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
function table(headers, rows, rowClass) {
  const t = el("table"), thead = el("thead"), tr = el("tr");
  for (const h of headers) tr.appendChild(el("th", h));
  thead.appendChild(tr); t.appendChild(thead);
  const tb = el("tbody");
  for (const r of rows) {
    const row = el("tr");
    if (rowClass) { const c = rowClass(r); if (c) row.className = c; }
    for (const cell of r) {
      const td = el("td", cell && cell.text != null ? cell.text : cell);
      if (cell && cell.cls) td.className = cell.cls;
      row.appendChild(td);
    }
    tb.appendChild(row);
  }
  t.appendChild(tb);
  return t;
}

$("#run-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const res = await fetch("/run", { method: "POST", body: new FormData(ev.target) });
  if (!res.ok) { const j = await res.json().catch(() => ({error: res.status})); alert("Error: " + (j.error || res.status)); return; }
  const { job_id } = await res.json();
  show("running");
  poll(job_id);
});

async function poll(id) {
  const res = await fetch("/status/" + encodeURIComponent(id));
  const j = await res.json();
  $("#log").textContent = (j.phase_lines || []).join("\n");
  $("#log").scrollTop = $("#log").scrollHeight;
  if (j.state === "running") { setTimeout(() => poll(id), 1000); return; }
  if (j.state === "error") { $("#log").textContent += "\n\nERROR:\n" + (j.error || ""); return; }
  renderReport(id);
}

async function renderReport(id) {
  const res = await fetch("/report/" + encodeURIComponent(id));
  const { summary, iocs, verdict, report_dir } = await res.json();
  const r = $("#report"); r.textContent = ""; show("report");

  const v = el("div", verdict.reasons.length ? verdict.reasons.join("; ") : "nothing notable", "verdict " + verdict.level);
  v.prepend(el("strong", verdict.level.toUpperCase() + " — "));
  r.appendChild(v);

  const db = summary.db_diff;
  r.appendChild(el("h3", "Users added"));
  r.appendChild(table(["login", "email", "roles"],
    db.users_added.map(u => [u.login, u.email || "",
      { text: (u.roles || []).join(", "), cls: (u.roles || []).includes("administrator") ? "admin" : "" }])));

  r.appendChild(el("h3", "Call chain (sample's own functions)"));
  r.appendChild(table(["function", "location"],
    summary.callchain.map(c => [c.function, c.file + ":" + c.line])));

  r.appendChild(el("h3", "Network — flows"));
  r.appendChild(table(["host", "method", "path", "status"],
    summary.network.flows.map(f => [f.host, f.method, f.path, f.status]),
    () => null));   // wp_core dimming applied below
  // dim wp_core rows
  const flowRows = r.querySelectorAll("table:last-of-type tbody tr");
  summary.network.flows.forEach((f, i) => { if (f.wp_core && flowRows[i]) flowRows[i].className = "wpcore"; });

  r.appendChild(el("h3", "Network — dropped"));
  r.appendChild(table(["dst", "port"], summary.network.dropped.map(d => [d.dst, d.port])));

  r.appendChild(el("h3", "IOCs"));
  r.appendChild(table(["type", "value", "notes"],
    (iocs.indicators || []).map(i => [i.type, i.value, i.notes || ""])));

  r.appendChild(el("h3", "Artifacts"));
  const arts = [].concat(summary.artifacts.traces, summary.artifacts.sp_dumps, summary.artifacts.pcaps,
    ["summary.json", "iocs.json"]);
  const links = el("p");
  for (const a of arts) {
    const base = a.split("/").pop();
    const link = el("a", base, "dl");
    link.href = "/artifact/" + encodeURIComponent(id) + "/" + encodeURIComponent(base);
    links.appendChild(link);
  }
  r.appendChild(links);
  r.appendChild(el("p", "Report dir: " + report_dir, "note"));
}
