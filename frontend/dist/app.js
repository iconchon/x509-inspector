"use strict";
// All data shown here comes from untrusted files: always escape before inserting.
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SEV = { error: "Error", warn: "Peringatan", info: "Info", ok: "OK" };
const ICON = { error: "!", warn: "!", info: "i", ok: "✓" };
const KIND = { certificate: "Sertifikat", crl: "CRL", csr: "CSR", "private-key": "Kunci privat", "public-key": "Kunci publik", cms: "PKCS#7 / CMS", pkcs12: "PKCS#12", unknown: "Tidak dikenal", params: "Parameter" };

const api = () => (window.go && window.go.main && window.go.main.App) || null;

const st = { report: null, gen: -1, sel: null, tab: "hasil", filter: "all", busy: 0, onlineBusy: false };

// ---------- helpers ----------
let toastT;
function toast(msg, ms = 2600) {
  if (!msg) return;
  const el = $("status");
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toastT);
  toastT = setTimeout(() => el.classList.remove("show"), ms);
}

async function call(fn, ...args) {
  const a = api();
  if (!a) { toast("Backend belum siap"); return null; }
  st.busy++;
  document.body.style.cursor = "progress";
  try { return await a[fn](...args); }
  catch (e) { toast("Gagal: " + (e && e.message ? e.message : e)); return null; }
  finally { if (--st.busy === 0) document.body.style.cursor = ""; }
}

function apply(res) {
  if (!res) return;
  if (res.error) toast(res.error, 5000);
  if (res.gen === -1 || !res.report) return;
  if (res.gen < st.gen) return; // stale result from an older state
  st.gen = res.gen;
  st.report = res.report;
  if (st.sel && !findObj(st.sel) && !findFile(st.sel)) st.sel = null;
  if (!st.sel) {
    const first = res.report.objects.find((o) => o.worst === "error") || res.report.objects[0];
    st.sel = first ? first.id : null;
  }
  render();
}

const findObj = (id) => st.report && st.report.objects.find((o) => o.id === id);
const findFile = (id) => st.report && st.report.files.find((f) => f.id === id);

// ---------- rendering ----------
function render() {
  const r = st.report;
  const has = r && r.files.length > 0;
  $("drop").classList.toggle("hidden", !!has);
  $("view").classList.toggle("hidden", !has);
  $("sideEmpty").classList.toggle("hidden", !!has);
  renderCounts();
  renderSide();
  if (has) renderView();
}

function renderCounts() {
  const c = (st.report && st.report.counts) || {};
  const el = $("counts");
  if (!st.report || !st.report.files.length) { el.innerHTML = ""; return; }
  el.innerHTML = ["error", "warn", "info", "ok"].map((s) => `<span class="chip ${s}" title="${SEV[s]}">${c[s] || 0} ${SEV[s]}</span>`).join("");
}

function renderSide() {
  const r = st.report;
  const box = $("fileList");
  if (!r) { box.innerHTML = ""; return; }
  const objs = Object.fromEntries(r.objects.map((o) => [o.id, o]));
  box.innerHTML = r.files.map((f) => {
    const fw = f.findings.reduce((w, x) => (rank(x.sev) > rank(w) ? x.sev : w), "ok");
    const list = f.objects.map((id) => {
      const o = objs[id]; if (!o) return "";
      const nested = o.where.includes("→");
      return `<div class="obj ${nested ? "nested" : ""} ${st.sel === o.id ? "sel" : ""}" data-id="${o.id}">
        <span class="dot ${o.worst}"></span>
        <div class="lbl"><div class="t">${esc(o.label)}</div><div class="r">${esc(KIND[o.kind] || o.kind)}${o.role ? " · " + esc(o.role) : ""}</div></div></div>`;
    }).join("");
    const ff = f.findings.filter((x) => x.sev !== "ok").map((x) => `<div class="small" style="color:var(--${x.sev === "error" ? "err" : x.sev})">• ${esc(x.msg)}</div>`).join("");
    const pw = f.needsPassword ? `<div class="pw"><input type="password" placeholder="Password PKCS#12" data-pw="${f.id}"><button class="small" data-pwbtn="${f.id}">Buka</button></div>` : "";
    return `<div class="file">
      <div class="file-head"><span class="dot ${fw}" title="${SEV[fw]}"></span><div class="file-name">${esc(f.name)}</div><button class="x" data-rm="${f.id}" title="Hapus file">×</button></div>
      <div class="file-meta">${esc(f.format)} · ${fmtSize(f.size)}${f.origin === "online" ? " · diunduh" : ""}</div>
      ${ff ? `<div class="file-find">${ff}</div>` : ""}${pw}${list}</div>`;
  }).join("");
}

const rank = (s) => ({ error: 3, warn: 2, info: 1, ok: 0 }[s] ?? 0);
const fmtSize = (n) => (n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");

function renderView() {
  const v = $("view");
  const o = findObj(st.sel);
  const notes = (st.report.notes || []).filter((n) => n.sev !== "ok" || n.cat === "Online");
  const notesHtml = notes.length ? `<div class="notes">${notes.map(findingHtml).join("")}</div>` : "";
  if (!o) { v.innerHTML = notesHtml + `<p class="muted">Pilih objek di panel kiri.</p>`; return; }
  const file = findFile(o.fileId);
  const tabs = [["hasil", `Hasil (${o.findings.filter((f) => f.sev !== "ok").length})`], ["field", "Detail"]];
  if (o.chain && o.chain.length) tabs.push(["rantai", "Rantai"]);
  tabs.push(["asn1", "ASN.1"]);
  if (o.pem) tabs.push(["pem", "PEM"]);
  if (!tabs.some((t) => t[0] === st.tab)) st.tab = "hasil";
  v.innerHTML = `${notesHtml}
    <div class="vhead"><div style="flex:1">
      <h1>${esc(o.label)}</h1>
      <div class="sub"><span class="badge">${esc(KIND[o.kind] || o.kind)}</span>${o.role ? `<span class="badge">${esc(o.role)}</span>` : ""}${esc(file ? file.name : "")} · ${esc(o.where)}</div>
    </div>
    <div class="row">${o.pem ? `<button class="small" data-exp="pem">Simpan PEM</button><button class="small" data-exp="der">Simpan DER</button>` : ""}</div></div>
    ${verdictHtml(o)}
    <div class="tabs">${tabs.map(([k, l]) => `<button data-tab="${k}" class="${st.tab === k ? "on" : ""}">${esc(l)}</button>`).join("")}</div>
    <div id="tabBody"></div>`;
  renderTab(o);
}

function verdictHtml(o) {
  const c = o.counts || {};
  const msg = { error: "Ada masalah yang perlu diperbaiki", warn: "Valid dengan catatan", info: "Tidak ada error", ok: "Tidak ada masalah" }[o.worst];
  return `<div class="verdict ${o.worst}">${msg} <span>— ${c.error || 0} error · ${c.warn || 0} peringatan · ${c.info || 0} info · ${c.ok || 0} lolos</span></div>`;
}

function renderTab(o) {
  const b = $("tabBody");
  if (st.tab === "hasil") {
    const fl = o.findings.filter((f) => st.filter === "all" || f.sev === st.filter);
    b.innerHTML = `${o.summary.length ? `<table class="kv">${o.summary.map((kv) => `<tr><td>${esc(kv.k)}</td><td>${esc(kv.v)}</td></tr>`).join("")}</table>` : ""}
      <div class="filters">${["all", "error", "warn", "info", "ok"].map((s) => `<button data-filter="${s}" class="${st.filter === s ? "on" : ""}">${s === "all" ? "Semua" : SEV[s]} (${s === "all" ? o.findings.length : (o.counts[s] || 0)})</button>`).join("")}</div>
      ${fl.map(findingHtml).join("") || `<p class="muted">Tidak ada temuan untuk filter ini.</p>`}`;
  } else if (st.tab === "field") {
    b.innerHTML = `<div class="tree-tools"><button class="small" data-tree="open">Buka semua</button><button class="small" data-tree="close">Tutup semua</button><button class="small" data-copy="fields">Salin</button></div><div class="tree">${treeHtml(o.fields, 0)}</div>`;
  } else if (st.tab === "rantai") {
    b.innerHTML = `<div class="chain">${o.chain.map((l, i) => `<div class="link"><div class="rail"><div class="node ${l.status}"></div>${i < o.chain.length - 1 ? `<div class="line"></div>` : ""}</div>
      <div class="card ${l.id ? "click" : ""}" ${l.id ? `data-go="${l.id}"` : ""}><div><b>${esc(l.label)}</b></div><div class="muted">${esc(l.note || "")}</div></div></div>`).join("")}</div>
      <p class="muted small">Urutan dari sertifikat ini (atas) menuju trust anchor (bawah). Klik kartu untuk membuka sertifikatnya.</p>`;
  } else if (st.tab === "asn1") {
    b.innerHTML = `<p class="muted"><span class="spin"></span>Memuat struktur ASN.1…</p>`;
    const id = o.id;
    call("ASN1", id).then((tree) => {
      if (st.sel !== id || st.tab !== "asn1") return;
      b.innerHTML = `<div class="tree-tools"><button class="small" data-tree="open">Buka semua</button><button class="small" data-tree="close">Tutup semua</button></div><div class="tree">${treeHtml(tree || [], 0, true)}</div>`;
    });
  } else if (st.tab === "pem") {
    b.innerHTML = `<div class="row" style="margin-bottom:8px"><button class="small" data-copy="pem">Salin PEM</button></div><pre class="pem">${esc(o.pem)}</pre>`;
  }
}

function findingHtml(f) {
  return `<div class="f ${f.sev}"><div class="ic">${ICON[f.sev]}</div><div style="flex:1;min-width:0">
    <div class="cat">${esc(f.cat)}</div><div class="msg">${esc(f.msg)}</div>
    ${f.detail ? `<div class="det">${esc(f.detail)}</div>` : ""}${f.ref ? `<div class="ref">${esc(f.ref)}</div>` : ""}</div></div>`;
}

function treeHtml(nodes, depth, asn1) {
  return (nodes || []).map((n) => {
    const head = `<span class="n">${esc(n.n)}</span>${n.v ? ` <span class="v">${esc(n.v)}</span>` : ""}`;
    if (n.k && n.k.length) {
      const open = asn1 ? depth < 3 : depth < 1;
      return `<details ${open ? "open" : ""}><summary>${head}</summary>${treeHtml(n.k, depth + 1, asn1)}</details>`;
    }
    return `<div class="leaf">${head}</div>`;
  }).join("");
}

function fieldsText(nodes, ind = "") {
  return (nodes || []).map((n) => ind + n.n + (n.v ? ": " + n.v : "") + "\n" + fieldsText(n.k, ind + "  ")).join("");
}

// ---------- events ----------
document.addEventListener("click", async (e) => {
  const t = e.target.closest("button, .obj, [data-go], a");
  if (!t) { $("exportMenu").classList.remove("open"); return; }
  if (t.id !== "btnExport") $("exportMenu").classList.remove("open");
  const d = t.dataset;
  if (t.classList.contains("obj")) { st.sel = d.id; st.filter = "all"; renderSide(); renderView(); return; }
  if (d.go) { st.sel = d.go; renderSide(); renderView(); return; }
  if (d.tab) { st.tab = d.tab; renderView(); return; }
  if (d.filter) { st.filter = d.filter; renderTab(findObj(st.sel)); return; }
  if (d.rm) { apply(await call("Remove", d.rm)); return; }
  if (d.pwbtn) { const i = document.querySelector(`[data-pw="${d.pwbtn}"]`); apply(await call("SetPassword", d.pwbtn, i ? i.value : "")); return; }
  if (d.exp) { toast(await call("ExportObject", st.sel, d.exp)); return; }
  if (d.fmt) { toast(await call("ExportReport", d.fmt), 4000); return; }
  if (d.tree) { document.querySelectorAll("#tabBody details").forEach((x) => (x.open = d.tree === "open")); return; }
  if (d.copy) {
    const o = findObj(st.sel);
    const text = d.copy === "pem" ? o.pem : fieldsText(o.fields);
    const ok = await call("CopyText", text);
    toast(ok ? "Disalin ke clipboard" : "Gagal menyalin");
    return;
  }
  switch (t.id) {
    case "btnOpen": case "linkOpen": e.preventDefault(); apply(await call("OpenFiles")); break;
    case "btnPaste": case "linkPaste": e.preventDefault(); openPaste(); break;
    case "btnClear": st.sel = null; apply(await call("Clear")); break;
    case "btnOpts": $("opts").classList.toggle("hidden"); break;
    case "btnExport": $("exportMenu").classList.toggle("open"); break;
    case "btnApply": applyOpts(); break;
    case "btnNow": $("optAt").value = ""; applyOpts(); break;
    case "btnOnline": runOnline(); break;
  }
});

document.addEventListener("keydown", (e) => {
  if (e.target.matches("input, textarea") && e.key === "Enter" && e.target.dataset.pw) {
    document.querySelector(`[data-pwbtn="${e.target.dataset.pw}"]`).click();
  }
  if (e.target.matches("input, textarea")) {
    if (e.key === "Enter" && e.target.closest("#opts")) applyOpts();
    return;
  }
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "o") { e.preventDefault(); $("btnOpen").click(); }
  if (["ArrowDown", "ArrowUp"].includes(e.key) && st.report) {
    const ids = st.report.objects.map((o) => o.id);
    const i = ids.indexOf(st.sel);
    const n = e.key === "ArrowDown" ? Math.min(ids.length - 1, i + 1) : Math.max(0, i - 1);
    if (ids[n]) { st.sel = ids[n]; renderSide(); renderView(); document.querySelector(".obj.sel")?.scrollIntoView({ block: "nearest" }); e.preventDefault(); }
  }
});

// paste anywhere (outside inputs) analyzes the clipboard text directly
document.addEventListener("paste", async (e) => {
  if (e.target.matches("input, textarea")) return;
  const text = e.clipboardData && e.clipboardData.getData("text");
  if (text && text.trim()) { e.preventDefault(); apply(await call("AddText", text)); }
});

function openPaste() {
  $("pasteText").value = "";
  $("pasteDlg").showModal();
}
$("pasteDlg").addEventListener("close", async () => {
  if ($("pasteDlg").returnValue === "ok") apply(await call("AddText", $("pasteText").value));
});

async function applyOpts() {
  const at = $("optAt").value;
  const opts = {
    hostname: $("optHost").value.trim(),
    at: at ? at.replace("T", " ") : "",
    online: false,
    systemTrust: $("optTrust").checked,
    profile: $("optProfile").value,
    expiryWarnDays: parseInt($("optExp").value, 10) || 30,
  };
  apply(await call("SetOptions", opts));
  toast("Opsi diterapkan");
}

async function runOnline() {
  if (st.onlineBusy) return;
  const btn = $("btnOnline");
  st.onlineBusy = true;
  btn.disabled = true;
  btn.innerHTML = `<span class="spin"></span>Mengunduh…`;
  toast("Mengunduh CRL / OCSP / issuer… aplikasi tetap bisa dipakai", 3500);
  try { apply(await call("Analyze", true)); }
  finally { st.onlineBusy = false; btn.disabled = false; btn.textContent = "Cek online"; }
}

// files dropped on the window arrive from Go as "result" events
function bindRuntime() {
  if (!window.runtime) { setTimeout(bindRuntime, 100); return; }
  window.runtime.EventsOn("result", (res) => apply(res));
}
window.addEventListener("dragover", (e) => { e.preventDefault(); document.body.classList.add("dragging"); });
window.addEventListener("dragleave", () => document.body.classList.remove("dragging"));
window.addEventListener("drop", (e) => { e.preventDefault(); document.body.classList.remove("dragging"); });

async function init() {
  bindRuntime();
  const wait = () => new Promise((r) => setTimeout(r, 50));
  for (let i = 0; i < 100 && !api(); i++) await wait();
  const o = await call("GetOptions");
  if (o) {
    $("optHost").value = o.hostname || "";
    $("optProfile").value = o.profile || "auto";
    $("optTrust").checked = !!o.systemTrust;
    $("optExp").value = o.expiryWarnDays || 30;
  }
  const v = await call("Version");
  if (v) document.title = "X.509 Inspector " + v;
  render();
}
init();
