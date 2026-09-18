"use strict";

/* ============================================================
   app.js — SPA controller for the w1r3hound console.
   Wires the dashboard UI to the real Go backend:
     • Console   — launch scans + live SSE engine output
     • Overview  — aggregate stats from /api/scans
     • Scans     — real scan history
     • Findings  — parsed from report.json (+ local triage)
     • Settings  — token, authorised-use notice, local state
   CSP-safe: no inline handlers, event delegation only.
   ============================================================ */

document.addEventListener("DOMContentLoaded", () => {
  const $ = (s, c = document) => c.querySelector(s);
  const $$ = (s, c = document) => [...c.querySelectorAll(s)];
  const esc = Utils.escapeHTML;

  const TRIAGE_KEY = "w1r3hound_triage";
  const TRIAGE_STATES = ["open", "in-progress", "fixed", "accepted", "false-positive"];

  const state = {
    modules: [],
    scans: [],
    currentPage: "overview",
    consoleScanId: null,
    lastRenderedConsoleId: null,
    es: null,
    pollTimer: null,
    logs: {},              // scanId -> [lines]
    findingScanId: null,
    findingsCache: {},     // scanId -> [findings]
    findingFilters: { severity: "all", status: "all", q: "", sort: "severity" },
    scanFilters: { status: "all", sort: "newest", q: "" },
    triage: loadTriage(),
    serverOk: true,
    auth: { enabled: false, user: null },
    users: [],
    workflows: [],
    booted: false,
    chatConvoId: null,
    chatConvos: [],
    chatMessages: [],
    chatStreaming: false,
  };

  function loadTriage() {
    try { return JSON.parse(localStorage.getItem(TRIAGE_KEY) || "{}"); } catch (_) { return {}; }
  }
  function saveTriage() {
    try { localStorage.setItem(TRIAGE_KEY, JSON.stringify(state.triage)); } catch (_) {}
  }
  function triageKey(scanId, idx) { return `${scanId}::${idx}`; }
  function triageOf(scanId, idx) { return state.triage[triageKey(scanId, idx)] || "open"; }

  const scanById = (id) => state.scans.find((s) => s.id === id);

  /* ── Toast ────────────────────────────────────────────── */
  function toast(msg, type = "info") {
    const c = $("#toast-container");
    const t = document.createElement("div");
    t.className = `toast toast-${type}`;
    t.textContent = msg;
    c.appendChild(t);
    requestAnimationFrame(() => t.classList.add("show"));
    setTimeout(() => { t.classList.remove("show"); setTimeout(() => t.remove(), 300); }, 3400);
  }

  /* ── Modal ────────────────────────────────────────────── */
  function openModal(html, cls = "") {
    const box = $("#modal-box");
    box.className = "modal-box" + (cls ? " " + cls : "");
    box.innerHTML = html;
    $("#modal-overlay").classList.add("open");
  }
  function closeModal() { $("#modal-overlay").classList.remove("open"); }

  /* ── Detail panel ─────────────────────────────────────── */
  function openPanel(html) {
    $("#detail-panel-body").innerHTML = html;
    $("#detail-panel").classList.add("open");
  }
  function closePanel() { $("#detail-panel").classList.remove("open"); }

  /* ── Navigation ───────────────────────────────────────── */
  const navItems = $$(".sidebar-nav-item[data-page]");
  const pageViews = $$(".page-view");

  function navigateTo(pageId) {
    state.currentPage = pageId;
    navItems.forEach((i) => i.classList.toggle("active", i.dataset.page === pageId));
    pageViews.forEach((v) => v.classList.toggle("active", v.id === "page-" + pageId));
    history.replaceState(null, "", "#" + pageId);
    renderPage(pageId);
  }
  navItems.forEach((i) => i.addEventListener("click", () => navigateTo(i.dataset.page)));

  /* ── Sidebar collapse ─────────────────────────────────── */
  $(".sidebar-collapse").addEventListener("click", () => {
    const sb = $(".sidebar");
    sb.classList.toggle("collapsed");
    const svg = $(".sidebar-collapse svg");
    if (svg) svg.style.transform = sb.classList.contains("collapsed") ? "rotate(180deg)" : "";
  });

  function renderPage(page) {
    switch (page) {
      case "overview": renderOverview(); break;
      case "audits": renderScans(); break;
      case "findings": renderFindings(); break;
      case "console": renderConsole(); break;
      case "chat": renderChat(); break;
      case "account": renderAccount(); break;
      case "settings": renderSettings(); break;
    }
  }

  /* ══════════════════════════════════════════════════════
     DATA / POLLING
     ══════════════════════════════════════════════════════ */
  async function refreshScans() {
    try {
      const scans = await API.scans();
      state.scans = scans;
      setServerStatus(true);
      renderPage(state.currentPage);
      schedulePolling();
    } catch (err) {
      setServerStatus(false);
    }
  }

  function schedulePolling() {
    const active = state.scans.some((s) => s.status === "running" || s.status === "queued");
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    if (active) state.pollTimer = setTimeout(refreshScans, 4000);
  }

  function setServerStatus(ok) {
    state.serverOk = ok;
    const led = $("#server-status-led");
    const txt = $("#server-status-text");
    if (led) led.classList.toggle("off", !ok);
    if (txt) txt.textContent = ok ? "127.0.0.1:8737 · local only" : "server unreachable";
  }

  function aggregate() {
    const s = state.scans;
    const done = s.filter((x) => x.status === "done");
    const running = s.filter((x) => x.status === "running" || x.status === "queued");
    const failed = s.filter((x) => x.status === "failed" || x.status === "cancelled");
    const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    let totalFindings = 0;
    s.forEach((x) => {
      if (x.counts) { const n = Utils.normCounts(x.counts); Utils.SEV_KEYS.forEach((k) => sev[k] += n[k]); }
      totalFindings += x.total_findings || 0;
    });
    const targets = new Set(s.map((x) => x.target).filter(Boolean));
    const finished = done.length + failed.length;
    return {
      total: s.length, done: done.length, running: running.length, failed: failed.length,
      targets: targets.size, totalFindings, sev,
      successRate: finished ? Math.round((done.length / finished) * 100) : 0,
      perScan: done.length ? (totalFindings / done.length).toFixed(1) : "0.0",
    };
  }

  /* ══════════════════════════════════════════════════════
     OVERVIEW
     ══════════════════════════════════════════════════════ */
  function renderOverview() {
    const a = aggregate();
    const days = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];
    const months = ["January","February","March","April","May","June","July","August","September","October","November","December"];
    const now = new Date();
    $("#overview-date").textContent = `${days[now.getDay()]}, ${months[now.getMonth()]} ${now.getDate()}`;

    $("#stat-scans").textContent = a.total;
    $("#stat-findings").textContent = a.totalFindings;
    $("#stat-critical").textContent = a.sev.critical + " critical";
    $("#stat-targets").textContent = a.targets;
    $("#stat-running").textContent = a.running;

    Utils.SEV_KEYS.forEach((k) => { const el = $("#count-" + k); if (el) el.textContent = a.sev[k]; });

    renderDonut(a);
    $("#legend-done").textContent = a.done;
    $("#legend-running").textContent = a.running;
    $("#legend-failed").textContent = a.failed;
    $("#metric-total").textContent = a.total;
    $("#metric-per-scan").textContent = a.perScan;
    $("#metric-success").textContent = (a.done + a.failed) > 0 ? a.successRate + "%" : "—";

    renderRecentScans();
    renderWorkflows();
  }

  function renderDonut(a) {
    const svg = $("#donut-svg");
    if (!svg) return;
    const total = a.done + a.running + a.failed;
    const segs = [
      { count: a.done, color: "var(--accent-green)" },
      { count: a.running, color: "var(--accent-cyan)" },
      { count: a.failed, color: "var(--accent-red)" },
    ];
    const cx = 55, r = 42, w = 7, circ = 2 * Math.PI * r;
    let offset = 0, arcs = "";
    if (total > 0) {
      arcs = segs.map((seg) => {
        if (!seg.count) return "";
        const len = (seg.count / total) * circ;
        const h = `<circle cx="${cx}" cy="${cx}" r="${r}" fill="none" stroke="${seg.color}" stroke-width="${w}" stroke-dasharray="${len} ${circ - len}" stroke-dashoffset="${-offset}" transform="rotate(-90 ${cx} ${cx})" stroke-linecap="round"/>`;
        offset += len;
        return h;
      }).join("");
    }
    svg.innerHTML =
      `<circle cx="55" cy="55" r="42" fill="none" stroke="#1e1e22" stroke-width="7"/>${arcs}` +
      `<text x="55" y="52" text-anchor="middle" fill="#fafafa" font-size="20" font-weight="600">${a.successRate}%</text>` +
      `<text x="55" y="66" text-anchor="middle" fill="#52525b" font-size="9" font-weight="600" letter-spacing="0.1em">SUCCESS</text>`;
  }

  function renderRecentScans() {
    const box = $("#recent-scans-body");
    const scans = state.scans.slice(0, 6);
    if (!scans.length) {
      box.innerHTML = `<div class="empty-state" style="padding:30px 20px"><p style="margin-bottom:0">No scans yet. <a class="js-new-scan">Start your first scan →</a></p></div>`;
      return;
    }
    box.innerHTML = scans.map((s) => `
      <div class="recent-audit-row" data-scan="${esc(s.id)}" style="grid-template-columns:1fr 130px 110px 90px">
        <div class="ra-target">${esc(s.target || s.id)}</div>
        <div>${Utils.scanStatusBadge(s.status)}</div>
        <div class="ra-findings">${s.has_report ? (s.total_findings + " findings") : "—"}</div>
        <div class="ra-time">${esc(Utils.timeAgo(s.started_at || s.created_at))}</div>
      </div>`).join("");
  }

  /* ── Workflow cards ─────────────────────────────────── */
  const wfIcons = {
    target: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    link: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>',
    radar: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 2a10 10 0 0110 10"/><path d="M12 2a10 10 0 016.93 4"/><line x1="12" y1="12" x2="12" y2="2"/></svg>',
    shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    microscope: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M12 12v6"/><line x1="8" y1="22" x2="16" y2="22"/><line x1="12" y1="18" x2="12" y2="22"/></svg>',
  };

  function renderWorkflows() {
    const box = $("#wf-grid");
    if (!box || !state.workflows.length) { if (box) box.innerHTML = ""; return; }
    box.innerHTML = state.workflows.map((w) => `
      <div class="wf-card" data-wf='${esc(JSON.stringify(w.defaults || {}))}'>
        <div class="wf-icon">${wfIcons[w.icon] || wfIcons.target}</div>
        <div class="wf-title">${esc(w.title)}</div>
        <div class="wf-desc">${esc(w.description)}</div>
      </div>`).join("");
  }

  function prefillScanModal(defaults) {
    openScanModal();
    setTimeout(() => {
      if (defaults.source === "mcp") { const cb = $("#scan-mcp"); if (cb) { cb.checked = true; cb.dispatchEvent(new Event("change")); } }
      if (defaults.passive != null) { const cb = $("#scan-passive"); if (cb) cb.checked = !!defaults.passive; }
      if (defaults.concurrency) { const el = $("#scan-concurrency"); if (el) el.value = defaults.concurrency; }
      if (defaults.rate) { const el = $("#scan-rate"); if (el) el.value = defaults.rate; }
      if (defaults.ports) { const el = $("#scan-ports"); if (el) el.value = defaults.ports; }
      if (defaults.timeout_sec) { const el = $("#scan-timeout"); if (el) el.value = defaults.timeout_sec; }
      if (defaults.dir_ext) { const el = $("#scan-dir-ext"); if (el) el.value = defaults.dir_ext; }
      if (defaults.wayback_limit) { const el = $("#scan-wayback"); if (el) el.value = defaults.wayback_limit; }
      if (defaults.crawl_pages) { const el = $("#scan-crawl"); if (el) el.value = defaults.crawl_pages; }
      if (defaults.js_files) { const el = $("#scan-js"); if (el) el.value = defaults.js_files; }
      if (defaults.modules && state.modules.length) {
        setAllModules(false);
        const mods = new Set(Array.isArray(defaults.modules) ? defaults.modules : [defaults.modules]);
        $$(".mod-check").forEach((cb) => { if (mods.has(cb.value)) cb.checked = true; });
        updateModulesCount();
      }
    }, 50);
  }

  /* ══════════════════════════════════════════════════════
     SCANS
     ══════════════════════════════════════════════════════ */
  function filteredScans() {
    let r = [...state.scans];
    const f = state.scanFilters;
    if (f.status !== "all") r = r.filter((s) => s.status === f.status);
    if (f.q) { const q = f.q.toLowerCase(); r = r.filter((s) => (s.target || "").toLowerCase().includes(q) || s.id.toLowerCase().includes(q)); }
    if (f.sort === "oldest") r.reverse();
    return r;
  }

  function renderScans() {
    $("#scans-count").textContent = state.scans.length;
    const body = $("#scans-body");
    const scans = filteredScans();
    if (!scans.length) {
      const filtering = state.scanFilters.status !== "all" || state.scanFilters.q;
      body.innerHTML = `
        <div class="card"><div class="empty-state">
          <div class="empty-icon"><svg viewBox="0 0 24 24"><line x1="4" y1="6" x2="20" y2="6"/><line x1="4" y1="12" x2="20" y2="12"/><line x1="4" y1="18" x2="20" y2="18"/></svg></div>
          <h3>No scans${filtering ? " match" : " yet"}</h3>
          <p>Point w1r3hound at a target you are authorised to test to run your first scan.</p>
          <button class="btn-secondary js-new-scan">+ New scan</button>
        </div></div>`;
      return;
    }
    body.innerHTML = `<div class="card audit-list">${scans.map((s) => {
      const live = s.status === "running" || s.status === "queued";
      return `
      <div class="audit-row" data-scan="${esc(s.id)}">
        <div class="audit-row-main">
          <div class="audit-row-target">${esc(s.target || s.id)}</div>
          <div class="audit-row-meta">
            ${Utils.scanStatusBadge(s.status)}${s.source === "mcp" ? ' <span class="source-badge source-mcp">MCP</span>' : ""}
            <span class="audit-row-findings">${s.has_report ? (s.total_findings + " findings") : "no report"}</span>
            <span>${esc(Utils.fmtDate(s.started_at || s.created_at))}</span>
            <span>${esc(Utils.fmtDuration(s.started_at, s.ended_at))}</span>
          </div>
        </div>
        <div class="audit-row-actions">
          <button class="icon-btn js-open-console" title="Open console" data-scan="${esc(s.id)}">
            <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M7 8l4 4-4 4"/><line x1="13" y1="16" x2="17" y2="16"/></svg>
          </button>
          ${s.has_report ? `<button class="icon-btn js-open-findings" title="View findings" data-scan="${esc(s.id)}">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 8v4"/><circle cx="12" cy="16" r="0.5" fill="currentColor"/></svg>
          </button>` : ""}
          ${live ? `<button class="btn-mini danger js-cancel-scan" data-scan="${esc(s.id)}">■ cancel</button>` : ""}
        </div>
      </div>`;
    }).join("")}</div>`;
  }

  /* ══════════════════════════════════════════════════════
     FINDINGS
     ══════════════════════════════════════════════════════ */
  function completedScans() { return state.scans.filter((s) => s.has_report); }

  function renderFindings() {
    const sel = $("#finding-scan-select");
    const completed = completedScans();

    if (!completed.length) {
      sel.innerHTML = `<option value="">No completed scans</option>`;
      $("#findings-tbody").innerHTML = emptyFindings("Findings appear here once a scan produces a report.");
      Utils.SEV_KEYS.forEach((k) => { const el = $("#fstat-" + k); if (el) el.textContent = 0; });
      $("#fstat-total").textContent = 0;
      state.findingScanId = null;
      return;
    }

    if (!state.findingScanId || !completed.some((s) => s.id === state.findingScanId)) {
      state.findingScanId = completed[0].id;
    }
    sel.innerHTML = completed.map((s) =>
      `<option value="${esc(s.id)}" ${s.id === state.findingScanId ? "selected" : ""}>${esc(s.target || s.id)} · ${s.total_findings} findings</option>`
    ).join("");

    loadAndRenderFindings(state.findingScanId);
  }

  async function loadAndRenderFindings(scanId) {
    let findings = state.findingsCache[scanId];
    if (!findings) {
      $("#findings-tbody").innerHTML = `<div class="empty-state"><p>Loading report…</p></div>`;
      try {
        const report = await API.report(scanId);
        findings = (report.findings || []).map((f, idx) => ({
          idx,
          module: f.module || "?",
          wstg: f.wstg_id || "",
          title: f.title || "(untitled)",
          description: f.description || "",
          severity: Utils.sevKey(f.severity),
          target: report.target || "",
          data: f.data,
        }));
        state.findingsCache[scanId] = findings;
      } catch (err) {
        $("#findings-tbody").innerHTML = `<div class="empty-state"><h3>Could not load report</h3><p>${esc(err.message)}</p></div>`;
        return;
      }
    }
    if (state.findingScanId !== scanId) return; // selection changed while loading
    renderFindingsTable(scanId, findings);
  }

  function renderFindingsTable(scanId, findings) {
    // status bar counts (of the whole report)
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => counts[f.severity]++);
    $("#fstat-total").textContent = findings.length;
    Utils.SEV_KEYS.forEach((k) => { const el = $("#fstat-" + k); if (el) el.textContent = counts[k]; });

    // filter + sort
    const f = state.findingFilters;
    let rows = findings.filter((x) => {
      if (f.severity !== "all" && x.severity !== f.severity) return false;
      if (f.status !== "all" && triageOf(scanId, x.idx) !== f.status) return false;
      if (f.q) {
        const q = f.q.toLowerCase();
        if (!(x.title.toLowerCase().includes(q) || x.module.toLowerCase().includes(q) || (x.wstg || "").toLowerCase().includes(q))) return false;
      }
      return true;
    });
    if (f.sort === "module") rows.sort((a, b) => a.module.localeCompare(b.module));
    else if (f.sort === "title") rows.sort((a, b) => a.title.localeCompare(b.title));
    else rows.sort((a, b) => Utils.sevRank(b.severity) - Utils.sevRank(a.severity));

    const body = $("#findings-tbody");
    if (!rows.length) { body.innerHTML = emptyFindings("No findings match the current filters."); return; }
    body.innerHTML = rows.map((x) => {
      const st = triageOf(scanId, x.idx);
      const sub = [x.target, x.wstg].filter(Boolean).join(" · ");
      return `
      <div class="finding-row" data-finding="${x.idx}">
        <div class="finding-title-cell">
          <div class="finding-title">${esc(x.title)}</div>
          <div class="finding-sub">${esc(sub)}</div>
        </div>
        <div class="finding-cell">${Utils.sevBadge(x.severity)}</div>
        <div class="finding-cell"><span class="status-chip status-${st}">${st.replace("-", " ")}</span></div>
        <div class="finding-cell"><span class="finding-module">${esc(x.module)}</span></div>
      </div>`;
    }).join("");
  }

  function emptyFindings(msg) {
    return `<div class="empty-state">
      <div class="empty-icon"><svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg></div>
      <h3>No findings</h3><p>${esc(msg)}</p></div>`;
  }

  function openFindingDetail(idx) {
    const scanId = state.findingScanId;
    const findings = state.findingsCache[scanId] || [];
    const f = findings.find((x) => x.idx === idx);
    if (!f) return;
    const st = triageOf(scanId, idx);
    openPanel(`
      <div class="panel-section">
        <div class="panel-top-row">${Utils.sevBadge(f.severity)}${f.wstg ? `<span class="panel-cvss">WSTG ${esc(f.wstg)}</span>` : ""}</div>
        <h2 class="panel-title">${esc(f.title)}</h2>
        <div class="panel-meta">
          <span>Module: <strong>${esc(f.module)}</strong></span>
          ${f.target ? `<span>Target: <strong>${esc(f.target)}</strong></span>` : ""}
          ${f.wstg ? `<span>WSTG: <strong>${esc(f.wstg)}</strong></span>` : ""}
        </div>
      </div>
      <div class="panel-section">
        <label class="panel-label">Triage status</label>
        <select class="form-select js-triage-select" data-finding="${idx}">
          ${TRIAGE_STATES.map((s) => `<option value="${s}" ${st === s ? "selected" : ""}>${s.replace("-", " ")}</option>`).join("")}
        </select>
      </div>
      ${f.description ? `<div class="panel-section"><label class="panel-label">Description</label><p class="panel-text">${esc(f.description)}</p></div>` : ""}
      ${renderDataSection(f.data)}
    `);
  }

  function renderDataSection(data) {
    if (data == null) return "";
    let inner = "";
    if (Array.isArray(data)) {
      const items = data.slice(0, 60).map((x) => `<li><code>${esc(String(x))}</code></li>`).join("");
      const more = data.length > 60 ? `<li>…and ${data.length - 60} more</li>` : "";
      inner = `<ul class="panel-data">${items}${more}</ul>`;
    } else if (typeof data === "object") {
      inner = `<ul class="panel-data">${Object.entries(data).slice(0, 60).map(([k, v]) =>
        `<li><span class="kv-key">${esc(k)}</span><code>${esc(String(v))}</code></li>`).join("")}</ul>`;
    } else {
      inner = `<ul class="panel-data"><li><code>${esc(String(data))}</code></li></ul>`;
    }
    return `<div class="panel-section"><label class="panel-label">Data</label>${inner}</div>`;
  }

  function exportFindings() {
    const scanId = state.findingScanId;
    const findings = state.findingsCache[scanId] || [];
    if (!findings.length) { toast("No findings to export", "error"); return; }
    const headers = ["Title", "Severity", "Module", "WSTG", "Triage", "Target", "Description"];
    const row = (arr) => arr.map((c) => '"' + String(c == null ? "" : c).replace(/"/g, '""') + '"').join(",");
    const csv = [row(headers), ...findings.map((f) =>
      row([f.title, Utils.sevLabel(f.severity), f.module, f.wstg, triageOf(scanId, f.idx), f.target, f.description]))].join("\n");
    downloadBlob(csv, "text/csv", `w1r3hound-findings-${scanId}.csv`);
    toast("Findings exported", "success");
  }

  function downloadBlob(content, type, name) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
  }

  /* ══════════════════════════════════════════════════════
     CONSOLE
     ══════════════════════════════════════════════════════ */
  function renderConsole() {
    const empty = $("#console-empty");
    const active = $("#console-active");
    if (!state.scans.length) {
      empty.hidden = false; active.hidden = true;
      state.lastRenderedConsoleId = null;
      return;
    }
    empty.hidden = true; active.hidden = false;

    if (!state.consoleScanId || !scanById(state.consoleScanId)) {
      state.consoleScanId = state.scans[0].id;
      loadConsoleStream(state.consoleScanId);
    }

    // Tabs
    $("#console-tabs").innerHTML = state.scans.slice(0, 12).map((s) => `
      <button class="console-tab ${s.id === state.consoleScanId ? "active" : ""}" data-console-tab="${esc(s.id)}">
        <span class="console-tab-dot ${esc(s.status)}"></span>
        <span class="console-tab-label">${esc(s.target || s.id)}</span>
      </button>`).join("");

    updateConsoleHeader();

    // Rebuild terminal only when the shown scan changed (SSE appends live).
    if (state.lastRenderedConsoleId !== state.consoleScanId) {
      renderTerminal();
      state.lastRenderedConsoleId = state.consoleScanId;
    }
  }

  function updateConsoleHeader() {
    const s = scanById(state.consoleScanId);
    if (!s) return;
    $("#console-target").textContent = s.target || s.id;
    $("#console-mods").textContent = s.id;
    $("#console-status").innerHTML = Utils.scanStatusBadge(s.status);

    const bar = $("#console-progress-bar");
    const label = $("#console-progress-label");
    const live = s.status === "running" || s.status === "queued";
    bar.classList.toggle("indeterminate", live);
    bar.style.background = "";
    if (live) { bar.style.width = ""; label.textContent = s.status; }
    else {
      bar.style.width = "100%";
      if (s.status === "failed") bar.style.background = "var(--accent-red)";
      else if (s.status === "cancelled") bar.style.background = "var(--accent-gray)";
      label.textContent = s.status === "done" ? "done" : s.status;
    }

    $("#btn-console-cancel").hidden = !(live && s.live);

    const dlLog = $("#dl-log"), dlJson = $("#dl-json"), dlMd = $("#dl-md");
    dlLog.hidden = false; dlLog.href = API.logUrl(s.id);
    dlJson.hidden = !s.has_report; dlJson.href = API.reportUrl(s.id, "json");
    dlMd.hidden = !s.has_report; dlMd.href = API.reportUrl(s.id, "md");
  }

  function renderTerminal() {
    const term = $("#console-terminal");
    const lines = state.logs[state.consoleScanId] || [];
    term.innerHTML = lines.map(logLineHTML).join("") || `<span class="log-plain">Waiting for output…</span>`;
    term.scrollTop = term.scrollHeight;
  }

  function logLineHTML(line) {
    return `<span class="log-line ${Utils.classifyLogLine(line)}">${esc(line)}</span>`;
  }

  function appendTerminalLine(scanId, line) {
    (state.logs[scanId] = state.logs[scanId] || []).push(line);
    if (state.currentPage === "console" && state.consoleScanId === scanId) {
      const term = $("#console-terminal");
      if (term) {
        if (term.children.length === 1 && term.firstChild.textContent === "Waiting for output…") term.innerHTML = "";
        term.insertAdjacentHTML("beforeend", logLineHTML(line));
        while (term.childElementCount > 6000) term.removeChild(term.firstChild);
        if ($("#log-autoscroll").checked) term.scrollTop = term.scrollHeight;
      }
    }
  }

  function openConsole(scanId) {
    state.consoleScanId = scanId;
    navigateTo("console");
    loadConsoleStream(scanId);
  }

  // Attach the live SSE stream (in-memory jobs) or fetch the static log
  // file (scans recovered from disk after a server restart).
  async function loadConsoleStream(scanId) {
    if (state.es) { state.es.close(); state.es = null; }
    state.logs[scanId] = [];
    state.lastRenderedConsoleId = null;
    const s = scanById(scanId);
    if (state.currentPage === "console") renderConsole();

    if (s && s.live) {
      const es = new EventSource(API.eventsUrl(scanId));
      state.es = es;
      es.addEventListener("log", (ev) => {
        let line = ev.data;
        try { line = JSON.parse(ev.data).line; } catch (_) {}
        appendTerminalLine(scanId, line);
      });
      es.addEventListener("status", (ev) => {
        try {
          const sum = JSON.parse(ev.data);
          const existing = scanById(scanId);
          if (existing) Object.assign(existing, sum);
          appendTerminalLine(scanId, `[webui] status: ${sum.status} (exit ${sum.exit_code ?? "?"})`);
        } catch (_) {}
        es.close(); state.es = null;
        if (state.currentPage === "console") updateConsoleHeader();
        refreshScans();
      });
      es.onerror = () => {
        if (es.readyState === EventSource.CLOSED) { state.es = null; }
      };
    } else if (s) {
      try {
        const res = await fetch(API.logUrl(scanId));
        const text = await res.text();
        state.logs[scanId] = text.split("\n").filter((l) => l.length);
      } catch (_) {
        state.logs[scanId] = ["[webui] log unavailable for this scan"];
      }
      if (state.currentPage === "console" && state.consoleScanId === scanId) { state.lastRenderedConsoleId = null; renderConsole(); }
    }
  }

  async function cancelScan(scanId) {
    try {
      await API.cancel(scanId);
      toast("Cancellation requested", "info");
      appendTerminalLine(scanId, "[webui] cancellation requested…");
      refreshScans();
    } catch (err) {
      toast("Cancel failed: " + err.message, "error");
    }
  }

  /* ══════════════════════════════════════════════════════
     NEW SCAN MODAL
     ══════════════════════════════════════════════════════ */
  function openScanModal() {
    openModal(`
      <div class="modal-header"><h2>New scan</h2><button class="modal-close">&times;</button></div>
      <div class="modal-body">
        <div class="form-group">
          <label>Target <code>-t</code></label>
          <input type="text" id="scan-target" class="form-input mono" placeholder="example.com · 10.10.10.10 · 192.168.1.0/24 · https://host:8080/path" autofocus>
        </div>

        <div class="form-group modules-box">
          <label>Modules <code>-m</code></label>
          <div class="modules-actions">
            <button type="button" class="btn-mini" id="mods-all">all</button>
            <button type="button" class="btn-mini" id="mods-none">none</button>
            <button type="button" class="btn-mini" id="mods-passive">passive only</button>
            <span class="modules-count" id="modules-count"></span>
          </div>
          <div class="modules-list" id="modules-list">${modulesPickerHTML()}</div>
        </div>

        <div class="form-grid-2">
          <div class="form-group"><label>Concurrency <code>-c</code></label><input type="number" id="scan-concurrency" class="form-input" min="1" max="500" value="20"></div>
          <div class="form-group"><label>Ports <code>-p</code></label>
            <select id="scan-ports" class="form-select"><option value="top100" selected>top100</option><option value="1-1024">1-1024</option><option value="full">full</option></select>
          </div>
          <div class="form-group"><label>Rate (req/s, 0=∞) <code>-rate</code></label><input type="number" id="scan-rate" class="form-input" min="0" max="10000" value="0"></div>
          <div class="form-group"><label>Timeout (s) <code>-timeout</code></label><input type="number" id="scan-timeout" class="form-input" min="1" max="300" value="10"></div>
        </div>

        <div class="form-group"><label>User-Agent <code>-ua</code></label><input type="text" id="scan-ua" class="form-input" placeholder="(default: Chrome / Linux)"></div>

        <div class="form-grid-2">
          <div class="form-group"><label>Subdomain wordlist <code>-w</code></label><input type="text" id="scan-wordlist" class="form-input mono" placeholder="empty = embedded list">
            <div class="field-hint">Must live inside <code>webui/wordlists/</code></div></div>
          <div class="form-group"><label>Output name <code>-o</code></label><input type="text" id="scan-output" class="form-input mono" placeholder="empty = automatic"></div>
        </div>

        <div class="form-group form-checks">
          <label class="form-check"><input type="checkbox" id="scan-mcp"> <span>MCP in-process <code>source: mcp</code> — run scan via the MCP bridge (in-process, no subprocess)</span></label>
          <label class="form-check"><input type="checkbox" id="scan-passive" checked> <span>Passive mode <code>-passive</code> — no active traffic; active modules are skipped</span></label>
          <label class="form-check"><input type="checkbox" id="scan-verbose"> <span>Verbose <code>-v</code></span></label>
        </div>

        <details class="adv-section">
          <summary>Advanced options <span class="adv-hint">CLI parity — dir-brute, headers, TLS, egress, resolvers, caps</span></summary>
          <div class="form-grid-2">
            <div class="form-group"><label>Dir-brute wordlist <code>-dir-wordlist</code></label><input type="text" id="scan-dir-wordlist" class="form-input mono" placeholder="empty = embedded list">
              <div class="field-hint">Must live inside <code>webui/wordlists/</code></div></div>
            <div class="form-group"><label>Dir-brute extensions <code>-dir-ext</code></label><input type="text" id="scan-dir-ext" class="form-input mono" placeholder=".bak,.php,.zip,~"></div>
          </div>
          <div class="form-group"><label>Custom headers <code>-H</code></label>
            <textarea id="scan-headers" class="form-input mono" rows="3" placeholder="X-Api-Key: secret"></textarea>
            <div class="field-hint">One <code>Name: value</code> per line. Passed as argv to the CLI (visible via <code>ps</code>) — avoid long-lived secrets.</div></div>
          <div class="form-grid-2">
            <div class="form-group"><label>DNS resolver <code>-resolver</code></label><input type="text" id="scan-resolver" class="form-input mono" placeholder="1.1.1.1 or 8.8.8.8:53"></div>
            <div class="form-group"><label>Resolver list <code>-resolvers</code></label><input type="text" id="scan-resolvers" class="form-input mono" placeholder="empty = system / -resolver">
              <div class="field-hint">Must live inside <code>webui/wordlists/</code></div></div>
          </div>
          <div class="form-grid-3">
            <div class="form-group"><label>Wayback cap <code>-wayback-limit</code></label><input type="number" id="scan-wayback" class="form-input" min="0" max="100000" placeholder="5000"></div>
            <div class="form-group"><label>Crawl pages <code>-crawl-pages</code></label><input type="number" id="scan-crawl" class="form-input" min="0" max="5000" placeholder="100"></div>
            <div class="form-group"><label>JS files <code>-js-files</code></label><input type="number" id="scan-js" class="form-input" min="0" max="2000" placeholder="50"></div>
          </div>
          <div class="form-group form-checks">
            <label class="form-check"><input type="checkbox" id="scan-verify-tls"> <span>Verify TLS certificate <code>-skip-tls-verify=false</code> — off (default) mirrors the CLI; recon often hits broken/self-signed TLS</span></label>
            <label class="form-check"><input type="checkbox" id="scan-block-egress"> <span>Block private/internal egress <code>-block-private-egress</code> — SSRF guard; refuses loopback/private/link-local dials</span></label>
          </div>
        </details>

        <div class="auth-box">
          <label class="form-check"><input type="checkbox" id="scan-authorized"> <span><strong>I am authorised to scan this target.</strong> Use only against systems you have explicit permission to test.</span></label>
        </div>

        <p class="form-error" id="scan-error" hidden></p>
      </div>
      <div class="modal-footer">
        <button class="btn-secondary" id="scan-cancel">Cancel</button>
        <button class="btn-primary" id="scan-launch">▶ Launch scan</button>
      </div>
    `, "modal-lg");

    wireModulePicker($("#modules-list"));
    updateModulesCount();
    if (!state.modules.length) {
      API.modules().then((m) => {
        state.modules = m;
        const list = $("#modules-list");
        if (list) { list.innerHTML = modulesPickerHTML(); wireModulePicker(list); updateModulesCount(); }
      }).catch((e) => { console.error("modules fetch:", e); });
    }
    $("#mods-all").addEventListener("click", () => { setAllModules(true); });
    $("#mods-none").addEventListener("click", () => { setAllModules(false); });
    $("#mods-passive").addEventListener("click", () => setPassiveModules());
    $("#scan-cancel").addEventListener("click", closeModal);
    $("#scan-launch").addEventListener("click", launchScan);
    $("#scan-target").addEventListener("keydown", (e) => { if (e.key === "Enter") launchScan(); });
    $("#scan-mcp").addEventListener("change", (e) => {
      const tf = $("#scan-timeout");
      tf.max = e.target.checked ? 1800 : 300;
      if (parseInt(tf.value, 10) > parseInt(tf.max, 10)) tf.value = tf.max;
    });
  }

  function modulesPickerHTML() {
    if (!state.modules.length) return `<p style="color:var(--text-dim);font-size:12px">Loading modules…</p>`;
    const byCat = new Map();
    state.modules.forEach((m) => { if (!byCat.has(m.category)) byCat.set(m.category, []); byCat.get(m.category).push(m); });
    let html = "";
    for (const [cat, mods] of byCat) {
      html += `<div class="mod-cat">
        <div class="mod-cat-head"><input type="checkbox" class="mod-cat-check" checked> ${esc(cat)} <span style="color:var(--text-faint)">(${mods.length})</span></div>
        ${mods.map((m) => `
          <label class="mod-item" title="${esc(m.desc)}">
            <input type="checkbox" class="mod-check" value="${esc(m.internal)}" checked>
            <span class="mod-alias">${esc(m.alias)}</span>
            <span class="mod-internal">${esc(m.internal)}</span>
            <span class="mod-badge ${m.active ? "active" : "passive"}">${m.active ? "active" : "passive"}</span>
            <span class="mod-desc">${esc(m.desc)}</span>
          </label>`).join("")}
      </div>`;
    }
    return html;
  }

  function wireModulePicker(root) {
    $$(".mod-cat", root).forEach((catDiv) => {
      const head = $(".mod-cat-check", catDiv);
      head.addEventListener("change", () => {
        $$(".mod-check", catDiv).forEach((cb) => { cb.checked = head.checked; });
        updateModulesCount();
      });
      $$(".mod-check", catDiv).forEach((cb) => cb.addEventListener("change", () => { syncCategoryChecks(); updateModulesCount(); }));
    });
  }
  function setAllModules(on) {
    $$("#modules-list .mod-check").forEach((cb) => { cb.checked = on; });
    $$("#modules-list .mod-cat-check").forEach((cb) => { cb.checked = on; });
    updateModulesCount();
  }
  function setPassiveModules() {
    const passive = new Set(state.modules.filter((m) => !m.active).map((m) => m.internal));
    $$("#modules-list .mod-check").forEach((cb) => { cb.checked = passive.has(cb.value); });
    syncCategoryChecks();
    updateModulesCount();
  }
  function syncCategoryChecks() {
    $$("#modules-list .mod-cat").forEach((catDiv) => {
      const items = $$(".mod-check", catDiv);
      const checked = items.filter((c) => c.checked);
      const head = $(".mod-cat-check", catDiv);
      if (head) head.checked = items.length > 0 && items.length === checked.length;
    });
  }
  function selectedModules() {
    const all = $$("#modules-list .mod-check");
    const sel = all.filter((c) => c.checked).map((c) => c.value);
    return sel.length === all.length ? [] : sel; // [] = all (omit -m)
  }
  function updateModulesCount() {
    const all = $$("#modules-list .mod-check");
    const sel = all.filter((c) => c.checked);
    const el = $("#modules-count");
    if (el) el.textContent = all.length && sel.length === all.length ? "all selected" : `${sel.length}/${all.length}`;
  }

  async function launchScan() {
    const errEl = $("#scan-error");
    errEl.hidden = true;
    const target = ($("#scan-target").value || "").trim();
    if (!target) { showScanError("Enter a target to scan."); return; }
    if (!$("#scan-authorized").checked) { showScanError("You must confirm you are authorised to scan this target."); return; }

    const body = {
      target,
      modules: selectedModules(),
      concurrency: parseInt($("#scan-concurrency").value, 10) || 0,
      ports: $("#scan-ports").value,
      wordlist: ($("#scan-wordlist").value || "").trim(),
      passive: $("#scan-passive").checked,
      rate: parseInt($("#scan-rate").value, 10) || 0,
      timeout_sec: parseInt($("#scan-timeout").value, 10) || 0,
      user_agent: ($("#scan-ua").value || "").trim(),
      output: ($("#scan-output").value || "").trim(),
      verbose: $("#scan-verbose").checked,
      authorized: true,
    };

    // ── CLI-parity advanced options ──
    Object.assign(body, {
      dir_wordlist: ($("#scan-dir-wordlist").value || "").trim(),
      dir_ext: ($("#scan-dir-ext").value || "").trim(),
      headers: ($("#scan-headers").value || "").split("\n").map((s) => s.trim()).filter(Boolean),
      block_private_egress: $("#scan-block-egress").checked,
      resolver: ($("#scan-resolver").value || "").trim(),
      resolvers: ($("#scan-resolvers").value || "").trim(),
      wayback_limit: parseInt($("#scan-wayback").value, 10) || 0,
      crawl_pages: parseInt($("#scan-crawl").value, 10) || 0,
      js_files: parseInt($("#scan-js").value, 10) || 0,
    });
    // Only send skip_tls_verify when the operator opts into verification; a
    // missing field means "use the CLI default" (skip). See docs/CLI_PARITY.md.
    if ($("#scan-verify-tls").checked) body.skip_tls_verify = false;
    if ($("#scan-mcp").checked) body.source = "mcp";

    const btn = $("#scan-launch");
    btn.disabled = true;
    try {
      const res = await API.startScan(body);
      closeModal();
      toast(`Scan launched on ${target}`, "success");
      await refreshScans();
      openConsole(res.id);
    } catch (err) {
      showScanError(err.message);
    } finally {
      btn.disabled = false;
    }
  }
  function showScanError(msg) {
    const el = $("#scan-error");
    el.textContent = msg; el.hidden = false;
  }

  /* ══════════════════════════════════════════════════════
     SETTINGS
     ══════════════════════════════════════════════════════ */
  function renderSettings() {
    const body = $("#settings-body");
    body.innerHTML = `
      <div class="legal-banner">
        <strong>Authorised use only.</strong> This console runs offensive reconnaissance. Use it only against
        targets you have explicit permission to test (bug bounty, CTF, contracted pentest). Unauthorised access
        may be a crime in your jurisdiction.
        <span class="legal-resp">Responsible disclosure: report findings through the program's official channels.</span>
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">Connection</h3>
        <div class="settings-row">
          <div>
            <div class="settings-label">Auth token</div>
            <div class="settings-desc">Required only if the server was started with <code>W1R3HOUND_UI_TOKEN</code>. Sent as the <code>X-Auth-Token</code> header on scan &amp; cancel requests.</div>
          </div>
          <div class="settings-control"><input type="password" id="set-token" class="form-input mono" placeholder="token (optional)" autocomplete="off"></div>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Bind address</div><div class="settings-desc">The GUI is hard-bound to loopback and refuses cross-origin / rebinding requests.</div></div>
          <div class="settings-control"><span class="scan-status-badge scan-done">127.0.0.1:8737</span></div>
        </div>
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">Reports &amp; data</h3>
        <div class="settings-row">
          <div><div class="settings-label">Report storage</div><div class="settings-desc">JSON, Markdown and raw logs are written to <code>webui/results/</code> on the host.</div></div>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Clear local triage state</div><div class="settings-desc">Removes the finding triage labels stored in this browser. Reports on disk are untouched.</div></div>
          <div class="settings-control"><button class="btn-danger" id="btn-clear-local">Clear</button></div>
        </div>
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">AI Chat</h3>
        <div class="settings-row">
          <div><div class="settings-label">Anthropic API key</div><div class="settings-desc">Required for the AI Chat feature. Your key is stored on the server, never sent to the browser.</div></div>
          <div class="settings-control"><input type="password" id="set-chat-apikey" class="form-input mono" placeholder="sk-ant-..." autocomplete="off"></div>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Model</div><div class="settings-desc">Claude model to use for chat.</div></div>
          <div class="settings-control"><input type="text" id="set-chat-model" class="form-input mono" placeholder="claude-sonnet-4-20250514"></div>
        </div>
        <div class="settings-row">
          <div><div class="settings-label">Max tokens</div><div class="settings-desc">Maximum response tokens per LLM call.</div></div>
          <div class="settings-control"><input type="number" id="set-chat-maxtokens" class="form-input mono" placeholder="4096" min="256" max="32768" step="256"></div>
        </div>
        <div class="settings-row">
          <div></div>
          <div class="settings-control"><button class="btn btn-accent" id="btn-save-chat-config">Save AI settings</button> <span id="chat-config-status" class="dim"></span></div>
        </div>
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">About</h3>
        <div class="settings-row">
          <div><div class="settings-label">w1r3hound</div><div class="settings-desc">Wiretap-grade offensive recon · OWASP WSTG · dependency-free local GUI.</div></div>
        </div>
      </div>
    `;
    const tokenInput = $("#set-token");
    tokenInput.value = API.getToken();
    tokenInput.addEventListener("change", () => { API.setToken(tokenInput.value); toast("Token saved", "success"); });
    $("#btn-clear-local").addEventListener("click", () => {
      state.triage = {}; saveTriage();
      toast("Local triage state cleared", "info");
      if (state.currentPage === "findings") renderFindings();
    });
    // Load current chat config
    API.chatConfig().then(cfg => {
      if (cfg.model) $("#set-chat-model").value = cfg.model;
      if (cfg.max_tokens) $("#set-chat-maxtokens").value = cfg.max_tokens;
      $("#chat-config-status").textContent = cfg.configured ? "✓ Key set" : "Not configured";
    }).catch((e) => { console.error("chat config fetch:", e); });
    $("#btn-save-chat-config").addEventListener("click", async () => {
      try {
        const body = {};
        const key = $("#set-chat-apikey").value.trim();
        if (key) body.api_key = key;
        const model = $("#set-chat-model").value.trim();
        if (model) body.model = model;
        const mt = parseInt($("#set-chat-maxtokens").value, 10);
        if (mt > 0) body.max_tokens = mt;
        const res = await API.setChatConfig(body);
        $("#set-chat-apikey").value = "";
        $("#chat-config-status").textContent = res.configured ? "✓ Key set" : "Not configured";
        toast("AI Chat settings saved", "success");
      } catch (err) { toast("Failed: " + err.message, "error"); }
    });
  }

  /* ══════════════════════════════════════════════════════
     AUTH GATE / ACCOUNT
     ══════════════════════════════════════════════════════ */
  function setGatePanel(panel) {
    const gate = $("#auth-gate"); if (gate) gate.hidden = false;
    const app = $(".app-layout"); if (app) app.hidden = true;
    const map = { loading: "#auth-loading", login: "#auth-login", setup: "#auth-setup" };
    Object.entries(map).forEach(([k, sel]) => { const el = $(sel); if (el) el.hidden = k !== panel; });
    const focusId = { login: "#login-username", setup: "#setup-username" }[panel];
    if (focusId) { const el = $(focusId); if (el) setTimeout(() => el.focus(), 30); }
  }
  function hideGate() {
    const gate = $("#auth-gate"); if (gate) gate.hidden = true;
    const app = $(".app-layout"); if (app) app.hidden = false;
  }
  function showAuthError(id, msg) { const el = $("#" + id); if (el) { el.textContent = msg; el.hidden = false; } }
  function hideAuthError(id) { const el = $("#" + id); if (el) el.hidden = true; }

  async function bootAuth() {
    setGatePanel("loading");
    let status;
    try { status = await API.status(); }
    catch (_) {
      setServerStatus(false);
      setGatePanel("login");
      showAuthError("login-error", "Cannot reach the server on 127.0.0.1:8737.");
      return;
    }
    state.auth.enabled = !!status.enabled;
    if (!status.enabled) { state.auth.user = status.user || null; await enterApp(); return; }
    if (status.authenticated) { state.auth.user = status.user; await enterApp(); return; }
    setGatePanel(status.setup_required ? "setup" : "login");
  }

  async function enterApp() {
    hideGate();
    updateUserBox();
    if (!state.booted) {
      state.booted = true;
      try { state.modules = await API.modules(); } catch (_) { /* shown on modal open */ }
      try { state.workflows = await API.workflows(); } catch (_) {}
    }
    await refreshScans();
    const initPage = (window.location.hash.replace("#", "") || "overview");
    const valid = ["overview", "audits", "findings", "console", "chat", "account", "settings"];
    navigateTo(valid.includes(initPage) ? initPage : "overview");
    if (state.auth.user && state.auth.user.must_change_password) {
      toast("Please change your administrator-set password.", "info");
      navigateTo("account");
    }
  }

  function updateUserBox() {
    const nameEl = $("#sb-user-name"), roleEl = $("#sb-user-role"), av = $("#sb-user-avatar"), logout = $("#sb-logout");
    const u = state.auth.user;
    if (u && state.auth.enabled) {
      if (nameEl) nameEl.textContent = u.username;
      if (roleEl) roleEl.textContent = u.role === "admin" ? "administrator" : "user";
      if (av) av.textContent = ((u.username || "w")[0] || "w").toUpperCase();
      if (logout) logout.hidden = false;
    } else {
      if (nameEl) nameEl.textContent = "wiretap-grade recon";
      if (roleEl) roleEl.textContent = "loopback GUI";
      if (av) av.textContent = "w1";
      if (logout) logout.hidden = true;
    }
  }

  async function handleLogin() {
    const u = ($("#login-username").value || "").trim();
    const p = $("#login-password").value || "";
    hideAuthError("login-error");
    if (!u || !p) { showAuthError("login-error", "Enter your username and password."); return; }
    const btn = $("#login-submit"); btn.disabled = true;
    try {
      const res = await API.login(u, p);
      state.auth.user = res.user;
      $("#login-password").value = "";
      await enterApp();
    } catch (err) {
      showAuthError("login-error", err.message || "Login failed.");
    } finally { btn.disabled = false; }
  }

  async function handleSetup() {
    const u = ($("#setup-username").value || "").trim();
    const p = $("#setup-password").value || "";
    const p2 = $("#setup-password2").value || "";
    hideAuthError("setup-error");
    if (p !== p2) { showAuthError("setup-error", "Passwords do not match."); return; }
    if (p.length < 12) { showAuthError("setup-error", "Use at least 12 characters."); return; }
    const btn = $("#setup-submit"); btn.disabled = true;
    try {
      const res = await API.setup(u, p);
      state.auth.enabled = true;
      state.auth.user = res.user;
      $("#setup-password").value = ""; $("#setup-password2").value = "";
      await enterApp();
    } catch (err) {
      showAuthError("setup-error", err.message || "Setup failed.");
    } finally { btn.disabled = false; }
  }

  async function handleLogout() {
    try { await API.logout(); } catch (_) {}
    state.auth.user = null;
    if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; }
    if (state.es) { state.es.close(); state.es = null; }
    setGatePanel("login");
    const un = $("#login-username"); if (un) un.value = "";
    hideAuthError("login-error");
  }

  function renderAccount() {
    const body = $("#account-body");
    if (!state.auth.enabled) {
      body.innerHTML = `
        <div class="legal-banner">
          <strong>Login panel not configured.</strong> This console is running in open loopback mode — any local
          process that can reach 127.0.0.1:8737 can use it. Create an administrator account to require a sign-in.
        </div>
        <div class="settings-section">
          <h3 class="settings-section-title">Enable authentication</h3>
          <div class="settings-row">
            <div><div class="settings-label">Create the first administrator</div>
            <div class="settings-desc">You will be signed in, and from then on a username &amp; password are required for everyone.</div></div>
            <div class="settings-control"><button class="btn-primary" data-action="enable-auth">Set up login</button></div>
          </div>
        </div>`;
      return;
    }
    const u = state.auth.user || {};
    const isAdmin = u.role === "admin";
    body.innerHTML = `
      <div class="settings-section">
        <h3 class="settings-section-title">Profile</h3>
        <div class="account-profile">
          <div class="account-avatar">${esc(((u.username || "?")[0] || "?").toUpperCase())}</div>
          <div>
            <div class="account-name">${esc(u.username || "")}</div>
            <div class="account-meta">
              <span class="role-badge role-${esc(u.role || "user")}">${esc(u.role || "user")}</span>
              <span>· since ${esc(Utils.fmtDate(u.created_at))}</span>
              ${u.last_login_at ? `<span>· last login ${esc(Utils.timeAgo(u.last_login_at))}</span>` : ""}
            </div>
          </div>
        </div>
        ${u.must_change_password ? `<div class="account-warn">You are using a password set by an administrator. Please change it now.</div>` : ""}
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">Change password</h3>
        <form id="account-pw-form" class="account-form" autocomplete="off">
          <div class="form-group"><label for="pw-current">Current password</label>
            <input id="pw-current" type="password" class="form-input" autocomplete="current-password" required></div>
          <div class="form-group"><label for="pw-new">New password</label>
            <input id="pw-new" type="password" class="form-input" autocomplete="new-password" required>
            <div class="field-hint">At least 12 characters. Changing it signs out every other session.</div></div>
          <div class="form-group"><label for="pw-new2">Confirm new password</label>
            <input id="pw-new2" type="password" class="form-input" autocomplete="new-password" required></div>
          <p class="form-error" id="pw-error" hidden></p>
          <button type="submit" class="btn-primary" id="pw-submit">Update password</button>
        </form>
      </div>

      <div class="settings-section">
        <h3 class="settings-section-title">Session</h3>
        <div class="settings-row">
          <div><div class="settings-label">Sign out</div><div class="settings-desc">End the session on this browser.</div></div>
          <div class="settings-control"><button class="btn-danger" data-action="logout">Sign out</button></div>
        </div>
      </div>

      ${isAdmin ? renderUsersSection() : ""}`;
    if (isAdmin) loadUsers();
  }

  function renderUsersSection() {
    return `
      <div class="settings-section">
        <div class="account-users-head">
          <h3 class="settings-section-title account-users-title">Users</h3>
          <button class="btn-mini" data-action="add-user">+ Add user</button>
        </div>
        <div class="users-table">
          <div class="users-row users-head-row"><span>User</span><span>Role</span><span>Status</span><span>Actions</span></div>
          <div id="users-tbody"><div class="users-empty">Loading users…</div></div>
        </div>
      </div>`;
  }

  async function loadUsers() {
    let users;
    try { users = await API.listUsers(); }
    catch (err) { const tb = $("#users-tbody"); if (tb) tb.innerHTML = `<div class="users-empty">${esc(err.message)}</div>`; return; }
    state.users = users;
    const tb = $("#users-tbody");
    if (!tb) return;
    const me = (state.auth.user || {}).username;
    tb.innerHTML = users.map((usr) => {
      const self = usr.username === me;
      const status = usr.locked
        ? `<span class="scan-status-badge scan-failed">locked</span>`
        : (usr.must_change_password ? `<span class="scan-status-badge scan-queued">must change</span>` : `<span class="scan-status-badge scan-done">active</span>`);
      return `
      <div class="users-row" data-user="${esc(usr.username)}">
        <span class="users-name">${esc(usr.username)}${self ? ` <span class="you-tag">you</span>` : ""}</span>
        <span><span class="role-badge role-${esc(usr.role)}">${esc(usr.role)}</span></span>
        <span>${status}</span>
        <span class="users-actions">
          <button class="btn-mini" data-action="reset-user" data-user="${esc(usr.username)}">reset pw</button>
          ${usr.locked ? `<button class="btn-mini" data-action="unlock-user" data-user="${esc(usr.username)}">unlock</button>` : ""}
          ${self ? "" : `<button class="btn-mini danger" data-action="delete-user" data-user="${esc(usr.username)}">delete</button>`}
        </span>
      </div>`;
    }).join("") || `<div class="users-empty">No users.</div>`;
  }

  async function handleChangePassword() {
    const cur = $("#pw-current").value;
    const nw = $("#pw-new").value;
    const nw2 = $("#pw-new2").value;
    hideAuthError("pw-error");
    if (nw !== nw2) { showAuthError("pw-error", "New passwords do not match."); return; }
    if (nw.length < 12) { showAuthError("pw-error", "Use at least 12 characters."); return; }
    const btn = $("#pw-submit"); if (btn) btn.disabled = true;
    try {
      const res = await API.changePassword(cur, nw);
      if (res && res.user) state.auth.user = res.user;
      toast("Password updated", "success");
      renderAccount();
    } catch (err) { showAuthError("pw-error", err.message); }
    finally { if (btn) btn.disabled = false; }
  }

  function openAddUserModal() {
    openModal(`
      <div class="modal-header"><h2>Add user</h2><button class="modal-close">&times;</button></div>
      <div class="modal-body">
        <div class="form-group"><label for="nu-username">Username</label>
          <input id="nu-username" class="form-input" autocapitalize="none" spellcheck="false" placeholder="analyst">
          <div class="field-hint">3–32 chars: letters, numbers, <code>.</code> <code>_</code> <code>-</code></div></div>
        <div class="form-group"><label for="nu-password">Temporary password</label>
          <input id="nu-password" type="password" class="form-input" autocomplete="new-password">
          <div class="field-hint">At least 12 characters. The user must change it on first sign-in.</div></div>
        <div class="form-group"><label for="nu-role">Role</label>
          <select id="nu-role" class="form-select"><option value="user" selected>user</option><option value="admin">admin</option></select></div>
        <p class="form-error" id="nu-error" hidden></p>
      </div>
      <div class="modal-footer"><button class="btn-secondary modal-close">Cancel</button><button class="btn-primary" id="nu-submit">Create user</button></div>`);
    $("#nu-submit").addEventListener("click", submitNewUser);
  }

  async function submitNewUser() {
    const u = ($("#nu-username").value || "").trim();
    const p = $("#nu-password").value || "";
    const role = $("#nu-role").value;
    hideAuthError("nu-error");
    const btn = $("#nu-submit"); btn.disabled = true;
    try {
      await API.createUser(u, p, role);
      closeModal();
      toast(`User ${u} created`, "success");
      loadUsers();
    } catch (err) { showAuthError("nu-error", err.message); }
    finally { btn.disabled = false; }
  }

  function openResetPwModal(username) {
    openModal(`
      <div class="modal-header"><h2>Reset password</h2><button class="modal-close">&times;</button></div>
      <div class="modal-body">
        <p class="modal-note">Set a new temporary password for <strong>${esc(username)}</strong>. Existing sessions are revoked and the user must change it on next sign-in.</p>
        <div class="form-group"><label for="rp-password">New password</label>
          <input id="rp-password" type="password" class="form-input" autocomplete="new-password"></div>
        <p class="form-error" id="rp-error" hidden></p>
      </div>
      <div class="modal-footer"><button class="btn-secondary modal-close">Cancel</button><button class="btn-primary" id="rp-submit">Reset password</button></div>`);
    $("#rp-submit").addEventListener("click", () => submitReset(username));
  }

  async function submitReset(username) {
    const p = $("#rp-password").value || "";
    hideAuthError("rp-error");
    const btn = $("#rp-submit"); btn.disabled = true;
    try {
      await API.resetPassword(username, p);
      closeModal();
      toast(`Password reset for ${username}`, "success");
      loadUsers();
    } catch (err) { showAuthError("rp-error", err.message); }
    finally { btn.disabled = false; }
  }

  function confirmDeleteUser(username) {
    openModal(`
      <div class="modal-header"><h2>Delete user</h2><button class="modal-close">&times;</button></div>
      <div class="modal-body"><p class="modal-note">Delete <strong>${esc(username)}</strong>? This revokes their sessions and cannot be undone.</p></div>
      <div class="modal-footer"><button class="btn-secondary modal-close">Cancel</button><button class="btn-danger" id="del-user-confirm">Delete user</button></div>`);
    $("#del-user-confirm").addEventListener("click", async () => {
      try { await API.deleteUser(username); closeModal(); toast(`User ${username} deleted`, "success"); loadUsers(); }
      catch (err) { toast(err.message, "error"); }
    });
  }

  async function unlockUser(username) {
    try { await API.unlockUser(username); toast(`${username} unlocked`, "success"); loadUsers(); }
    catch (err) { toast(err.message, "error"); }
  }

  // Auth-related delegated events (kept separate from the main handlers).
  document.addEventListener("submit", (e) => {
    const f = e.target;
    if (f.id === "auth-login") { e.preventDefault(); handleLogin(); }
    else if (f.id === "auth-setup") { e.preventDefault(); handleSetup(); }
    else if (f.id === "account-pw-form") { e.preventDefault(); handleChangePassword(); }
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("#sb-logout")) { handleLogout(); return; }
    const actionEl = e.target.closest("[data-action]");
    if (!actionEl) return;
    const action = actionEl.dataset.action;
    const user = actionEl.dataset.user;
    if (action === "logout") handleLogout();
    else if (action === "enable-auth") setGatePanel("setup");
    else if (action === "add-user") openAddUserModal();
    else if (action === "reset-user") openResetPwModal(user);
    else if (action === "unlock-user") unlockUser(user);
    else if (action === "delete-user") confirmDeleteUser(user);
  });

  /* ══════════════════════════════════════════════════════
     GLOBAL EVENT DELEGATION
     ══════════════════════════════════════════════════════ */
  document.addEventListener("click", (e) => {
    const t = e.target;

    if (t.closest(".js-new-scan")) { e.preventDefault(); openScanModal(); return; }
    const wfCard = t.closest(".wf-card");
    if (wfCard) { try { prefillScanModal(JSON.parse(wfCard.dataset.wf)); } catch (_) { openScanModal(); } return; }

    const navEl = t.closest("[data-nav]");
    if (navEl) { e.preventDefault(); navigateTo(navEl.dataset.nav); return; }

    if (t.closest(".modal-close")) { closeModal(); return; }
    if (t.closest(".detail-panel-close")) { closePanel(); return; }

    // Open console from a scan row / recent row / console tab
    const consoleBtn = t.closest(".js-open-console");
    if (consoleBtn) { e.stopPropagation(); openConsole(consoleBtn.dataset.scan); return; }
    const findingsBtn = t.closest(".js-open-findings");
    if (findingsBtn) { e.stopPropagation(); state.findingScanId = findingsBtn.dataset.scan; navigateTo("findings"); return; }
    const cancelBtn = t.closest(".js-cancel-scan");
    if (cancelBtn) { e.stopPropagation(); cancelScan(cancelBtn.dataset.scan); return; }

    const tab = t.closest("[data-console-tab]");
    if (tab) { openConsole(tab.dataset.consoleTab); return; }

    const recent = t.closest("[data-scan]");
    if (recent && recent.classList.contains("recent-audit-row")) { openConsole(recent.dataset.scan); return; }
    const auditRow = t.closest(".audit-row[data-scan]");
    if (auditRow) { openConsole(auditRow.dataset.scan); return; }

    const findingRow = t.closest(".finding-row[data-finding]");
    if (findingRow) { openFindingDetail(parseInt(findingRow.dataset.finding, 10)); return; }

    if (t.closest("#btn-export-findings")) { exportFindings(); return; }
    if (t.closest("#btn-refresh-scans")) { refreshScans(); return; }
    if (t.closest("#btn-clear-log")) { const term = $("#console-terminal"); if (term) term.innerHTML = ""; if (state.consoleScanId) state.logs[state.consoleScanId] = []; return; }
    if (t.closest("#btn-console-cancel")) { if (state.consoleScanId) cancelScan(state.consoleScanId); return; }
    if (t.closest("#btn-new-chat")) { createNewChat(); return; }
    if (t.closest("#btn-chat-send")) { sendChatMessage(); return; }
    const convoDelete = t.closest(".chat-convo-delete");
    if (convoDelete) { e.stopPropagation(); deleteChatConvo(convoDelete.dataset.id); return; }
    const convoItem = t.closest(".chat-convo-item");
    if (convoItem) { loadChatMessages(convoItem.dataset.id); return; }
  });

  // Modal / panel backdrop
  $("#modal-overlay").addEventListener("click", (e) => { if (e.target === e.currentTarget) closeModal(); });
  $("#detail-panel-overlay").addEventListener("click", closePanel);

  // Change events (filters, triage)
  document.addEventListener("change", (e) => {
    const t = e.target;
    if (t.id === "filter-scan-status") { state.scanFilters.status = t.value; renderScans(); }
    if (t.id === "filter-severity") { state.findingFilters.severity = t.value; renderFindings(); }
    if (t.id === "filter-status") { state.findingFilters.status = t.value; renderFindings(); }
    if (t.id === "filter-fsort") { state.findingFilters.sort = t.value; renderFindings(); }
    if (t.id === "finding-scan-select") { state.findingScanId = t.value; renderFindings(); }
    if (t.classList && t.classList.contains("js-triage-select")) {
      const idx = parseInt(t.dataset.finding, 10);
      state.triage[triageKey(state.findingScanId, idx)] = t.value;
      saveTriage();
      toast("Triage updated", "success");
      renderFindings();
    }
  });

  // Search inputs
  document.addEventListener("input", (e) => {
    const t = e.target;
    if (t.id === "search-audits") { state.scanFilters.q = t.value; renderScans(); }
    if (t.id === "search-findings") { state.findingFilters.q = t.value; renderFindings(); }
    if (t.id === "chat-textarea") {
      t.style.height = "auto";
      t.style.height = Math.min(t.scrollHeight, 120) + "px";
      const btn = $("#btn-chat-send");
      if (btn) btn.disabled = !t.value.trim() || state.chatStreaming;
    }
  });

  // Scan sort toggle + overview search
  document.addEventListener("click", (e) => {
    if (e.target.closest("#toggle-scan-sort")) {
      state.scanFilters.sort = state.scanFilters.sort === "newest" ? "oldest" : "newest";
      $("#toggle-scan-sort").textContent = `Sort: ${state.scanFilters.sort === "newest" ? "Newest" : "Oldest"} first ▾`;
      renderScans();
    }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.id === "search-overview") {
      const q = e.target.value.trim();
      if (q) { state.findingFilters.q = q; navigateTo("findings"); const sf = $("#search-findings"); if (sf) sf.value = q; }
    }
    if (e.key === "Escape") { closeModal(); closePanel(); }
    if (e.key === "Enter" && !e.shiftKey && e.target.id === "chat-textarea") {
      e.preventDefault();
      sendChatMessage();
    }
  });

  /* ── Decorative severity mini-charts ──────────────────── */
  function generateChart(id, color) {
    const c = document.getElementById(id);
    if (!c || c.children.length) return;
    [5,7,4,9,6,8,3,7,5,6,4,8,7,5,6,9,4,7,5,6].forEach((v) => {
      const bar = document.createElement("div");
      bar.className = "bar";
      bar.style.height = (v * 1.8) + "px";
      bar.style.background = color;
      c.appendChild(bar);
    });
  }

  /* ══════════════════════════════════════════════════════
     AI CHAT
     ══════════════════════════════════════════════════════ */
  async function renderChat() {
    await loadConversations();
    renderConvoList();
    const empty = $("#chat-empty");
    const bar = $("#chat-input-bar");
    if (state.chatConvoId) {
      if (empty) empty.hidden = true;
      if (bar) bar.hidden = false;
      await loadChatMessages(state.chatConvoId);
    } else {
      if (empty) empty.hidden = false;
      if (bar) bar.hidden = true;
      const msgs = $("#chat-messages");
      if (msgs) msgs.innerHTML = '<div class="chat-empty" id="chat-empty"><p>Select a conversation or start a new one.</p><p class="dim">AI Chat lets you interact with w1r3hound tools through natural language.</p></div>';
    }
  }

  async function loadConversations() {
    try { state.chatConvos = await API.chatConversations(); } catch (_) { state.chatConvos = []; }
  }

  function renderConvoList() {
    const el = $("#chat-convo-list");
    if (!el) return;
    if (!state.chatConvos.length) {
      el.innerHTML = '<div class="dim" style="padding:1rem;text-align:center">No conversations yet</div>';
      return;
    }
    el.innerHTML = state.chatConvos.map(c => `
      <div class="chat-convo-item${c.id === state.chatConvoId ? " active" : ""}" data-id="${Utils.escapeHTML(c.id)}">
        <div class="chat-convo-title">${Utils.escapeHTML(truncate(c.title, 40))}</div>
        <div class="chat-convo-meta">${c.message_count} msg · ${Utils.timeAgo(c.updated_at)}</div>
        <button class="chat-convo-delete" data-id="${Utils.escapeHTML(c.id)}" title="Delete">×</button>
      </div>
    `).join("");
  }

  async function loadChatMessages(id) {
    state.chatConvoId = id;
    renderConvoList();
    const bar = $("#chat-input-bar");
    const empty = $("#chat-empty");
    if (bar) bar.hidden = false;
    if (empty) empty.hidden = true;
    try {
      const convo = await API.chatGet(id);
      state.chatMessages = convo.messages || [];
      renderChatMessages();
    } catch (err) {
      toast("Failed to load conversation: " + err.message, "error");
    }
  }

  function renderChatMessages() {
    const el = $("#chat-messages");
    if (!el) return;
    if (!state.chatMessages.length) {
      el.innerHTML = '<div class="chat-empty-conv dim" style="padding:2rem;text-align:center">Send a message to start chatting.</div>';
      return;
    }
    el.innerHTML = state.chatMessages.filter(m => m.role === "user" || m.role === "assistant").map(m => `
      <div class="chat-bubble chat-${m.role}">
        <div class="chat-bubble-role">${m.role === "user" ? "You" : "w1r3hound"}</div>
        <div class="chat-bubble-text">${formatChatText(m.content)}</div>
      </div>
    `).join("");
    el.scrollTop = el.scrollHeight;
  }

  function formatChatText(text) {
    let s = Utils.escapeHTML(text);
    s = s.replace(/```([\s\S]*?)```/g, '<pre class="chat-code">$1</pre>');
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>');
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/\n/g, '<br>');
    return s;
  }

  function truncate(s, max) {
    if (!s) return "";
    return s.length > max ? s.slice(0, max) + "…" : s;
  }

  async function createNewChat() {
    try {
      const convo = await API.chatCreate("");
      state.chatConvoId = convo.id;
      state.chatMessages = [];
      await loadConversations();
      renderConvoList();
      renderChatMessages();
      const bar = $("#chat-input-bar");
      const empty = $("#chat-empty");
      if (bar) bar.hidden = false;
      if (empty) empty.hidden = true;
      const ta = $("#chat-textarea");
      if (ta) ta.focus();
    } catch (err) { toast("Failed to create conversation: " + err.message, "error"); }
  }

  async function deleteChatConvo(id) {
    if (!confirm("Delete this conversation?")) return;
    try {
      await API.chatDelete(id);
      if (state.chatConvoId === id) {
        state.chatConvoId = null;
        state.chatMessages = [];
      }
      await renderChat();
    } catch (err) { toast("Delete failed: " + err.message, "error"); }
  }

  async function sendChatMessage() {
    const ta = $("#chat-textarea");
    if (!ta) return;
    const msg = ta.value.trim();
    if (!msg || state.chatStreaming) return;
    if (!state.chatConvoId) return;

    state.chatStreaming = true;
    ta.value = "";
    ta.style.height = "auto";
    const btn = $("#btn-chat-send");
    if (btn) btn.disabled = true;

    state.chatMessages.push({ role: "user", content: msg, timestamp: new Date().toISOString() });
    renderChatMessages();

    // Start SSE stream
    const url = API.chatMessageUrl(state.chatConvoId);
    try {
      const headers = Object.assign({ "Content-Type": "application/json" }, API.authHeaders());
      const csrf = API.getCsrf();
      if (csrf) headers["X-CSRF-Token"] = csrf;
      const resp = await fetch(url, {
        method: "POST",
        headers,
        credentials: "same-origin",
        body: JSON.stringify({ message: msg }),
      });
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        throw new Error(err.error || `HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let assistantText = "";
      let bubbleAdded = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            switch (ev.type) {
              case "text":
                assistantText += ev.data;
                if (!bubbleAdded) {
                  state.chatMessages.push({ role: "assistant", content: "", timestamp: new Date().toISOString() });
                  bubbleAdded = true;
                }
                updateStreamingBubble(assistantText);
                break;
              case "tool_start":
                appendToolCard(ev.tool, ev.id, "running");
                break;
              case "tool_result":
                updateToolCard(ev.id, ev.data);
                break;
              case "error":
                toast("Chat error: " + ev.data, "error");
                break;
              case "done":
                if (bubbleAdded) {
                  state.chatMessages[state.chatMessages.length - 1].content = assistantText;
                }
                break;
            }
          } catch (_) { /* skip malformed SSE lines */ }
        }
      }
    } catch (err) {
      toast("Chat failed: " + err.message, "error");
    } finally {
      state.chatStreaming = false;
      if (btn) btn.disabled = !ta.value.trim();
    }
  }

  function updateStreamingBubble(text) {
    const el = $("#chat-messages");
    if (!el) return;
    let last = el.querySelector(".chat-bubble.chat-assistant:last-child");
    if (!last) {
      last = document.createElement("div");
      last.className = "chat-bubble chat-assistant";
      last.innerHTML = '<div class="chat-bubble-role">w1r3hound</div><div class="chat-bubble-text"></div>';
      el.appendChild(last);
    }
    const textEl = last.querySelector(".chat-bubble-text");
    if (textEl) textEl.innerHTML = formatChatText(text);
    el.scrollTop = el.scrollHeight;
  }

  function appendToolCard(tool, id, status) {
    const el = $("#chat-messages");
    if (!el) return;
    const card = document.createElement("div");
    card.className = "chat-tool";
    card.dataset.toolId = id;
    card.innerHTML = `<div class="chat-tool-label">⚙ ${Utils.escapeHTML(tool)} <span class="dim">${Utils.escapeHTML(status)}</span></div><div class="chat-tool-content"></div>`;
    el.appendChild(card);
    el.scrollTop = el.scrollHeight;
  }

  function updateToolCard(id, result) {
    const card = document.querySelector(`.chat-tool[data-tool-id="${CSS.escape(id)}"]`);
    if (!card) return;
    const label = card.querySelector(".chat-tool-label span");
    if (label) label.textContent = "done";
    const content = card.querySelector(".chat-tool-content");
    if (content) content.textContent = truncate(result, 500);
  }

  /* ══════════════════════════════════════════════════════
     INIT
     ══════════════════════════════════════════════════════ */
  async function init() {
    generateChart("chart-critical", "var(--accent-red)");
    generateChart("chart-high", "var(--accent-orange)");
    generateChart("chart-medium", "var(--accent-yellow)");
    generateChart("chart-low", "var(--accent-blue)");
    generateChart("chart-info", "var(--accent-gray)");

    // Fall back to the login screen if the session expires mid-use. Only acts
    // when the login panel is active — in open mode a 401 is the legacy shared
    // token gate, not a session, so we leave that flow untouched.
    API.setAuthHandler(() => {
      if (!state.auth.enabled) return;
      const gate = $("#auth-gate");
      if (gate && gate.hidden) {
        state.auth.user = null;
        setGatePanel("login");
        showAuthError("login-error", "Your session expired. Please sign in again.");
      }
    });

    await bootAuth();
  }

  init();
});
