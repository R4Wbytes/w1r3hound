"use strict";

/* ============================================================
   api.js — backend client + shared helpers for the w1r3hound
   console. Talks to the real Go webui server (REST + SSE).
   Exposes window.API and window.Utils (classic scripts, no
   modules, so app.js can use them directly).
   ============================================================ */

const TOKEN_KEY = "w1r3hound_token";

const API = (() => {
  // Legacy open-mode shared token (X-Auth-Token). The account-based login
  // panel uses an HttpOnly session cookie instead, so the session token is
  // never exposed to JavaScript.
  function getToken() {
    try { return localStorage.getItem(TOKEN_KEY) || ""; } catch (_) { return ""; }
  }
  function setToken(t) {
    try { localStorage.setItem(TOKEN_KEY, (t || "").trim()); } catch (_) {}
  }
  function authHeaders() {
    const t = getToken();
    return t ? { "X-Auth-Token": t } : {};
  }

  // CSRF synchroniser token, bound to the session and kept only in memory.
  let csrfToken = "";
  function getCsrf() { return csrfToken; }
  function setCsrf(t) { csrfToken = t || ""; }

  // Invoked when a request is rejected with 401 mid-session so the SPA can
  // fall back to the login screen. Set by app.js.
  let authHandler = null;
  function setAuthHandler(fn) { authHandler = fn; }
  const NO_GATE_ON_401 = new Set(["/api/auth/login", "/api/auth/setup", "/api/auth/status"]);

  async function req(path, opts = {}) {
    const method = (opts.method || "GET").toUpperCase();
    const headers = Object.assign({}, opts.headers || {}, authHeaders());
    if (csrfToken && method !== "GET" && method !== "HEAD") headers["X-CSRF-Token"] = csrfToken;
    opts.headers = headers;
    opts.credentials = "same-origin";
    const res = await fetch(path, opts);
    if (res.status === 401 && !NO_GATE_ON_401.has(path.split("?")[0]) && typeof authHandler === "function") {
      try { authHandler(); } catch (_) {}
    }
    return res;
  }

  async function json(path, opts = {}) {
    const res = await req(path, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-json body */ }
    // Any response may refresh the session-bound CSRF token.
    if (data && typeof data.csrf_token === "string") setCsrf(data.csrf_token);
    if (!res.ok) {
      const msg = (data && data.error) ? data.error : `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function postJSON(path, body) {
    return json(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
  }

  return {
    getToken, setToken, authHeaders, getCsrf, setCsrf, setAuthHandler,

    /* ── Auth / login panel ── */
    async status() { return json("/api/auth/status"); },
    async me() { return json("/api/auth/me"); },
    async login(username, password) { return postJSON("/api/auth/login", { username, password }); },
    async setup(username, password) { return postJSON("/api/auth/setup", { username, password }); },
    async logout() { try { return await postJSON("/api/auth/logout", {}); } finally { setCsrf(""); } },
    async changePassword(currentPassword, newPassword) {
      return postJSON("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword });
    },
    async listUsers() { const d = await json("/api/auth/users"); return (d && d.users) || []; },
    async createUser(username, password, role) { return postJSON("/api/auth/users", { username, password, role }); },
    async deleteUser(username) { return json(`/api/auth/users/${encodeURIComponent(username)}`, { method: "DELETE" }); },
    async resetPassword(username, newPassword) { return postJSON(`/api/auth/users/${encodeURIComponent(username)}/reset`, { new_password: newPassword }); },
    async unlockUser(username) { return postJSON(`/api/auth/users/${encodeURIComponent(username)}/unlock`, {}); },

    async modules() {
      const d = await json("/api/modules");
      return (d && d.modules) || [];
    },
    async scans() {
      const d = await json("/api/scans");
      return (d && d.scans) || [];
    },
    async scan(id) {
      return json(`/api/scans/${encodeURIComponent(id)}`);
    },
    async startScan(body) {
      return json("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
    },
    async cancel(id) {
      return json(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" });
    },
    async report(id) {
      const res = await req(`/api/scans/${encodeURIComponent(id)}/report.json`);
      if (!res.ok) throw new Error(`report unavailable (HTTP ${res.status})`);
      return res.json();
    },
    reportUrl(id, ext) { return `/api/scans/${encodeURIComponent(id)}/report.${ext}`; },
    logUrl(id) { return `/api/scans/${encodeURIComponent(id)}/log`; },
    eventsUrl(id) { return `/api/scans/${encodeURIComponent(id)}/events`; },
  };
})();

const Utils = (() => {
  const SEV_ORDER = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const SEV_KEYS = ["critical", "high", "medium", "low", "info"];

  function escapeHTML(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // Backend severities are UPPERCASE (CRITICAL/HIGH/…); dashboard CSS uses
  // lowercase tokens (sev-critical). Normalise everything to lowercase.
  function sevKey(s) {
    const k = String(s || "").toLowerCase().trim();
    return SEV_KEYS.includes(k) ? k : "info";
  }
  function sevLabel(s) { return sevKey(s).toUpperCase(); }
  function sevBadge(s) { const k = sevKey(s); return `<span class="sev-badge sev-${k}">${k}</span>`; }
  function sevRank(s) { return SEV_ORDER[sevKey(s)] || 0; }

  // Fold a per-severity counts map (any casing) into lowercase keys.
  function normCounts(counts) {
    const out = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (counts && typeof counts === "object") {
      for (const [k, v] of Object.entries(counts)) {
        const key = sevKey(k);
        out[key] = (out[key] || 0) + (Number(v) || 0);
      }
    }
    return out;
  }

  function timeAgo(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return "—";
    const s = Math.floor((Date.now() - d.getTime()) / 1000);
    if (s < 0) return "just now";
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  function fmtDate(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (isNaN(d)) return "—";
    return d.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  }
  function fmtDuration(startIso, endIso) {
    if (!startIso || !endIso) return "—";
    const ms = new Date(endIso) - new Date(startIso);
    if (isNaN(ms) || ms < 0) return "—";
    const sec = Math.round(ms / 1000);
    if (sec < 60) return sec + "s";
    const m = Math.floor(sec / 60), r = sec % 60;
    if (m < 60) return `${m}m ${r}s`;
    return `${Math.floor(m / 60)}h ${m % 60}m`;
  }

  // Colour classification for a raw engine log line.
  function classifyLogLine(line) {
    const m = line.match(/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/i);
    if (m) return "log-sev-" + m[1].toLowerCase();
    if (line.startsWith("[webui]")) return "log-webui";
    if (/\[done\]/i.test(line) || /scan complete/i.test(line)) return "log-done";
    if (line.includes("⚠ Found") || /found:/i.test(line)) return "log-finding";
    if (line.includes("⚠")) return "log-warn";
    if (line.includes("✖") || line.includes("✗")) return "log-err";
    if (line.includes("✔") || line.includes("✓")) return "log-ok";
    if (line.includes("▸")) return "log-info";
    if (/^\s*─/.test(line)) return "log-debug";
    if (/^[┌│└◉├]/.test(line.trim()) || line.includes("◉")) return "log-mod";
    return "log-plain";
  }

  // Human label for the backend module list count on a scan.
  function scanStatusBadge(status) {
    const s = String(status || "").toLowerCase();
    const label = s === "done" ? "completed" : s;
    return `<span class="scan-status-badge scan-${s}">${escapeHTML(label)}</span>`;
  }

  return {
    SEV_KEYS, escapeHTML, sevKey, sevLabel, sevBadge, sevRank, normCounts,
    timeAgo, fmtDate, fmtDuration, classifyLogLine, scanStatusBadge,
  };
})();
