// cgdns operator console.
//
// No framework and no build step: the whole UI is three files served from the
// management listener, so there is nothing to fetch from a CDN and nothing a
// content-security policy has to make an exception for.
"use strict";

const $ = (id) => document.getElementById(id);
let csrf = "";
let me = { name: "", scopes: [] };
let refreshTimer = null;

// --- transport ---------------------------------------------------------

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = typeof body === "string" ? body : JSON.stringify(body);
  }
  // The CSRF token is what a cross-origin page cannot produce; the cookie
  // alone is not enough for anything that changes state.
  if (method !== "GET" && csrf) opts.headers["X-CGDNS-CSRF"] = csrf;

  const res = await fetch(path, opts);
  const text = await res.text();
  let data = null;
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text }; }
  }
  if (res.status === 401 && path !== "/api/v1/login") {
    showLogin("Session expired. Sign in again.");
    throw new Error("unauthenticated");
  }
  if (!res.ok) throw new Error((data && data.error) || `HTTP ${res.status}`);
  return data;
}

function can(scope) {
  const rank = { read: 1, write: 2, admin: 3 };
  const have = Math.max(0, ...me.scopes.map((s) => rank[s] || 0));
  return have >= (rank[scope] || 99);
}

function toast(msg, bad) {
  const el = $("toast");
  el.textContent = msg;
  el.classList.toggle("bad", !!bad);
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, bad ? 6000 : 3000);
}

// --- login -------------------------------------------------------------

function showLogin(err) {
  clearInterval(refreshTimer);
  $("app").hidden = true;
  $("login").hidden = false;
  $("login-err").textContent = err || "";
  $("p").value = "";
}

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("login-err").textContent = "";
  try {
    const out = await api("POST", "/api/v1/login", {
      username: $("u").value,
      password: $("p").value,
      code: $("c").value || undefined,
    });
    csrf = out.csrf;
    me = { name: out.user, scopes: out.scopes || [] };
    start();
  } catch (err) {
    // A missing second factor is not a failure, it is the next step.
    if (String(err.message).includes("TOTP")) {
      $("code-row").hidden = false;
      $("c").focus();
      $("login-err").textContent = "Enter the code from your authenticator.";
      return;
    }
    $("login-err").textContent = err.message;
  }
});

$("logout").addEventListener("click", async () => {
  try { await api("POST", "/api/v1/logout"); } catch { /* signing out anyway */ }
  csrf = "";
  showLogin("Signed out.");
});

// --- shell -------------------------------------------------------------

function start() {
  $("login").hidden = true;
  $("app").hidden = false;
  $("hdr-who").textContent = `${me.name} · ${me.scopes.join(", ")}`;
  document.querySelectorAll("[data-new], #new-token, #new-user").forEach((b) => {
    b.hidden = !can(b.id === "new-user" ? "admin" : "write");
  });
  show("overview");
  refresh();
  refreshTimer = setInterval(() => {
    if (current === "overview") refresh();
  }, 5000);
}

let current = "overview";

document.querySelectorAll("nav button").forEach((b) => {
  b.addEventListener("click", () => show(b.dataset.view));
});

function show(view) {
  current = view;
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("on", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((s) => { s.hidden = s.id !== `view-${view}`; });
  const loaders = {
    overview: refresh,
    subscribers: () => loadRecords("subscribers"),
    overrides: () => loadRecords("overrides"),
    classes: () => loadRecords("classes"),
    feeds: () => loadRecords("feeds"),
    tokens: loadTokens,
    users: loadUsers,
    account: loadAccount,
  };
  (loaders[view] || (() => {}))();
}

// --- overview ----------------------------------------------------------

function tile(k, v, cls) {
  const d = document.createElement("div");
  d.className = "tile";
  const kk = document.createElement("div");
  kk.className = "k";
  kk.textContent = k;
  const vv = document.createElement("div");
  vv.className = "v" + (cls ? " " + cls : "");
  vv.textContent = v;
  if (String(v).length > 18) vv.classList.add("small");
  d.append(kk, vv);
  return d;
}

function yesNo(b) { return b ? "yes" : "no"; }
function upDown(b) { return b ? "up" : "down"; }

async function refresh() {
  let s, m;
  try {
    [s, m] = await Promise.all([api("GET", "/api/v1/status"), api("GET", "/api/v1/metrics")]);
  } catch { return; }

  $("hdr-node").textContent = `${s.node_id} · ${s.version}`;
  $("login-node").textContent = s.node_id || "operator console";

  const g = $("status-grid");
  g.replaceChildren(
    tile("node", s.node_id || "—"),
    tile("uptime", s.uptime || "—"),
    tile("healthy", yesNo(s.healthy), s.healthy ? "ok" : "bad"),
    // The single most useful line for an operator: is this node taking traffic.
    tile("anycast", s.anycast_advertised ? "advertising" : "withdrawn", s.anycast_advertised ? "ok" : "bad"),
    tile("pair link out", upDown(s.peer_outbound_up), s.peer_outbound_up ? "ok" : "warn"),
    tile("pair link in", upDown(s.peer_inbound_up), s.peer_inbound_up ? "ok" : "warn"),
    tile("records", s.records ?? 0),
    // Both nodes of a pair should report the same hash; a lasting difference
    // means a write reached one and not the other.
    tile("store hash", s.store_hash || "—"),
  );

  const n = (k) => Math.round(m[k] || 0);
  $("resolve-grid").replaceChildren(
    tile("queries", n("cgdns_queries_total")),
    tile("cache hits", n("cgdns_cache_lookup_hits_total")),
    tile("cache entries", n("cgdns_cache_entries")),
    tile("dnssec secure", n("cgdns_dnssec_secure_total"), "ok"),
    tile("dnssec bogus", n("cgdns_dnssec_bogus_total"), n("cgdns_dnssec_bogus_total") ? "bad" : ""),
    tile("outbound queries", n("cgdns_recursion_outbound_total")),
    tile("served stale", n("cgdns_serve_stale_served_total"), n("cgdns_serve_stale_served_total") ? "warn" : ""),
    tile("prefetched", n("cgdns_prefetch_completed_total")),
  );

  $("defence-grid").replaceChildren(
    tile("rate limited", n("cgdns_ratelimit_dropped_total") + n("cgdns_ratelimit_slipped_total"),
      n("cgdns_ratelimit_dropped_total") ? "warn" : ""),
    tile("nsec synthesised", n("cgdns_nsec_synthesised_total"), n("cgdns_nsec_synthesised_total") ? "ok" : ""),
    tile("policy blocked", n("cgdns_policy_blocked_total")),
    tile("whitelist hits", n("cgdns_policy_override_allowed_total")),
    tile("case mismatch", n("cgdns_recursion_case_mismatch_total"),
      n("cgdns_recursion_case_mismatch_total") ? "warn" : ""),
    tile("anycast flaps", n("cgdns_anycast_flaps_total"), n("cgdns_anycast_flaps_total") ? "warn" : ""),
  );
}

// --- records -----------------------------------------------------------

const RECORDS = {
  subscribers: {
    cols: ["prefix", "id", "class"],
    key: (r) => r.prefix,
    hint: 'A client prefix, e.g. {"prefix":"203.0.113.0/24","id":"acme","class":"filtered"}',
    blank: '{\n  "prefix": "203.0.113.0/24",\n  "id": "acme",\n  "class": "filtered"\n}',
  },
  overrides: {
    cols: ["subscriber_id", "allow", "block"],
    key: (r) => r.subscriber_id,
    hint: "Allow wins over block, and both win over the class feeds.",
    blank: '{\n  "subscriber_id": "acme",\n  "allow": ["example.com"],\n  "block": []\n}',
  },
  classes: {
    cols: ["name", "feeds", "action", "redirect_to"],
    key: (r) => r.name,
    hint: "A class binds feeds and a block action to a group of subscribers.",
    blank: '{\n  "name": "filtered",\n  "feeds": [],\n  "action": "nxdomain"\n}',
  },
  feeds: {
    cols: ["name", "format", "url", "file", "version"],
    key: (r) => r.name,
    hint: "Blocklist metadata. The content lives outside the control plane.",
    blank: '{\n  "name": "malware",\n  "format": "rpz",\n  "url": "https://example.net/malware.rpz"\n}',
  },
};

async function loadRecords(noun) {
  const spec = RECORDS[noun];
  const out = await api("GET", `/api/v1/${noun}`);
  const rows = (out.items || []).map((x) => (typeof x === "string" ? JSON.parse(x) : x));
  renderTable($(`tbl-${noun}`), spec.cols, rows, (r) => {
    const key = spec.key(r);
    const acts = [];
    if (can("write")) {
      acts.push(btn("Edit", () => openEditor(noun, key, r)));
      acts.push(btn("Delete", () => del(noun, key), "danger"));
    }
    return acts;
  });
}

function btn(label, fn, cls) {
  const b = document.createElement("button");
  b.textContent = label;
  if (cls) b.className = cls;
  b.addEventListener("click", fn);
  return b;
}

function cell(v) {
  if (v === undefined || v === null) return "";
  if (Array.isArray(v)) return v.join(", ");
  return String(v);
}

function renderTable(table, cols, rows, actions) {
  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  cols.forEach((c) => {
    const th = document.createElement("th");
    th.textContent = c.replace(/_/g, " ");
    hr.append(th);
  });
  hr.append(document.createElement("th"));
  thead.append(hr);

  const tbody = document.createElement("tbody");
  if (!rows.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = cols.length + 1;
    td.className = "empty";
    td.textContent = "Nothing configured.";
    tr.append(td);
    tbody.append(tr);
  }
  rows.forEach((r) => {
    const tr = document.createElement("tr");
    cols.forEach((c) => {
      const td = document.createElement("td");
      td.className = "mono";
      // textContent throughout: a record is operator-supplied data and must
      // never be parsed as markup.
      td.textContent = cell(r[c]);
      tr.append(td);
    });
    const td = document.createElement("td");
    td.className = "actions";
    (actions ? actions(r) : []).forEach((b) => td.append(b));
    tr.append(td);
    tbody.append(tr);
  });

  table.replaceChildren(thead, tbody);
}

document.querySelectorAll("[data-new]").forEach((b) => {
  b.addEventListener("click", () => openEditor(b.dataset.new, null, null));
});

function openEditor(noun, key, record) {
  const spec = RECORDS[noun];
  $("editor-title").textContent = key ? `Edit ${noun.replace(/s$/, "")} ${key}` : `New ${noun.replace(/s$/, "")}`;
  $("editor-hint").textContent = spec.hint;
  $("editor-body").value = record ? JSON.stringify(record, null, 2) : spec.blank;
  $("editor-err").textContent = "";
  $("editor").dataset.noun = noun;
  $("editor").showModal();
}

$("editor-form").addEventListener("submit", async (e) => {
  if (e.submitter && e.submitter.value !== "save") return;
  e.preventDefault();
  const noun = $("editor").dataset.noun;
  const body = $("editor-body").value;
  try {
    JSON.parse(body);
  } catch (err) {
    $("editor-err").textContent = "Not valid JSON: " + err.message;
    return;
  }
  try {
    const out = await api("POST", `/api/v1/${noun}`, body);
    $("editor").close();
    toast(`Saved ${out.kind} ${out.key}. Store hash ${out.hash.slice(0, 12)}…`);
    loadRecords(noun);
  } catch (err) {
    $("editor-err").textContent = err.message;
  }
});

async function del(noun, key) {
  if (!confirm(`Delete ${noun.replace(/s$/, "")} ${key}?`)) return;
  try {
    await api("DELETE", `/api/v1/${noun}/${key}`);
    toast(`Deleted ${key}.`);
    loadRecords(noun);
  } catch (err) {
    toast(err.message, true);
  }
}

// --- tokens ------------------------------------------------------------

async function loadTokens() {
  const out = await api("GET", "/api/v1/tokens");
  renderTable($("tbl-tokens"), ["id", "name", "scopes", "expires"], out.tokens || [], (t) =>
    can("admin") ? [btn("Revoke", () => revokeToken(t.id), "danger")] : []);
}

$("new-token").addEventListener("click", async () => {
  const name = prompt("Token name (what will use it)?");
  if (!name) return;
  const scopes = prompt("Scopes (read, write, admin)?", "write");
  if (!scopes) return;
  try {
    const out = await api("POST", "/api/v1/tokens", { name, scopes: scopes.split(",").map((s) => s.trim()) });
    showSecret("This token is shown once and cannot be recovered.", out.token);
    loadTokens();
  } catch (err) {
    toast(err.message, true);
  }
});

async function revokeToken(id) {
  if (!confirm(`Revoke token ${id}?`)) return;
  try {
    await api("DELETE", `/api/v1/tokens/${id}`);
    toast(`Revoked ${id}.`);
    loadTokens();
  } catch (err) {
    toast(err.message, true);
  }
}

function showSecret(title, secret) {
  $("editor-title").textContent = title;
  $("editor-hint").textContent = "Copy it now.";
  $("editor-body").value = secret;
  $("editor-err").textContent = "";
  $("editor").dataset.noun = "";
  $("editor-save").hidden = true;
  $("editor").showModal();
  $("editor").addEventListener("close", () => { $("editor-save").hidden = false; }, { once: true });
}

// --- users -------------------------------------------------------------

async function loadUsers() {
  const out = await api("GET", "/api/v1/users");
  const rows = (out.users || []).map((u) => ({
    name: u.name,
    scopes: u.scopes,
    totp: u.totp_confirmed ? "enrolled" : "not enrolled",
    last_login: u.last_login && !u.last_login.startsWith("0001") ? u.last_login : "never",
  }));
  renderTable($("tbl-users"), ["name", "scopes", "totp", "last_login"], rows, (u) =>
    can("admin") ? [btn("Delete", () => deleteUser(u.name), "danger")] : []);
}

$("new-user").addEventListener("click", async () => {
  const name = prompt("Username?");
  if (!name) return;
  const password = prompt("Password (at least 12 characters)?");
  if (!password) return;
  const scopes = prompt("Scopes (read, write, admin)?", "read");
  if (!scopes) return;
  try {
    await api("POST", "/api/v1/users", { name, password, scopes: scopes.split(",").map((s) => s.trim()) });
    toast(`Created ${name}. They should enrol a second factor at first sign-in.`);
    loadUsers();
  } catch (err) {
    toast(err.message, true);
  }
});

async function deleteUser(name) {
  if (!confirm(`Delete operator ${name}? Their sessions end immediately.`)) return;
  try {
    await api("DELETE", `/api/v1/users/${name}`);
    toast(`Deleted ${name}.`);
    loadUsers();
  } catch (err) {
    toast(err.message, true);
  }
}

// --- account -----------------------------------------------------------

async function loadAccount() {
  const who = await api("GET", "/api/v1/me");
  const box = $("totp-state");
  box.replaceChildren();

  if (who.totp_enrolled) {
    const p = document.createElement("p");
    p.textContent = "A second factor is enrolled on this account.";
    box.append(p);
    return;
  }

  const p = document.createElement("p");
  p.className = "hint";
  p.textContent = "No second factor yet. A password alone is one leak away from an account takeover.";
  const b = btn("Set up authenticator", startEnrol, "primary");
  box.append(p, b);
}

async function startEnrol() {
  let enrol;
  try {
    enrol = await api("POST", "/api/v1/me/totp");
  } catch (err) {
    toast(err.message, true);
    return;
  }

  const box = $("totp-state");
  box.replaceChildren();

  const p1 = document.createElement("p");
  p1.className = "hint";
  p1.textContent = "Add this secret to your authenticator, then enter a code to confirm. Nothing changes until you do.";

  const sec = document.createElement("div");
  sec.className = "secret";
  sec.textContent = enrol.secret;

  const uri = document.createElement("p");
  uri.className = "hint mono";
  uri.textContent = enrol.uri;

  const form = document.createElement("form");
  form.className = "card inline";
  const label = document.createElement("label");
  label.textContent = "Code ";
  const input = document.createElement("input");
  input.inputMode = "numeric";
  input.maxLength = 6;
  input.required = true;
  label.append(input);
  const submit = document.createElement("button");
  submit.className = "primary";
  submit.textContent = "Confirm";
  form.append(label, submit);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("POST", "/api/v1/me/totp/confirm", { code: input.value });
      toast("Two-factor authentication is on.");
      loadAccount();
    } catch (err) {
      toast(err.message, true);
    }
  });

  box.append(p1, sec, uri, form);
}

$("pw-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    await api("POST", "/api/v1/me/password", { current: $("pw-cur").value, new: $("pw-new").value });
    toast("Password changed. Sign in again.");
    setTimeout(() => showLogin("Password changed. Sign in again."), 1200);
  } catch (err) {
    toast(err.message, true);
  }
});

// --- boot --------------------------------------------------------------

// A live session survives a page reload, so try it before showing the form.
(async () => {
  try {
    const who = await fetch("/api/v1/me", { credentials: "same-origin" });
    if (!who.ok) throw new Error("no session");
    const data = await who.json();
    if (data.kind !== "session") throw new Error("not a session");
    // The CSRF token is not recoverable after a reload, so reads work but the
    // first write would fail. Signing in again is the honest option.
    showLogin("");
    $("u").value = data.name || "";
  } catch {
    showLogin("");
  }
})();
