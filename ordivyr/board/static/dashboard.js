"use strict";
// ORDIVYR Board customer dashboard. Live data only (no mock rows). SECURITY: every API-supplied value is rendered as a text node (markup is never parsed);
// the session token lives in this closure only (not in browser storage, so a reload signs you out and an XSS cannot read a persisted token); CSP forbids inline script/style.
const $ = (s) => document.querySelector(s);
const S = {tok: null, me: null, tab: "overview", proj: null, projects: [], job: null, pending: null, enrolTok: null};
const TABS = {overview: "Overview", jobs: "Jobs", agents: "Agents", schedules: "Schedules", workers: "Workers", billing: "Spending", secrets: "Secrets", team: "Team", keys: "Keys", security: "Security", audit: "Audit"};
const ADMIN_ONLY = new Set(["secrets", "team", "keys"]);

async function api(method, path, body, tok) {
  const t = tok === undefined ? S.tok : tok;
  const r = await fetch(path, {method, headers: {...(t ? {Authorization: "Bearer " + t} : {}), ...(body !== undefined ? {"Content-Type": "application/json"} : {})}, body: body !== undefined ? JSON.stringify(body) : undefined});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) { const e = new Error((j.error && j.error.message) || r.statusText); e.status = r.status; e.code = j.error && j.error.code; if (r.status === 401 && S.tok) signOut(); throw e; }
  return j;
}
function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) { if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else if (v !== undefined && v !== null && v !== false) e[k] = v; }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) e.append(k instanceof Node ? k : document.createTextNode(String(k)));
  return e;
}
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "-");
const usd = (c) => "$" + (c / 100).toFixed(2);
const stamp = (s) => el("span", {class: "stamp " + String(s).replace(/[^a-z_]/gi, "")}, String(s).replace("_", " "));
const panel = (title, body, cls = "") => el("section", {class: "panel " + cls}, el("h2", {}, title), el("div", {class: "body"}, body));
function table(cols, rows, onrow) {
  const t = el("table", {}, el("tr", {}, cols.map((c) => el("th", {}, c))));
  for (const r of rows) { const tr = el("tr", onrow ? {class: "click", onclick: () => onrow(r)} : {}, r.cells.map((c) => el("td", {}, c))); t.append(tr); }
  return rows.length ? t : el("p", {class: "muted"}, "Nothing here yet.");
}
function say(text, kind = "ok") { const m = $("#msg"); m.className = "bubble toast " + kind; m.textContent = text; clearTimeout(say.t); say.t = setTimeout(() => m.classList.add("hide"), 5000); }
function fail(e) { say(e.message || String(e), "bad"); }
function btn(label, fn, cls = "") { return el("button", {class: "btn small " + cls, onclick: async (ev) => { ev.stopPropagation(); try { await fn(); await show(); } catch (e) { fail(e); } }}, label); }
function form(fields, submit, onsubmit) {
  const refs = {};
  const f = el("form", {class: "f", onsubmit: async (ev) => { ev.preventDefault(); const v = {}; for (const [n, i] of Object.entries(refs)) v[n] = i.type === "checkbox" ? i.checked : i.value; try { await onsubmit(v); await show(); } catch (e) { fail(e); } }},
    fields.map((x) => { const i = x.options ? el("select", {}, x.options.map((o) => el("option", {value: o}, o))) : x.area ? el("textarea", {placeholder: x.ph || ""}) : el("input", {type: x.type || "text", placeholder: x.ph || "", autocomplete: x.type === "password" ? "current-password" : "off", checked: x.checked}); if (x.value !== undefined) i.value = x.value; refs[x.name] = i; return el("label", {class: "fl"}, x.label, i); }),
    el("div", {class: "row"}, el("button", {class: "btn"}, submit)));
  return f;
}
const isAdmin = () => S.me && S.me.role === "admin";
const canWrite = () => S.me && ["admin", "member"].includes(S.me.role);
const bucket = (p) => "w" + Math.max(0, Math.min(100, Math.round(p / 10) * 10));

// ------------------------------------------------------------------ auth
function signOut() { S.tok = null; S.me = null; S.job = null; S.pending = null; S.enrolTok = null; S.jobLogs = new Map(); paintChrome(); show(); }
function paintChrome() {
  $("#who").textContent = S.me ? `${S.me.email || S.me.role} · ${S.me.role} @ ${S.me.org || "platform"}${S.me.project ? "/" + S.me.project : ""}` : "not signed in";
  $("#out").classList.toggle("hide", !S.tok);
  const tabs = $("#tabs"); tabs.replaceChildren();
  if (S.me && S.me.role !== "enrol") for (const [k, l] of Object.entries(TABS)) { if (ADMIN_ONLY.has(k) && !isAdmin()) continue; tabs.append(el("button", {class: k === S.tab ? "on" : "", onclick: () => { S.tab = k; S.job = null; paintChrome(); show(); }}, l)); }
}
async function establish(tok) {
  S.tok = tok; try { S.me = await api("GET", "/v1/me"); } catch (e) { S.tok = null; throw e; }
  S.tab = S.me.role === "platform" ? "audit" : "overview"; paintChrome(); show();
}
function loginView() {
  const org = {name: "org", label: "Organization (if you belong to several)", ph: "acme"};
  const pw = form([{name: "email", label: "Email", type: "email"}, {name: "password", label: "Password", type: "password"}, org], "Sign in", async (v) => {
    const r = await api("POST", "/v1/auth/login", {email: v.email, password: v.password, org: v.org || undefined}, null);
    if (r.mfa_required) { S.pending = {mfa: r.mfa_token}; return; }
    if (r.choose_org) { say("You belong to: " + r.choose_org.join(", ") + ". Type one in the Organization box.", "warn"); return; }
    if (r.mfa_enrol_required) { await establish(r.session); S.tab = "security"; paintChrome(); say("Your organization requires MFA: set it up now.", "warn"); return; }
    await establish(r.session);
  });
  const key = form([{name: "key", label: "API key (ordb_...)", type: "password"}], "Use API key", async (v) => { await establish(v.key.trim()); });
  const nodes = [panel("Sign in", pw, "pink"), panel("Or paste an API key", [key, el("p", {class: "muted gap"}, "Kept in memory for this tab only and sent only to this server.")], "cyan")];
  if (S.link && S.link.kind === "accept") return [el("div", {class: "login"}, panel("Accept your invitation", form([{name: "name", label: "Your name"}, {name: "password", label: "Choose a password (12+ characters)", type: "password"}], "Join", async (v) => { await api("POST", "/v1/auth/accept-invite", {invite: S.link.token, password: v.password, name: v.name}, null); S.link = null; say("Account created: sign in."); }), "pink"))];
  if (S.link && S.link.kind === "reset") return [el("div", {class: "login"}, panel("Choose a new password", form([{name: "password", label: "New password (12+ characters)", type: "password"}], "Reset password", async (v) => { await api("POST", "/v1/auth/reset", {token: S.link.token, password: v.password}, null); S.link = null; say("Password changed: sign in."); }), "pink"))];
  nodes.push(panel("Forgot your password?", form([{name: "email", label: "Email", type: "email"}], "Email me a reset link", async (v) => { const r = await api("POST", "/v1/auth/forgot", {email: v.email}, null); say(r.message || "If that address has an account, a reset link is on its way."); }), "violet"));
  nodes.push(panel("Locked out? Use your authenticator", [el("p", {class: "muted"}, "Too many failed sign-ins from a new network? A code from your authenticator app (or a recovery code) lifts the block."), form([{name: "email", label: "Email", type: "email"}, {name: "code", label: "6-digit or recovery code"}], "Restore access", async (v) => { await api("POST", "/v1/auth/unlock", {email: v.email, code: v.code}, null); say("Access restored: sign in again."); })], "cyan"));
  if (S.pending && S.pending.mfa) nodes.unshift(panel("Second factor", form([{name: "code", label: "6-digit code or a recovery code", ph: "123456"}], "Verify", async (v) => { const r = await api("POST", "/v1/auth/login/mfa", {mfa_token: S.pending.mfa, code: v.code}, null); S.pending = null; await establish(r.session); }), "violet"));
  return [el("div", {class: "login"}, nodes)];
}

// ------------------------------------------------------------------ views
async function projectsBar() {
  S.projects = (await api("GET", "/v1/projects")).projects; if (!S.proj || !S.projects.find((p) => p.id === S.proj)) S.proj = S.projects[0] ? S.projects[0].id : null;
  const sel = el("select", {onchange: (e) => { S.proj = e.target.value; S.job = null; show(); }}, S.projects.map((p) => Object.assign(el("option", {value: p.id}, `${p.id} (${p.status})`), {selected: p.id === S.proj})));
  const cur = S.projects.find((p) => p.id === S.proj);
  return panel("Project", el("div", {class: "row"}, sel, isAdmin() && cur ? btn(cur.status === "paused" ? "Resume" : "Pause", () => api("POST", `/v1/projects/${S.proj}/${cur.status === "paused" ? "resume" : "pause"}`, {})) : null,
    isAdmin() ? form([{name: "id", label: "New project id", ph: "support"}], "Create project", (v) => api("POST", "/v1/projects", {id: v.id})) : null), "wide");
}
async function overview() {
  const [h, b, a] = await Promise.all([api("GET", "/v1/health"), api("GET", "/v1/spending"), api("GET", "/v1/alerts")]);
  const q = Object.values(h.queue).reduce((s, x) => ({queued: s.queued + x.queued, running: s.running + x.running, failed: s.failed + x.failed}), {queued: 0, running: 0, failed: 0});
  const kp = (n, l) => el("div", {class: "kpi"}, el("b", {}, n), el("span", {}, l));
  const nodes = [panel("Mission control", [el("div", {class: "bubble " + (h.status === "ok" ? "ok" : "warn")}, h.status === "ok" ? "All systems nominal." : h.status), el("div", {class: "kpis"}, kp(q.queued, "queued"), kp(q.running, "running"), kp(q.failed, "failed"), kp(h.workers.filter((w) => w.online).length + "/" + h.workers.length, "workers online"), kp(usd(b.running.total_cents), "this period"))]),
    panel("Usage", [el("p", {}, `${b.usage.jobs} jobs · ${b.usage.compute_min} compute min this period`), el("p", {class: "muted"}, `Provider cost $${b.usage.provider_cost_usd}`)], "cyan")];
  nodes.push(panel("Alerts", a.alerts.length ? table(["when", "kind", "detail"], a.alerts.slice(0, 8).map((x) => ({cells: [when(x.ts), stamp(x.kind), JSON.stringify(x.detail)]}))) : el("p", {class: "muted"}, "No alerts."), "pink"));
  return nodes;
}
async function jobsView() {
  const nodes = [await projectsBar()]; if (!S.proj) return nodes;
  if (S.job) return nodes.concat(await jobDetail());
  const js = (await api("GET", `/v1/projects/${S.proj}/jobs`)).jobs;
  if (canWrite()) { const ags = (await api("GET", `/v1/projects/${S.proj}/agents`)).agents;
    nodes.push(panel("Launch a job", ags.length ? form([{name: "agent", label: "Agent", options: ags.map((x) => x.id)}, {name: "prompt", label: "Mission", area: true, ph: "What should the agent do?"}], "Launch", async (v) => { const r = await api("POST", `/v1/projects/${S.proj}/jobs`, {agent_id: v.agent, prompt: v.prompt}); say("Launched " + r.job_id); }) : el("p", {class: "muted"}, "Define an agent first (Agents tab)."), "pink")); }
  nodes.push(panel("Jobs", table(["job", "status", "agent", "depth", "created", ""], js.map((j) => ({id: j.job_id, cells: [el("span", {class: "mono"}, j.job_id), stamp(j.status), j.agent_id || j.agent || "", j.depth, when(j.created),
    el("span", {class: "row"}, canWrite() && ["queued", "running", "claimed"].includes(j.status) ? btn("Cancel", () => api("POST", `/v1/projects/${S.proj}/jobs/${j.job_id}/cancel`, {}), "bad") : null, canWrite() && ["failed", "cancelled"].includes(j.status) ? btn("Retry", () => api("POST", `/v1/projects/${S.proj}/jobs/${j.job_id}/retry`, {})) : null)]})), (r) => { S.job = r.id; show(); }), "wide"));
  return nodes;
}
async function jobOutputs(project, job) {
  S.jobLogs ||= new Map();
  const key = `${S.me.org}/${project}/${job}`;
  let cached = S.jobLogs.get(key);
  if (!cached) { cached = {after: 0, outputs: []}; S.jobLogs.set(key, cached); }
  // Drain a bounded backlog on each refresh; retain the latest 200 rows rather
  // than repeatedly showing the first page after a long-running task.
  for (let page = 0; page < 5; page++) {
    const batch = await api("GET", `/v1/projects/${project}/jobs/${job}/outputs?after=${cached.after}&limit=200`);
    if (!batch.outputs.length) break;
    cached.outputs = cached.outputs.concat(batch.outputs).slice(-200);
    cached.after = batch.next_after;
    if (batch.outputs.length < 200) break;
  }
  return cached;
}
async function jobDetail() {
  const [j, ev, logs] = await Promise.all([api("GET", `/v1/projects/${S.proj}/jobs/${S.job}`), api("GET", `/v1/projects/${S.proj}/jobs/${S.job}/events`), jobOutputs(S.proj, S.job)]);
  const u = (j.result && j.result.usage) || {}; const res = j.result || {};
  const nodes = [panel("Job " + j.job_id, [el("p", {}, stamp(j.status), " ", el("span", {class: "mono muted"}, `attempt ${j.attempt || 1} · depth ${j.depth} · ${j.agent_id || ""}`)),
    el("div", {class: "row"}, btn("← Back", () => { S.job = null; }), canWrite() && ["queued", "running", "claimed"].includes(j.status) ? btn("Cancel", () => api("POST", `/v1/projects/${S.proj}/jobs/${j.job_id}/cancel`, {}), "bad") : null, j.status === "held" && canWrite() ? btn("Approve retry", () => api("POST", `/v1/projects/${S.proj}/jobs/${j.job_id}/approve`, {resolution: "retry"})) : null),
    el("h3", {class: "faint"}, "Result"), el("pre", {}, res.text || j.error || res.error && JSON.stringify(res.error) || "(none yet)"),
    el("h3", {class: "faint"}, "Verification"), el("pre", {}, JSON.stringify(res.completion || {}, null, 2)),
    el("h3", {class: "faint"}, "Artifacts"), el("pre", {}, JSON.stringify(res.artifacts || [], null, 2)),
    j.trace ? el("p", {class: "mono muted"}, "trace " + j.trace) : null, el("p", {class: "mono muted gap"}, `tokens in/out ${u.prompt_tokens ?? "unknown"}/${u.completion_tokens ?? "unknown"} · tool calls ${u.tool_calls ?? "unknown"} · cost ${u.cost_usd == null ? "unknown" : "$" + u.cost_usd.toFixed(4)}`)], "pink"),
    panel("Timeline", table(["when", "event", "worker"], ev.events.map((e) => ({cells: [when(e.ts), e.kind, e.worker || ""]}))), "cyan"),
    panel("Execution log", logs.outputs.map((x) => el("div", {}, el("p", {class: "mono muted"}, `${when(x.ts)} · ${x.tool}`), el("pre", {}, JSON.stringify(x.args), "\n", x.output))), "wide")];
  if ((j.children || []).length) nodes.push(panel("Delegated children", table(["job"], j.children.map((c) => ({id: c, cells: [el("span", {class: "mono"}, c)]})), (r) => { S.job = r.id; show(); }), "violet"));
  return nodes;
}
async function agentsView() {
  const nodes = [await projectsBar()]; if (!S.proj) return nodes;
  const as = (await api("GET", `/v1/projects/${S.proj}/agents`)).agents;
  nodes.push(panel("Agents", table(["agent", "v", "model", "tools", "permissions"], as.map((a) => ({cells: [a.id, a.version, a.model_ref ? `${a.model_ref.endpoint}/${a.model_ref.model}` : "", a.tools ? a.tools.join(", ") : "all", JSON.stringify(a.permissions || {})]}))), "wide"));
  if (isAdmin()) nodes.push(panel("Define / update an agent", form([{name: "id", label: "Agent id", ph: "triage"}, {name: "system", label: "System prompt", area: true}, {name: "endpoint", label: "Model endpoint (logical name)", ph: "local"}, {name: "model", label: "Model", ph: "qwen3-1.7b"},
    {name: "write", label: "May write files", type: "checkbox"}, {name: "web", label: "May fetch URLs", type: "checkbox"}, {name: "delegate", label: "Delegate to (comma separated agent ids, empty = none)", ph: "reviewer"}, {name: "secrets", label: "Secret names it may read (comma separated)", ph: "crm_token"}], "Save agent", async (v) => {
      const list = (s) => s.split(",").map((x) => x.trim()).filter(Boolean); const perms = {write: v.write, web: v.web}; const d = list(v.delegate); if (d.length) perms.delegate = d; const sc = list(v.secrets); if (sc.length) perms.secrets = sc;
      await api("PUT", `/v1/projects/${S.proj}/agents/${v.id}`, {system: v.system, permissions: perms, ...(v.endpoint && v.model ? {model_ref: {endpoint: v.endpoint, model: v.model}} : {})}); say("Agent saved"); }), "pink"));
  return nodes;
}
async function schedulesView() {
  const nodes = [await projectsBar()]; if (!S.proj) return nodes;
  const ss = (await api("GET", `/v1/projects/${S.proj}/schedules`)).schedules;
  nodes.push(panel("Schedules and webhooks", table(["id", "name", "kind", "when", "runs", "state", ""], ss.map((s) => ({cells: [el("span", {class: "mono"}, s.id), s.name, s.kind, s.describe || s.every_min || "", s.runs, stamp(s.enabled ? "active" : "stopped"), canWrite() ? btn(s.enabled ? "Disable" : "Enable", () => api("POST", `/v1/projects/${S.proj}/schedules/${s.id}/${s.enabled ? "disable" : "enable"}`, {})) : null]}))), "wide"));
  if (canWrite()) { const ags = (await api("GET", `/v1/projects/${S.proj}/agents`)).agents; if (ags.length) nodes.push(panel("New schedule", form([{name: "name", label: "Name"}, {name: "agent", label: "Agent", options: ags.map((x) => x.id)}, {name: "prompt", label: "Mission", area: true}, {name: "every", label: "Every (e.g. every 2 hours, every day at 9:00)", ph: "every 2 hours"}, {name: "webhook", label: "Webhook trigger instead", type: "checkbox"}], "Create", async (v) => {
    const r = await api("POST", `/v1/projects/${S.proj}/schedules`, {name: v.name, prompt: v.prompt, agent_id: v.agent, every: v.webhook ? undefined : v.every, webhook: v.webhook}); say(r.hook_path ? "Webhook created (shown once): " + r.hook_path : "Schedule created: " + r.describe, "warn"); }), "pink")); }
  return nodes;
}
async function workersView() {
  const [ws, hs] = await Promise.all([api("GET", "/v1/workers"), api("GET", "/v1/hosted")]); const nodes = [];
  nodes.push(panel("Hosted workers (sandboxed, run by Board)", table(["id", "name", "slots", "state", "online", "restarts", "last error", ""], hs.hosted.map((h) => ({cells: [el("span", {class: "mono"}, h.id), h.name, h.slots, stamp(h.state), h.online ? "yes" : "no", h.restarts, h.last_error || h.last_exit || "",
    isAdmin() ? el("span", {class: "row"}, h.desired === "running" ? btn("Stop", () => api("POST", `/v1/hosted/${h.id}/stop`, {})) : btn("Start", () => api("POST", `/v1/hosted/${h.id}/start`, {})), btn("Remove", () => api("POST", `/v1/hosted/${h.id}/deprovision`, {}), "bad")) : null]}))), "wide cyan"));
  if (isAdmin()) nodes.push(panel("Provision a hosted worker", form([{name: "name", label: "Name", ph: "main"}, {name: "slots", label: "Slots (parallel jobs)", type: "number", value: "2"}, {name: "endpoints", label: "Model endpoints (comma separated; each needs a secret named endpoint:<name>)", ph: "anthropic"}], "Provision", async (v) => {
    const r = await api("POST", "/v1/hosted", {name: v.name, slots: Number(v.slots), endpoints: v.endpoints.split(",").map((x) => x.trim()).filter(Boolean)}); say("Provisioning " + r.id); }), "pink"));
  nodes.push(panel("Registered workers", table(["worker", "engine", "node", "last seen", "state"], ws.workers.map((w) => ({cells: [el("span", {class: "mono"}, w.id), w.engine, w.node || "", when(w.last_seen), stamp(w.revoked ? "stopped" : w.drained ? "held" : "active")]}))), "wide"));
  return nodes;
}
async function billingView() {
  const b = await api("GET", "/v1/spending"); const lim = b.limits || {};
  return [panel("This period", [el("p", {}, `${b.usage.jobs} jobs · ${b.usage.compute_min} compute min · provider cost $${b.usage.provider_cost_usd}`)], "pink"),
    panel("Provider spending budget", [el("p", {class: "muted"}, `Budget ${lim.gateway_budget_usd == null ? "off" : "$" + lim.gateway_budget_usd} (your own provider keys; new work is refused once spend plus in-flight reservations would exceed it)`),
      isAdmin() ? form([{name: "budget", label: "Monthly budget (USD)", type: "number", ph: "20"}], "Set budget", async (v) => { await api("PUT", "/v1/spending/limits", {gateway_budget_usd: v.budget === "" ? null : Number(v.budget)}); say("Budget saved"); }) : null], "cyan")];
}
async function secretsView() {
  const ss = (await api("GET", "/v1/secrets")).secrets;
  return [panel("Secrets (write-only: values are never shown again)", table(["name", "scope", "version", "updated", ""], ss.map((s) => ({cells: [el("span", {class: "mono"}, s.name), s.project || "org", s.version, when(s.updated), btn("Delete", () => api("DELETE", `/v1/secrets/${encodeURIComponent(s.name)}${s.project ? "?project=" + encodeURIComponent(s.project) : ""}`), "bad")]}))), "wide violet"),
    panel("Store a secret", form([{name: "name", label: "Name", ph: "endpoint:anthropic"}, {name: "value", label: "Value", type: "password"}, {name: "project", label: "Project scope (empty = whole org)"}], "Seal it", async (v) => { await api("PUT", `/v1/secrets/${encodeURIComponent(v.name)}`, {value: v.value, project: v.project || undefined}); say("Sealed (AES-256-GCM)"); }), "pink")];
}
async function teamView() {
  const [m, inv, sso] = await Promise.all([api("GET", "/v1/members"), api("GET", "/v1/invites"), api("GET", "/v1/sso")]);
  return [panel("Members", table(["email", "role", "project", "MFA", "last login", ""], m.members.map((x) => ({cells: [x.email, x.role, x.project || "", x.mfa ? "on" : "off", when(x.last_login), el("span", {class: "row"}, btn("Viewer", () => api("PUT", `/v1/members/${x.user}`, {role: "viewer"})), btn("Member", () => api("PUT", `/v1/members/${x.user}`, {role: "member"})), btn("Admin", () => api("PUT", `/v1/members/${x.user}`, {role: "admin"})), btn("Reset pw", async () => { const r = await api("POST", `/v1/members/${x.user}/reset-password`, {}); say("Reset token (give it to them out-of-band): " + r.reset_token, "warn"); }), btn("Remove", () => api("DELETE", `/v1/members/${x.user}`), "bad"))]}))), "wide"),
    panel("Invite someone", form([{name: "email", label: "Email", type: "email"}, {name: "role", label: "Role", options: ["member", "viewer", "admin"]}], "Create invite", async (v) => { const r = await api("POST", "/v1/invites", {email: v.email, role: v.role}); say("Invite token (shown once, send it to them): " + r.invite, "warn"); }), "pink"),
    panel("Pending invites", table(["email", "role", "expires", ""], inv.invites.filter((i) => !i.used).map((i) => ({cells: [i.email, i.role, when(i.expires), btn("Revoke", () => api("DELETE", `/v1/invites/${i.id}`), "bad")]}))), "cyan"),
    panel("Email delivery", (await api("GET", "/v1/outbox")).length ? table(["when", "to", "kind", "status", "tries"], (await api("GET", "/v1/outbox")).slice(0, 10).map((o) => ({cells: [when(o.created), o.to, o.kind, stamp(o.status), o.attempts]}))) : el("p", {class: "muted"}, "No email sent yet.")),
    panel("Data retention", form([{name: "days", label: "Keep finished jobs for (days, 1-3650; empty = default 90)", type: "number", ph: "90"}], "Save", async (v) => { const r = await api("PUT", "/v1/retention", {job_days: v.days === "" ? null : Number(v.days)}); say(`Finished jobs are kept ${r.job_days} days. Billing records are always kept.`); })),
    panel("Policy and SSO", [el("p", {class: "muted"}, sso.sso ? `SSO: ${sso.sso.issuer} for ${sso.sso.domains.join(", ")} (${sso.sso.enforce ? "enforced" : "optional"}).` : "SSO is not configured (configure with PUT /v1/sso)."), btn("Require MFA for everyone", () => api("POST", "/v1/org/require-mfa", {on: true})), " ", btn("Stop requiring MFA", () => api("POST", "/v1/org/require-mfa", {on: false}), "ghost")], "violet")];
}
async function keysView() {
  const ks = (await api("GET", "/v1/keys")).keys;
  return [panel("API keys", table(["kid", "role", "scope", "label", "last used", "expires", ""], ks.map((k) => ({cells: [el("span", {class: "mono"}, k.kid), k.role, k.project || "org", k.label, when(k.last_used), k.revoked ? stamp("stopped") : when(k.expires), k.revoked ? "" : el("span", {class: "row"}, k.rotated_to ? null : btn("Rotate", async () => { const r = await api("POST", `/v1/keys/${k.kid}/rotate`, {grace_s: 3600}); say("New key (shown once): " + r.key, "warn"); }), btn("Revoke", () => api("DELETE", `/v1/keys/${k.kid}`), "bad"))]}))), "wide"),
    panel("Issue a key", form([{name: "role", label: "Role", options: ["member", "viewer", "admin"]}, {name: "label", label: "Label", ph: "ci-bot"}], "Issue", async (v) => { const r = await api("POST", "/v1/keys", {role: v.role, label: v.label}); say("Key (shown once): " + r.key, "warn"); }), "pink")];
}
async function securityView() {
  const nodes = [];
  if (!S.me.user) return [panel("Security", el("p", {class: "muted"}, "You are signed in with an API key: sessions and MFA belong to user accounts."))];
  if (S.enrol) nodes.push(panel("Authenticator setup", [el("p", {}, "Add this secret to your authenticator app, then enter a code."), el("pre", {}, S.enrol.secret), el("p", {class: "mono muted"}, S.enrol.otpauth_uri), form([{name: "code", label: "6-digit code"}], "Confirm", async (v) => { const r = await api("POST", "/v1/auth/mfa/confirm", {code: v.code}); S.enrol = null; if (r.session) { S.tok = r.session; S.me = await api("GET", "/v1/me"); paintChrome(); } say("MFA enabled. SAVE THESE RECOVERY CODES: " + r.recovery_codes.join("  "), "warn"); })], "pink"));
  else if (!S.me.mfa) nodes.push(panel("Two-factor authentication", [el("p", {class: "muted"}, "MFA is off."), btn("Set up MFA", async () => { S.enrol = await api("POST", "/v1/auth/mfa/begin", {}); })], "pink"));
  else nodes.push(panel("Two-factor authentication", [el("p", {}, stamp("active"), " MFA is on."), form([{name: "password", label: "Password", type: "password"}, {name: "code", label: "Current code"}], "Turn off MFA", async (v) => { await api("POST", "/v1/auth/mfa/disable", {password: v.password, code: v.code}); say("MFA disabled"); })], "pink"));
  const ss = (await api("GET", "/v1/auth/sessions")).sessions;
  nodes.push(panel("Change password", form([{name: "old", label: "Current password", type: "password"}, {name: "neu", label: "New password (12+ characters)", type: "password"}], "Change", async (v) => { await api("POST", "/v1/auth/password", {old: v.old, new: v.neu}); say("Password changed; other sessions signed out"); }), "cyan"));
  nodes.push(panel("Your sessions", table(["created", "last used", "ip", ""], ss.map((s) => ({cells: [when(s.created), when(s.last_used), s.ip, s.current ? stamp("active") : btn("Sign out", () => api("DELETE", `/v1/auth/sessions/${s.id}`), "bad")]}))), "wide"));
  return nodes;
}
async function auditView() {
  if (S.me.role === "platform") { const h = await api("GET", "/v1/admin/health"); return [panel("Platform health", [el("p", {}, stamp(h.audit_chain_ok ? "ok" : "bad"), " audit chain"), el("pre", {}, JSON.stringify(h, null, 1))], "pink")]; }
  const a = await api("GET", "/v1/audit?limit=200");
  return [panel("Audit log", [el("p", {class: a.chain_ok ? "" : "bad"}, stamp(a.chain_ok ? "ok" : "bad"), a.chain_ok ? " hash chain verified" : " CHAIN BROKEN at row " + a.first_bad), table(["when", "actor", "action", "detail"], a.rows.slice().reverse().map((r) => ({cells: [when(r.ts), r.actor, r.action, JSON.stringify(r.detail)]})))], "wide")];
}
const VIEWS = {overview, jobs: jobsView, agents: agentsView, schedules: schedulesView, workers: workersView, billing: billingView, secrets: secretsView, team: teamView, keys: keysView, security: securityView, audit: auditView};
async function show() {
  if (!S.me) { v.replaceChildren(...loginView()); return; }
  if (S.me.role === "enrol") { S.tab = "security"; }
  try { v.replaceChildren(...(await VIEWS[S.tab]())); } catch (e) { if (S.me) v.replaceChildren(panel("Houston, we have a problem", el("div", {class: "bubble bad"}, e.message), "wide pink")); }
}
$("#out").addEventListener("click", async () => { try { if (S.me && S.me.user) await api("POST", "/v1/auth/logout", {}); } catch (_) {} signOut(); });
setInterval(() => { if (S.me && ["overview", "jobs", "workers"].includes(S.tab) && !document.hidden && !document.activeElement.matches("input,textarea,select")) show(); }, 5000);
function readLink() {
  const m = /^#\/(accept|reset)\?token=([A-Za-z0-9_\-]{10,120})$/.exec(location.hash || "");
  if (m) { S.link = {kind: m[1], token: m[2]}; history.replaceState(null, "", location.pathname); }          // the one-time token never stays in the address bar / history
}
readLink(); paintChrome(); show();
