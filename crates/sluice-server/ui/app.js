// Sluice console. No framework and no build step: it reads the control plane's JSON API and
// builds the page from DOM nodes. Every value from the API, archived events above all, is
// written with textContent, never as HTML.
"use strict";

const POLL_MS = 5000;
const TOKEN_KEY = "sluice.token";

const state = {
  status: null,
  error: null,
  needsToken: false,
  filter: "all",
  profile: null,
  search: null,
  searching: false,
  searchError: null,
  timer: null,
};

// ---------- small helpers ----------

/** Element with attributes and children; strings become text nodes. */
function h(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svg(paths, size, className) {
  const ns = "http://www.w3.org/2000/svg";
  const node = document.createElementNS(ns, "svg");
  for (const [k, v] of Object.entries({ width: size, height: size, viewBox: `0 0 ${size} ${size}`, fill: "none", stroke: "currentColor", "stroke-width": 2, "aria-hidden": "true" })) {
    node.setAttribute(k, v);
  }
  if (className) node.setAttribute("class", className);
  for (const d of paths) {
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    node.append(path);
  }
  return node;
}

const nf = new Intl.NumberFormat("en-US");
const num = (n) => nf.format(n || 0);

function mb(bytes) {
  const b = bytes || 0;
  if (b >= 1e9) return (b / 1e9).toFixed(2) + " GB";
  if (b >= 1e6) return (b / 1e6).toFixed(1) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(0) + " KB";
  return b + " B";
}

function saved(volume) {
  if (!volume || !volume.bytes_in) return "–";
  return Math.round((1 - volume.bytes_out / volume.bytes_in) * 100) + "%";
}

function utc(seconds) {
  if (!seconds) return "–";
  return new Date(seconds * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

function readToken() {
  try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
}

function writeToken(token) {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* storage blocked: the token lasts until reload */ }
  memoryToken = token;
}

let memoryToken = readToken();

async function api(path) {
  const headers = memoryToken ? { Authorization: "Bearer " + memoryToken } : {};
  const response = await fetch(path, { headers, cache: "no-store" });
  if (response.status === 401) {
    const error = new Error("unauthorized");
    error.unauthorized = true;
    throw error;
  }
  if (!response.ok) throw new Error((await response.text()).trim() || response.statusText);
  return response.json();
}

// ---------- data ----------

async function refresh() {
  const hadStatus = state.status !== null;
  const hadToken = !state.needsToken;
  try {
    state.status = await api("/status" + (state.profile ? "?profile=" + encodeURIComponent(state.profile) : ""));
    state.error = null;
    state.needsToken = false;
    setConnection("Live · refreshed " + new Date().toLocaleTimeString());
  } catch (error) {
    if (error.unauthorized) {
      state.needsToken = true;
      setConnection("Token required");
    } else {
      state.error = error.message;
      setConnection("Control plane unreachable");
    }
  }
  // The archive form keeps what the user typed: only redraw it when its inputs (the source
  // list) first arrive or the token state changes.
  const onArchive = parseRoute().name === "archive";
  if (!onArchive || !hadStatus || hadToken === state.needsToken) render();
}

function setConnection(text) {
  document.getElementById("connection").textContent = text;
}

function startPolling() {
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    const route = parseRoute();
    if (route.name !== "archive" && !document.hidden) refresh();
  }, POLL_MS);
}

// ---------- routing ----------

function parseRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  if (hash.startsWith("template/")) return { name: "template", id: decodeURIComponent(hash.slice(9)) };
  if (hash === "archive") return { name: "archive" };
  return { name: "overview" };
}

function render() {
  const main = document.getElementById("main");
  const route = parseRoute();
  for (const link of document.querySelectorAll(".navlink")) {
    const current = link.dataset.route === (route.name === "template" ? "overview" : route.name);
    if (current) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  let view;
  if (state.needsToken) view = tokenView();
  else if (route.name === "archive") view = archiveView();
  else if (!state.status) view = [h("p", { class: "muted" }, state.error ? "Cannot reach the control plane: " + state.error : "Loading…")];
  else if (route.name === "template") view = templateView(route.id);
  else view = overviewView();
  main.replaceChildren(...view);
}

// ---------- token ----------

function tokenView() {
  const input = h("input", { id: "token", type: "password", autocomplete: "off", spellcheck: "false" });
  return [
    h("div", { class: "head" }, h("div", {}, h("h1", {}, "Control token"),
      h("p", { class: "sub" }, "This control plane requires a bearer token (SLUICE_CONTROL_TOKEN)."))),
    h("form", {
      class: "card token search",
      onsubmit: (event) => {
        event.preventDefault();
        writeToken(input.value.trim());
        refresh();
      },
    },
    h("div", {}, h("label", { for: "token" }, "Token"), input,
      h("p", { class: "hint" }, "Kept in this browser tab only, and sent only to this control plane.")),
    h("div", { class: "actions" }, h("button", { type: "submit", class: "primary" }, "Connect"))),
  ];
}

// ---------- overview ----------

function proofBadge(cycle, profile) {
  if (cycle && profile && !profile.split("+").includes("sigma")) {
    // The offline proof replays Sigma only; other engines' rules are held by the guardrails.
    return h("div", { class: "proof", role: "status" },
      h("div", {}, h("div", { class: "proof-title" }, "Guarded by the rules' requirements"),
        h("div", { class: "proof-detail" }, `No Sigma rules in profile ${profile}: nothing is replayed offline`)));
  }
  if (!cycle) {
    return h("div", { class: "proof", role: "status" },
      h("div", {}, h("div", { class: "proof-title" }, "Waiting for the first cycle"),
        h("div", { class: "proof-detail" }, "Nothing is cut before a recipe is proven.")));
  }
  const ok = cycle.proven;
  return h("div", { class: "proof " + (ok ? "ok" : "bad"), role: "status" },
    ok ? svg(["M6.5 11.5l3 3 6-7", "M11 2a9 9 0 1 0 0 18a9 9 0 1 0 0-18"], 22)
      : svg(["M11 6v6", "M11 15.5v.5", "M11 2a9 9 0 1 0 0 18a9 9 0 1 0 0-18"], 22),
    h("div", {},
      h("div", { class: "proof-title" }, ok ? "No detection changed" : "Proof failed: affected recipes roll back"),
      h("div", { class: "proof-detail" },
        `${num(cycle.alerts_full)} alerts on full data, ${num(cycle.alerts_forwarded)} on forwarded`)));
}

function kpi(label, value, note, noteClass, valueClass) {
  return h("div", { class: "card" },
    h("div", { class: "kpi-label" }, label),
    h("div", { class: "kpi-value " + (valueClass || "") }, value),
    note ? h("div", { class: "kpi-note " + (noteClass || "") }, note) : null);
}

function stageCounts(status) {
  const counts = { all: status.details.length, enforced: 0, shadow: 0, none: 0, rolled_back: 0 };
  for (const d of status.details) counts[d.stage] = (counts[d.stage] || 0) + 1;
  counts.rolled_back = status.history.filter((t) => t.kind === "rolled_back").length;
  return counts;
}

function overviewView() {
  const s = state.status;
  const cycle = s.last_cycle;
  const counts = stageCounts(s);
  const view = [
    h("header", { class: "head" },
      h("div", {}, h("h1", {}, "Overview"),
        h("p", { class: "sub" }, cycle ? `Cycle ${num(s.cycles)} · last cycle ${utc(cycle.at)}` : "No cycle has run yet")),
      proofBadge(cycle, s.profile)),
  ];
  if (s.profiles && s.profiles.length > 1) view.push(profilePicker(s));
  if (s.last_error) view.push(h("div", { class: "banner", role: "alert" }, "Last cycle failed: " + s.last_error));
  if (cycle) {
    view.push(h("section", { class: "kpis", "aria-label": "Last cycle" },
      kpi("Ingest, last cycle", `${mb(cycle.bytes_in)} → ${mb(cycle.bytes_out)}`,
        saved(cycle) + " less to the SIEM", "cut"),
      kpi("Events, last cycle", num(cycle.events), "all archived before any cut"),
      kpi("Templates", `${counts.enforced} / ${cycle.templates}`, `enforced · ${counts.shadow} in shadow`),
      kpi("Rollbacks", num(counts.rolled_back), counts.rolled_back ? "see the template's history" : "no failed proof in recent history")));
  }
  view.push(sourcesCard(s), templatesCard(s, counts));
  const notes = [
    ["Coverage gaps", "Rules no source can feed: they cannot fire on this traffic.", s.coverage_gaps],
    ["Scope hints", "Rules stay in scope where a source leaves an attribute unknown. Declaring it frees more.", s.scope_hints],
    ["Problems", "Rules or recipes that could not be fully understood; they were widened, never narrowed.", s.problems],
  ];
  for (const [title, intro, items] of notes) {
    if (!items || !items.length) continue;
    view.push(h("section", { class: "card" }, h("h2", {}, title), h("p", { class: "sub" }, intro),
      h("ul", { class: "plain small", style: null }, items.slice(0, 50).map((item) => h("li", {}, item))),
      items.length > 50 ? h("p", { class: "hint" }, `and ${items.length - 50} more`) : null));
  }
  return view;
}

/** Destinations whose SIEMs run different rules are proven, and cut, separately. */
function profilePicker(s) {
  return h("section", { class: "card", "aria-labelledby": "profile-h" },
    h("div", { class: "card-head" },
      h("div", {}, h("h2", { id: "profile-h" }, "Rule profile"),
        h("p", { class: "sub" }, "Each group of destinations is proven against the rules its SIEM runs. Savings and recipes below are for this profile.")),
      h("div", { class: "tabs", role: "group", "aria-label": "Rule profile" },
        s.profiles.map((name) => h("button", {
          type: "button",
          class: "mono",
          "aria-pressed": name === s.profile ? "true" : "false",
          onclick: () => { state.profile = name; state.filter = "all"; refresh(); },
        }, name)))));
}

function sourcesCard(s) {
  const rows = s.sources.map((src) => {
    const v = src.volume;
    const share = v.bytes_in ? (v.bytes_out / v.bytes_in) * 100 : 0;
    const fill = h("span", {});
    fill.style.width = share.toFixed(1) + "%";
    const ls = src.logsource || {};
    return h("tr", {},
      h("td", { class: "mono" }, src.source),
      h("td", { class: "mono muted" }, [ls.product, ls.service, ls.category].filter(Boolean).join(" · ") || "–"),
      h("td", { class: "num mono" }, num(src.templates)),
      h("td", { class: "num mono" }, num(v.events)),
      h("td", {}, h("div", { class: v.bytes_in ? "bar" : "bar empty", "aria-hidden": "true" }, fill),
        h("div", { class: "bytes" }, v.events ? `${mb(v.bytes_in)} → ${mb(v.bytes_out)}` : "no events in the window")),
      h("td", { class: "num mono" }, saved(v)));
  });
  return h("section", { class: "card", "aria-labelledby": "sources-h" },
    h("div", { class: "card-head" }, h("h2", { id: "sources-h" }, "Sources"),
      h("div", { class: "legend" },
        h("span", {}, h("span", { class: "swatch forward" }), "forwarded"),
        h("span", {}, h("span", { class: "swatch cut" }), "cut (archived only)"))),
    h("div", { class: "scroll" }, h("table", { class: "min-sources" },
      h("thead", {}, h("tr", {}, h("th", {}, "Source"), h("th", {}, "Log source"), h("th", { class: "num" }, "Templates"),
        h("th", { class: "num" }, "Events"), h("th", {}, "Bytes in → out"), h("th", { class: "num" }, "Saved"))),
      h("tbody", {}, rows))));
}

const STAGES = [
  ["all", "All"], ["enforced", "Enforced"], ["shadow", "Shadow"], ["none", "Pass-through"], ["rolled_back", "Rolled back"],
];
const STAGE_LABEL = { enforced: "enforced", shadow: "shadow", none: "pass-through" };

function templatesCard(s, counts) {
  const tabs = STAGES.map(([id, label]) => h("button", {
    type: "button",
    "aria-pressed": state.filter === id ? "true" : "false",
    onclick: () => { state.filter = id; render(); },
  }, label, h("span", { class: "count" }, String(counts[id] || 0))));

  let body;
  if (state.filter === "rolled_back") {
    const rolled = s.history.filter((t) => t.kind === "rolled_back").reverse();
    body = rolled.length
      ? h("ul", { class: "plain small" }, rolled.map((t) => h("li", {}, utc(t.at) + " · ",
          h("a", { href: "#/template/" + encodeURIComponent(t.template), class: "mono" }, t.template))))
      : h("p", { class: "muted small" }, "Nothing was rolled back. A recipe that fails a later proof returns to pass-through on the next cycle.");
  } else {
    const details = s.details
      .filter((d) => state.filter === "all" || d.stage === state.filter)
      .sort((a, b) => b.volume.bytes_in - a.volume.bytes_in);
    body = details.length
      ? h("div", { class: "scroll" }, h("table", { class: "min-templates" },
          h("thead", {}, h("tr", {}, h("th", {}, "Template"), h("th", {}, "Stage"), h("th", {}, "What Sluice does"),
            h("th", { class: "num" }, "Events"), h("th", { class: "num" }, "Forwarded"), h("th", { class: "num" }, "Bytes in → out"))),
          h("tbody", {}, details.map((d) => h("tr", {},
            h("td", {}, h("a", { class: "mono", href: "#/template/" + encodeURIComponent(d.template) }, d.template),
              h("div", { class: "pattern" }, d.pattern)),
            h("td", {}, h("span", { class: "stage stage-" + d.stage }, STAGE_LABEL[d.stage] || d.stage)),
            h("td", { class: "small" }, d.actions.length ? d.actions.join("; ") : "Forwarded unchanged"),
            h("td", { class: "num mono" }, num(d.volume.events)),
            h("td", { class: "num mono" }, num(d.volume.forwarded)),
            h("td", { class: "num mono" }, `${mb(d.volume.bytes_in)} → ${mb(d.volume.bytes_out)}`))))))
      : h("p", { class: "muted small" }, {
          shadow: "No template is in shadow. A new recipe shadows for its configured time and must pass every proof before it is enforced.",
          none: "Every template has a recipe.",
          enforced: "No recipe is enforced yet.",
        }[state.filter] || "No templates yet.");
  }
  return h("section", { class: "card", "aria-labelledby": "templates-h" },
    h("div", { class: "card-head" }, h("h2", { id: "templates-h" }, "Templates"),
      h("div", { class: "tabs", role: "group", "aria-label": "Filter by stage" }, tabs)),
    body);
}

// ---------- template detail ----------

const TRANSITION = {
  shadowing: "Recipe proven on the sample. Shadowing: computed, not applied.",
  promoted: "Enforced. Vector reloaded with the recipe.",
  demoted: "Returned to shadow.",
  rolled_back: "Rolled back: a proof failed, so the template passes through unchanged again.",
};

function templateView(id) {
  const s = state.status;
  const d = s.details.find((x) => x.template === id);
  const life = s.templates.find((x) => x.template === id);
  const history = s.history.filter((t) => t.template === id);
  const crumbs = h("div", { class: "crumbs" }, h("a", { href: "#/" }, "Overview"), " / ", h("span", { class: "mono" }, id));
  if (!d) {
    return [crumbs, h("h1", { class: "mono" }, id),
      h("p", { class: "notice" }, "This template was not in the last window. It may have gone quiet; its recipe stays as it was.")];
  }
  const v = d.volume;
  const badges = h("div", { class: "tabs" },
    h("span", { class: "stage stage-" + d.stage }, life ? `${STAGE_LABEL[d.stage] || d.stage} since ${utc(life.since)}` : STAGE_LABEL[d.stage] || d.stage),
    life && life.proofs !== null && life.proofs !== undefined ? h("span", { class: "stage stage-none" }, `${life.proofs} proofs so far`) : null);
  return [
    crumbs,
    h("header", { class: "head" },
      h("div", {}, h("h1", { class: "mono" }, d.template),
        h("p", { class: "sub" }, `${d.pattern} · source `, h("span", { class: "mono" }, d.source))),
      badges),
    h("section", { class: "kpis", "aria-label": "Volume in the last window" },
      kpi("Events", num(v.events)),
      kpi("Forwarded", num(v.forwarded), "each event sent on, shaped by the recipe", null, "forward"),
      kpi("Summarized", num(v.summarized), "into count records; originals in the archive", null, "cut"),
      kpi("Bytes", `${mb(v.bytes_in)} → ${mb(v.bytes_out)}`, saved(v) + " less", "cut")),
    h("div", { class: "row" },
      h("section", { class: "card wide", "aria-labelledby": "recipe-h" },
        h("h2", { id: "recipe-h" }, "Effective recipe"),
        h("p", { class: "sub" }, d.provenance ? d.provenance : "No recipe proposed for this template."),
        d.actions.length
          ? h("ol", { class: "steps" }, d.actions.map((a) => h("li", {}, a)))
          : h("p", { class: "muted small" }, "Forwarded unchanged (contract rule 1).")),
      h("section", { class: "card", "aria-labelledby": "guard-h" },
        h("h2", { id: "guard-h" }, "Guardrails"),
        d.adjustments.length
          ? [h("p", { class: "sub" }, "What the safety contract changed in the proposal, and why:"),
             h("ul", { class: "plain small" }, d.adjustments.map((a) => h("li", {}, a)))]
          : h("p", { class: "sub" }, "No guardrail had to change this recipe."))),
    d.example ? exampleCard(d.example) : null,
    h("section", { class: "card", "aria-labelledby": "life-h" },
      h("h2", { id: "life-h" }, "Lifecycle"),
      history.length
        ? h("ol", { class: "timeline" }, history.map((t) => h("li", {},
            h("time", { datetime: new Date(t.at * 1000).toISOString() }, utc(t.at)),
            h("span", {}, TRANSITION[t.kind] || t.kind))))
        : h("p", { class: "muted small" }, "No transitions in recent history."),
      h("p", { class: "hint" }, "Originals of every event, including summarized ones, are in the ",
        h("a", { href: "#/archive" }, "archive"), ".")),
  ];
}

/** Dotted leaf paths of an event, as the guardrails name fields. */
function leaves(value, prefix, out) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value)) leaves(child, prefix ? prefix + "." + key : key, out);
  } else {
    out.add(prefix);
  }
  return out;
}

function exampleCard(example) {
  const before = leaves(example.before, "", new Set());
  const after = example.after ? leaves(example.after, "", new Set()) : new Set();
  const removed = [...before].filter((f) => !after.has(f)).sort();
  const json = (v) => JSON.stringify(v, null, 2);
  const beforeBytes = json(example.before).length;
  return h("section", { class: "card", "aria-labelledby": "example-h" },
    h("h2", { id: "example-h" }, "One event, before and after"),
    h("p", { class: "sub" }, example.after
      ? `${removed.length} of ${before.size} fields removed: ${removed.join(", ") || "none"}.`
      : "This event is counted into a summary record; the SIEM does not receive it. The original stays in the archive."),
    h("div", { class: "row" },
      h("div", { class: "pane" }, h("h3", {}, `As it arrived · ${mb(beforeBytes)}`), h("pre", { class: "json" }, json(example.before))),
      h("div", { class: "pane" }, h("h3", {}, example.after ? `What the SIEM receives · ${mb(json(example.after).length)}` : "What the SIEM receives"),
        example.after ? h("pre", { class: "json" }, json(example.after)) : h("p", { class: "notice" }, "Nothing for this event: it is part of a summary."))));
}

// ---------- archive ----------

function archiveView() {
  const sources = state.status ? state.status.sources.map((s) => s.source) : [];
  const source = h("select", { id: "src", name: "source" },
    h("option", { value: "" }, "All sources"), sources.map((s) => h("option", { value: s }, s)));
  const from = h("input", { id: "from", name: "from", class: "mono", placeholder: "2026-10-10T06:00:00Z" });
  const to = h("input", { id: "to", name: "to", class: "mono", placeholder: "2026-10-10T07:00:00Z" });
  const where = h("textarea", { id: "where", name: "where", spellcheck: "false", placeholder: "EventID=10\nTargetImage~lsass.exe" });
  const limit = h("select", { id: "limit", name: "limit" }, ["25", "50", "100"].map((n) => h("option", { value: n }, n)));
  if (state.search && state.search.params) {
    source.value = state.search.params.source || "";
    from.value = state.search.params.from || "";
    to.value = state.search.params.to || "";
    where.value = state.search.params.where || "";
    limit.value = state.search.params.limit || "25";
  }
  const form = h("form", {
    class: "card search", "aria-labelledby": "search-h",
    onsubmit: async (event) => {
      event.preventDefault();
      const params = { source: source.value, from: from.value.trim(), to: to.value.trim(), where: where.value, limit: limit.value };
      state.searching = true;
      state.searchError = null;
      render();
      try {
        const query = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
        state.search = { params, result: await api("/archive/search?" + query) };
      } catch (error) {
        if (error.unauthorized) state.needsToken = true;
        state.search = { params, result: null };
        state.searchError = error.message;
      }
      state.searching = false;
      render();
    },
  },
  h("h2", { id: "search-h" }, "Search"),
  h("div", { class: "fields" },
    h("div", {}, h("label", { for: "src" }, "Source"), source),
    h("div", {}, h("label", { for: "from" }, "From (UTC)"), from),
    h("div", {}, h("label", { for: "to" }, "To (UTC)"), to),
    h("div", {}, h("label", { for: "limit" }, "Events"), limit)),
  h("div", {}, h("label", { for: "where" }, "Where"), where,
    h("p", { class: "hint" }, "One condition per line: field=value, field!=value or field~text (contains, any case). All must hold.")),
  h("div", { class: "actions" }, h("button", { type: "submit", class: "primary", disabled: state.searching }, state.searching ? "Searching…" : "Search")));

  const view = [
    h("header", {}, h("h1", {}, "Archive"),
      h("p", { class: "sub" }, "Every event exactly as it arrived, before any cut.")),
    form,
  ];
  if (state.searchError) view.push(h("div", { class: "banner", role: "alert" }, state.searchError));
  if (state.search && state.search.result) view.push(resultsCard(state.search.result));
  view.push(h("section", { class: "card" }, h("h2", {}, "Replay to the SIEM"),
    h("p", { class: "sub" }, "Sending originals back into a SIEM changes what it holds, so the console does not do it. Use ",
      h("code", {}, "sluice replay --archive DIR --source … --url …"), " or the MCP replay tool, where the destination is named explicitly.")));
  return view;
}

function resultsCard(result) {
  const notes = [];
  if (result.more_available) notes.push("more events match; narrow the search or raise the limit");
  if (result.truncated) notes.push("stopped after " + num(result.lines_read) + " lines; narrow the time range");
  if (result.incomplete_files) notes.push(result.incomplete_files + " file(s) still being written or damaged; read up to that point");
  return h("section", { class: "card", "aria-labelledby": "results-h" },
    h("div", { class: "card-head" },
      h("h2", { id: "results-h" }, `${num(result.events.length)}${result.more_available ? "+" : ""} matches`),
      h("span", { class: "hint" }, `${num(result.lines_read)} lines in ${num(result.files_read)} files`)),
    notes.length ? h("p", { class: "notice" }, notes.join(" · ")) : null,
    result.events.length
      ? h("div", { class: "scroll" }, h("table", { class: "min-results" },
          h("thead", {}, h("tr", {}, h("th", {}, "Received"), h("th", {}, "Source"), h("th", {}, "Event"))),
          h("tbody", {}, result.events.map((e) => h("tr", {},
            h("td", { class: "mono" }, e.received.replace("T", " ").replace("+00:00", "")),
            h("td", { class: "mono" }, e.source),
            h("td", {}, h("details", { class: "event" },
              h("summary", {}, preview(e.event)),
              h("pre", { class: "json" }, JSON.stringify(e.event, null, 2)))))))))
      : h("p", { class: "muted small" }, "No archived event matches."));
}

/** A one-line preview: the first few scalar fields. */
function preview(event) {
  const parts = [];
  for (const [key, value] of Object.entries(event)) {
    if (value === null || typeof value === "object") continue;
    const text = String(value);
    parts.push(`${key}=${text.length > 60 ? text.slice(0, 57) + "…" : text}`);
    if (parts.length === 4) break;
  }
  return parts.join("  ") || "{…}";
}

// ---------- start ----------

window.addEventListener("hashchange", () => {
  render();
  document.getElementById("main").focus();
});
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
refresh();
startPolling();
