"use strict";
/*
 * PermCheck — popup.js
 * Reads installed extensions' permissions via chrome.management and produces a
 * verdict-first assessment in plain English.
 *
 * Security (Baseline Security / extension-security standard):
 *  - No network calls. No data leaves the computer.         (privacy §7)
 *  - All dynamic text renders via textContent, never         (DOM-safety §2 / OWASP A03)
 *    innerHTML — extension names are untrusted data.
 *  - The only permission is "management" (least privilege).  (§1)
 */

// ---------------------------------------------------------------------------
// Risk model — the verdict reflects ACCESS LEVEL and required TRUST, not "dangerous".
// An extension can have high access for entirely legitimate reasons (e.g. an ad blocker).
// The point is to make hidden access visible, not to accuse.
// ---------------------------------------------------------------------------

// Each permission carries three things: what it CAN do (neutral), who legitimately
// NEEDS it, and how it gets ABUSED. The audit's job is to help the user ask
// "does this extension's purpose explain this?" — not to accuse.
const CRITICAL_PERMS = {
  debugger: {
    text: "can inspect and change everything on every page you open",
    why: "browser developer tools, automated testing extensions",
    abuse: "reading and rewriting any page, including banking and email",
  },
  proxy: {
    text: "can route your internet traffic",
    why: "VPN clients, corporate proxy tools, ad blockers with proxy modes",
    abuse: "silently redirecting all your traffic through someone else's server",
  },
  nativeMessaging: {
    text: "can talk to programs on your computer, outside the browser",
    why: "password managers with desktop apps, hardware key support, download managers",
    abuse: "bridging a web page to code running on your machine",
  },
  vpnProvider: {
    text: "can take over your network connection",
    why: "VPN extensions",
    abuse: "intercepting everything you send and receive",
  },
};

const SENSITIVE_PERMS = {
  webRequest: {
    text: "can see and change network traffic",
    why: "ad blockers, tracker blockers, security scanners, developer tools",
    abuse: "logging every request you make, including tokens in URLs",
  },
  webRequestBlocking: {
    text: "can block and change network traffic",
    why: "ad and tracker blockers, content filters",
    abuse: "injecting or rewriting requests you never made",
  },
  declarativeNetRequestWithHostAccess: {
    text: "can see and block network traffic",
    why: "ad blockers, content filters",
    abuse: "silently redirecting requests to attacker-controlled servers",
  },
  management: {
    text: "can disable or remove your other extensions",
    why: "extension managers, security auditors, enterprise policy tools",
    abuse: "disabling your security or ad-blocking extensions without asking",
  },
  cookies: {
    text: "can read your cookies",
    why: "password managers, session tools, cookie cleaners, privacy auditors",
    abuse: "stealing logged-in sessions — but only combined with broad site access",
  },
  history: {
    text: "can read your browsing history",
    why: "history search tools, bookmark managers, privacy cleaners",
    abuse: "building a profile of everywhere you've been",
  },
  tabs: {
    text: "can see the titles and addresses of your tabs",
    why: "tab managers, session savers, productivity tools, note-takers",
    abuse: "logging every page you open, even without page access",
  },
  bookmarks: {
    text: "can read and change your bookmarks",
    why: "bookmark managers, read-later tools, sync services",
    abuse: "exfiltrating your saved links, or injecting malicious ones",
  },
  downloads: {
    text: "can manage your downloads",
    why: "download managers, video savers, file converters",
    abuse: "downloading files to your machine without a prompt",
  },
  clipboardRead: {
    text: "can read what you've copied",
    why: "clipboard managers, paste-formatting tools",
    abuse: "capturing copied passwords and wallet addresses",
  },
  privacy: {
    text: "can change your browser's privacy settings",
    why: "privacy hardening tools, security extensions",
    abuse: "quietly weakening protections you turned on",
  },
  scripting: {
    text: "can run code on pages you visit",
    why: "almost every extension that modifies pages — blockers, themes, form fillers",
    abuse: "injecting code that reads or alters what you see and type",
  },
  contentSettings: {
    text: "can change site permissions (camera, location, etc.)",
    why: "privacy tools, permission managers",
    abuse: "granting camera or location access to sites on your behalf",
  },
  webNavigation: {
    text: "can track where you browse",
    why: "analytics for the extension's own features, page-load triggers, redirect blockers",
    abuse: "recording your full browsing path in real time",
  },
  geolocation: {
    text: "can read your location",
    why: "weather, maps, local search, regional tools",
    abuse: "tracking your physical whereabouts",
  },
};

// Broad site access = "can read and change everything you do online".
function hasBroadHost(hostPerms) {
  return (hostPerms || []).some((h) => {
    const s = String(h).toLowerCase();
    return (
      s === "<all_urls>" ||
      s === "*://*/*" ||
      s === "http://*/*" ||
      s === "https://*/*" ||
      s === "file:///*" ||
      /^\*:\/\/\*\/?$/.test(s) ||
      /^https?:\/\/\*\/?$/.test(s)
    );
  });
}

// The core: one extension in -> verdict + ranked reasons out.
function assess(ext) {
  const perms = ext.permissions || [];
  const hosts = ext.hostPermissions || [];
  const reasons = [];
  let score = 0;

  const broad = hasBroadHost(hosts);

  if (broad) {
    score += 3;
    reasons.push({ w: 3, text: "can read and change everything you do on all websites" });
  } else if (hosts.length > 0) {
    score += 1;
    const n = hosts.length;
    const txt = n === 1 ? "can read data on 1 specified website" : `can read data on ${n} specified websites`;
    reasons.push({ w: 1, text: txt });
  }

  for (const p of perms) {
    if (CRITICAL_PERMS[p]) {
      score += 3;
      reasons.push({ w: 3, text: CRITICAL_PERMS[p].text });
    }
  }

  for (const p of perms) {
    if (SENSITIVE_PERMS[p]) {
      const w = broad ? 2 : 1;
      score += w;
      reasons.push({ w, text: SENSITIVE_PERMS[p].text });
    }
  }

  // How the extension was installed. Dev-mode/admin are CONTEXT, not capability —
  // flagged so they never outrank what the extension can actually do.
  if (ext.installType === "development") {
    score += 2;
    reasons.push({ w: 2, text: "installed in developer mode — not via the Chrome Web Store", context: true });
  } else if (ext.installType === "sideload") {
    // Sideload IS the headline: something installed this without you.
    score += 3;
    reasons.push({ w: 4, text: "installed by another program on your computer — not by you" });
  } else if (ext.installType === "admin") {
    reasons.push({ w: 0, text: "installed via an organization policy", context: true });
  }

  // Combo detection (à la DropCheck) — dangerous permission *combinations* say more
  // than the parts. These get the highest weight so they lead the verdict.
  // Deliberately narrow: a combo must describe a capability the parts don't imply
  // on their own, otherwise we cry wolf on legitimate tools.
  const has = (p) => perms.includes(p);
  const combos = [];
  if (broad && has("cookies") && has("scripting")) {
    combos.push("can read your logged-in sessions on every site and run code there — enough to take over accounts");
  }
  if (broad && (has("webRequest") || has("declarativeNetRequestWithHostAccess")) && has("cookies")) {
    combos.push("can watch your traffic and read your cookies together — a credential-theft combination");
  }
  if (has("nativeMessaging") && broad) {
    combos.push("can bridge the web to a program on your computer — a sandbox-escape combination");
  }
  if (has("debugger")) {
    combos.push("debugger access alone can read and rewrite any page you open");
  }
  if (broad && has("scripting") && has("history")) {
    combos.push("can run code everywhere and read where you've been — broad surveillance reach");
  }
  for (const c of combos) {
    score += 3;
    reasons.push({ w: 5, text: c, combo: true }); // w:5 → always leads
  }

  let verdict;
  if (score >= 5) verdict = "red";
  else if (score >= 2) verdict = "amber";
  else verdict = "green";

  // No actual access reasons at all → explicit calm line.
  const hasCapability = reasons.some((r) => !r.context);
  if (!hasCapability) {
    reasons.push({ w: 0, text: "requests no sensitive access" });
  }

  // Capability first, context (install type) last — then by weight.
  reasons.sort((a, b) => {
    const ac = a.context ? 1 : 0;
    const bc = b.context ? 1 : 0;
    if (ac !== bc) return ac - bc;
    return b.w - a.w;
  });
  return { verdict, score, reasons };
}

const VERDICT_LABEL = {
  red: "High access",
  amber: "Some access",
  green: "Low access",
};

// ---------------------------------------------------------------------------
// Rendering — createElement + textContent throughout (never innerHTML).
// ---------------------------------------------------------------------------

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text; // safe for untrusted extension names
  return node;
}

const INSTALL_LABEL = {
  normal: "Chrome Web Store",
  development: "Manual (developer mode)",
  sideload: "Installed by another program",
  admin: "Organization policy",
  other: "Unknown",
};

function makeRow(ext, isSelf) {
  const { verdict, reasons } = assess(ext);
  const broad = hasBroadHost(ext.hostPermissions);

  const row = el("div", `row v-${verdict}${ext.enabled ? "" : " disabled"}`);

  const lamp = el("span", "lamp");
  const main = el("div", "row-main");

  const head = el("div", "row-head");
  const headLeft = el("div", "head-left");
  headLeft.appendChild(el("span", "name", ext.name));
  if (isSelf) headLeft.appendChild(el("span", "tag tag-self", "this extension"));
  if (!ext.enabled) headLeft.appendChild(el("span", "tag tag-off", "disabled"));
  head.appendChild(headLeft);
  const expand = el("span", "expand");
  expand.appendChild(el("span", "expand-text", "details"));
  expand.appendChild(el("span", "caret", "▸"));
  head.appendChild(expand);
  main.appendChild(head);

  // Collapsed: just the verdict chip + the single most important reason, as a sentence.
  const verdictLine = el("div", "verdict");
  verdictLine.appendChild(el("span", `chip chip-${verdict}`, VERDICT_LABEL[verdict]));
  const leadReason = reasons[0];
  const lead = leadReason.text;
  const leadEl = el("span", "lead", lead.charAt(0).toUpperCase() + lead.slice(1));
  if (leadReason.combo) leadEl.classList.add("lead-combo");
  verdictLine.appendChild(leadEl);
  main.appendChild(verdictLine);

  // Everything else lives in the detail view (click the row).
  const detail = el("div", "detail");

  // Remaining reasons.
  const rest = reasons.slice(1).filter((r) => r.text);
  if (rest.length) {
    const block = el("div", "det-block");
    block.appendChild(el("div", "det-label", "What it can do"));
    const ul = el("ul", "reasons");
    for (const r of rest) {
      const li = el("li", null, r.text);
      if (r.combo) li.classList.add("li-combo");
      ul.appendChild(li);
    }
    block.appendChild(ul);
    detail.appendChild(block);
  }

  // Nuance — only for broad access, now accurately worded.
  if (broad) {
    detail.appendChild(el(
      "div",
      "note",
      "Broad access is required by many legitimate tools — password managers, blockers, writing assistants, site scanners. The question isn't whether the access is dangerous, but whether this extension's purpose explains needing it."
    ));
  }

  // Raw permissions, explained.
  appendExplainedPerms(detail, ext.permissions);
  appendPermBlock(detail, "Site access", ext.hostPermissions, "no site access");

  const meta = el("div", "det-block");
  meta.appendChild(el("div", "det-label", "Installed via"));
  meta.appendChild(el("div", "det-meta", INSTALL_LABEL[ext.installType] || ext.installType || "unknown"));
  detail.appendChild(meta);

  // Manage — opens Chrome's own page for THIS extension. PermCheck still touches nothing.
  if (!isSelf && /^[a-p]{32}$/.test(ext.id)) {
    const manage = el("button", "manage-btn", "Manage in Chrome →");
    manage.type = "button";
    manage.addEventListener("click", (e) => {
      e.stopPropagation(); // don't toggle the row
      chrome.tabs.create({ url: `chrome://extensions/?id=${ext.id}` });
    });
    detail.appendChild(manage);
  }

  main.appendChild(detail);

  const toggle = () => {
    const open = row.classList.toggle("open");
    row.setAttribute("aria-expanded", open ? "true" : "false");
  };
  row.setAttribute("role", "button");
  row.setAttribute("tabindex", "0");
  row.setAttribute("aria-expanded", "false");
  row.setAttribute("aria-label", `${ext.name} — ${VERDICT_LABEL[verdict]}. Show details.`);
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
  });

  row.appendChild(lamp);
  row.appendChild(main);
  return { row, verdict };
}

// Permissions rendered WITH context: what it does, who legitimately needs it,
// how it gets abused. Turns "scary list" into "informed judgement".
function appendExplainedPerms(parent, perms) {
  const wrap = el("div", "det-block");
  wrap.appendChild(el("div", "det-label", "Permissions"));

  const known = (perms || []).filter((p) => CRITICAL_PERMS[p] || SENSITIVE_PERMS[p]);
  const other = (perms || []).filter((p) => !CRITICAL_PERMS[p] && !SENSITIVE_PERMS[p]);

  if (!known.length && !other.length) {
    wrap.appendChild(el("div", "det-empty", "no permissions requested"));
    parent.appendChild(wrap);
    return;
  }

  for (const p of known) {
    const info = CRITICAL_PERMS[p] || SENSITIVE_PERMS[p];
    const entry = el("div", "perm-entry");

    const head = el("div", "perm-head");
    head.appendChild(el("code", null, p));
    head.appendChild(el("span", "perm-what", info.text));
    entry.appendChild(head);

    const need = el("div", "perm-line perm-need");
    need.appendChild(el("span", "perm-tag", "Needed by"));
    need.appendChild(el("span", null, info.why));
    entry.appendChild(need);

    const abuse = el("div", "perm-line perm-abuse");
    abuse.appendChild(el("span", "perm-tag", "Abused for"));
    abuse.appendChild(el("span", null, info.abuse));
    entry.appendChild(abuse);

    wrap.appendChild(entry);
  }

  if (other.length) {
    const rest = el("div", "perm-other");
    rest.appendChild(el("span", "perm-tag", "Also requests"));
    const ul = el("ul", "det-list");
    for (const p of other) {
      const li = el("li");
      li.appendChild(el("code", null, p)); // untrusted -> code + textContent
      ul.appendChild(li);
    }
    rest.appendChild(ul);
    wrap.appendChild(rest);
  }

  // The question that actually matters.
  wrap.appendChild(el(
    "div",
    "perm-question",
    "Ask yourself: does this extension's purpose explain the access above?"
  ));

  parent.appendChild(wrap);
}

function appendPermBlock(parent, label, items, emptyText) {
  const wrap = el("div", "det-block");
  wrap.appendChild(el("div", "det-label", label));
  if (items && items.length) {
    const ul = el("ul", "det-list");
    for (const it of items) {
      const li = el("li");
      li.appendChild(el("code", null, it)); // untrusted -> code + textContent
      ul.appendChild(li);
    }
    wrap.appendChild(ul);
  } else {
    wrap.appendChild(el("div", "det-empty", emptyText));
  }
  parent.appendChild(wrap);
}

// ---------------------------------------------------------------------------
// Change watch — snapshot in chrome.storage.local, diff on next open.
// This catches the real-world attack the security standard flags: a trusted
// extension silently gaining new power via an update (hijacked dev account).
// ---------------------------------------------------------------------------

const SNAP_KEY = "permcheck_snapshot_v1";

function snapshotOf(exts) {
  const snap = {};
  for (const x of exts) {
    snap[x.id] = {
      name: x.name,
      perms: (x.permissions || []).slice().sort(),
      hosts: (x.hostPermissions || []).slice().sort(),
    };
  }
  return snap;
}

function diffSnapshots(prev, current) {
  const added = [];   // newly installed
  const gained = [];  // gained permissions/host access
  for (const id of Object.keys(current)) {
    const now = current[id];
    const was = prev[id];
    if (!was) {
      added.push(now.name);
      continue;
    }
    const newPerms = now.perms.filter((p) => !was.perms.includes(p));
    const newHosts = now.hosts.filter((h) => !was.hosts.includes(h));
    const wasBroad = hasBroadHost(was.hosts);
    const nowBroad = hasBroadHost(now.hosts);
    const additions = [];
    for (const p of newPerms) {
      const info = CRITICAL_PERMS[p] || SENSITIVE_PERMS[p];
      if (info) additions.push(info.text);
    }
    if (!wasBroad && nowBroad) additions.push("can now read and change everything you do on all websites");
    else if (newHosts.length && !nowBroad) additions.push(`can now read data on ${newHosts.length} more site(s)`);
    if (additions.length) gained.push({ name: now.name, additions });
  }
  return { added, gained };
}

function renderChanges(container, diff) {
  container.textContent = "";
  if (!diff || (!diff.added.length && !diff.gained.length)) return;

  const box = el("div", "changes-box");
  box.appendChild(el("div", "changes-title", "Changes since your last scan"));

  for (const g of diff.gained) {
    const item = el("div", "change-item change-gain");
    item.appendChild(el("span", "change-name", g.name));
    const ul = el("ul", "reasons");
    for (const a of g.additions) ul.appendChild(el("li", null, a));
    item.appendChild(ul);
    box.appendChild(item);
  }
  if (diff.added.length) {
    const item = el("div", "change-item change-new");
    item.appendChild(el("span", "change-name", "New since last scan"));
    const ul = el("ul", "reasons");
    for (const n of diff.added) ul.appendChild(el("li", null, n));
    item.appendChild(ul);
    box.appendChild(item);
  }
  container.appendChild(box);
}

// ---------------------------------------------------------------------------
// Copy report — plain text, ready for a Baseline Security script. No network.
// ---------------------------------------------------------------------------

function buildReport(headline, active, off) {
  const date = new Date().toISOString().slice(0, 10);
  const lines = [`PermCheck report — ${date}`, headline, ""];
  const section = (title, rows) => {
    if (!rows.length) return;
    lines.push(title.toUpperCase());
    for (const a of rows) {
      const { verdict, reasons } = assess(a.ext);
      const tag = { red: "HIGH", amber: "SOME", green: "LOW " }[verdict];
      const state = a.ext.enabled ? "" : " (disabled)";
      lines.push(`[${tag}] ${a.ext.name}${state} — ${reasons[0].text}`);
    }
    lines.push("");
  };
  section("Active", active);
  section("Disabled", off);
  lines.push("Only reads. No data leaves your computer. github.com/keets (Baseline Security)");
  return lines.join("\n");
}

async function copyReport(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = "Copied ✓";
  } catch {
    btn.textContent = "Copy failed";
  }
  setTimeout(() => { btn.textContent = "Copy report"; }, 1800);
}

function setText(id, text) {
  const node = document.getElementById(id);
  if (node) node.textContent = text;
}

async function main() {
  const listEl = document.getElementById("list");
  const statusEl = document.getElementById("status");

  let self, all;
  try {
    self = await chrome.management.getSelf();
    all = await chrome.management.getAll();
  } catch (e) {
    statusEl.textContent = "Couldn't read the extension list.";
    return;
  }

  // Only real extensions — skip themes and apps. Self is kept but flagged.
  const exts = all.filter((x) => x.type === "extension");

  const order = { red: 0, amber: 1, green: 2 };
  const byRisk = (a, b) => {
    if (order[a.verdict] !== order[b.verdict]) return order[a.verdict] - order[b.verdict];
    return a.ext.name.localeCompare(b.ext.name, undefined, { sensitivity: "base" });
  };

  const assessed = exts.map((x) => ({ ext: x, ...assess(x) }));
  const active = assessed.filter((a) => a.ext.enabled).sort(byRisk);
  const off = assessed.filter((a) => !a.ext.enabled).sort(byRisk);

  // Headline and counts reflect ACTIVE extensions — disabled ones have no access now.
  const counts = { red: 0, amber: 0, green: 0 };
  for (const a of active) counts[a.verdict]++;
  const broadActive = active.filter((a) => hasBroadHost(a.ext.hostPermissions)).length;

  const headline = document.getElementById("headline");
  const extWord = active.length === 1 ? "active extension" : "active extensions";
  if (broadActive > 0) {
    headline.textContent = `${broadActive} of your ${active.length} ${extWord} can read everything you do online`;
    headline.classList.add("hl-alert");
  } else {
    headline.textContent = `None of your ${active.length} ${extWord} can read everything you do online`;
    headline.classList.add("hl-calm");
  }

  setText("count-red", String(counts.red));
  setText("count-amber", String(counts.amber));
  setText("count-green", String(counts.green));
  statusEl.textContent = "";

  // Change watch: diff against the last snapshot, then save the current one.
  const current = snapshotOf(exts);
  try {
    const stored = await chrome.storage.local.get(SNAP_KEY);
    const prev = stored && stored[SNAP_KEY];
    if (prev) {
      const diff = diffSnapshots(prev, current);
      renderChanges(document.getElementById("changes"), diff);
    }
    await chrome.storage.local.set({ [SNAP_KEY]: current });
  } catch {
    // storage failing must never break the audit — fail quietly.
  }

  // Copy report button.
  const copyBtn = document.getElementById("copy-btn");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      copyReport(buildReport(headline.textContent, active, off), copyBtn);
    });
  }

  // Active extensions.
  for (const a of active) {
    listEl.appendChild(makeRow(a.ext, a.ext.id === self.id).row);
  }

  // Disabled — collapsible section, clearly muted, kept out of the scary numbers.
  if (off.length) {
    const secBtn = el("button", "section-toggle");
    secBtn.appendChild(el("span", "caret", "▸"));
    secBtn.appendChild(el("span", null, `Disabled extensions (${off.length})`));
    const secBody = el("div", "section-body");
    secBtn.addEventListener("click", () => {
      secBtn.classList.toggle("open");
      secBody.classList.toggle("open");
    });
    for (const a of off) {
      secBody.appendChild(makeRow(a.ext, a.ext.id === self.id).row);
    }
    listEl.appendChild(secBtn);
    listEl.appendChild(secBody);
  }
}

document.addEventListener("DOMContentLoaded", main);
