"""Render a payload as one self-contained HTML file: no server, no network."""

import html
import json
import re

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#e3e3e3;--card:#f7f7f8;--accent:#2b6cb0;--ok:#188038;--bad:#d93025;--warnbg:#fdf0d5;--warnfg:#8a5a00}
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e8e8e8;--mut:#9aa0a6;--line:#2c2f36;--card:#1e2127;--accent:#7aa7d9;--ok:#5bb974;--bad:#f28b82;--warnbg:#4a3a12;--warnfg:#f0c674}}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem;background:var(--bg);color:var(--fg);font:14px/1.5 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif}
h1{font-size:1.3rem;margin:0 0 .2rem}h2{font-size:.95rem;margin:1.5rem 0 .6rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.sub{color:var(--mut);font-size:.85rem;margin-bottom:1.25rem}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:.6rem}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem}
.tile b{display:block;font-size:1.4rem;font-weight:600}
.tile span{color:var(--mut);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.srcs{display:flex;flex-wrap:wrap;gap:.4rem;margin:.9rem 0 0}
.chip{font-size:.75rem;padding:.2rem .55rem;border-radius:999px;border:1px solid var(--line);background:var(--card)}
.chip.on{border-color:var(--ok);color:var(--ok)}.chip.part{border-color:var(--warnfg);color:var(--warnfg)}.chip.off{background:var(--warnbg);color:var(--warnfg);border-color:transparent;font-weight:600}
.controls{display:flex;flex-wrap:wrap;gap:.5rem;margin:.9rem 0}
input,select{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:.45rem .6rem;font:inherit}
input{flex:1 1 260px}
.count{color:var(--mut);font-size:.85rem;margin-bottom:.5rem}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;min-width:860px}
th,td{text-align:left;padding:.5rem .65rem;border-bottom:1px solid var(--line);vertical-align:top}
th{background:var(--card);position:sticky;top:0;cursor:pointer;white-space:nowrap;font-size:.78rem}
tbody tr:last-child td{border-bottom:none}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em;color:var(--mut)}
.sev{font-weight:600;white-space:nowrap;font-size:.78rem}
.CRITICAL,.BLOCKER,.HIGH{color:var(--bad)}.MAJOR,.MEDIUM{color:#e37400}.MINOR,.LOW{color:#1a73e8}.INFO{color:var(--mut)}
.tag{font-size:.72rem;padding:.1rem .4rem;border-radius:4px;background:var(--card);border:1px solid var(--line);white-space:nowrap;margin-right:.2rem}
.empty{padding:2rem;text-align:center;color:var(--mut)}
footer{margin-top:1.5rem;color:var(--mut);font-size:.78rem;border-top:1px solid var(--line);padding-top:.8rem}
.banner{background:var(--warnbg);color:var(--warnfg);border-radius:8px;padding:.7rem .9rem;margin:0 0 1rem;font-size:.9rem}
</style></head><body>
<h1>__TITLE__</h1>
<div class="sub">__SUBTITLE__</div>
__BANNER__
<h2>Security</h2><div class="tiles">__SEC_TILES__</div>
<h2>Quality</h2><div class="tiles">__QUAL_TILES__</div>
<div class="srcs">__CHIPS__</div>
<h2>Findings</h2>
<div class="controls">
  <input id="q" placeholder="Search message, location, rule, CVE…" autocomplete="off">
  <select id="proj"><option value="">All projects</option></select>
  <select id="src"><option value="">All sources</option></select>
  <select id="kind"><option value="">All types</option></select>
  <select id="sev"><option value="">All severities</option></select>
</div>
<div class="count" id="count"></div>
<div class="wrap"><table>
<thead><tr><th data-k="rank">Severity</th><th data-k="proj">Project</th><th data-k="src">Seen by</th>
<th data-k="kind">Type</th><th data-k="msg">Finding</th><th data-k="loc">Location</th><th data-k="fix">Fix</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<div class="empty" id="empty" hidden>No findings match this filter.</div>
<footer>Sources marked “not collected” were unavailable at build time; their absence is not a clean result.
A row seen by several scanners is listed once; its other sightings are listed under it.</footer>
<script>
const DATA = __DATA__;
const $ = i => document.getElementById(i);
let sortKey = null, sortAsc = true;
const facet = {proj:r=>[r.proj], src:r=>r.by, kind:r=>[r.kind], sev:r=>[r.sev]};
for (const k of Object.keys(facet))
  [...new Set(DATA.flatMap(facet[k]))].filter(Boolean).sort().forEach(v =>
    $(k).insertAdjacentHTML("beforeend", `<option>${esc(v)}</option>`));
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
function render(){
  const q=$("q").value.toLowerCase().trim(), f={};
  for (const k of Object.keys(facet)) f[k]=$(k).value;
  let rows=DATA.filter(r=>Object.keys(facet).every(k=>!f[k]||facet[k](r).includes(f[k]))&&
    (!q||`${r.msg} ${r.loc} ${r.ref} ${(r.ids||[]).join(" ")}`.toLowerCase().includes(q)));
  if(sortKey) rows=[...rows].sort((a,b)=>{const x=a[sortKey]??"",y=b[sortKey]??"";return (x>y?1:x<y?-1:0)*(sortAsc?1:-1);});
  $("rows").innerHTML=rows.map(r=>`<tr>
    <td class="sev ${esc(r.sev)}">${esc(r.sev)}</td>
    <td><span class="tag">${esc(r.proj)}</span></td>
    <td>${r.by.map(s=>`<span class="tag">${esc(s)}</span>`).join("")}</td><td>${esc(r.kind)}</td>
    <td>${esc(r.msg)}<br><code>${esc([r.ref,...(r.ids||[])].filter((v,i,a)=>v&&a.indexOf(v)===i).join(" · "))}</code>${(r.also||[]).length?`<details><summary>${r.also.length} more sighting(s)</summary>${r.also.map(a=>`<div><span class="tag">${esc(a.src)}</span> <span class="sev ${esc(a.sev)}">${esc(a.sev)}</span> ${esc(a.msg)} <code>${esc(a.ref)} ${esc(a.loc)}${a.line?":"+esc(a.line):""}</code></div>`).join("")}</details>`:""}</td>
    <td><code>${esc(r.loc)}</code>${r.line?` <code>:${esc(r.line)}</code>`:""}</td>
    <td>${esc(r.fix)}</td></tr>`).join("");
  $("count").textContent=`${rows.length} of ${DATA.length} findings`;
  $("empty").hidden=rows.length>0;
}
document.querySelectorAll("th").forEach(th=>th.onclick=()=>{const k=th.dataset.k;sortAsc=sortKey===k?!sortAsc:true;sortKey=k;render();});
["q","proj","src","kind","sev"].forEach(i=>$(i).addEventListener("input",render));
render();
</script></body></html>
"""


_PLACEHOLDER = re.compile(r"__([A-Z_]+)__")


def _script_json(value):
    """JSON safe inside <script>: no <, > or & can open a tag, comment or entity."""
    return (json.dumps(value, ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _tile(label, value, cls=""):
    v = "—" if value is None else value
    return f'<div class="tile {cls}"><b>{html.escape(str(v))}</b><span>{html.escape(label)}</span></div>'


def _num(v):
    try:
        return float(v) if v not in (None, "", "—") else None
    except (TypeError, ValueError):
        return None


def _sum(values):
    vals = [v for v in (_num(x) for x in values) if v is not None]
    return int(sum(vals)) if vals else None


def render(payload):
    rows, summaries, sources = payload["findings"], payload["generated_from"], payload["sources"]
    crit_high = sum(s["sec_crit_high"] for s in summaries)
    unrated = sum(s.get("sec_unrated") or 0 for s in summaries)
    malware = sum(s.get("malware") or 0 for s in summaries)
    if not malware:
        malware = sum(1 for r in rows if r.get("kind") in ("Malware", "Malicious Package"))
    sonar = lambda k: _sum((s.get("sonar") or {}).get(k) for s in summaries)  # noqa: E731
    dbot = _sum((s.get("dependabot") or {}).get("unique") for s in summaries)
    ncloc = sonar("ncloc")
    covs = [s["coverage"] for s in summaries if s.get("coverage")]
    measured = sum(c["measured"] for c in covs) if covs else None
    covered = sum(c["covered"] for c in covs) if covs else None
    # Only projects that have both numbers share a denominator.
    paired = [(s["coverage"]["measured"], _num((s.get("sonar") or {}).get("ncloc")))
              for s in summaries if s.get("coverage") and _num((s.get("sonar") or {}).get("ncloc"))]
    stats = payload.get("dedup") or {}

    # Green only when every required source is complete — a zero under a gap is not clean.
    required = [v for v in sources.values() if not v.get("optional")]
    gaps = sum(1 for v in required if not v.get("complete"))
    if crit_high:
        clean_ok = "bad"
    elif gaps:
        clean_ok = ""  # zero, but incomplete — neither green nor red
    else:
        clean_ok = "ok"

    suppressed = sum(int(v.get("suppressed") or 0) for v in sources.values())
    sec = "".join([
        _tile("Security crit + high", crit_high, clean_ok if crit_high == 0 else "bad"),
        _tile("Security findings", sum(s["security"] for s in summaries)),
        _tile("Security unrated", unrated, "bad" if unrated else ""),
        _tile("Malware / malicious pkgs", malware, "bad" if malware else ""),
        _tile("Dependabot advisories", dbot, "bad" if dbot else ""),
        _tile("Suppressed (waived)", suppressed),
        _tile("Security hotspots", sonar("security_hotspots")),
        _tile("Duplicates merged", stats.get("input", 0) - stats.get("output", 0)),
    ])
    qual = "".join([
        _tile("Bugs", sonar("bugs")),
        _tile("Code smells", sonar("code_smells")),
        # Two tiles, never one: a pooled percentage hides how little is measured.
        _tile("Coverage of measured", round(covered / measured * 100, 1) if measured else None),
        _tile("Codebase measured %", round(sum(m for m, _ in paired) / sum(n for _, n in paired)
                                           * 100, 1) if paired else None),
        _tile("Lines of code", f"{ncloc:,}" if ncloc else None),
        _tile("Deps scanned", _sum(s.get("deps") for s in summaries)),
    ])

    def chip(name, v):
        if v.get("optional") and not v["collected"]:
            return (f'<span class="chip">○ skipped — {html.escape(name)} '
                    f'{html.escape(v["note"])}</span>')
        if not v["collected"]:
            return (f'<span class="chip off">✗ not collected — {html.escape(name)} '
                    f'{html.escape(v["note"])}</span>')
        if not v.get("complete", True):
            return f'<span class="chip part">◐ {html.escape(name)} — {html.escape(v["note"])}</span>'
        extra = f' · {v["suppressed"]} waived' if v.get("suppressed") else ""
        return f'<span class="chip on">✓ {html.escape(name)}{html.escape(extra)}</span>'

    chips = "".join(chip(n, v) for n, v in sources.items())
    collected = sum(1 for v in sources.values() if v["collected"])
    required_n = len(required)
    settings = payload.get("settings") or {}
    # Keep the subtitle short: only floors / mode, not the whole images map.
    floor_keys = ("snyk_severity", "trivy_severity", "semgrep", "semgrep_mode", "dedup", "tools")
    floors = ", ".join(f"{k}: {settings[k]}" for k in floor_keys if settings.get(k) is not None)
    dirty = sum(1 for s in summaries if s.get("commit_dirty"))
    subtitle = (f"{html.escape(payload.get('version') or '')} · <b>{len(rows)}</b> findings "
                f"after merging {stats.get('input', len(rows))} sightings · "
                f"{collected} of {len(sources)} sources collected"
                f" · {required_n - gaps}/{required_n} required complete"
                + (f" · {dirty} dirty checkout(s)" if dirty else "")
                + (f" · {html.escape(floors)}" if floors else ""))
    if gaps:
        banner = (f'<div class="banner">⚠ {gaps} required source(s) incomplete or missing — '
                  f'a zero count is not a clean scan. Use --lenient only when that is intentional.</div>')
    else:
        banner = ""
    parts = {
        "TITLE": html.escape(payload["title"]),
        "SUBTITLE": subtitle,
        "BANNER": banner,
        "SEC_TILES": sec,
        "QUAL_TILES": qual,
        "CHIPS": chips,
        "DATA": _script_json(rows),
    }
    # One pass over the template: an inserted value is never searched again, so
    # a title containing a placeholder name cannot pull raw data into the page.
    return _PLACEHOLDER.sub(lambda m: parts.get(m.group(1), m.group(0)), TEMPLATE)
