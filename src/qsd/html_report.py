"""Render a payload as one self-contained HTML file: no server, no network."""

import html
import json

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
.chip.on{border-color:var(--ok);color:var(--ok)}.chip.off{background:var(--warnbg);color:var(--warnfg);border-color:transparent;font-weight:600}
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
</style></head><body>
<h1>__TITLE__</h1>
<div class="sub">__SUBTITLE__</div>
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
A row seen by several scanners is listed once.</footer>
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
    <td>${esc(r.msg)}<br><code>${esc([r.ref,...(r.ids||[])].filter((v,i,a)=>v&&a.indexOf(v)===i).join(" · "))}</code></td>
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


def _tile(label, value, cls=""):
    v = "—" if value is None else value
    return f'<div class="tile {cls}"><b>{html.escape(str(v))}</b><span>{html.escape(label)}</span></div>'


def _sum(summaries, get):
    vals = []
    for s in summaries:
        v = get(s)
        try:
            if v not in (None, "", "—"):
                vals.append(float(v))
        except (TypeError, ValueError):
            pass
    return int(sum(vals)) if vals else None


def render(payload):
    rows, summaries, sources = payload["findings"], payload["generated_from"], payload["sources"]
    crit_high = sum(s["sec_crit_high"] for s in summaries)
    sonar = lambda k: _sum(summaries, lambda s: (s.get("sonar") or {}).get(k))  # noqa: E731
    dbot = _sum(summaries, lambda s: (s.get("dependabot") or {}).get("unique"))
    ncloc = sonar("ncloc")
    covs = [s["coverage"] for s in summaries if s.get("coverage")]
    measured = sum(c["measured"] for c in covs) if covs else None
    covered = sum(c["covered"] for c in covs) if covs else None
    stats = payload.get("dedup") or {}

    sec = "".join([
        _tile("Security crit + high", crit_high, "bad" if crit_high else "ok"),
        _tile("Security findings", sum(s["security"] for s in summaries)),
        _tile("Dependabot advisories", dbot, "bad" if dbot else ""),
        _tile("Sonar vulnerabilities", sonar("vulnerabilities")),
        _tile("Security hotspots", sonar("security_hotspots")),
        _tile("Duplicates merged", (stats.get("input", 0) - stats.get("output", 0)) or 0),
    ])
    qual = "".join([
        _tile("Bugs", sonar("bugs")),
        _tile("Code smells", sonar("code_smells")),
        # Two tiles, never one: a pooled percentage hides how little is measured.
        _tile("Coverage of measured", round(covered / measured * 100, 1) if measured else None),
        _tile("Codebase measured %", round(measured / ncloc * 100, 1) if measured and ncloc else None),
        _tile("Lines of code", f"{ncloc:,}" if ncloc else None),
        _tile("Deps scanned", _sum(summaries, lambda s: s.get("deps"))),
    ])
    chips = "".join(
        f'<span class="chip {"on" if v["collected"] else "off"}">'
        f'{"✓" if v["collected"] else "✗ not collected —"} {html.escape(name)}'
        f'{"" if v["collected"] else " " + html.escape(v["note"])}</span>'
        for name, v in sources.items())
    collected = sum(1 for v in sources.values() if v["collected"])
    subtitle = (f"{html.escape(payload.get('version') or '')} · <b>{len(rows)}</b> findings "
                f"after merging {stats.get('input', len(rows))} sightings · "
                f"{collected} of {len(sources)} sources collected")
    return (TEMPLATE
            .replace("__TITLE__", html.escape(payload["title"]))
            .replace("__SUBTITLE__", subtitle)
            .replace("__SEC_TILES__", sec)
            .replace("__QUAL_TILES__", qual)
            .replace("__CHIPS__", chips)
            # </script> inside a message must not end the script block.
            .replace("__DATA__", json.dumps(rows, ensure_ascii=False).replace("</", "<\\/")))
