"""Collapse the same problem reported more than once into one row.

Five scanners overlap: Snyk, Semgrep Supply Chain, Trivy and Dependabot all read
dependency advisories, and SonarQube, Snyk Code and Semgrep Code all do SAST.
Reporting every sighting would double or triple the headline counts, so each
group of sightings becomes one row whose `by` lists every scanner that saw it.

Three passes, each conservative on purpose (a wrong merge hides a finding; a
missed merge only over-counts):

1. exact     same project, source, rule, location, line and message
2. advisory  same project, a shared CVE/GHSA id, and the same package
             (or a package unknown on one side)
3. sast      same project, file and line, and a shared CWE

Nothing is merged across projects. Misconfiguration rules (Snyk IaC vs Trivy)
use unrelated rule catalogues with no shared id, so they are never merged.
"""

from .model import rank

# Which row survives as the primary when a group merges: the richest metadata first.
SOURCE_PREFERENCE = ("Snyk", "Semgrep", "SonarQube", "Trivy", "Dependabot")

CODE_KINDS = {"Code", "Vulnerability", "Security Hotspot", "Bug", "Code Smell"}


class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        self.p[max(ra, rb)] = min(ra, rb)
        return True


def _pref(row):
    src = row["src"]
    order = SOURCE_PREFERENCE.index(src) if src in SOURCE_PREFERENCE else len(SOURCE_PREFERENCE)
    return (order, rank(row["sev"]))


def _merge(group):
    group = sorted(group, key=_pref)
    primary = dict(group[0])
    by = []
    for r in group:
        for s in r.get("by") or [r["src"]]:
            if s not in by:
                by.append(s)
    primary["by"] = by
    primary["ids"] = sorted({i for r in group for i in r.get("ids", [])})
    primary["cwe"] = sorted({c for r in group for c in r.get("cwe", [])})
    # The most severe opinion wins: under-stating a merged finding is the worse error.
    primary["sev"] = min((r["sev"] for r in group), key=rank)
    if not primary.get("fix"):
        primary["fix"] = next((r["fix"] for r in group if r.get("fix")), "")
    also = list(primary.get("also") or [])
    for r in group[1:]:
        also.append({k: r.get(k, "") for k in ("src", "kind", "ref", "loc", "line")})
        also.extend(r.get("also") or [])
    primary["also"] = also
    return primary


def _apply(rows, uf):
    groups = {}
    for i, r in enumerate(rows):
        groups.setdefault(uf.find(i), []).append(r)
    return [g[0] if len(g) == 1 else _merge(g) for _, g in sorted(groups.items())]


def _norm_path(p):
    p = (p or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def exact(rows):
    uf, first = _UF(len(rows)), {}
    for i, r in enumerate(rows):
        key = (r["proj"], r["src"], r["kind"], r["ref"], r["loc"], str(r["line"]), r["msg"])
        if key in first:
            uf.union(first[key], i)
        else:
            first[key] = i
    return _apply(rows, uf)


def advisory(rows):
    uf, by_id = _UF(len(rows)), {}
    for i, r in enumerate(rows):
        for adv in r.get("ids") or ():
            by_id.setdefault((r["proj"], adv), []).append(i)
    for members in by_id.values():
        by_pkg, unknown = {}, []
        for i in members:
            pkg = rows[i].get("_package", "")
            (by_pkg.setdefault(pkg, []) if pkg else unknown).append(i)
        for same in by_pkg.values():
            for i in same[1:]:
                uf.union(same[0], i)
        # A sighting with no package joins only when the id names one package;
        # otherwise it would bridge two different packages into one row.
        if unknown and len(by_pkg) <= 1:
            anchor = next(iter(by_pkg.values()))[0] if by_pkg else unknown[0]
            for i in unknown:
                uf.union(anchor, i)
    return _apply(rows, uf)


def sast(rows):
    uf, seen = _UF(len(rows)), {}
    for i, r in enumerate(rows):
        if r["kind"] not in CODE_KINDS or not r.get("cwe") or not r["line"]:
            continue
        for c in r["cwe"]:
            key = (r["proj"], _norm_path(r["loc"]), str(r["line"]), c)
            if key in seen:
                uf.union(seen[key], i)
            else:
                seen[key] = i
    return _apply(rows, uf)


def dedup(rows, passes=("exact", "advisory", "sast")):
    """Run the passes in order. Returns (rows, stats)."""
    stats = {"input": len(rows)}
    fns = {"exact": exact, "advisory": advisory, "sast": sast}
    for name in passes:
        before = len(rows)
        rows = fns[name](rows)
        stats[name] = before - len(rows)
    stats["output"] = len(rows)
    for r in rows:
        r.setdefault("by", [r["src"]])
        r.setdefault("also", [])
    return rows, stats
