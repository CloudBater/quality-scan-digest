"""Collapse the same problem reported by more than one scanner into one row.

Snyk, Semgrep Supply Chain, Trivy and Dependabot read the same advisory
databases, so one vulnerable package can arrive three or four times. Each group
of sightings becomes one row whose `by` lists every scanner that saw it, and
whose `also` keeps every other sighting in full, so nothing is lost.

Every pass is conservative on purpose: a wrong merge hides a finding, a missed
merge only over-counts.

  exact     same project, source, kind, rule, location, line, column and message
  advisory  same project and package (ecosystem-aware) and a shared CVE/GHSA id,
            reported by DIFFERENT scanners. Rows with no package never bridge two
            packages.
  sast      OFF by default. Same project, file, line and CWE, reported by
            DIFFERENT scanners; each row joins at most one group, so findings
            never chain into each other.

Nothing is merged across projects (keyed by project id, not display label), and a
group never holds two rows from the same scanner: a tool's own separate findings are
its own determination (Snyk files one CVE under several ids, one per affected range),
and only a second scanner agreeing is evidence of a duplicate.
"""

from .model import rank

# Which sighting becomes the primary row of a group: the richest metadata first.
SOURCE_PREFERENCE = ("Snyk", "Semgrep", "SonarQube", "OSV-Scanner", "Trivy", "Dependabot",
                     "GuardDog", "ClamAV", "Gitleaks", "zizmor")

CODE_KINDS = {"Vulnerability", "Security Hotspot", "Bug", "Code Smell"}
DEFAULT_PASSES = ("exact", "advisory")
ALL_PASSES = ("exact", "advisory", "sast")

_SIGHTING = ("src", "kind", "sev", "msg", "loc", "line", "col", "ref", "fix", "ids", "cwe")


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
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


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
    primary["security"] = any(r.get("security") for r in group)
    if not primary.get("fix"):
        primary["fix"] = next((r["fix"] for r in group if r.get("fix")), "")
    also = list(primary.get("also") or [])
    for r in group[1:]:
        also.append({k: r.get(k, "") for k in _SIGHTING})
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
        # Column is part of the key: two smells of one rule on one line are two findings.
        key = (r["project_id"], r["src"], r["kind"], r["ref"], r["loc"],
               str(r["line"]), str(r.get("col", "")), r["msg"])
        if key in first:
            uf.union(first[key], i)
        else:
            first[key] = i
    return _apply(rows, uf)


def _pkg_key(r):
    return (r["project_id"], r.get("_eco", ""), r.get("_package", ""))


def _compatible(a, b):
    """Same package, and the same ecosystem when both rows know theirs."""
    if a[0] != b[0] or a[2] != b[2]:
        return False
    return not a[1] or not b[1] or a[1] == b[1]


def advisory(rows):
    uf = _UF(len(rows))
    scanners = {i: set(r.get("by") or [r["src"]]) for i, r in enumerate(rows)}

    def join(a, b):
        ra, rb = uf.find(a), uf.find(b)
        if ra == rb or scanners[ra] & scanners[rb]:
            return  # never merge two rows one scanner reported separately
        uf.union(ra, rb)
        scanners[uf.find(ra)] = scanners[ra] | scanners[rb]

    known = [i for i, r in enumerate(rows) if r.get("ids") and r.get("_package")]
    unknown = [i for i, r in enumerate(rows) if r.get("ids") and not r.get("_package")]

    # 1. Rows that name a package merge only with rows naming the same package.
    by_id = {}
    for i in known:
        for adv in rows[i]["ids"]:
            for j in by_id.get((rows[i]["project_id"], adv), []):
                if _compatible(_pkg_key(rows[i]), _pkg_key(rows[j])):
                    join(i, j)
            by_id.setdefault((rows[i]["project_id"], adv), []).append(i)

    # 2. A row with no package joins only if every id it carries leads to one
    #    and the same package group; otherwise it stays on its own.
    for i in unknown:
        roots = set()
        for adv in rows[i]["ids"]:
            for j in by_id.get((rows[i]["project_id"], adv), []):
                roots.add(uf.find(j))
        if len(roots) == 1:
            join(i, roots.pop())
    return _apply(rows, uf)


def sast(rows):
    uf, groups = _UF(len(rows)), {}
    for i, r in enumerate(rows):
        if r["kind"] not in CODE_KINDS or not r.get("cwe") or not r["line"]:
            continue
        keys = [(r["project_id"], _norm_path(r["loc"]), str(r["line"]), c) for c in r["cwe"]]
        # Cross-tool only, and each row belongs to exactly one group: no chains.
        target = next((k for k in keys if k in groups
                       and all(rows[m]["src"] != r["src"] for m in groups[k])), None)
        if target is not None:
            uf.union(groups[target][0], i)
            groups[target].append(i)
        else:
            free = next((k for k in keys if k not in groups), None)
            if free is not None:
                groups[free] = [i]
    return _apply(rows, uf)


def dedup(rows, passes=DEFAULT_PASSES):
    """Run the passes in order. Returns (rows, stats)."""
    stats = {"input": len(rows), "passes": list(passes)}
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
