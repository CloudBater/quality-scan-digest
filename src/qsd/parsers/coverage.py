"""Test coverage: Cobertura XML or an Istanbul coverage-summary.json."""

import json
import xml.etree.ElementTree as ET


def load(path):
    """Return ({pct, covered, measured}, note). The denominator is the point:
    100% of a narrowly scoped `include` is not 100% of the codebase."""
    try:
        if path.endswith(".xml"):
            root = ET.parse(path).getroot()
            rate = root.get("line-rate")
            if rate is None:
                return None, "coverage XML has no line-rate attribute"
            return {"pct": round(float(rate) * 100, 1),
                    "covered": int(root.get("lines-covered") or 0),
                    "measured": int(root.get("lines-valid") or 0)}, ""
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        lines = doc.get("total", {}).get("lines", {})
        if lines.get("pct") is None:
            return None, "coverage summary has no total.lines.pct"
        return {"pct": round(float(lines["pct"]), 1),
                "covered": int(lines.get("covered") or 0),
                "measured": int(lines.get("total") or 0)}, ""
    except (OSError, ET.ParseError, ValueError, AttributeError) as exc:
        return None, f"coverage unreadable ({exc.__class__.__name__})"
