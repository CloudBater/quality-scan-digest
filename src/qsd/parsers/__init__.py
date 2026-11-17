"""One parser per tool.

Every parser returns (rows, status). status is a dict:
  ok        the file was this tool's output and was read; False = not collected
  note      why the source is not collected, or why it is incomplete
  ...       optional extras (dependency count, alert counts)
A source with ok=True and a note is collected but incomplete. Nothing that is
not recognisably the tool's output is ever read as an empty, clean result.
"""

import json
import os


def read_json(path):
    """Load a JSON file, or a stream of concatenated JSON documents.

    `gh api --paginate` without --slurp prints one array per page back to back,
    which is not a single valid document.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        dec, pos, docs = json.JSONDecoder(), 0, []
        while pos < len(text):
            while pos < len(text) and text[pos].isspace():
                pos += 1
            if pos >= len(text):
                break
            doc, pos = dec.raw_decode(text, pos)
            docs.append(doc)
        if not docs:
            raise
        return docs


def status(ok=True, note="", **extra):
    return {"ok": ok, "note": note, **extra}


def failed(note):
    return [], status(False, note)


def unreadable(path, exc):
    return failed(f"{os.path.basename(path)}: unreadable ({exc.__class__.__name__})")
