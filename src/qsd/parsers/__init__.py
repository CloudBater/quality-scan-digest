"""One parser per tool. Each returns rows built by qsd.model.finding plus a note.

A note is empty when the source was read cleanly, and otherwise says why it is
incomplete, so the report can mark it rather than show a short, reassuring list.
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


def unreadable(path, exc):
    return f"{os.path.basename(path)}: unreadable ({exc.__class__.__name__})"
