#!/usr/bin/env python3
"""Refresh the vendored EOL snapshot (eol_data.json) from endoflife.date.

Run by the weekly CI job (.github/workflows/scheduled.yml), which opens a PR if
the snapshot changed. This is the ONLY place remedify touches the network for
EOL data — the tool itself reads the committed snapshot offline at runtime, so
the zero-dependency / air-gap promise is preserved.

    python3 scripts/update_eol.py            # rewrite eol_data.json
    python3 scripts/update_eol.py --check    # exit 1 if it would change (CI)
"""

import datetime
import json
import os
import sys
import urllib.request

# family product-slug on endoflife.date -> kept in sync with ENDOFLIFE_PRODUCTS
PRODUCTS = ["ubuntu", "debian", "amazon-linux", "centos", "alpine", "rhel"]
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "eol_data.json")


def fetch(product):
    url = f"https://endoflife.date/api/{product}.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    # keep only the fields remedify uses — small, stable, reviewable diffs
    return [{"cycle": str(c.get("cycle")), "eol": c.get("eol")}
            for c in data if isinstance(c, dict) and c.get("cycle") is not None]


def build():
    return {
        "_comment": ("Vendored end-of-life snapshot. Read at runtime OFFLINE "
                     "(no network, air-gap safe). Refreshed by "
                     "scripts/update_eol.py via a weekly CI pull request. "
                     "Source: https://endoflife.date"),
        "generated": datetime.date.today().isoformat(),
        "products": {p: fetch(p) for p in PRODUCTS},
    }


def _normalize(doc):
    # ignore the generated date when comparing for changes
    return json.dumps({"products": doc.get("products")}, sort_keys=True)


def main():
    new = build()
    if "--check" in sys.argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                old = json.load(f)
        except (OSError, ValueError):
            old = {}
        if _normalize(old) != _normalize(new):
            print("eol_data.json is out of date — run scripts/update_eol.py")
            sys.exit(1)
        print("eol_data.json is up to date")
        return
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(new, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
