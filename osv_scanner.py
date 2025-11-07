# --- FILE: osv_scanner.py ---

import json
import sys
import urllib.request
import urllib.error
import os
import csv
from datetime import datetime

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def query_osv(ecosystem: str, name: str, version: str, timeout: float = 30.0) -> dict:
    """Query OSV API for a given package/version."""
    package_obj = {"name": name}
    if ecosystem:
        package_obj["ecosystem"] = ecosystem
    payload = {"package": package_obj, "version": version}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body or '{"vulns": []}')
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        print(f"[HTTPError {e.code}] {ecosystem}:{name}:{version} -> {body}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[URLError] {ecosystem}:{name}:{version} -> {e}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] {ecosystem}:{name}:{version} -> {e}", file=sys.stderr)
    return {"vulns": []}


def read_csv_rows(path: str):
    """Yield (ecosystem, name, version) from CSV."""
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("name") or "").strip()
            version = (row.get("version") or "").strip()
            ecosystem = (row.get("ecosystem") or "").strip()
            if not name or not version:
                continue
            yield ecosystem, name, version


def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <input_csv_file>")
        sys.exit(1)

    csv_path = sys.argv[1]
    if not os.path.exists(csv_path):
        print(f"[!] Input CSV file not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[{os.path.basename(__file__)}] Reading from: {csv_path}")

    rows = list(read_csv_rows(csv_path))
    total = len(rows)

    out_json = "osv_results.json"
    partial_path = "osv_results_partial.json"

    # === reprise automatique ===
    processed = set()
    results = []
    if os.path.exists(partial_path):
        try:
            with open(partial_path, "r", encoding="utf-8") as f:
                prev = json.load(f)
            for e in prev:
                pkg = e.get("package", {})
                processed.add((pkg.get("ecosystem"), pkg.get("name"), pkg.get("version")))
            results = prev
            print(f"[RESUME] Found {len(processed)} already processed packages.")
        except Exception as e:
            print(f"[!] Failed to load partial results: {e}", file=sys.stderr)

    # === scan incrémental ===
    try:
        for i, (ecosystem, name, version) in enumerate(rows, 1):
            if (ecosystem, name, version) in processed:
                continue

            print(f"[{i}/{total}] Querying OSV for: {ecosystem or '?'} / {name} @ {version}")
            resp = query_osv(ecosystem, name, version)
            # auto-détection d’écosystème si absent mais un seul résultat OSV
            if not ecosystem and isinstance(resp, dict):
                aff = resp.get("vulns") or []
                ecos = set()
                for v in aff:
                    for a in v.get("affected", []):
                        pkg = a.get("package", {})
                        eco = pkg.get("ecosystem")
                        if eco:
                            ecos.add(eco)
                if len(ecos) == 1:
                    ecosystem = ecos.pop()

            entry = {
                "package": {"ecosystem": ecosystem, "name": name, "version": version},
                "osv_response": resp,
            }
            results.append(entry)

            # écriture incrémentale à chaque résultat
            with open(partial_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Saving progress to osv_results_partial.json")
        with open(partial_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        sys.exit(0)

    # écriture finale complète
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"[{os.path.basename(__file__)}] OSV results written to {out_json} ({len(results)} packages checked)")


if __name__ == "__main__":
    main()
