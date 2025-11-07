# --- START OF FILE osv_scanner.py ---

import json
import sys
import urllib.request
import urllib.error
import os
import csv
from datetime import datetime

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

def query_osv(ecosystem: str, name: str, version: str, timeout: float = 30.0) -> dict:
    if not ecosystem: # OSV API requires an ecosystem
        return {"vulns": []}
        
    payload = {
        "package": {"ecosystem": ecosystem, "name": name},
        "version": version,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            # An empty response from OSV means no vulnerabilities found
            return json.loads(resp_body or '{"vulns": []}')
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        print(f"OSV API HTTPError {e.code} for {ecosystem}:{name}:{version}. Body: {body}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"OSV API URLError for {ecosystem}:{name}:{version}. Error: {e}", file=sys.stderr)
    return {"vulns": []} # Return an empty structure on error


def read_csv_rows(path: str):
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

    results = []
    rows = list(read_csv_rows(csv_path))
    total = len(rows)

    for i, (ecosystem, name, version) in enumerate(rows, 1):
        print(f"[{i}/{total}] Querying OSV for: {ecosystem} / {name} @ {version}")
        resp = query_osv(ecosystem, name, version)
        results.append({
            "package": {"ecosystem": ecosystem, "name": name, "version": version},
            "osv_response": resp,
        })

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_json = f"osv_results_{ts}.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"[{os.path.basename(__file__)}] OSV results written to {out_json} ({len(results)} packages checked)")


if __name__ == "__main__":
    main()