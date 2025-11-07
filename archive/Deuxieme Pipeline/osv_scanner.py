# --- START OF FILE osv_scanner.py ---

import json
import urllib.request
import urllib.error
import sys

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

def query_osv(ecosystem: str, name: str, version: str, timeout: float = 30.0) -> dict:
    """
    Queries the OSV API for a single package.
    Returns the JSON response from the API or an empty dict on error.
    """
    # OSV API requires a valid ecosystem. It's better to skip than send an empty one.
    if not ecosystem or ecosystem.lower() == "unknown":
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
        print(f"[osv_scanner] OSV API HTTPError {e.code} for {ecosystem}:{name}:{version}. Body: {body}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[osv_scanner] OSV API URLError for {ecosystem}:{name}:{version}. Error: {e}", file=sys.stderr)
    
    # Return a consistent empty structure on error
    return {"vulns": []}