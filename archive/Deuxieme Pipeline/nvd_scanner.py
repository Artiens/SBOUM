# --- START OF FILE nvd_scanner.py ---

import os
import json
import urllib.request
import urllib.error
import urllib.parse
import sys
import time
from typing import Dict, Any

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD requires a delay between requests. With an API key, this can be short.
# Without a key, it should be ~6 seconds.
REQUEST_DELAY_SECONDS = 0.6 

def build_cpe_uri(vendor: str, product: str, version: str) -> str:
    """Builds a CPE URI for precise matching in the NVD API."""
    # Basic sanitization
    vendor = urllib.parse.quote(vendor.lower())
    product = urllib.parse.quote(product.lower())
    version = urllib.parse.quote(version)
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

def query_nvd(name: str, version: str, vendor: str, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Queries the NVD API for a single package using CPE if possible.
    """
    api_key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}

    # CPE matching is the most reliable method
    if vendor and name:
        cpe_name = build_cpe_uri(vendor, name, version)
        params = {"cpeName": cpe_name}
    else:
        # Fallback to keyword search if vendor is missing (less accurate)
        keyword = f"{name} {version}"
        params = {"keywordSearch": keyword, "keywordExactMatch": ""}
    
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    
    req = urllib.request.Request(url, headers=headers)

    # Respect NVD rate limiting
    time.sleep(REQUEST_DELAY_SECONDS)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            return json.loads(resp_body)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if hasattr(e, "read") else ""
        print(f"[nvd_scanner] NVD API HTTPError {e.code} for {name}:{version}. Body: {body}", file=sys.stderr)
    except urllib.error.URLError as e:
        print(f"[nvd_scanner] NVD API URLError for {name}:{version}. Error: {e}", file=sys.stderr)
        
    return {"vulnerabilities": []} # Return a consistent empty structure on error