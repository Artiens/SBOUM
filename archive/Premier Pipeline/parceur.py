# --- START OF FILE parceur.py ---

import json
import sys
import re
import argparse
import csv
import html
from pathlib import Path
from urllib.parse import parse_qs
from typing import Dict, Any, Iterable, List, Optional, Tuple

ECOSYSTEM_MAP = {
    "golang": "Go", "cargo": "crates.io", "npm": "npm", "pypi": "PyPI",
    "maven": "Maven", "gem": "RubyGems", "composer": "Packagist", "nuget": "NuGet",
    "apk": "APK", "rpm": "RPM", "deb": "Debian", "alpm": "Arch Linux",
    "cocoapods": "CocoaPods", "github": "GitHub", "generic": "generic",
}

def parse_purl(purl: str) -> Dict[str, Any]:
    out = {"type": None, "name": None, "version": None, "namespace": None, "qualifiers": {}}
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return out
    body = purl[4:]
    body, *_ = body.split("#", 1)
    qs: Dict[str, str] = {}
    if "?" in body:
        body, query = body.split("?", 1)
        qs = {k: v[0] for k, v in parse_qs(query).items()}
    if "@" in body:
        left, version = body.rsplit("@", 1)
    else:
        left, version = body, None
    if "/" in left:
        purl_type, path = left.split("/", 1)
    else:
        purl_type, path = left, ""
    name = path.split("/")[-1] if path else None
    namespace = path.rsplit("/", 1)[0] if "/" in path else None
    return {"type": purl_type or None, "name": name or None, "version": version or None,
            "namespace": namespace, "qualifiers": qs}

def cpe_version(cpe: str) -> Optional[str]:
    try:
        parts = cpe.split(":")
        return parts[5] if len(parts) > 5 else None
    except Exception:
        return None

def cpe_vendor(cpe: str) -> Optional[str]:
    try:
        parts = cpe.split(":")
        if len(parts) > 3:
            v = clean_vendor(parts[3])
            return v or None
    except Exception:
        pass
    return None

def spdx_purl_from_external_refs(pkg: Dict[str, Any]) -> Optional[str]:
    refs = pkg.get("externalRefs") or pkg.get("externalReferences")
    if not isinstance(refs, list):
        return None
    for ref in refs:
        if (ref.get("referenceType") == "purl" or ref.get("type") == "purl"):
            loc = ref.get("referenceLocator") or ref.get("locator")
            if isinstance(loc, str) and loc:
                return loc
    return None

def iterate_sbom_items(sbom: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(sbom, dict):
        if isinstance(sbom.get("components"), list):   # CycloneDX
            yield from sbom["components"]
        if isinstance(sbom.get("packages"), list):     # SPDX
            yield from sbom["packages"]
        if isinstance(sbom.get("artifacts"), list):    # Syft JSON
            yield from sbom["artifacts"]
    elif isinstance(sbom, list):
        for item in sbom:
            yield item

def clean_vendor(v: str) -> str:
    if not isinstance(v, str):
        return ""
    v = html.unescape(v)
    v = re.sub(r'^\s*(Organization|Person|Tool)\s*:\s*', '', v, flags=re.I)
    v = re.sub(r'<[^>]*>', '', v)
    v = v.replace('\\/', '/').strip()
    return v

def vendor_from_supplier_or_publisher(item: Dict[str, Any]) -> Optional[str]:
    supplier = item.get("supplier") or item.get("publisher") or item.get("author")
    if isinstance(supplier, str) and supplier and supplier.upper() != "NOASSERTION":
        v = clean_vendor(supplier)
        if v:
            return v
    return None

def vendor_from_cpe_fields(item: Dict[str, Any]) -> Optional[str]:
    if isinstance(item.get("cpe"), str):
        v = cpe_vendor(item["cpe"])
        if v:
            return v
    cpes = item.get("cpes")
    if isinstance(cpes, list):
        for e in cpes:
            if isinstance(e, dict) and isinstance(e.get("cpe"), str):
                v = cpe_vendor(e["cpe"])
                if v:
                    return v
    props = item.get("properties") or []
    for p in props:
        if isinstance(p, dict) and p.get("name") == "syft:cpe23" and isinstance(p.get("value"), str):
            v = cpe_vendor(p["value"])
            if v:
                return v
    return None

def vendor_from_purl(p: Dict[str, Any]) -> Optional[str]:
    if not p or not p.get("type"):
        return None
    t = p["type"]
    ns = p.get("namespace") or ""
    if t == "golang":
        if ns.startswith("github.com/"):
            parts = ns.split("/")
            if len(parts) >= 2:
                return parts[1]
    if t == "npm" and isinstance(ns, str) and ns.startswith("@"):
        return ns[1:]
    if t == "maven":
        return ns or None
    if ns:
        return ns.split("/")[-1]
    return None

def guess_ecosystem(item: dict) -> str:
    purl = item.get("purl") or item.get("package_url") or spdx_purl_from_external_refs(item)
    if isinstance(purl, str) and purl.startswith("pkg:"):
        typ = purl[4:].split("/", 1)[0]
        return ECOSYSTEM_MAP.get(typ, typ)
    # This function can be expanded with more heuristics
    return "unknown"

def normalize_entry(item: Dict[str, Any]) -> Optional[Tuple[str, str, str, str]]:
    purl = item.get("purl") or item.get("package_url") or spdx_purl_from_external_refs(item)
    eco = name = version = None
    vendor = ""

    parsed_purl = parse_purl(purl) if purl else {}
    eco = ECOSYSTEM_MAP.get(str(parsed_purl.get("type")), parsed_purl.get("type"))
    name = parsed_purl.get("name")
    version = parsed_purl.get("version")

    if not name:
        n = item.get("name")
        if isinstance(n, str) and n:
            name = n

    if not version:
        version = item.get("version") or item.get("versionInfo")
        if not version and isinstance(item.get("cpe"), str):
            version = cpe_version(item["cpe"])

    if not eco or eco == 'None':
        eco = guess_ecosystem(item)
    
    # Clean up name from potential namespace in npm
    if eco == 'npm' and name and name.startswith('@') and '/' in name:
        name = name.split('/', 1)[1]

    vendor = (
        vendor_from_supplier_or_publisher(item)
        or vendor_from_cpe_fields(item)
        or vendor_from_purl(parsed_purl)
        or ""
    )

    eco = eco or "unknown"
    if not name or not version:
        return None
    return (name, str(version), eco, vendor)

def main():
    parser = argparse.ArgumentParser(description="SBOM JSON -> CSV (name,version,ecosystem,vendor)")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--json", help="SBOM as a JSON string.")
    g.add_argument("--file", help="Path to the SBOM JSON file.")
    parser.add_argument("--out", "-o", default="sbom_packages.csv", help="Output CSV file.")
    args = parser.parse_args()

    if args.json:
        raw = args.json
    else: # args.file is guaranteed to be there
        raw = Path(args.file).read_text(encoding="utf-8")

    try:
        sbom = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON file. {e}", file=sys.stderr)
        sys.exit(1)

    rows: List[Tuple[str, str, str, str]] = []
    seen = set()
    for item in iterate_sbom_items(sbom):
        norm = normalize_entry(item)
        if not norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        rows.append(norm)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "version", "ecosystem", "vendor"])
        writer.writerows(rows)

    print(f"[{Path(__file__).name}] Wrote {len(rows)} rows to {out_path}")

if __name__ == "__main__":
    main()