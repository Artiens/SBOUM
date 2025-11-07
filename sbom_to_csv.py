#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import html
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# -------------------------
# Constantes & Regex
# -------------------------

ECOSYSTEM_MAP = {
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "gem": "RubyGems",
    "composer": "Packagist",
    "nuget": "NuGet",
    "apk": "APK",
    # "rpm": "RPM",
    "deb": "Debian",
    "alpm": "Arch Linux",
    #"cocoapods": "CocoaPods",
    "github": "GitHub",
    "generic": "generic",
}

VERSION_RX = re.compile(r'^(?:v)?\d+(?:\.\d+)*(?:[-+._][0-9A-Za-z.\-+]+)?$')
GO_NAME_RX = re.compile(r"^github\.com/[^/]+/[^/]+(?:/v\d+)?$")
GO_VER_RX  = re.compile(r"^v?\d+(\.\d+)*")

# motifs de “noms” plausibles dans les PDF
PKG_PATTERNS = [
    re.compile(r'^github\.com/[^/]+/[^/\s]+'),             # Go module
    re.compile(r'^[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+$'),    # Maven group:artifact
    re.compile(r'^@[^/\s]+/[^/\s]+$'),                     # npm scope/pkg
    re.compile(r'^(?=.*[A-Za-z])[a-z0-9][a-z0-9+\-_.]*$'),
]

# bruit typique à filtrer (TOC/titres)
STOPWORDS = { s.lower() for s in [
    "name", "version", "license", "licenses",
    "pan-os", "panorama", "wildfire", "cn-series",
    "globalprotect", "prisma", "remote browser isolation", "traps",
    "documentation", "portal", "contact information", "copyright",
    "january","february","march","april","may","june",
    "july","august","september","october","november","december"
]}

# --- écosystèmes connus par paquet (fallback soft) ---
KNOWN = {
    "cargo": {
        "tokio", "serde", "serde_json", "clap", "reqwest", "anyhow", "rayon", "regex",
        "lazy_static", "rand", "log", "chrono", "sqlx", "diesel", "axum", "hyper",
        "tokio-stream", "uuid", "thiserror", "async-trait", "futures", "git2",
        "warp", "tonic", "prost", "actix-web", "env_logger"
    },
    "npm": {
        "react", "react-dom", "express", "lodash", "axios", "moment", "chalk",
        "typescript", "webpack", "rxjs", "vue", "jquery", "redux", "next", "jest",
        "eslint", "commander", "dotenv", "body-parser", "graphql", "socket.io",
        "prettier", "ts-node", "tailwindcss", "vite", "angular", "svelte"
    },
    "pypi": {
        "requests", "numpy", "pandas", "flask", "pytest", "beautifulsoup4",
        "sqlalchemy", "matplotlib", "tensorflow", "scipy", "django", "urllib3",
        "boto3", "botocore", "certifi", "idna", "click", "pillow", "pyyaml", "six",
        "python-dateutil", "jmespath", "psutil", "pexpect", "pyasn1", "pyasn1-modules",
        "pycparser", "pymongo", "pyparsing", "pytz", "reportlab", "s3transfer",
        "setuptools", "uritemplate", "pypdf2", "vcstools", "rosdep", "rosdistro",
        "rospkg", "wheel", "pip", "virtualenv", "celery", "notebook", "fastapi"
    },
    "maven": {
        "spring-core", "spring-context", "spring-boot-starter", "spring-web", "spring-webmvc",
        "guava", "log4j", "log4j-core", "slf4j-api", "slf4j-simple", "commons-lang3",
        "commons-io", "commons-collections4", "hibernate-core", "hibernate-validator",
        "jackson-databind", "jackson-core", "jackson-annotations", "gson", "junit",
        "junit-jupiter", "okhttp", "protobuf-java", "netty-all", "fastjson",
        "lombok", "mockito-core"
    },
    "go": {
        "gin", "gorilla/mux", "cobra", "zap", "logrus", "go-chi/chi", "ginkgo",
        "gomega", "gorm", "viper", "grpc", "protobuf", "go-sql-driver/mysql",
        "prometheus", "go-restful", "echo", "fiber", "zerolog", "aws-sdk-go"
    },
    "rubygems": {
        "rails", "rack", "rake", "bundler", "sinatra", "jekyll", "nokogiri",
        "rspec", "capistrano"
    },
    "nuget": {
        "newtonsoft.json", "entityframework", "serilog", "nunit", "xunit",
        "autofac", "polly", "dapper"
    },
    "composer": {
        "symfony", "laravel", "guzzlehttp/guzzle", "monolog/monolog", "phpunit/phpunit",
        "twig/twig", "doctrine/orm"
    },
    
    "deb": {
        "openssl", "glibc", "zlib", "libxml2", "libssl", "curl", "systemd"
    }
}
KNOWN_LOWER = {eco: {n.lower() for n in names} for eco, names in KNOWN.items()}

PREFIX_HINTS = {
    "python3-": "pypi",
    "python2-": "pypi",
    "python-":  "pypi",
    "py-":      "pypi",
    "node-":    "npm",
    "npm-":     "npm",
    "js-":      "npm",
    "libjs-":   "npm",
    "java-":    "maven",
    "maven-":   "maven",
    "gradle-":  "maven",
}

SUFFIX_HINTS = {
    "-python3": "pypi",
    "-python2": "pypi",
    "-python":  "pypi",
    "-py":      "pypi",
    "-js":      "npm",
    "-java":    "maven",
    "-maven":   "maven",
    "-gradle":  "maven",
}

def clean_vendor(v: str) -> str:
    if not isinstance(v, str):
        return ""
    v = html.unescape(v)
    v = re.sub(r'^\s*(Organization|Person|Tool)\s*:\s*', '', v, flags=re.I)
    v = re.sub(r'<[^>]*>', '', v)
    v = v.replace('\\/', '/').strip()
    return v

def parse_purl(purl: str) -> Dict[str, Optional[str]]:
    
    out = {"type": None, "name": None, "version": None, "namespace": None, "qualifiers": {}}
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return out
    body = purl[4:]
    body = body.split("#", 1)[0]
    qs = {}
    if "?" in body:
        body, query = body.split("?", 1)
        from urllib.parse import parse_qs
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

def vendor_from_purl(p: Dict[str, Optional[str]]) -> Optional[str]:
    if not p or not p.get("type"):
        return None
    t = p["type"]
    ns = p.get("namespace") or ""
    if t == "golang":
        if ns.startswith("github.com/"):
            parts = ns.split("/")
            if len(parts) >= 2:
                return parts[1]
    if t == "npm":
        return ns or None
    if t == "maven":
        return ns or None
    if ns:
        return ns.split("/")[-1]
    return None

def guess_ecosystem_from_known(name: str) -> str:
    """
    Fallback basé sur la liste KNOWN.
    À utiliser uniquement si purl/lang/type/patterns n’ont rien donné.
    - Normalise le nom (dernier segment '/', ':', lstrip '@', '_'->'-')
    - Retire préfixes/suffixes distro (python3-*, *-devel, etc.)
    - Tokenize (ex: 'react', 'router', 'dom' pour 'react-router-dom')
    - Utilise des 'hints' (pré/suffixe) pour restreindre l’écosystème et éviter les faux positifs
    Retourne le libellé écosystème final (ECOSYSTEM_MAP) ou "" si inconnu.
    """
    import re

    if not isinstance(name, str) or not name:
        return ""
    s = name.strip().lower()

    # 1) hint par pré/suffixe
    hint = None
    for p, h in PREFIX_HINTS.items():
        if s.startswith(p):
            hint = h
            break
    if not hint:
        for suf, h in SUFFIX_HINTS.items():
            if s.endswith(suf):
                hint = h
                break

    # 2) candidats “bruts”
    cands = set()
    cands.add(s)
    if "/" in s:
        cands.add(s.split("/")[-1])      # dernier segment
    if ":" in s:
        cands.add(s.split(":")[-1])      # artifact
    cands.add(s.lstrip("@"))             # sans scope npm
    cands.add(s.replace("_", "-"))       # underscores -> tirets
    if s.startswith("@") and "/" in s:   # @scope/pkg -> pkg
        cands.add(s.split("/", 1)[1])

    # 3) retirer préfixe/suffixe pour obtenir la “base”
    base = s
    for p in PREFIX_HINTS.keys():
        if base.startswith(p):
            base = base[len(p):]
            break
    for suf in SUFFIX_HINTS.keys():
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    cands.add(base)

    # 4) tokens (séparateurs non alphanumériques)
    tokens = [t for t in re.split(r'[^a-z0-9]+', base) if t]
    cands.update(tokens)

    # 5) règle fréquente utile : react-* => npm
    if "react" in tokens:
        return "npm"

    # 6) recherche dans KNOWN, restreinte au hint si présent
    ecos_to_scan = KNOWN_LOWER.keys() if not hint else [hint]
    for eco_key in ecos_to_scan:
        names = KNOWN_LOWER[eco_key]
        if any(t in names for t in cands):
            return ECOSYSTEM_MAP.get(eco_key, eco_key)

    return ""

def guess_ecosystem(item: dict) -> str:
    # purl
    purl = item.get("purl") or item.get("package_url") or spdx_purl_from_external_refs(item)
    if isinstance(purl, str) and purl.startswith("pkg:"):
        typ = purl[4:].split("/", 1)[0]
        return ECOSYSTEM_MAP.get(typ, typ)
    # language / type
    lang = item.get("language")
    if isinstance(lang, str):
        l = lang.lower()
        if l in ("go", "golang"): return "Go"
        if l == "python": return "PyPI"
        if l == "rust": return "crates.io"
    typ = item.get("type")
    if isinstance(typ, str) and typ.lower() == "go-module":
        return "Go"
    # properties
    props = {p.get("name"): p.get("value") for p in item.get("properties", []) if isinstance(p, dict)}
    lang = (props.get("syft:package:language") or props.get("language"))
    if lang:
        l = lang.lower()
        if l in ("go", "golang"): return "Go"
        if l == "python": return "PyPI"
        if l == "rust": return "crates.io"
    # sourceInfo
    src = (item.get("sourceInfo") or "").lower()
    if "go module" in src or "go-module" in src: return "Go"
    if "maven" in src: return "Maven"
    if "npm" in src or "node" in src: return "npm"
    if "cargo" in src or "crate" in src: return "crates.io"
    if "pip" in src or "pypi" in src: return "PyPI"
    # Go name+version motifs
    name = item.get("name") or ""
    ver  = item.get("version") or item.get("versionInfo") or ""
    if GO_NAME_RX.match(name) and GO_VER_RX.match(ver):
        return "Go"
    # fallback KNOWN (si on a un nom)
    if name:
        eco = guess_ecosystem_from_known(name)
        if eco:
            return eco
    return ""

def normalize_json_item(item: Dict[str, Any]) -> Optional[Tuple[str, str, str, str]]:
    """
    Retourne (name, version, ecosystem, vendor) pour un item SBOM JSON
    """
    purl = item.get("purl") or item.get("package_url") or spdx_purl_from_external_refs(item)
    eco = name = version = None
    vendor = ""

    parsed_purl = parse_purl(purl) if purl else None
    if parsed_purl:
        eco = ECOSYSTEM_MAP.get(parsed_purl["type"], parsed_purl["type"])
        name = parsed_purl["name"]
        version = parsed_purl["version"]

    if not name:
        n = item.get("name")
        if isinstance(n, str) and n:
            name = n.split("/")[-1]

    if not version:
        version = item.get("version") or item.get("versionInfo")
        if not version and isinstance(item.get("cpe"), str):
            version = cpe_version(item["cpe"])

    if not eco:
        eco = guess_ecosystem(item)
        # fallback KNOWN si toujours rien
        if (not eco) and name:
            eco = guess_ecosystem_from_known(name)

    vendor = (
        vendor_from_supplier_or_publisher(item)
        or vendor_from_cpe_fields(item)
        or vendor_from_purl(parsed_purl)
        or ""
    )

    eco = eco or ""
    if not name or not version:
        return None
    return (name, version, eco, vendor)

def iterate_sbom_items(sbom: Any) -> Iterable[Dict[str, Any]]:
    """
    Supporte:
      - CycloneDX: dict["components"]
      - SPDX: dict["packages"]
      - Syft JSON: dict["artifacts"]
      - Liste d'items: list
    """
    if isinstance(sbom, dict):
        if isinstance(sbom.get("components"), list):
            yield from sbom["components"]
        if isinstance(sbom.get("packages"), list):
            yield from sbom["packages"]
        if isinstance(sbom.get("artifacts"), list):
            yield from sbom["artifacts"]
    elif isinstance(sbom, list):
        for item in sbom:
            if isinstance(item, dict):
                yield item

def extract_from_json_text(text: str) -> List[Tuple[str, str, str, str]]:
    sbom = json.loads(text)
    rows: List[Tuple[str, str, str, str]] = []
    seen = set()
    for item in iterate_sbom_items(sbom):
        norm = normalize_json_item(item)
        if not norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        rows.append(norm)
    return rows

def looks_like_pkg(name: str) -> bool:
    if not name:
        return False
    s = name.strip().lower()
    if s in STOPWORDS:
        return False
    if " " in name.strip() and not name.startswith("github.com/") and not name.startswith("@"):
        return False
    for rx in PKG_PATTERNS:
        if rx.match(name.strip()):
            return True
    return False

def detect_columns_from_headers(page) -> Tuple[Optional[float], Optional[float], Optional[float]]:
    """
    Retourne (x_name, x_version, header_y) d'après les spans contenant 'Name' et 'Version'.
    Si non trouvés: (None, None, None) -> page ignorée.
    """
    d = page.get_text("dict")
    cand_name, cand_ver, ys = [], [], []
    for b in d.get("blocks", []):
        for l in b.get("lines", []):
            y0 = l["bbox"][1]
            joined = "".join(s["text"] for s in l.get("spans", [])).strip()
            if not joined:
                continue
            low = joined.lower()
            if "name" in low and "version" in low:
                for s in l["spans"]:
                    st = s["text"].strip().lower()
                    if st == "name":
                        cand_name.append(s["bbox"][0])
                        ys.append(y0)
                    elif st == "version":
                        cand_ver.append(s["bbox"][0])
                        ys.append(y0)
            else:
                for s in l["spans"]:
                    st = s["text"].strip().lower()
                    if st == "name":
                        cand_name.append(s["bbox"][0]); ys.append(y0)
                    elif st == "version":
                        cand_ver.append(s["bbox"][0]); ys.append(y0)
    if cand_name and cand_ver and ys:
        x_name = sum(cand_name) / len(cand_name)
        x_ver  = sum(cand_ver)  / len(cand_ver)
        y_hdr  = min(ys)
        return (x_name, x_ver, y_hdr)
    return (None, None, None)

def extract_from_pdf(path: str, ocr_if_empty: bool = False) -> List[Tuple[str, str, str, str]]:
    import fitz  # PyMuPDF
    doc = fitz.open(path)
    pairs: List[Tuple[str, str]] = []

    for page in doc:
        x_name, x_ver, y_hdr = detect_columns_from_headers(page)
        if x_name is None or x_ver is None:
            # Pas d'entêtes détectées -> ignorer la page (évite TOC/titres)
            continue

        d = page.get_text("dict")
        rows = defaultdict(list)
        for b in d.get("blocks", []):
            for l in b.get("lines", []):
                y0 = l["bbox"][1]
                # ignorer tout ce qui est au-dessus de la ligne d'entête
                if y_hdr is not None and y0 <= y_hdr:
                    continue
                for s in l.get("spans", []):
                    txt = s.get("text", "").strip()
                    if not txt:
                        continue
                    x0 = s["bbox"][0]
                    rows[round(y0)].append((x0, txt))

        for y, items in sorted(rows.items()):
            items.sort(key=lambda t: t[0])

            name = version = None
            nearest_name = min(items, key=lambda t: abs(t[0] - x_name))
            if nearest_name and looks_like_pkg(nearest_name[1]):
                name = nearest_name[1]

            vers = [(abs(x - x_ver), txt) for (x, txt) in items if VERSION_RX.match(txt)]
            if vers:
                version = sorted(vers, key=lambda t: t[0])[0][1]

            if name and version:
                # filtres anti-numéros de page et bruit
                if name == version:
                    continue
                if re.fullmatch(r'\d{1,4}', name):  # nom purement numérique
                    continue
                pairs.append((name, version))

    # 2) Si rien trouvé et OCR autorisé → OCR de repli (PDF image/scanné)
    if not pairs and ocr_if_empty:
        try:
            from pdf2image import convert_from_path
            import pytesseract
            from PIL import Image
            pages = convert_from_path(path, dpi=300)
            for img in pages:
                txt = pytesseract.image_to_string(img, lang="eng")
                for raw in txt.splitlines():
                    line = raw.strip()
                    if not line:
                        continue
                    m = re.match(r'^([A-Za-z0-9._/@\-\+:]+)\s+(v?\d[\w.\-\+]*)\b', line)
                    if not m:
                        continue
                    cand_name, cand_ver = m.group(1), m.group(2)
                    if not looks_like_pkg(cand_name):
                        continue
                    if cand_name == cand_ver or re.fullmatch(r'\d{1,4}', cand_name):
                        continue
                    pairs.append((cand_name, cand_ver))
        except Exception:
            pass

    seen = set()
    rows: List[Tuple[str, str, str, str]] = []
    for name, version in pairs:
        key = (name, version)
        if key in seen:
            continue
        seen.add(key)

        ecosystem, vendor = "", ""

        # github.com/<org>/<repo>  -> Go + org, name = repo
        m = re.match(r'^github\.com/([^/]+)/([^/\s]+)', name)
        if m:
            vendor = m.group(1)
            name   = m.group(2)
            ecosystem = "Go"

        # Maven group:artifact
        elif ":" in name and "/" not in name and not name.startswith("@"):
            parts = name.split(":")
            if len(parts) == 2 and all(parts):
                vendor    = parts[0]
                name      = parts[1]
                ecosystem = "Maven"

        # npm @scope/pkg
        elif name.startswith("@") and "/" in name:
            scope, pkg = name[1:].split("/", 1)
            vendor    = scope
            name      = pkg
            ecosystem = "npm"

        # fallback écosystème via KNOWN si encore vide
        if not ecosystem:
            ecosystem = guess_ecosystem_from_known(name)

        rows.append((name, version, ecosystem or "", vendor or ""))

    # 4) Dédup final
    uniq, seen4 = [], set()
    for r in rows:
        if r in seen4:
            continue
        seen4.add(r)
        uniq.append(r)

    return uniq

def main():
    ap = argparse.ArgumentParser(
        description="SBOM JSON (CycloneDX/SPDX/Syft) ou PDF (OSS listings) -> CSV name,version,ecosystem,vendor"
    )
    ap.add_argument("--in", dest="inputs", nargs="+", required=True,
                    help="Un ou plusieurs fichiers SBOM/OSS (json|pdf).")
    ap.add_argument("--out", "-o", default="dependencies.csv",
                    help="Fichier CSV de sortie (défaut: dependencies.csv)")
    ap.add_argument("--ocr", action="store_true",
                    help="Autoriser l'OCR en repli si un PDF n'a pas de texte (nécessite tesseract + poppler).")
    args = ap.parse_args()

    all_rows: List[Tuple[str, str, str, str]] = []
    for inp in args.inputs:
        p = Path(inp)
        if not p.exists():
            print(f"[warn] introuvable: {p}", file=sys.stderr)
            continue

        rows: List[Tuple[str, str, str, str]] = []
        try:
            if p.suffix.lower() == ".pdf":
                rows = extract_from_pdf(p.as_posix(), ocr_if_empty=args.ocr)
            else:
                text = p.read_text(encoding="utf-8")
                rows = extract_from_json_text(text)
        except json.JSONDecodeError:
            # ce n'était pas du JSON → tenter PDF
            rows = extract_from_pdf(p.as_posix(), ocr_if_empty=args.ocr)

        all_rows.extend(rows)

    # dédup global
    seen = set()
    final: List[Tuple[str, str, str, str]] = []
    for r in all_rows:
        if r in seen:
            continue
        seen.add(r)
        final.append(r)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["name", "version", "ecosystem", "vendor"])
        w.writerows(final)

    print(f"Wrote {len(final)} rows to {out_path}")

if __name__ == "__main__":
    main()
