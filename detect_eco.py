import json
from collections import Counter

INPUT_PATH = 'osv_results.json'
OUTPUT_PATH = 'osv_results_pareto.json'
DOMINANCE_THRESHOLD = 0.70


def vuln_ecosystems(vuln: dict) -> set:
    affected = vuln.get('affected') or []
    ecos = set()
    for aff in affected:
        pkg = aff.get('package') or {}
        eco = pkg.get('ecosystem')
        if eco:
            ecos.add(eco)
    return ecos


def normalize_ecosystem(raw: str) -> str:
    if not raw:
        return ""
    token = str(raw).strip()
    # Drop version/channel suffixes like "Alpine:v3.18" -> "Alpine"
    if ":" in token:
        token = token.split(":", 1)[0].strip()
    lower = token.lower()
    mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "pip": "PyPI",
        "rubygems": "RubyGems",
        "gem": "RubyGems",
        "maven": "Maven",
        "go": "Go",
        "golang": "Go",
        "crates.io": "crates.io",
        "cargo": "crates.io",
        "packagist": "Packagist",
        "nuget": "NuGet",
        "hex": "Hex",
        "pub": "Pub",
        "cocoapods": "CocoaPods",
        "alpine": "Alpine",
        "debian": "Debian",
        "ubuntu": "Ubuntu",
        "android": "Android",
    }
    if lower in mapping:
        return mapping[lower]
    # Default: return the token with original capitalization (or title-case)
    return token


def collect_library_ecosystems(entries: list) -> dict:
    lib_to_ecos = {}
    for e in entries:
        name = (e.get('package') or {}).get('name') or ''
        vulns = (e.get('osv_response') or {}).get('vulns') or []
        ecos = set()
        for v in vulns:
            ecos.update(vuln_ecosystems(v))
        # Fallback: if no vuln ecosystems listed, consider the package's own ecosystem as a hint
        if not ecos:
            pkg_eco = (e.get('package') or {}).get('ecosystem')
            if pkg_eco:
                ecos.add(pkg_eco)
        lib_to_ecos[name] = ecos
    return lib_to_ecos


def dominant_ecosystem(lib_to_ecos: dict, threshold: float) -> tuple:
    unique_lib_ecos = [next(iter(ecos)) for ecos in lib_to_ecos.values() if len(ecos) == 1]
    if not unique_lib_ecos:
        return None, 0.0
    counts = Counter(unique_lib_ecos)
    eco, cnt = counts.most_common(1)[0]
    ratio = cnt / len(unique_lib_ecos)
    if ratio > threshold:
        return eco, ratio
    return None, ratio


def filter_entries_by_ecosystem(entries: list, target_eco: str) -> list:
    filtered = []
    for e in entries:
        vulns = (e.get('osv_response') or {}).get('vulns') or []
        kept_vulns = []
        inferred_eco = None
        for v in vulns:
            ecos = vuln_ecosystems(v)
            if not ecos:
                # If OSV did not specify ecosystems at vuln level, fall back to package ecosystem
                pkg_eco = (e.get('package') or {}).get('ecosystem')
                if pkg_eco == target_eco:
                    kept_vulns.append(v)
                    inferred_eco = target_eco
            else:
                if target_eco in ecos:
                    kept_vulns.append(v)
                    inferred_eco = target_eco
            # If the vulnerability only lists a single ecosystem, we can use it as inferred value
            if not inferred_eco and ecos and len(ecos) == 1:
                inferred_eco = next(iter(ecos))
        new_entry = {
            "package": dict(e.get('package') or {}),
            "osv_response": {"vulns": kept_vulns}
        }
        if inferred_eco:
            new_entry["package"]["ecosystem"] = inferred_eco
        else:
            new_entry["package"].setdefault("ecosystem", target_eco)
        filtered.append(new_entry)
    return filtered


def main():
    with open(INPUT_PATH, 'r', encoding='utf-8') as f:
        entries = json.load(f)

    lib_to_ecos = collect_library_ecosystems(entries)
    # Build normalized ecosystems per lib (used for both printing and Pareto understanding)
    normalized_lib_to_ecos = {}
    for lib, ecos in lib_to_ecos.items():
        norm = {normalize_ecosystem(e) for e in ecos if normalize_ecosystem(e)}
        normalized_lib_to_ecos[lib] = norm

    # Identify libraries that have multiple normalized ecosystems (require a choice)
    conflict_libs = [lib for lib, ecos in normalized_lib_to_ecos.items() if len(ecos) > 1]

    # Do not print the conflict list anymore; only print percentages below

    # Compute and print percentage distribution among libs that have a single normalized ecosystem
    unique_norm_ecos = [next(iter(ecos)) for ecos in normalized_lib_to_ecos.values() if len(ecos) == 1]
    if unique_norm_ecos:
        from collections import Counter
        counts = Counter(unique_norm_ecos)
        total_unique = len(unique_norm_ecos)
        for eco_name, cnt in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            pct = (cnt / total_unique) * 100.0
            print(f"% {eco_name}: {pct:.2f}% ({cnt}/{total_unique})")
    eco, ratio = dominant_ecosystem(lib_to_ecos, DOMINANCE_THRESHOLD)

    if eco is None:
        out = entries
        decision = {
            "dominant": None,
            "ratio": ratio,
            "threshold": DOMINANCE_THRESHOLD,
            "action": "no_selection"
        }
    else:
        out = filter_entries_by_ecosystem(entries, eco)
        decision = {
            "dominant": eco,
            "ratio": ratio,
            "threshold": DOMINANCE_THRESHOLD,
            "action": "filtered_by_dominant_ecosystem"
        }
        # No extra printing here; candidates already printed above in normalized form

    # Wrap result with a small header for traceability
    result = {
        "pareto": decision,
        "results": out
    }
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    # Only percentages are printed above; keep file write silent


if __name__ == '__main__':
    main()