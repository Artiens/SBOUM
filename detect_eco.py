import json
import sys
import argparse
from collections import Counter

# Constantes
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
    """Filtre la liste complète d'entrées par l'écosystème dominant (mode Pareto)."""
    filtered = []
    for e in entries:
        vulns = (e.get('osv_response') or {}).get('vulns') or []
        kept_vulns = []
        inferred_eco = None
        for v in vulns:
            ecos = vuln_ecosystems(v)
            if not ecos:
                # Fallback à l'écosystème du paquet si non spécifié au niveau de la vuln
                pkg_eco = (e.get('package') or {}).get('ecosystem')
                if pkg_eco == target_eco:
                    kept_vulns.append(v)
                    inferred_eco = target_eco
            else:
                if target_eco in ecos:
                    kept_vulns.append(v)
                    inferred_eco = target_eco
            # Si la vulnérabilité liste un seul écosystème, nous pouvons l'utiliser
            if not inferred_eco and ecos and len(ecos) == 1:
                inferred_eco = next(iter(ecos))
                
        new_entry = {
            "package": dict(e.get('package') or {}),
            "osv_response": {"vulns": kept_vulns}
        }
        # Mise à jour de l'écosystème du paquet avec l'écosystème dominant/inféré
        if inferred_eco:
            new_entry["package"]["ecosystem"] = inferred_eco
        else:
            new_entry["package"].setdefault("ecosystem", target_eco)
            
        filtered.append(new_entry)
    return filtered

# --- NOUVELLES FONCTIONS POUR LE MODE MANUEL ---

def filter_entries_by_ecosystem_for_one_package(e: dict, target_eco: str) -> dict:
    """Filtre les vulnérabilités d'un SEUL paquet par l'écosystème choisi manuellement."""
    vulns = (e.get('osv_response') or {}).get('vulns') or []
    kept_vulns = []
    
    for v in vulns:
        # Normaliser les écosystèmes de la vulnérabilité avant de comparer au target_eco
        ecos = {normalize_ecosystem(raw) for raw in vuln_ecosystems(v)}
        
        if target_eco in ecos:
            kept_vulns.append(v)
            
    new_entry = {
        "package": dict(e.get('package') or {}),
        "osv_response": {"vulns": kept_vulns}
    }
    # Définir l'écosystème sur le choix de l'utilisateur (déjà normalisé)
    new_entry["package"]["ecosystem"] = target_eco 
    return new_entry


def manual_ecosystem_selection(lib_name: str, ecos_set: set) -> str:
    """
    Affiche la distribution des écosystèmes possibles et demande à l'utilisateur
    de choisir manuellement. Retourne l'écosystème choisi ou 'unknown'.
    """
    print("\n" + "="*80)
    print(f"Conflicting ecosystems for package: '{lib_name}'")
    
    # Calcul de la répartition uniforme (pourcentages) en l'absence de données de confiance plus précises
    distribution = {eco: 1.0 / len(ecos_set) for eco in sorted(ecos_set)}
    
    candidates = {}
    print("Potential ecosystems (based on linked CVEs):")
    for i, (eco, prob) in enumerate(distribution.items(), 1):
        # Utiliser le nom normalisé pour le choix et l'affichage
        candidates[str(i)] = eco 
        print(f"  [{i}] {eco} ({prob*100:.2f}% chance)")
    
    print(f"  [u] Leave as unknown (keep all CVEs for this package)")
    
    while True:
        try:
            choice = input(f"Select dominant ecosystem [1-{len(candidates)}] or [u]: ").strip().lower()
        except EOFError:
            return "unknown" 
            
        if choice == 'u':
            print(f"-> Package '{lib_name}' left as unknown. No filtering applied to its CVEs.")
            return "unknown"
        if choice in candidates:
            selected_eco = candidates[choice]
            print(f"-> Selected ecosystem: {selected_eco}")
            return selected_eco
        print("Invalid choice. Please try again.")

# --- MAIN ---

def main():
    parser = argparse.ArgumentParser(description="Applies Pareto filtering or allows manual ecosystem selection on OSV results.")
    parser.add_argument("input_path", help=f"Path to the input JSON file (default: {INPUT_PATH})", nargs='?', default=INPUT_PATH)
    parser.add_argument("--manual-select", action="store_true", help="Bypass Pareto rule and force manual selection for conflicting ecosystems.")
    
    args = parser.parse_args()
    
    try:
        with open(args.input_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)
    except FileNotFoundError:
        print(f"Error: Input file not found at '{args.input_path}'", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{args.input_path}': {e}", file=sys.stderr)
        sys.exit(1)


    lib_to_ecos = collect_library_ecosystems(entries)
    # Build normalized ecosystems per lib
    normalized_lib_to_ecos = {}
    for lib, ecos in lib_to_ecos.items():
        # Utiliser le normalize_ecosystem pour uniformiser les noms d'écosystèmes (ex: 'go' et 'golang' deviennent 'Go')
        norm = {normalize_ecosystem(e) for e in ecos if normalize_ecosystem(e)}
        normalized_lib_to_ecos[lib] = norm

    # --- Mode Manuel ---
    if args.manual_select:
        print("\n--- Manual Ecosystem Selection Mode Activated ---")
        
        final_entries = []
        
        for entry in entries:
            name = (entry.get('package') or {}).get('name') or ''
            
            # Récupérer les écosystèmes normalisés associés à ce paquet
            normalized_ecos = normalized_lib_to_ecos.get(name) or set()
            
            target_eco = None
            
            if len(normalized_ecos) == 1:
                # Écosystème unique, pas besoin de choisir
                target_eco = next(iter(normalized_ecos))
            elif len(normalized_ecos) > 1:
                # Conflit: demande à l'utilisateur et affiche les pourcentages
                choice = manual_ecosystem_selection(name, normalized_ecos)
                if choice != "unknown":
                    target_eco = choice
            
            if target_eco:
                # Appliquer le filtrage pour ce paquet spécifique
                new_entry = filter_entries_by_ecosystem_for_one_package(entry, target_eco)
            else:
                # Si inconnu ou conflit non résolu, conservez l'entrée originale (toutes les vulnérabilités)
                new_entry = entry 
            
            final_entries.append(new_entry)
            
        out = final_entries
        decision = {
            "dominant": "Manual Selection",
            "ratio": 1.0,
            "threshold": DOMINANCE_THRESHOLD,
            "action": "filtered_by_manual_selection"
        }

    # --- Mode Pareto (Automatique) ---
    else:
        # Compute and print percentage distribution among libs that have a single normalized ecosystem
        unique_norm_ecos = [next(iter(ecos)) for ecos in normalized_lib_to_ecos.values() if len(ecos) == 1]
        if unique_norm_ecos:
            counts = Counter(unique_norm_ecos)
            total_unique = len(unique_norm_ecos)
            print("\n--- Ecosystem Distribution (Single Match Packages) ---")
            for eco_name, cnt in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
                pct = (cnt / total_unique) * 100.0
                print(f"Percentage {eco_name}: {pct:.2f}% ({cnt}/{total_unique})")
            print("-----------------------------------------------------")

        eco, ratio = dominant_ecosystem(lib_to_ecos, DOMINANCE_THRESHOLD)

        if eco is None:
            # Pas de dominance > 70%: Garde toutes les vulnérabilités (comporte l'étape "LLM decide" non implémentée ici)
            out = entries
            decision = {
                "dominant": None,
                "ratio": ratio,
                "threshold": DOMINANCE_THRESHOLD,
                "action": "no_selection"
            }
        else:
            # Dominance > 70%: Filtrage par l'écosystème dominant
            out = filter_entries_by_ecosystem(entries, eco)
            decision = {
                "dominant": eco,
                "ratio": ratio,
                "threshold": DOMINANCE_THRESHOLD,
                "action": "filtered_by_dominant_ecosystem"
            }
            print(f"\n[INFO] Dominant ecosystem '{eco}' ({ratio*100:.2f}%) applied.")

    # Wrap result and write
    result = {
        "pareto": decision,
        "results": out
    }
    try:
        with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n[SUCCESS] Final results written to {OUTPUT_PATH}")
    except Exception as e:
        print(f"\n[ERROR] Could not write output file {OUTPUT_PATH}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()