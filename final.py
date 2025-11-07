import json
import os
import sys
from textwrap import fill

DEFAULT_INPUT = "osv_results_pareto.json"


def load_results(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Input file not found: {path}")
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {path}: {exc}")
        sys.exit(1)

    if isinstance(data, dict) and "results" in data:
        entries = data.get("results", [])
        pareto = data.get("pareto", {})
    elif isinstance(data, list):
        entries = data
        pareto = {}
    else:
        print(f"Unexpected JSON structure in {path}")
        sys.exit(1)

    return pareto, entries


def summarise_pareto(pareto: dict):
    if not pareto:
        return "No Pareto metadata found."

    dominant = pareto.get("dominant") or "(none)"
    ratio = pareto.get("ratio")
    threshold = pareto.get("threshold")
    action = pareto.get("action") or "unknown"

    ratio_pct = f"{ratio * 100:.2f}%" if isinstance(ratio, (int, float)) else "n/a"
    threshold_pct = f"{threshold * 100:.0f}%" if isinstance(threshold, (int, float)) else "n/a"

    lines = [
        f"Dominant ecosystem: {dominant}",
        f"Dominance ratio:    {ratio_pct} (threshold {threshold_pct})",
        f"Action:             {action}",
    ]
    return "\n".join(lines)


def wrap_field(label: str, value: str, width: int = 88) -> str:
    if not value:
        return ""
    prefix = f"        {label}: "
    return fill(str(value).strip(), width=width,
                initial_indent=prefix,
                subsequent_indent=" " * len(prefix))


def format_vuln(vuln: dict, index: int, width: int = 88) -> str:
    vid = vuln.get("id") or "(no id)"
    summary = vuln.get("summary") or vuln.get("details") or "(no summary)"
    aliases = ", ".join(vuln.get("aliases", [])[:5])
    if vuln.get("aliases") and len(vuln["aliases"]) > 5:
        aliases += ", …"

    published = vuln.get("published") or vuln.get("modified")
    references = vuln.get("references", [])
    top_ref = next((r.get("url") for r in references if isinstance(r, dict) and "url" in r), None)

    lines = [f"    [{index}] {vid}"]
    lines.append(wrap_field("Summary", summary, width))
    if aliases:
        lines.append(wrap_field("Aliases", aliases, width))
    if published:
        lines.append(wrap_field("Published", published, width))
    if top_ref:
        lines.append(wrap_field("Reference", top_ref, width))

    return "\n".join(filter(None, lines))


def main(argv=None):
    argv = argv or sys.argv
    path = argv[1] if len(argv) > 1 else DEFAULT_INPUT

    print("=== OSV Pareto Report ===")
    print(f"Source file: {os.path.abspath(path)}\n")

    pareto, entries = load_results(path)
    print(summarise_pareto(pareto))

    total_packages = len(entries)
    packages_with_vulns = 0
    total_vulns = 0

    printable_sections = []
    separator = "-" * 80

    for entry in entries:
        package = entry.get("package", {}) or {}
        vulns = (entry.get("osv_response") or {}).get("vulns") or []
        if not vulns:
            continue

        packages_with_vulns += 1
        total_vulns += len(vulns)

        name = package.get("name") or "(unknown)"
        version = package.get("version") or "?"
        ecosystem = package.get("ecosystem") or ""

        header_lines = [
            separator,
            f"Package       : {name} {version}",
            f"Ecosystem     : {ecosystem or 'unknown'}",
            f"Vulnerabilities: {len(vulns)}",
        ]

        formatted_vulns = [format_vuln(v, idx) for idx, v in enumerate(vulns, start=1)]
        section = "\n".join(header_lines + [""] + formatted_vulns)
        printable_sections.append(section)

    print("\n")
    print(f"Packages analysed:           {total_packages}")
    print(f"Packages with vulnerabilities: {packages_with_vulns}")
    print(f"Total vulnerabilities:        {total_vulns}")

    if printable_sections:
        print("\n=== Vulnerable Packages ===")
        for section in printable_sections:
            print(section)
        print("\n" + separator)
    else:
        print("\nNo vulnerabilities found in the filtered results.")


if __name__ == "__main__":
    main()

