# --- START OF FILE main_pipeline.py ---

import sys
import os
import subprocess
import csv
import json
from datetime import datetime

# Import scanner modules
import llm_enricher
import osv_scanner
import nvd_scanner

# --- Configuration ---
PARSED_CSV_PATH = "temp_parsed.csv"
FINAL_CSV_PATH = "final_sbom_data.csv"

def run_parsing_step(sbom_path: str, output_path: str):
    print(f"\n[STEP 1/4] Parsing SBOM file: {sbom_path}")
    try:
        proc = subprocess.run(
            [sys.executable, "parceur.py", "--file", sbom_path, "--out", output_path],
            check=True, capture_output=True, text=True, encoding='utf-8'
        )
        print(f"Successfully parsed SBOM. Intermediate file: '{output_path}'")
        print(proc.stdout.strip())
    except subprocess.CalledProcessError as e:
        print("Error during parsing step with parceur.py.", file=sys.stderr)
        print("Stderr:", e.stderr, file=sys.stderr)
        sys.exit(1)

def run_enrichment_step(input_path: str, output_path: str):
    print(f"\n[STEP 2/4] Filtering for packages needing enrichment...")
    
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            all_rows = list(csv.DictReader(f))
    except FileNotFoundError:
        print(f"Error: Parsed file '{input_path}' not found. Aborting.", file=sys.stderr)
        sys.exit(1)

    complete_rows = [row for row in all_rows if row.get("ecosystem") and row["ecosystem"].lower() != "unknown"]
    incomplete_rows = [row for row in all_rows if not row.get("ecosystem") or row["ecosystem"].lower() == "unknown"]

    print(f"Found {len(complete_rows)} complete packages.")
    print(f"Found {len(incomplete_rows)} incomplete packages to enrich with LLM.")
    
    enriched_rows = []
    if incomplete_rows:
        print("\n[STEP 3/4] Enriching incomplete data with LLM...")
        enriched_rows = llm_enricher.enrich_rows(incomplete_rows)
        print(f"LLM enrichment complete. Successfully enriched {len(enriched_rows)} packages.")
    else:
        print("\n[STEP 3/4] Skipping LLM enrichment, no incomplete data found.")

    final_rows = complete_rows + enriched_rows
    final_rows = [row for row in final_rows if row.get('name') and row.get('version')]
    
    print(f"\nWriting final data for scanning to '{output_path}' ({len(final_rows)} total packages).")
    header = ["name", "version", "ecosystem", "vendor"]
    with open(output_path, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(final_rows)

def run_vulnerability_scans(input_csv_path: str):
    print(f"\n[STEP 4/4] Starting vulnerability scans (OSV & NVD)...")
    
    if not os.path.exists(input_csv_path):
        print(f"Final CSV file '{input_csv_path}' not found. Cannot run scans.", file=sys.stderr)
        return

    with open(input_csv_path, "r", encoding="utf-8") as f:
        packages = list(csv.DictReader(f))

    all_results = []
    total = len(packages)

    for i, pkg in enumerate(packages, 1):
        name = pkg.get("name", "")
        version = pkg.get("version", "")
        ecosystem = pkg.get("ecosystem", "")
        vendor = pkg.get("vendor", "")

        print(f"\n[{i}/{total}] Scanning: {name} {version} (Ecosystem: {ecosystem}, Vendor: {vendor})")
        
        # 1. OSV Scan
        print("  - Querying OSV...")
        osv_result = osv_scanner.query_osv(ecosystem, name, version)
        
        # 2. NVD Scan
        print("  - Querying NVD...")
        nvd_result = nvd_scanner.query_nvd(name, version, vendor)

        # 3. Consolidate results
        consolidated_report = {
            "package": pkg,
            "vulnerabilities": {
                "osv": osv_result,
                "nvd": nvd_result
            }
        }
        all_results.append(consolidated_report)

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    output_filename = f"final_vulnerability_report_{ts}.json"
    print(f"\nAll scans complete. Writing consolidated report to '{output_filename}'")
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

def main():
    if len(sys.argv) != 2:
        print("Usage: python main_pipeline.py <path_to_sbom.json>")
        sys.exit(1)
    sbom_input_path = sys.argv[1]
    if not os.path.exists(sbom_input_path):
        print(f"Error: Input SBOM file not found at '{sbom_input_path}'", file=sys.stderr)
        sys.exit(1)
    
    if not os.getenv("NVD_API_KEY"):
        print("\nWARNING: NVD_API_KEY environment variable not set.")
        print("NVD scans will be heavily rate-limited and may fail. Get a key from https://nvd.nist.gov/developers/request-an-api-key\n")

    print("--- STARTING SBOM VULNERABILITY PIPELINE ---")
    
    run_parsing_step(sbom_input_path, PARSED_CSV_PATH)
    
    run_enrichment_step(PARSED_CSV_PATH, FINAL_CSV_PATH)
    
    run_vulnerability_scans(FINAL_CSV_PATH)
    
    print("\n--- PIPELINE COMPLETED SUCCESSFULLY ---")
    
    if os.path.exists(PARSED_CSV_PATH): os.remove(PARSED_CSV_PATH)
    if os.path.exists(FINAL_CSV_PATH): os.remove(FINAL_CSV_PATH)
    print(f"\nCleaned up intermediate files.")

if __name__ == "__main__":
    main()