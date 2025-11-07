# --- START OF FILE main_pipeline.py ---

import sys
import os
import subprocess
import csv
import llm_enricher # We import our refactored module

# --- Configuration ---
# You can change these filenames if you want.
PARSED_CSV_PATH = "temp_parsed.csv"
FINAL_CSV_PATH = "final_sbom_data.csv"


def main():
    # --- 1. Argument validation ---
    if len(sys.argv) != 2:
        print("Usage: python main_pipeline.py <path_to_sbom.json>")
        sys.exit(1)

    sbom_input_path = sys.argv[1]
    if not os.path.exists(sbom_input_path):
        print(f"Error: Input SBOM file not found at '{sbom_input_path}'")
        sys.exit(1)

    print("--- STARTING SBOM VULNERABILITY PIPELINE ---")

    # --- 2. Initial Parsing (parceur.py) ---
    print(f"\n[STEP 1/4] Parsing SBOM file: {sbom_input_path}")
    try:
        subprocess.run(
            [sys.executable, "parceur.py", "--file", sbom_input_path, "--out", PARSED_CSV_PATH],
            check=True, capture_output=True, text=True
        )
        print(f"Successfully parsed SBOM. Intermediate file created: '{PARSED_CSV_PATH}'")
    except subprocess.CalledProcessError as e:
        print(f"Error during parsing step with parceur.py.")
        print("Stderr:", e.stderr)
        sys.exit(1)

    # --- 3. Filtering and Enrichment (llm_enricher.py) ---
    print(f"\n[STEP 2/4] Filtering for packages needing enrichment...")
    
    complete_rows = []
    incomplete_rows = []
    try:
        with open(PARSED_CSV_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # A row is incomplete if the ecosystem is 'unknown' or empty
                if not row.get("ecosystem") or row["ecosystem"].lower() == "unknown":
                    incomplete_rows.append(row)
                else:
                    complete_rows.append(row)
    except FileNotFoundError:
        print(f"Error: Parsed file '{PARSED_CSV_PATH}' not found. Aborting.")
        sys.exit(1)

    print(f"Found {len(complete_rows)} complete packages.")
    print(f"Found {len(incomplete_rows)} incomplete packages to enrich with LLM.")
    
    enriched_rows = []
    if incomplete_rows:
        print("\n[STEP 3/4] Enriching incomplete data with LLM...")
        enriched_rows = llm_enricher.enrich_rows(incomplete_rows)
        print(f"LLM enrichment complete. Successfully enriched {len(enriched_rows)} packages.")
    else:
        print("\n[STEP 3/4] Skipping LLM enrichment, no incomplete data found.")

    # --- 4. Merging and Finalizing CSV ---
    final_rows = complete_rows + enriched_rows
    
    # Let's ensure the enriched data is sane before writing
    final_rows = [row for row in final_rows if row.get('name') and row.get('version')]
    
    print(f"\nWriting final data for OSV scanning to '{FINAL_CSV_PATH}' ({len(final_rows)} total packages).")
    header = ["name", "version", "ecosystem", "vendor"]
    with open(FINAL_CSV_PATH, "w", encoding="utf-8", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(final_rows)
        
    # --- 5. OSV Scanning (osv_scanner.py) ---
    print(f"\n[STEP 4/4] Starting OSV vulnerability scan...")
    try:
        # We run the scanner on the final, enriched CSV file
        subprocess.run(
            [sys.executable, "osv_scanner.py", FINAL_CSV_PATH],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print("Error during OSV scanning step.")
        sys.exit(1)
        
    print("\n--- PIPELINE COMPLETED SUCCESSFULLY ---")
    
    # --- Cleanup ---
    if os.path.exists(PARSED_CSV_PATH):
        os.remove(PARSED_CSV_PATH)
        print(f"\nCleaned up intermediate file: {PARSED_CSV_PATH}")

if __name__ == "__main__":
    main()