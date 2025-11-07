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


def run_step(command, description, timeout=None, **run_kwargs):
    try:
        subprocess.run(command, check=True, timeout=timeout, **run_kwargs)
        return True
    except subprocess.TimeoutExpired:
        msg = f"{description} timed out"
        if timeout:
            msg += f" after {timeout}s"
        print(msg)
        return False
    except subprocess.CalledProcessError as e:
        stderr = getattr(e, 'stderr', None)
        if stderr:
            print(stderr)
        print(f"Error during {description}.")
        return False


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
    if not run_step(
        [sys.executable, "parceur.py", "--file", sbom_input_path, "--out", PARSED_CSV_PATH],
        "SBOM parsing (parceur.py)", timeout=600, capture_output=True, text=True
    ):
        sys.exit(1)
    print(f"Successfully parsed SBOM. Intermediate file created: '{PARSED_CSV_PATH}'")

    # --- 3. Filtering and Enrichment (llm_enricher.py) ---
    print(f"\n[STEP 2/4] Filtering for packages needing enrichment...")
    
    complete_rows = []
    incomplete_rows = []
    try:
        with open(PARSED_CSV_PATH, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row.get("ecosystem") or row["ecosystem"].lower() == "":
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
    print(f"\nWriting final data for OSV scanning to '{FINAL_CSV_PATH}' (streaming mode)...")
    header = ["name", "version", "ecosystem", "vendor"]
    total_rows = 0
    try:
        with open(FINAL_CSV_PATH, "w", encoding="utf-8", newline='') as out_f:
            writer = csv.DictWriter(out_f, fieldnames=header)
            writer.writeheader()

            def emit_rows(rows):
                nonlocal total_rows
                for row in rows:
                    name = (row.get("name") or "").strip()
                    version = (row.get("version") or "").strip()
                    ecosystem = (row.get("ecosystem") or "").strip()
                    vendor = (row.get("vendor") or "").strip()
                    if not name or not version:
                        continue
                    writer.writerow({
                        "name": name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "vendor": vendor
                    })
                    total_rows += 1

            emit_rows(complete_rows)
            emit_rows(enriched_rows)
    except Exception as e:
        print(f"Error while streaming CSV rows: {e}")
        sys.exit(1)

    print(f"Streaming write complete. Total rows: {total_rows}")
        
    # --- 5. OSV Scanning (osv_scanner.py) ---
    print(f"\n[STEP 4/4] Starting OSV vulnerability scan...")
    if not run_step(
        [sys.executable, "osv_scanner.py", FINAL_CSV_PATH],
        "OSV scanning", timeout=900
    ):
        sys.exit(1)
    print("\n--- PIPELINE COMPLETED SUCCESSFULLY ---")
    
    # --- Cleanup ---
    if os.path.exists(PARSED_CSV_PATH):
        os.remove(PARSED_CSV_PATH)
        print(f"\nCleaned up intermediate file: {PARSED_CSV_PATH}")

if __name__ == "__main__":
    main()