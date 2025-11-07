import sys
import os
import csv
import subprocess

FINAL_CSV_PATH = "final_sbom_data.csv"


def run_step(command, description, timeout=None):
    try:
        subprocess.run(command, check=True, timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        msg = f"{description} timed out"
        if timeout:
            msg += f" after {timeout}s"
        print(msg)
        return False
    except subprocess.CalledProcessError:
        print(f"Error during {description}.")
        return False


def main():
    pdf_path = "oss-listings.pdf"
    generated_csv = "dependencies.csv"

    if not os.path.exists(pdf_path):
        print(f"Error: PDF not found at '{pdf_path}'")
        sys.exit(1)

    print("--- STARTING PIPELINE FROM PDF -> CSV ---")
    print(f"[STEP 1/4] Extracting dependencies from PDF: {pdf_path}")
    if not run_step([sys.executable, "sbom_to_csv.py", "--in", pdf_path],
                    "PDF to CSV extraction", timeout=600):
        sys.exit(1)

    input_csv_path = generated_csv
    header = ["name", "version", "ecosystem", "vendor"]
    total_rows = 0

    print(f"[STEP 2/4] Building '{FINAL_CSV_PATH}' for OSV scanning...")
    try:
        with open(input_csv_path, "r", encoding="utf-8") as in_f, \
             open(FINAL_CSV_PATH, "w", encoding="utf-8", newline='') as out_f:
            reader = csv.DictReader(in_f)
            writer = csv.DictWriter(out_f, fieldnames=header)
            writer.writeheader()
            for row in reader:
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
    except Exception as e:
        print(f"Error while writing CSV: {e}")
        sys.exit(1)

    print(f"Streaming write complete. Total rows: {total_rows}")

    # Skip OSV scan if partial results exist
    if os.path.exists("osv_results_partial.json"):
        print("\n[INFO] Detected existing osv_results_partial.json — resuming scan.")
    else:
        print(f"\n[STEP 3/4] Running OSV scan...")
        if not run_step([sys.executable, "osv_scanner.py", FINAL_CSV_PATH],
                        "OSV scanning", timeout=900):
            sys.exit(1)

    print(f"\n[STEP 4/4] Applying Pareto filter (detect_eco) on osv_results.json ...")
    if not os.path.exists("osv_results.json") and not os.path.exists("osv_results_partial.json"):
        print("No OSV results found.")
        sys.exit(1)

    osv_source = "osv_results.json" if os.path.exists("osv_results.json") else "osv_results_partial.json"
    if not run_step([sys.executable, "detect_eco.py", osv_source],
                    "Pareto filtering", timeout=300):
        sys.exit(1)

    print("\n--- PIPELINE COMPLETED SUCCESSFULLY ---")


if __name__ == "__main__":
    main()
