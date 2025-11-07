import sys
import os
import csv
import subprocess
import argparse

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
    except subprocess.CalledProcessError as e:
        print(f"Error during {description}. Command: {' '.join(command)}. Return code: {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"Error: Python interpreter or script not found for {description}.")
        return False


def main():
    parser = argparse.ArgumentParser(description="Runs the full SBOM processing pipeline.")
    
    # Argument précédent: Sélection manuelle
    parser.add_argument("--manual-select", action="store_true", 
                        help="Bypass Pareto rule and force manual selection for conflicting ecosystems in detect_eco.py.")
    
    # NOUVEL ARGUMENT: Limiter le nombre de paquets à scanner
    parser.add_argument("--limit", type=int, default=None, 
                        help="Limit the OSV scan to the first N valid packages found in the SBOM/PDF (e.g., --limit 40).")
    
    args = parser.parse_args()

    pdf_path = "sbom.json" #"oss-listings.pdf" # Chemin d'entrée par défaut
    generated_csv = "dependencies.csv"
    
    if not os.path.exists(pdf_path):
        print(f"Error: PDF not found at '{pdf_path}'. Please ensure 'oss-listings.pdf' is in the current directory.")
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
    
    # LOGIQUE DE LIMITATION: Définit la limite ou l'infini si --limit n'est pas utilisé
    limit_count = args.limit if args.limit is not None else float('inf')
    
    try:
        with open(input_csv_path, "r", encoding="utf-8") as in_f, \
             open(FINAL_CSV_PATH, "w", encoding="utf-8", newline='') as out_f:
            reader = csv.DictReader(in_f)
            writer = csv.DictWriter(out_f, fieldnames=header)
            writer.writeheader()
            
            for row in reader:
                # Arrêter l'écriture si la limite est atteinte
                if total_rows >= limit_count:
                    break
                
                name = (row.get("name") or "").strip()
                version = (row.get("version") or "").strip()
                ecosystem = (row.get("ecosystem") or "").strip()
                vendor = (row.get("vendor") or "").strip()
                
                # N'écrire que les paquets valides (avec nom et version)
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

    if args.limit is not None:
        print(f"Streaming write complete. Total rows written (limited): {total_rows} / Requested limit: {args.limit}")
    else:
        print(f"Streaming write complete. Total rows: {total_rows}")


    # Step 3: OSV Scan (Avec écriture incrémentale dans osv_scanner.py)
    osv_source_partial = "osv_results_partial.json"
    osv_source_final = "osv_results.json"

    # Run the scan unless the final file exists
    if not os.path.exists(osv_source_final):
        if os.path.exists(osv_source_partial):
             print("\n[INFO] Detected existing osv_results_partial.json — resuming scan.")

        print(f"\n[STEP 3/4] Running OSV scan (outputting incrementally to {osv_source_partial})...")
        if not run_step([sys.executable, "osv_scanner.py", FINAL_CSV_PATH],
                        "OSV scanning", timeout=900):
            sys.exit(1)
    else:
        print(f"\n[INFO] {osv_source_final} found. Skipping OSV scan.")


    # Step 4: Pareto/Manual Filtering
    print(f"\n[STEP 4/4] Applying filter (detect_eco) on OSV results...")
    
    # Utiliser le fichier final s'il existe, sinon le partiel
    osv_source = osv_source_final
    if not os.path.exists(osv_source) and os.path.exists(osv_source_partial):
        osv_source = osv_source_partial

    if not os.path.exists(osv_source):
        print("No OSV results found to process.")
        sys.exit(1)
        
    command = [sys.executable, "detect_eco.py", osv_source]
    
    # Propagation du paramètre de sélection manuelle
    if args.manual_select:
        command.append("--manual-select")

    if not run_step(command, "Pareto/Manual filtering", timeout=300):
        sys.exit(1)

    print("\n--- PIPELINE COMPLETED SUCCESSFULLY ---")


if __name__ == "__main__":
    main()