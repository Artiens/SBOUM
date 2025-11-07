# --- START OF FILE llm_enricher.py ---

import json
import subprocess
import re
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

MODEL = "mistral"
CHUNK_SIZE = 5
MAX_WORKERS = 3

VALID_ECOSYSTEMS = {
    "npm", "pypi", "maven", "crates.io", "nuget", "packagist", "rubygems",
    "cargo", "go", "hex", "pub", "swiftpm", "cocoapods", "composer", "conan",
    "conda", "puppet", "purescript", "alpine", "debian", "ubuntu", "rhel",
    "alma", "rocky", "maven", "gradle", "sbt", "ivy", "golang", "rust",
    "erlang", "elm", "dart", "swift", "carthage", "Go", "PyPI"
}

def chunkify(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

def extract_csv(text: str) -> List[Dict[str, str]]:
    text = (text or "").strip()
    if not text:
        return []
    
    # Try to find the header to ignore explanations before it
    lines = text.splitlines()
    start_idx = 0
    for i, line in enumerate(lines):
        line_lower = line.lower().strip()
        if 'name' in line_lower and 'version' in line_lower and 'ecosystem' in line_lower:
            start_idx = i
            break
            
    # Use csv.reader for robust parsing
    reader = csv.reader(lines[start_idx:])
    header = []
    results = []
    
    try:
        header_line = next(reader)
        header = [h.strip().lower() for h in header_line]
        if "name" not in header or "version" not in header or "ecosystem" not in header:
             # If the first line after search is not a header, reset and try from the beginning
            reader = csv.reader(lines[start_idx:])

    except StopIteration:
        return [] # Empty input

    for row in reader:
        if len(row) < 3:
            continue
        
        # Create a dict, handling potential missing vendor column
        entry = {
            "name": row[0].strip(),
            "version": row[1].strip(),
            "ecosystem": row[2].strip(),
            "vendor": row[3].strip() if len(row) > 3 else ""
        }
        
        # Basic validation
        if not entry["name"] or not entry["version"]:
            continue
        
        # Validate ecosystem
        if entry["ecosystem"].lower() not in VALID_ECOSYSTEMS:
            entry["ecosystem"] = "unknown" # Mark as invalid if LLM hallucinates
            
        results.append(entry)
        
    return results

def _process_chunk_with_llm(chunk: List[Dict[str, str]], model: str = MODEL) -> List[Dict[str, str]]:
    # Convert the partial data into a simplified JSON for the prompt
    input_json = json.dumps([
        {"name": row["name"], "version": row["version"]} for row in chunk
    ], indent=2)

    prompt = f"""
Only output a valid CSV format with a header row.
Based on the name and version of the following packages, complete the `ecosystem` and `vendor` fields.
The original parser failed to identify them.

Rules:
- The `ecosystem` MUST be one of the following: Go, PyPI, npm, Maven, RubyGems, crates.io, etc.
- If you cannot determine the ecosystem with high confidence, set it to "unknown".
- The `vendor` is the organization or main author. If unknown, leave it empty.
- Output ONLY the CSV data, including the header: name,version,ecosystem,vendor
- Do not add any commentary, explanations or surrounding text.

Input JSON:
{input_json}
"""

    try:
        proc = subprocess.run(
            ["ollama", "run", model],
            input=prompt.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120
        )
        raw_out = proc.stdout.decode(errors="ignore").strip()
        return extract_csv(raw_out)
    except Exception as e:
        print(f"[llm_enricher] Error calling Ollama: {e}")
        return []

def enrich_rows(rows_to_enrich: List[Dict[str, str]]) -> List[Dict[str, str]]:
    if not rows_to_enrich:
        return []

    chunks = list(chunkify(rows_to_enrich, CHUNK_SIZE))
    enriched_results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_process_chunk_with_llm, chunk): chunk for chunk in chunks}
        for i, fut in enumerate(as_completed(futures), 1):
            try:
                normalized = fut.result()
                enriched_results.extend(normalized)
                print(f"[llm_enricher] Chunk {i}/{len(chunks)} processed, found {len(normalized)} items.")
            except Exception as e:
                print(f"[llm_enricher] A chunk failed during processing: {e}")

    return enriched_results