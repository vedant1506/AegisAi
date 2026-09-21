import os
import json
import glob
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
SEEDS_DIR = BASE_DIR / "seeds" / "bola"
OUTPUT_FILE = BASE_DIR / "formatted_bola_dataset.json"

REQUIRED_FIELDS = {
    "vulnerable_code",
    "diagnosis",
    "exploit_request",
    "corrected_code"
}

def build_dataset():
    if not SEEDS_DIR.exists():
        print(f"Error: Seeds directory {SEEDS_DIR} does not exist.")
        return

    dataset = []
    seed_files = glob.glob(str(SEEDS_DIR / "**" / "*.json"), recursive=True)
    
    if not seed_files:
        print(f"No seed files found in {SEEDS_DIR}")
        return

    print(f"Found {len(seed_files)} seed files. Validating...")

    error_count = 0
    for seed_file in seed_files:
        try:
            with open(seed_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Validate fields
            missing_fields = REQUIRED_FIELDS - data.keys()
            if missing_fields:
                print(f"Error in {seed_file}: Missing fields: {', '.join(missing_fields)}")
                error_count += 1
                continue
                
            # Format the output matching the schema
            output_json = {
                "vulnerability": "Broken Object Level Authorization (BOLA/IDOR)",
                "cwe_id": "CWE-639",
                "owasp_category": "API1:2023 - Broken Object Level Authorization",
                "severity": data.get("severity", "HIGH"),
                "confidence": data.get("confidence", 0.95),
                "description": data["diagnosis"],
                "exploit_payload": data["exploit_request"],
                "remediation": f"Corrected Code Patch:\n{data['corrected_code']}",
                "references": [
                    "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                    "https://cwe.mitre.org/data/definitions/639.html"
                ]
            }
            
            formatted_entry = {
                "instruction": "Analyse the following route handler for security vulnerabilities. Identify any OWASP Top 10 issues, assign a severity level, suggest a CWE identifier, and provide a remediation recommendation.",
                "input": data["vulnerable_code"],
                "output": json.dumps(output_json, indent=2)
            }
            
            dataset.append(formatted_entry)
            print(f"Validated: {Path(seed_file).relative_to(SEEDS_DIR)}")
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON in {seed_file}: {e}")
            error_count += 1
        except Exception as e:
            print(f"Unexpected error processing {seed_file}: {e}")
            error_count += 1

    if error_count == 0:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(dataset, f, indent=2)
        print(f"\nSuccessfully compiled {len(dataset)} examples into {OUTPUT_FILE.name}")
    else:
        print(f"\nBuild failed with {error_count} errors. Please fix them before dataset can be built.")

if __name__ == "__main__":
    build_dataset()
