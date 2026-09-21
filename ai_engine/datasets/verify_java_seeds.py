import os
import json
import glob
from pathlib import Path

BASE_DIR = Path(__file__).parent
SPRING_DIR = BASE_DIR / "seeds" / "bola" / "java_spring"
FORMATTED_DATASET = BASE_DIR / "formatted_bola_dataset.json"

REQUIRED_FIELDS = {"vulnerable_code", "diagnosis", "exploit_request", "corrected_code", "severity", "confidence"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

def verify():
    print("=== STEP 1: Verifying Individual Java/Spring Seeds ===")
    seed_files = sorted(SPRING_DIR.glob("seed_*.json"), key=lambda p: int(p.stem.split("_")[1]))
    print(f"Found {len(seed_files)} Java/Spring seed files in {SPRING_DIR.relative_to(BASE_DIR)}")
    
    if len(seed_files) == 0:
        print("[FAIL] No seed files found!")
        return False
        
    all_spring_inputs = []
    step1_passed = True

    for sf in seed_files:
        try:
            with open(sf, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[FAIL] {sf.name}: JSON decode error: {e}")
            step1_passed = False
            continue

        missing = REQUIRED_FIELDS - data.keys()
        if missing:
            print(f"[FAIL] {sf.name}: Missing required fields: {missing}")
            step1_passed = False
            continue

        sev = data.get("severity")
        if sev not in VALID_SEVERITIES:
            print(f"[FAIL] {sf.name}: Invalid severity '{sev}' (must be one of {VALID_SEVERITIES})")
            step1_passed = False

        conf = data.get("confidence")
        if not (isinstance(conf, (int, float)) and 0.75 <= conf <= 0.98):
            print(f"[FAIL] {sf.name}: Invalid confidence {conf} (must be between 0.75 and 0.98 inclusive)")
            step1_passed = False

        all_spring_inputs.append((sf.name, data["vulnerable_code"]))

    if step1_passed:
        print(f"[PASS] All {len(seed_files)} seed files strictly conform to schema, severities, and confidence limits.")
    else:
        print("[FAIL] Seed verification encountered errors.")
        return False

    print("\n=== STEP 2: Verifying Intra-batch Uniqueness ===")
    seen_spring_inputs = {}
    intra_duplicates = 0
    for name, code in all_spring_inputs:
        normalized = code.strip()
        if normalized in seen_spring_inputs:
            print(f"[FAIL] Duplicate input code between {name} and {seen_spring_inputs[normalized]}")
            intra_duplicates += 1
        else:
            seen_spring_inputs[normalized] = name

    if intra_duplicates == 0:
        print(f"[PASS] All {len(all_spring_inputs)} Java/Spring seeds have 100% unique input code within the batch.")
    else:
        print(f"[FAIL] Found {intra_duplicates} duplicate input entries within batch.")
        return False

    print("\n=== STEP 3: Checking Compiled Dataset (formatted_bola_dataset.json) ===")
    if not FORMATTED_DATASET.exists():
        print(f"[FAIL] {FORMATTED_DATASET.name} does not exist. Please run build_dataset.py first.")
        return False

    with open(FORMATTED_DATASET, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    total_count = len(dataset)
    print(f"Total entries in formatted_bola_dataset.json: {total_count}")

    # Check global uniqueness of "input"
    seen_global_inputs = {}
    global_duplicates = 0
    for idx, entry in enumerate(dataset):
        inp = entry.get("input", "").strip()
        if inp in seen_global_inputs:
            global_duplicates += 1
            if global_duplicates <= 5:
                print(f"[FAIL] Duplicate input found at index {idx} (originally at index {seen_global_inputs[inp]})")
        else:
            seen_global_inputs[inp] = idx

    if global_duplicates == 0:
        print(f"[PASS] Confirmed: No two entries in the entire dataset ({total_count} total entries) have identical 'input' code.")
        print("Self-verification result: PASS")
        return True
    else:
        print(f"[FAIL] Found {global_duplicates} duplicate input entries across the dataset.")
        print("Self-verification result: FAIL")
        return False

if __name__ == "__main__":
    verify()
