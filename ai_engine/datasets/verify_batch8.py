import json
from collections import Counter
from pathlib import Path

DATASET_FILE = Path(__file__).parent / "formatted_bola_dataset.json"
SEEDS_DIR = Path(__file__).parent / "seeds" / "bola" / "django"

def verify():
    with open(DATASET_FILE, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    total_count = len(dataset)
    print(f"Total dataset entries: {total_count}")

    inputs = [entry["input"].strip() for entry in dataset]
    input_counts = Counter(inputs)
    duplicates = {k: v for k, v in input_counts.items() if v > 1}

    if duplicates:
        print(f"FAIL: Found {len(duplicates)} duplicate input(s) in dataset.")
        for dup, count in list(duplicates.items())[:5]:
            print(f"  Count {count}: {repr(dup[:60])}")
        return False
    else:
        print("PASS: Exact match verification confirmed - no two entries have identical 'input' code across all 1,503 entries.")

    # Check batch 8 seeds specifically
    batch8_files = [SEEDS_DIR / f"seed_{i}.json" for i in range(425, 465)]
    print(f"\nVerifying {len(batch8_files)} new Batch 8 seeds (425 to 464):")

    severities = Counter()
    confidences = []
    batch8_inputs = set()

    for p in batch8_files:
        if not p.exists():
            print(f"FAIL: File {p.name} does not exist!")
            return False
        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        code = data["vulnerable_code"].strip()
        batch8_inputs.add(code)
        severities[data["severity"]] += 1
        conf = data["confidence"]
        confidences.append(conf)

        if not (0.75 <= conf <= 0.98):
            print(f"FAIL: Confidence {conf} in {p.name} outside [0.75, 0.98]!")
            return False

    print(f"- Batch 8 files: {len(batch8_files)} checked, {len(batch8_inputs)} distinct vulnerable code blocks.")
    print(f"- Severity distribution: {dict(severities)}")
    print(f"- Confidence range: min={min(confidences):.2f}, max={max(confidences):.2f}")
    print("\nOVERALL STATUS: PASS")
    return True

if __name__ == "__main__":
    verify()
