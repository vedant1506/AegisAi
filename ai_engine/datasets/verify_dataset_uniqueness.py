import json
from pathlib import Path
from collections import Counter

def verify():
    dataset_path = Path(__file__).parent / "formatted_bola_dataset.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_count = len(data)
    print(f"Total compiled entries: {total_count}")

    inputs = [entry["input"].strip() for entry in data]
    counter = Counter(inputs)
    duplicates = {code: count for code, count in counter.items() if count > 1}

    if duplicates:
        print("RESULT: FAIL - Duplicates detected in input code:")
        for code, count in duplicates.items():
            print(f"Count: {count} | Snippet: {code[:120]}")
        return False
    else:
        print(f"RESULT: PASS - All {total_count} entries have 100% unique 'input' code. Zero duplicates detected.")
        return True

if __name__ == "__main__":
    verify()
