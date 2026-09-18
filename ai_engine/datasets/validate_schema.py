import json
import re
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATASET_PATH = BASE_DIR / "formatted_bola_dataset.json"
SEEDS_DIR = BASE_DIR / "seeds" / "bola"

def build_file_map():
    file_map = {}
    seed_files = list(SEEDS_DIR.glob("**/*.json"))
    for sf in seed_files:
        try:
            with open(sf, "r", encoding="utf-8") as f:
                data = json.load(f)
                vuln = data.get("vulnerable_code", "")
                if vuln:
                    file_map[vuln.strip()] = sf.relative_to(BASE_DIR).as_posix()
        except Exception:
            pass
    return file_map

def main():
    if not DATASET_PATH.exists():
        print(f"Error: {DATASET_PATH} does not exist.")
        return

    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    file_map = build_file_map()
    total_entries = len(dataset)
    print(f"Loaded {total_entries} entries from {DATASET_PATH.name}")
    print(f"Mapped {len(file_map)} seed files.\n")

    REQUIRED_OUTPUT_FIELDS = [
        "vulnerability", "cwe_id", "owasp_category", "severity",
        "confidence", "description", "exploit_payload", "remediation", "references"
    ]
    VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    
    meta_patterns = [
        re.compile(r"\bwait\s*,?\s*no\b", re.IGNORECASE),
        re.compile(r"\blet'?s\s+make\s+this\b", re.IGNORECASE),
        re.compile(r"\blet\s+us\s+make\s+this\b", re.IGNORECASE),
        re.compile(r"\bactually\s*,?\s*no\b", re.IGNORECASE),
        re.compile(r"\bwait\s+actually\b", re.IGNORECASE),
        re.compile(r"\boh\s+wait\b", re.IGNORECASE),
    ]

    failures = {
        "check1_required_fields": [],
        "check2_severity": [],
        "check3_confidence": [],
        "check4_cwe_id": [],
        "check5_placeholders": [],
        "check6_meta_commentary": [],
    }

    placeholder_breakdown = {
        "todo": [],
        "placeholder_comment_or_omission": [],
        "string_truncation": [],
        "js_spread_operator": [],
        "fastapi_parameter_sentinel": [],
    }

    for idx, entry in enumerate(dataset):
        input_code = entry.get("input", "").strip()
        filename = file_map.get(input_code, f"unknown_entry_index_{idx}")

        # Check 1: Required fields & non-empty
        c1_fail = []
        if not entry.get("instruction") or not str(entry.get("instruction")).strip():
            c1_fail.append("instruction missing/empty")
        if not entry.get("input") or not str(entry.get("input")).strip():
            c1_fail.append("input missing/empty")
        if not entry.get("output") or not str(entry.get("output")).strip():
            c1_fail.append("output missing/empty")
        
        output_obj = None
        if "output" in entry and entry["output"]:
            try:
                output_obj = json.loads(entry["output"])
                for fld in REQUIRED_OUTPUT_FIELDS:
                    val = output_obj.get(fld)
                    if val is None:
                        c1_fail.append(f"output.{fld} missing")
                    elif isinstance(val, str) and not val.strip():
                        c1_fail.append(f"output.{fld} empty string")
                    elif isinstance(val, list) and len(val) == 0:
                        c1_fail.append(f"output.{fld} empty list")
            except Exception as e:
                c1_fail.append(f"output is not valid json: {e}")

        if c1_fail:
            failures["check1_required_fields"].append((filename, ", ".join(c1_fail)))

        # If output_obj exists, proceed with detailed checks
        if output_obj:
            # Check 2: Severity is one of LOW/MEDIUM/HIGH/CRITICAL
            sev = output_obj.get("severity")
            if sev not in VALID_SEVERITIES:
                failures["check2_severity"].append((filename, f"Invalid severity: {sev}"))

            # Check 3: Confidence between 0.75 and 0.98
            conf = output_obj.get("confidence")
            if not isinstance(conf, (int, float)) or not (0.75 <= conf <= 0.98):
                failures["check3_confidence"].append((filename, f"Invalid confidence: {conf}"))

            # Check 4: CWE ID is always 'CWE-639'
            cwe = output_obj.get("cwe_id")
            if cwe != "CWE-639":
                failures["check4_cwe_id"].append((filename, f"Invalid CWE: {cwe}"))

            # Check 5: Remediation contains no placeholder text like 'TODO' or '...'
            rem = output_obj.get("remediation", "")
            has_todo = "TODO" in rem
            has_ellipsis = "..." in rem

            if has_todo or has_ellipsis:
                failures["check5_placeholders"].append((filename, f"Contains {'TODO and ...' if has_todo and has_ellipsis else 'TODO' if has_todo else '...' }"))
                
                # Granular categorization for detailed reporting
                lines_with_ellipsis = [line.strip() for line in rem.split("\n") if "..." in line]
                if has_todo:
                    placeholder_breakdown["todo"].append((filename, [l for l in rem.split("\n") if "TODO" in l]))
                
                # Check line types
                for line in lines_with_ellipsis:
                    if line.startswith("//") or line.startswith("#") or line.startswith("/*") or line == "...":
                        placeholder_breakdown["placeholder_comment_or_omission"].append((filename, line))
                    elif any(sentinel in line for sentinel in ["File(...)", "Query(...)", "Header(...)", "Path(...)", "Form(...)", "Body(...)"]):
                        placeholder_breakdown["fastapi_parameter_sentinel"].append((filename, line))
                    elif any(quote in line for quote in ["'...' ", "'...'", '"..."', 'f"...']):
                        placeholder_breakdown["string_truncation"].append((filename, line))
                    else:
                        placeholder_breakdown["js_spread_operator"].append((filename, line))

            # Check 6: Meta-commentary phrases
            full_text = f"{entry.get('instruction', '')} {entry.get('input', '')} {output_obj.get('description', '')} {output_obj.get('remediation', '')} {output_obj.get('exploit_payload', '')}"
            found_meta = []
            for pat in meta_patterns:
                m = pat.findall(full_text)
                if m:
                    found_meta.extend(m)
            if found_meta:
                failures["check6_meta_commentary"].append((filename, f"Meta-commentary found: {list(set(found_meta))}"))

    print("=" * 80)
    print("SCHEMA VALIDATION REPORT")
    print("=" * 80)

    checks = [
        ("Check 1: Required fields (instruction, input, output with all subfields) and none empty", "check1_required_fields"),
        ("Check 2: Severity is one of LOW/MEDIUM/HIGH/CRITICAL", "check2_severity"),
        ("Check 3: Confidence is a number between 0.75 and 0.98", "check3_confidence"),
        ("Check 4: cwe_id is always 'CWE-639'", "check4_cwe_id"),
        ("Check 5: Remediation contains no placeholder text like 'TODO' or '...'", "check5_placeholders"),
        ("Check 6: No entry contains meta-commentary phrases like 'wait no' or 'let\\'s make this'", "check6_meta_commentary"),
    ]

    for title, key in checks:
        fails = failures[key]
        fail_count = len(fails)
        pass_count = total_entries - fail_count
        status = "PASS" if fail_count == 0 else "FAIL"
        print(f"\n{title}")
        print(f"  Result: {status}")
        print(f"  Passed: {pass_count}/{total_entries}")
        print(f"  Failed: {fail_count}/{total_entries}")
        if fails:
            print("  Failing entries list:")
            for fname, reason in fails:
                print(f"    - {fname} ({reason})")

    # Display granular breakdown for Check 5
    if failures["check5_placeholders"]:
        print("\n" + "-" * 80)
        print("Check 5 Detailed Analysis:")
        print(f"  - Total entries containing 'TODO': {len(placeholder_breakdown['todo'])}")
        print(f"  - Entries with actual placeholder comments/omissions (e.g. '// ...', '...'): {len(set(f for f, _ in placeholder_breakdown['placeholder_comment_or_omission']))}")
        for f, l in set(placeholder_breakdown['placeholder_comment_or_omission']):
            print(f"      * {f}: {l}")
        print(f"  - Entries using Python/FastAPI required parameter sentinels (e.g. File(...), Query(...)): {len(set(f for f, _ in placeholder_breakdown['fastapi_parameter_sentinel']))}")
        print(f"  - Entries using JavaScript ES6 spread/rest operator (...): {len(set(f for f, _ in placeholder_breakdown['js_spread_operator']))}")
        print(f"  - Entries using literal string ellipsis for preview/masking (e.g. '...'): {len(set(f for f, _ in placeholder_breakdown['string_truncation']))}")

    print("\n" + "=" * 80)
    all_passed = all(len(failures[k]) == 0 for _, k in checks)
    if all_passed:
        print("OVERALL RESULT: PASS - All 1703 entries passed all 6 schema checks!")
    else:
        print("OVERALL RESULT: FAIL - Discrepancies detected.")
    print("=" * 80)

if __name__ == "__main__":
    main()
