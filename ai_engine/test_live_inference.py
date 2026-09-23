r"""
AegisAI — Live Interactive Model Inspection & Demo Script
=========================================================
Runs an actual inference test through your fine-tuned model weights
to inspect its security reasoning, JSON schema adherence, and patch output.

Usage:
    cd C:/Users/DELL/Desktop/PDS/AegisAi
    .\venv\Scripts\python.exe ai_engine/test_live_inference.py
"""

import json
import time
from pathlib import Path

# Sample vulnerable route snippet to test
TEST_CODE_SNIPPET = """
@app.get("/api/v1/invoices/{invoice_id}")
async def download_invoice(invoice_id: str, db: Session = Depends(get_db)):
    invoice = db.query(Invoice).filter(Invoice.id == invoice_id).first()
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice
"""

PROMPT_TEMPLATE = f"""<|im_start|>system
You are AegisAI, an elite autonomous penetration testing AI. Analyze the route handler for OWASP API Security flaws. Respond ONLY in valid JSON matching:
{{
  "vulnerability": "Vulnerability Name",
  "cwe_id": "CWE-XXX",
  "owasp_category": "Category",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.0 - 1.0,
  "description": "Diagnosis",
  "exploit_payload": "HTTP Proof-of-Concept",
  "remediation": "Corrected Code"
}}
<|im_end|>
<|im_start|>user
Analyse the following route handler for security vulnerabilities:

{TEST_CODE_SNIPPET}
<|im_end|>
<|im_start|>assistant
"""


def test_model():
    print("=" * 70)
    print("  AegisAI — Live Model Reasoning & Quality Inspection")
    print("=" * 70)
    print("\n[*] Target Code Snippet Being Tested:")
    print("-" * 50)
    print(TEST_CODE_SNIPPET.strip())
    print("-" * 50)

    adapter_path = Path("./lora_adapters/aegisai-security")
    if not adapter_path.exists():
        print(f"[ERROR] Adapter not found at {adapter_path}")
        return

    print("\n[1/3] Loading fine-tuned weights from:", adapter_path)
    t0 = time.time()
    try:
        from unsloth import FastLanguageModel
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=str(adapter_path),
            max_seq_length=2048,
            dtype=None,
            load_in_4bit=True,
        )
        FastLanguageModel.for_inference(model)
        print(f"[+] Model loaded successfully into VRAM in {time.time() - t0:.1f}s")
    except Exception as exc:
        print(f"[-] Could not load model into GPU: {exc}")
        print("[!] Note: You can also run this test via Ollama once registered.")
        return

    print("\n[2/3] Generating AI Security Analysis (Live Inference)...")
    inputs = tokenizer([PROMPT_TEMPLATE], return_tensors="pt").to("cuda")
    
    gen_start = time.time()
    outputs = model.generate(
        **inputs,
        max_new_tokens=512,
        temperature=0.1,
        top_p=0.95,
        use_cache=True,
    )
    gen_duration = time.time() - gen_start

    response_text = tokenizer.batch_decode(outputs)[0]
    raw_output = response_text.split("<|im_start|>assistant\n")[-1].replace("<|im_end|>", "").strip()

    print(f"[+] Generation complete in {gen_duration:.2f}s!")
    print("\n[3/3] RAW AI MODEL OUTPUT (Inspecting Quality):")
    print("=" * 70)
    print(raw_output)
    print("=" * 70)

    # Check if output is valid JSON (Pillar 3 test)
    try:
        parsed = json.loads(raw_output)
        print("\n✅ QUALITY VERIFICATION PASS:")
        print(f"  * Valid JSON Structure : TRUE")
        print(f"  * Detected CWE         : {parsed.get('cwe_id')} ({parsed.get('vulnerability')})")
        print(f"  * Severity Rating      : {parsed.get('severity')}")
        print(f"  * Confidence Score     : {parsed.get('confidence')}")
        print(f"  * Exploit Generated    : {'YES' if parsed.get('exploit_payload') else 'NO'}")
        print(f"  * Patch Provided       : {'YES' if parsed.get('remediation') else 'NO'}")
    except json.JSONDecodeError:
        print("\n⚠️ WARNING: Output was not strictly JSON.")


if __name__ == "__main__":
    test_model()
