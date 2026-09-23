"""
AegisAI — Merge LoRA Adapter into Base Model (16-bit)
=====================================================
Loads the trained LoRA adapter from ./lora_adapters/aegisai-security
and mathematically fuses the weights into the base Qwen2.5-Coder-7B model,
saving a standalone, unified Hugging Face model to ./merged_model/aegisai-security-7b.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Unsloth import
from unsloth import FastLanguageModel

ADAPTER_DIR = "./lora_adapters/aegisai-security"
OUTPUT_DIR = "./merged_model/aegisai-security-7b"


def main() -> None:
    print("=" * 65)
    print("  AegisAI: Step 1 — Merging LoRA Adapter into Base Model (16-bit)")
    print("=" * 65)

    if not os.path.isdir(ADAPTER_DIR):
        print(f"[ERROR] Adapter directory '{ADAPTER_DIR}' does not exist!")
        sys.exit(1)

    start_time = time.time()

    print(f"\n[1/3] Loading trained LoRA adapter from '{ADAPTER_DIR}'...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=ADAPTER_DIR,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"\n[2/3] Fusing LoRA weights into base model & saving to '{OUTPUT_DIR}'...")
    print("      (This dequantizes and adds adapter weights in float16 precision)")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    model.save_pretrained_merged(
        OUTPUT_DIR,
        tokenizer,
        save_method="merged_16bit",
    )

    elapsed = time.time() - start_time
    print(f"\n[3/3] Done! Merged 16-bit model successfully created in {elapsed:.1f}s.")
    print(f"      Saved location: {os.path.abspath(OUTPUT_DIR)}")
    print("=" * 65)


if __name__ == "__main__":
    main()
