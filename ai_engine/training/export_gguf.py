"""
AegisAI — Export Fine-Tuned Model to GGUF Format
=================================================
Loads the trained LoRA adapter from ./lora_adapters/aegisai-security
and exports it to quantized GGUF format (q4_k_m, q5_k_m, or f16)
for direct deployment with Ollama or llama.cpp.

Usage:
    python ai_engine/training/export_gguf.py --quantization q4_k_m
"""

from __future__ import annotations

import argparse
import os
import sys
import time

try:
    from unsloth import FastLanguageModel
except ImportError:
    print("[ERROR] Unsloth is not installed in the active environment.")
    sys.exit(1)

ADAPTER_DIR = "./lora_adapters/aegisai-security"
GGUF_DIR = "./gguf_output"


def export_gguf(
    adapter_dir: str = ADAPTER_DIR,
    output_dir: str = GGUF_DIR,
    quantization: str = "q4_k_m",
) -> None:
    print("=" * 65)
    print(f"  AegisAI: Exporting LoRA to GGUF ({quantization})")
    print("=" * 65)

    if not os.path.isdir(adapter_dir):
        print(f"[ERROR] Adapter directory '{adapter_dir}' does not exist!")
        sys.exit(1)

    start_time = time.time()

    print(f"\n[1/3] Loading LoRA adapter from '{adapter_dir}'...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=adapter_dir,
        max_seq_length=2048,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"\n[2/3] Quantizing and exporting to GGUF ({quantization}) in '{output_dir}'...")
    os.makedirs(output_dir, exist_ok=True)

    model.save_pretrained_gguf(
        output_dir,
        tokenizer,
        quantization_method=quantization,
    )

    elapsed = time.time() - start_time
    print(f"\n[3/3] Export complete in {elapsed:.1f}s!")
    print(f"      GGUF file saved to: {os.path.abspath(output_dir)}")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisAI GGUF Exporter")
    parser.add_argument("--adapter-dir", default=ADAPTER_DIR, help="Path to LoRA adapter")
    parser.add_argument("--output-dir", default=GGUF_DIR, help="Destination directory for GGUF")
    parser.add_argument(
        "--quantization",
        default="q4_k_m",
        choices=["q4_k_m", "q5_k_m", "q8_0", "f16"],
        help="Quantization method (q4_k_m recommended for 12GB VRAM / Ollama)",
    )
    args = parser.parse_args()

    export_gguf(args.adapter_dir, args.output_dir, args.quantization)
