"""
AegisAI — Hugging Face Hub Model Uploader
=========================================
Helper script to push your trained LoRA adapter or full merged model
to your personal Hugging Face repository with a single command.

Usage:
    # 1. Upload LoRA adapter (~161 MB - Quick, recommended):
    python ai_engine/training/push_to_hub.py --repo-id your-username/aegisai-security-lora --token hf_yourToken

    # 2. Upload full 16-bit merged model (~15.2 GB):
    python ai_engine/training/push_to_hub.py --repo-id your-username/aegisai-security-7b --token hf_yourToken --merged
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

try:
    from huggingface_hub import HfApi, login
except ImportError:
    print("[ERROR] huggingface_hub is not installed in the environment.")
    sys.exit(1)

LORA_DIR = Path("./lora_adapters/aegisai-security")
MERGED_DIR = Path("./merged_model/aegisai-security-7b")


def push_model(repo_id: str, token: str | None = None, upload_merged: bool = False) -> None:
    folder_to_upload = MERGED_DIR if upload_merged else LORA_DIR
    target_type = "Full 16-bit Merged Model (~15.2 GB)" if upload_merged else "LoRA Adapter (~161 MB)"

    if not folder_to_upload.exists():
        print(f"[ERROR] Folder '{folder_to_upload}' does not exist on disk!")
        sys.exit(1)

    print("=" * 65)
    print(f"  AegisAI — Uploading {target_type} to Hugging Face Hub")
    print("=" * 65)

    api_token = token or os.getenv("HF_TOKEN")
    if not api_token:
        print("\n[!] No token passed. Checking existing huggingface login...")
    else:
        print("\n[*] Authenticating with Hugging Face...")
        login(token=api_token)

    api = HfApi()

    print(f"[*] Target Repository: https://huggingface.co/{repo_id}")
    print(f"[*] Local Folder:      {folder_to_upload.resolve()}")
    print("\n[1/2] Creating repository if it doesn't already exist...")
    api.create_repo(
        repo_id=repo_id,
        repo_type="model",
        private=True,   # Default to private so your college project remains secure
        exist_ok=True,
    )

    print("[2/2] Uploading files to Hugging Face (this may take a few minutes)...")
    api.upload_folder(
        folder_path=str(folder_to_upload),
        repo_id=repo_id,
        repo_type="model",
    )

    print("\n" + "=" * 65)
    print("  UPLOAD SUCCESSFUL!")
    print("=" * 65)
    print(f"  Model is now live at: https://huggingface.co/{repo_id}")
    print("=" * 65)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload AegisAI model to Hugging Face Hub")
    parser.add_argument("--repo-id", required=True, help="Your Hugging Face repo ID (e.g. username/aegisai-security)")
    parser.add_argument("--token", default=None, help="Your Hugging Face Write Token (starts with hf_...)")
    parser.add_argument("--merged", action="store_true", help="Upload the full 15GB merged model instead of the 161MB LoRA adapter")
    args = parser.parse_args()

    push_model(repo_id=args.repo_id, token=args.token, upload_merged=args.merged)
