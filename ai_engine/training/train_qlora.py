"""
AegisAI — Unsloth QLoRA Fine-Tuning Script
===========================================
Boilerplate for fine-tuning a 7B parameter model (Llama-3, Mistral, Phi-3)
on the AegisAI security analysis dataset using QLoRA (4-bit quantisation).

Hardware requirements:
  - Minimum: NVIDIA GPU with 16GB VRAM (RTX 4080, A10)
  - Recommended: A100 40GB / H100 for production training
  - CPU training: Extremely slow — use Colab T4 for free GPU

Setup:
  # Install Unsloth for your CUDA version
  pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
  # Or for CUDA 12.1+:
  pip install unsloth

  # Install other dependencies
  pip install -r requirements.txt

Run:
  python training/train_qlora.py

Output:
  - LoRA adapter saved to: ./lora_adapters/aegisai-security/
  - Merged model (optional): ./merged_model/aegisai-security-7b/
  - Training logs: ./training/logs/
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Unsloth imports (conditionally imported to allow syntax check w/o GPU) ──
try:
    from unsloth import FastLanguageModel
    from unsloth.chat_templates import get_chat_template
    UNSLOTH_AVAILABLE = True
except ImportError:
    UNSLOTH_AVAILABLE = False
    print("⚠️  Unsloth not installed. Run: pip install unsloth")

try:
    from trl import SFTTrainer
    from transformers import TrainingArguments
    from datasets import Dataset, load_dataset
    TRL_AVAILABLE = True
except ImportError:
    TRL_AVAILABLE = False

import structlog

logger = structlog.get_logger(__name__)


# ── Training Configuration ─────────────────────────────────────

@dataclass
class TrainingConfig:
    """All hyperparameters and paths for the QLoRA fine-tuning run."""

    # ── Base model ────────────────────────────────────────────
    # Options: "unsloth/Meta-Llama-3.1-8B-Instruct"
    #          "unsloth/mistral-7b-instruct-v0.3"
    #          "unsloth/Phi-3-mini-4k-instruct"
    model_name: str = "unsloth/Meta-Llama-3.1-8B-Instruct"
    max_seq_length: int = 2048        # Context window (increase if OOM)
    dtype: str | None = None          # None = auto-detect (float16 on V100, bfloat16 on A100+)
    load_in_4bit: bool = True         # QLoRA 4-bit quantisation

    # ── LoRA hyperparameters ──────────────────────────────────
    lora_r: int = 16                  # LoRA rank (higher = more parameters, higher quality)
    lora_alpha: int = 16              # Scaling factor (usually == lora_r)
    lora_dropout: float = 0.0         # 0 is optimised by Unsloth
    lora_bias: str = "none"
    use_gradient_checkpointing: str = "unsloth"  # Saves VRAM

    # ── Target modules for LoRA ───────────────────────────────
    # These are the attention + MLP projections that LoRA adapts
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # ── Dataset ───────────────────────────────────────────────
    dataset_path: str = "./datasets/formatted_train_dummy.json"
    dataset_split: str = "train"
    val_set_size: float = 0.1         # 10% validation split

    # ── Training hyperparameters ──────────────────────────────
    output_dir: str = "./lora_adapters/aegisai-security"
    num_train_epochs: int = 3
    per_device_train_batch_size: int = 2
    gradient_accumulation_steps: int = 4   # Effective batch = 2 * 4 = 8
    warmup_steps: int = 10
    learning_rate: float = 2e-4
    weight_decay: float = 0.01
    lr_scheduler_type: str = "cosine"
    fp16: bool = False                # Disabled when using bf16
    bf16: bool = True                 # Faster on Ampere+; set False for T4/V100
    optim: str = "adamw_8bit"         # 8-bit AdamW saves ~4GB VRAM
    logging_steps: int = 10
    save_strategy: str = "epoch"
    evaluation_strategy: str = "epoch"
    seed: int = 42

    # ── Inference export (after training) ────────────────────
    save_merged_model: bool = False   # Merge LoRA + base for Ollama deployment
    merged_model_dir: str = "./merged_model/aegisai-security-7b"
    push_to_hub: bool = False
    hub_model_id: str = "your-org/aegisai-security-7b"


# ── Alpaca-format prompt template ────────────────────────────

ALPACA_PROMPT = """\
Below is an instruction that describes a security analysis task. \
Write a response that appropriately completes the request.

### Instruction:
{instruction}

### Input:
{input}

### Response:
{output}"""

EOS_TOKEN_PLACEHOLDER = "<|end_of_text|>"  # Will be replaced by actual tokenizer EOS


def format_alpaca_sample(
    sample: dict[str, str],
    eos_token: str = EOS_TOKEN_PLACEHOLDER,
) -> dict[str, str]:
    """Format a single dataset sample into Alpaca prompt format."""
    return {
        "text": ALPACA_PROMPT.format(
            instruction=sample.get("instruction", ""),
            input=sample.get("input", ""),
            output=sample.get("output", ""),
        ) + eos_token
    }


# ── Dataset Loading ───────────────────────────────────────────

def load_training_dataset(config: TrainingConfig) -> "Dataset":
    """
    Load and format the training dataset.

    Supports:
      - Local JSON file in Alpaca format (default)
      - HuggingFace Hub dataset (set dataset_path to "org/dataset-name")

    TODO: For production, curate a large dataset of:
      - Vulnerable code snippets with ground-truth vulnerability labels
      - Exploit payload examples (ethically sourced from CVE PoCs, CTF write-ups)
      - Remediation pairs (vulnerable → secure code)
    """
    path = config.dataset_path

    if Path(path).exists():
        logger.info("dataset.loading_local", path=path)
        with open(path, encoding="utf-8") as f:
            raw_data = json.load(f)
        if isinstance(raw_data, list):
            dataset = Dataset.from_list(raw_data)
        else:
            raise ValueError(f"Expected a JSON list in {path}, got {type(raw_data)}")
    else:
        # Assume HuggingFace Hub dataset ID
        logger.info("dataset.loading_hub", dataset_id=path)
        dataset = load_dataset(path, split=config.dataset_split)

    logger.info("dataset.loaded", size=len(dataset))
    return dataset


# ── Main Training Function ────────────────────────────────────

def train(config: TrainingConfig | None = None) -> None:
    """
    Main fine-tuning entrypoint.

    Workflow:
      1. Load base model with 4-bit quantisation
      2. Apply LoRA adapters to target modules
      3. Load and format training dataset
      4. Run SFTTrainer
      5. Save LoRA adapter
      6. (Optional) Merge and export for Ollama
    """
    if not UNSLOTH_AVAILABLE:
        raise RuntimeError(
            "Unsloth is required for training. "
            "Install: pip install unsloth"
        )
    if not TRL_AVAILABLE:
        raise RuntimeError(
            "TRL is required for training. "
            "Install: pip install trl transformers datasets"
        )

    cfg = config or TrainingConfig()

    logger.info(
        "training.start",
        model=cfg.model_name,
        epochs=cfg.num_train_epochs,
        lora_r=cfg.lora_r,
        batch_size=cfg.per_device_train_batch_size,
        grad_accum=cfg.gradient_accumulation_steps,
    )

    # ── Step 1: Load model + tokenizer ────────────────────────
    logger.info("training.loading_model", model=cfg.model_name)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=cfg.model_name,
        max_seq_length=cfg.max_seq_length,
        dtype=cfg.dtype,
        load_in_4bit=cfg.load_in_4bit,
        # token="hf_xxx",  # Required for gated models (Llama-3)
    )

    # ── Step 2: Apply LoRA ────────────────────────────────────
    logger.info("training.applying_lora", r=cfg.lora_r, alpha=cfg.lora_alpha)
    model = FastLanguageModel.get_peft_model(
        model,
        r=cfg.lora_r,
        target_modules=cfg.target_modules,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias=cfg.lora_bias,
        use_gradient_checkpointing=cfg.use_gradient_checkpointing,
        random_state=cfg.seed,
        use_rslora=False,
        loftq_config=None,
    )

    # ── Step 3: Load dataset ──────────────────────────────────
    raw_dataset = load_training_dataset(cfg)
    eos_token = tokenizer.eos_token or EOS_TOKEN_PLACEHOLDER

    formatted_dataset = raw_dataset.map(
        lambda sample: format_alpaca_sample(sample, eos_token),
        remove_columns=raw_dataset.column_names,
        desc="Formatting dataset",
    )

    # ── Step 4: Configure trainer ─────────────────────────────
    training_args = TrainingArguments(
        output_dir=cfg.output_dir,
        num_train_epochs=cfg.num_train_epochs,
        per_device_train_batch_size=cfg.per_device_train_batch_size,
        gradient_accumulation_steps=cfg.gradient_accumulation_steps,
        warmup_steps=cfg.warmup_steps,
        learning_rate=cfg.learning_rate,
        weight_decay=cfg.weight_decay,
        lr_scheduler_type=cfg.lr_scheduler_type,
        fp16=cfg.fp16,
        bf16=cfg.bf16,
        optim=cfg.optim,
        logging_steps=cfg.logging_steps,
        save_strategy=cfg.save_strategy,
        evaluation_strategy=cfg.evaluation_strategy if hasattr(formatted_dataset, "split") else "no",
        seed=cfg.seed,
        report_to="none",  # TODO: Set to "wandb" or "tensorboard" for experiment tracking
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=formatted_dataset,
        dataset_text_field="text",
        max_seq_length=cfg.max_seq_length,
        dataset_num_proc=2,
        packing=False,  # Packing can speed up training for short sequences
        args=training_args,
    )

    # ── Step 5: Train ─────────────────────────────────────────
    logger.info("training.running")
    trainer_stats = trainer.train()
    logger.info(
        "training.complete",
        runtime=trainer_stats.metrics.get("train_runtime"),
        loss=trainer_stats.metrics.get("train_loss"),
    )

    # ── Step 6: Save LoRA adapter ─────────────────────────────
    adapter_path = cfg.output_dir
    model.save_pretrained(adapter_path)
    tokenizer.save_pretrained(adapter_path)
    logger.info("training.adapter_saved", path=adapter_path)

    # ── Step 7: (Optional) Merge + save full model ─────────────
    if cfg.save_merged_model:
        logger.info("training.merging_model")
        model.save_pretrained_merged(
            cfg.merged_model_dir,
            tokenizer,
            save_method="merged_16bit",
        )
        logger.info("training.merged_model_saved", path=cfg.merged_model_dir)

    # ── Step 8: (Optional) Push to HuggingFace Hub ─────────────
    if cfg.push_to_hub:
        logger.info("training.pushing_to_hub", repo=cfg.hub_model_id)
        model.push_to_hub_merged(
            cfg.hub_model_id,
            tokenizer,
            save_method="lora",
            token=os.getenv("HF_TOKEN", ""),
        )


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AegisAI QLoRA Fine-Tuning")
    parser.add_argument("--model", default=TrainingConfig.model_name, help="Base model name")
    parser.add_argument("--epochs", type=int, default=TrainingConfig.num_train_epochs)
    parser.add_argument("--lora-r", type=int, default=TrainingConfig.lora_r)
    parser.add_argument("--batch-size", type=int, default=TrainingConfig.per_device_train_batch_size)
    parser.add_argument("--dataset", default=TrainingConfig.dataset_path)
    parser.add_argument("--output-dir", default=TrainingConfig.output_dir)
    parser.add_argument("--merge", action="store_true", help="Merge LoRA + base after training")
    parser.add_argument("--push-to-hub", action="store_true")
    args = parser.parse_args()

    config = TrainingConfig(
        model_name=args.model,
        num_train_epochs=args.epochs,
        lora_r=args.lora_r,
        per_device_train_batch_size=args.batch_size,
        dataset_path=args.dataset,
        output_dir=args.output_dir,
        save_merged_model=args.merge,
        push_to_hub=args.push_to_hub,
    )

    train(config)
