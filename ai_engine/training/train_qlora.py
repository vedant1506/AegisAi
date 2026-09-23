"""
AegisAI — Unsloth QLoRA Fine-Tuning Script
===========================================
Fine-tuning a 7B/8B parameter model (Qwen2.5-Coder-7B-Instruct, Llama-3.1-8B-Instruct)
on the AegisAI BOLA security analysis dataset using QLoRA (4-bit quantization).

Hardware requirements:
  - Minimum: NVIDIA GPU with 12GB/16GB VRAM (RTX 3060 12GB, RTX 4080, A10)
  - Recommended: A100 40GB / H100 for production training
  - CPU training: Extremely slow — use lab workstation or Colab for GPU

Setup:
  # Install Unsloth for CUDA 12.1+:
  pip install unsloth

  # Install other dependencies
  pip install -r requirements.txt

Run:
  python training/train_qlora.py
  # or from repo root:
  python ai_engine/training/train_qlora.py

Output:
  - LoRA adapter saved to: ./lora_adapters/aegisai-security/
  - Merged model (optional): ./merged_model/aegisai-security-7b/
  - GGUF export (optional): ./gguf_output/
  - Training logs: ./training/logs/
"""

from __future__ import annotations

import argparse
import inspect
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ── Unsloth imports (conditionally imported to allow syntax check w/o GPU) ──
try:
    from unsloth import FastLanguageModel, is_bfloat16_supported
    try:
        from unsloth.chat_templates import get_chat_template
    except ImportError:
        from unsloth import get_chat_template  # type: ignore
    UNSLOTH_AVAILABLE = True
except ImportError:
    UNSLOTH_AVAILABLE = False
    is_bfloat16_supported = None
    get_chat_template = None  # type: ignore
    print("[WARNING] Unsloth not installed. Run: pip install unsloth")

try:
    from datasets import Dataset, load_dataset
    DATASETS_AVAILABLE = True
except ImportError:
    DATASETS_AVAILABLE = False
    Dataset = None  # type: ignore
    load_dataset = None  # type: ignore

try:
    from trl import SFTTrainer
    from transformers import TrainingArguments
    TRL_AVAILABLE = True
except ImportError:
    TRL_AVAILABLE = False

import structlog

logger = structlog.get_logger(__name__)


# ── Training Configuration ─────────────────────────────────────

@dataclass
class TrainingConfig:
    """All hyperparameters and paths for the QLoRA fine-tuning run."""

    # ── Base model & Prompt Format ────────────────────────────
    # Primary (Roadmap Phase 2): "unsloth/Qwen2.5-Coder-7B-Instruct"
    # Alternative: "unsloth/Meta-Llama-3.1-8B-Instruct" (Gated - requires HF token)
    model_name: str = "unsloth/Qwen2.5-Coder-7B-Instruct"
    prompt_format: str = "chatml"         # "chatml" (Qwen2.5 native ChatML) or "alpaca"
    chat_template: str = "qwen2.5"        # Chat template for Unsloth get_chat_template
    system_prompt: str | None = None      # Optional override for security analysis system prompt
    max_seq_length: int = 2048            # Context window (per roadmap Phase 2.1)
    dtype: str | None = None              # None = auto-detect (float16 on T4/V100, bfloat16 on Ampere+)
    load_in_4bit: bool = True             # QLoRA 4-bit quantization

    # ── LoRA hyperparameters ──────────────────────────────────
    lora_r: int = 16                  # LoRA rank (16 or 32 per roadmap Phase 2.2)
    lora_alpha: int = 16              # Scaling factor (typically == lora_r or 2*lora_r)
    lora_dropout: float = 0.0         # 0 is optimized by Unsloth
    lora_bias: str = "none"
    use_gradient_checkpointing: str = "unsloth"  # "unsloth" saves ~30% VRAM

    # ── Target modules for LoRA ───────────────────────────────
    # Attention + MLP projections adapted for Qwen2.5 and Llama-3 architectures
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])

    # ── Dataset ───────────────────────────────────────────────
    dataset_path: str = "ai_engine/datasets/formatted_bola_dataset.json"
    dataset_split: str = "train"
    val_set_size: float = 0.1         # 10% validation split for evaluation

    # ── Training hyperparameters ──────────────────────────────
    output_dir: str = "./lora_adapters/aegisai-security"
    num_train_epochs: int = 3         # 3-4 Epochs per roadmap Phase 2.2
    max_steps: int = -1               # If > 0, overrides num_train_epochs (for sanity checks)
    per_device_train_batch_size: int = 1   # Batch size 1 reduces peak VRAM spikes
    gradient_accumulation_steps: int = 8   # Effective batch = 1 * 8 = 8 (preserves training dynamics)
    warmup_steps: int = 10
    learning_rate: float = 2e-4
    weight_decay: float = 0.01
    lr_scheduler_type: str = "cosine"
    fp16: bool = False                # Auto-selected if bf16 is unsupported
    bf16: bool = True                 # Faster on Ampere+ (auto-detected on target GPU)
    optim: str = "adamw_8bit"         # 8-bit AdamW saves ~4GB VRAM
    logging_steps: int = 5
    save_strategy: str = "steps"      # Save by steps so progress is never lost if interrupted
    save_steps: int = 25              # Checkpoint every 25 steps
    save_total_limit: int = 2         # Keep only 2 most recent checkpoints to save disk space
    eval_strategy: str = "steps"
    eval_steps: int = 25
    seed: int = 42
    report_to: str = "none"           # Set to "wandb" for tracking per roadmap
    resume: bool = True               # Auto-resume from latest checkpoint if one exists in output_dir

    # ── Inference & Export (after training) ────────────────────
    save_merged_model: bool = False   # Merge LoRA + base in 16-bit for deployment
    merged_model_dir: str = "./merged_model/aegisai-security-7b"
    save_gguf: bool = False           # Export to GGUF format (q4_k_m/q5_k_m) for Ollama
    gguf_output_dir: str = "./gguf_output"
    gguf_quantization: str = "q4_k_m" # "q4_k_m" or "q5_k_m" per roadmap Phase 2.3
    push_to_hub: bool = False
    hub_model_id: str = "your-org/aegisai-security-7b"


# ── Prompt Templates & ChatML Conversation Formatting ──────────

DEFAULT_SECURITY_SYSTEM_PROMPT = (
    "You are AegisAI, an expert application security analysis engine. "
    "Your task is to analyze code, route handlers, and application logic for "
    "security vulnerabilities (specifically OWASP Top 10 and API security flaws like "
    "Broken Object Level Authorization / BOLA), identify root causes, determine "
    "severity and CWE identifiers, and provide actionable exploit payloads and "
    "remediation patches in structured JSON."
)

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


def entry_to_chatml_conversation(
    sample: dict[str, Any],
    system_prompt: str = DEFAULT_SECURITY_SYSTEM_PROMPT,
) -> list[dict[str, str]]:
    """
    Convert a raw dataset entry's instruction/input/output fields into a
    ChatML conversation:
      - system message: explains the security-analysis task
      - user message: instruction + input
      - assistant message: output
    """
    # If already formatted as ChatML messages/conversations, pass through
    if "conversations" in sample and isinstance(sample["conversations"], list):
        return sample["conversations"]
    if "messages" in sample and isinstance(sample["messages"], list):
        return sample["messages"]

    instruction = str(sample.get("instruction", "")).strip()
    input_text = str(sample.get("input", "")).strip()
    output_text = str(sample.get("output", "")).strip()

    user_content = f"{instruction}\n\n{input_text}" if input_text else instruction

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_content},
        {"role": "assistant", "content": output_text},
    ]


def format_chatml_sample(
    sample: dict[str, Any],
    tokenizer: Any = None,
    system_prompt: str = DEFAULT_SECURITY_SYSTEM_PROMPT,
) -> dict[str, str]:
    """
    Format a single dataset sample into ChatML text using tokenizer.apply_chat_template.
    Falls back to canonical ChatML formatting if tokenizer lacks apply_chat_template.
    """
    messages = entry_to_chatml_conversation(sample, system_prompt=system_prompt)
    if tokenizer is not None and hasattr(tokenizer, "apply_chat_template"):
        text = tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
    else:
        text = (
            f"<|im_start|>system\n{messages[0]['content']}<|im_end|>\n"
            f"<|im_start|>user\n{messages[1]['content']}<|im_end|>\n"
            f"<|im_start|>assistant\n{messages[2]['content']}<|im_end|>\n"
        )
    return {"text": text}


def formatting_prompts_func(
    batch: dict[str, list[Any]],
    tokenizer: Any = None,
    system_prompt: str = DEFAULT_SECURITY_SYSTEM_PROMPT,
) -> dict[str, list[str]]:
    """
    Batch formatting function that converts raw dataset entries into ChatML
    conversations and formats them via tokenizer.apply_chat_template.
    Used with Dataset.map(batched=True).
    """
    instructions = batch.get("instruction", [])
    inputs = batch.get("input", [])
    outputs = batch.get("output", [])
    batch_size = max(len(instructions), len(inputs), len(outputs))

    texts: list[str] = []
    for i in range(batch_size):
        sample = {
            "instruction": instructions[i] if i < len(instructions) else "",
            "input": inputs[i] if i < len(inputs) else "",
            "output": outputs[i] if i < len(outputs) else "",
        }
        res = format_chatml_sample(sample, tokenizer=tokenizer, system_prompt=system_prompt)
        texts.append(res["text"])

    return {"text": texts}


def format_alpaca_sample(
    sample: dict[str, str],
    eos_token: str = EOS_TOKEN_PLACEHOLDER,
) -> dict[str, str]:
    """Format a single dataset sample into Alpaca prompt format (legacy fallback)."""
    return {
        "text": ALPACA_PROMPT.format(
            instruction=sample.get("instruction", ""),
            input=sample.get("input", ""),
            output=sample.get("output", ""),
        ) + eos_token
    }


# ── Dataset Loading & Resolution ──────────────────────────────

def resolve_dataset_path(path_str: str) -> Path:
    """
    Resolve local dataset path across different working directories:
    - Relative to current working directory
    - Relative to ai_engine directory
    - Relative to repository root
    """
    path = Path(path_str)
    if path.is_file():
        return path

    ai_engine_dir = Path(__file__).resolve().parent.parent
    if (ai_engine_dir / path_str).is_file():
        return ai_engine_dir / path_str

    repo_root = ai_engine_dir.parent
    if (repo_root / path_str).is_file():
        return repo_root / path_str

    cleaned = path_str.replace("ai_engine/", "").replace("ai_engine\\", "")
    if (ai_engine_dir / cleaned).is_file():
        return ai_engine_dir / cleaned

    return path


def load_training_dataset(config: TrainingConfig) -> "Dataset":
    """
    Load the training dataset.

    Supports:
      - Local JSON file in Alpaca format (default)
      - HuggingFace Hub dataset (fallback when path is not a local file)
    """
    resolved_path = resolve_dataset_path(config.dataset_path)

    if resolved_path.is_file():
        logger.info("dataset.loading_local", path=str(resolved_path))
        with open(resolved_path, encoding="utf-8") as f:
            raw_data = json.load(f)
        if isinstance(raw_data, list):
            dataset = Dataset.from_list(raw_data)
        else:
            raise ValueError(f"Expected a JSON list in {resolved_path}, got {type(raw_data)}")
    else:
        # Assume HuggingFace Hub dataset ID
        logger.info("dataset.loading_hub", dataset_id=config.dataset_path)
        dataset = load_dataset(config.dataset_path, split=config.dataset_split)

    logger.info("dataset.loaded", size=len(dataset))
    return dataset


# ── Main Training Function ────────────────────────────────────

def train(config: TrainingConfig | None = None) -> None:
    """
    Main fine-tuning entrypoint.

    Workflow:
      1. Load base model with 4-bit quantization
      2. Apply LoRA adapters to target modules
      3. Enable native Unsloth fast training mode
      4. Load and format training dataset (with validation split)
      5. Run SFTTrainer
      6. Save LoRA adapter
      7. (Optional) Merge and export in 16-bit
      8. (Optional) Export to GGUF format for Ollama
      9. (Optional) Push to HuggingFace Hub
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
        lora_alpha=cfg.lora_alpha,
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
    )

    # Configure ChatML chat template (Qwen2.5 native)
    if cfg.prompt_format == "chatml":
        if get_chat_template is not None:
            logger.info("training.applying_chat_template", template=cfg.chat_template)
            tokenizer = get_chat_template(
                tokenizer,
                chat_template=cfg.chat_template,
            )
        else:
            logger.warning("training.get_chat_template_unavailable", reason="Unsloth not installed")

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

    # Enable native 2x faster training mode
    model = FastLanguageModel.for_training(model)

    # ── Step 3: Load dataset & prepare train/eval splits ────────
    raw_dataset = load_training_dataset(cfg)
    system_prompt = cfg.system_prompt or DEFAULT_SECURITY_SYSTEM_PROMPT

    if cfg.prompt_format == "chatml":
        logger.info("dataset.formatting_chatml", template=cfg.chat_template)
        formatted_dataset = raw_dataset.map(
            lambda batch: formatting_prompts_func(batch, tokenizer=tokenizer, system_prompt=system_prompt),
            batched=True,
            remove_columns=raw_dataset.column_names,
            desc="Formatting dataset (ChatML)",
        )
    else:
        logger.info("dataset.formatting_alpaca")
        eos_token = tokenizer.eos_token or EOS_TOKEN_PLACEHOLDER
        formatted_dataset = raw_dataset.map(
            lambda sample: format_alpaca_sample(sample, eos_token),
            remove_columns=raw_dataset.column_names,
            desc="Formatting dataset (Alpaca)",
        )

    if cfg.val_set_size > 0.0:
        logger.info("dataset.splitting", val_set_size=cfg.val_set_size)
        split_data = formatted_dataset.train_test_split(
            test_size=cfg.val_set_size,
            seed=cfg.seed,
        )
        train_dataset = split_data["train"]
        eval_dataset = split_data["test"]
        logger.info(
            "dataset.split_complete",
            train_size=len(train_dataset),
            eval_size=len(eval_dataset),
        )
    else:
        train_dataset = formatted_dataset
        eval_dataset = None

    # ── Step 4: Configure precision & training args ───────────
    # Auto-detect bf16 support on the lab workstation GPU
    bf16_ready = is_bfloat16_supported() if (callable(is_bfloat16_supported)) else False
    use_bf16 = cfg.bf16 and bf16_ready
    use_fp16 = cfg.fp16 or (cfg.bf16 and not bf16_ready)

    # Handle eval_strategy (Transformers >= 4.41) vs evaluation_strategy gracefully
    eval_kwargs: dict[str, Any] = {}
    eval_mode = cfg.eval_strategy if (eval_dataset is not None and cfg.max_steps <= 0) else "no"
    try:
        sig = inspect.signature(TrainingArguments.__init__)
        if "eval_strategy" in sig.parameters:
            eval_kwargs["eval_strategy"] = eval_mode
        else:
            eval_kwargs["evaluation_strategy"] = eval_mode
    except Exception:
        eval_kwargs["eval_strategy"] = eval_mode

    if eval_mode == "steps":
        eval_kwargs["eval_steps"] = cfg.eval_steps

    training_args_kwargs: dict[str, Any] = dict(
        output_dir=cfg.output_dir,
        num_train_epochs=cfg.num_train_epochs,
        per_device_train_batch_size=cfg.per_device_train_batch_size,
        gradient_accumulation_steps=cfg.gradient_accumulation_steps,
        warmup_steps=cfg.warmup_steps,
        learning_rate=cfg.learning_rate,
        weight_decay=cfg.weight_decay,
        lr_scheduler_type=cfg.lr_scheduler_type,
        fp16=use_fp16,
        bf16=use_bf16,
        optim=cfg.optim,
        logging_steps=cfg.logging_steps,
        save_strategy=cfg.save_strategy,
        save_steps=cfg.save_steps,
        save_total_limit=cfg.save_total_limit,
        seed=cfg.seed,
        report_to=cfg.report_to,
        **eval_kwargs,
    )
    if cfg.max_steps > 0:
        training_args_kwargs["max_steps"] = cfg.max_steps

    training_args = TrainingArguments(**training_args_kwargs)

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        dataset_text_field="text",
        max_seq_length=cfg.max_seq_length,
        dataset_num_proc=1 if os.name == "nt" else 2,
        packing=False,
        args=training_args,
    )

    # ── Step 5: Train (with auto-resume if checkpoint exists) ──
    resume_checkpoint = None
    if cfg.resume and os.path.isdir(cfg.output_dir):
        checkpoints = [
            d for d in os.listdir(cfg.output_dir)
            if d.startswith("checkpoint-") and os.path.isdir(os.path.join(cfg.output_dir, d))
        ]
        if checkpoints:
            checkpoints.sort(key=lambda x: int(x.split("-")[1]))
            resume_checkpoint = os.path.join(cfg.output_dir, checkpoints[-1])
            logger.info("training.resuming_from_checkpoint", checkpoint=resume_checkpoint)

    logger.info("training.running", resume_from=resume_checkpoint)
    trainer_stats = trainer.train(resume_from_checkpoint=resume_checkpoint)
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

    # ── Step 8: (Optional) Export to GGUF format for Ollama ───
    if cfg.save_gguf:
        logger.info("training.exporting_gguf", path=cfg.gguf_output_dir, method=cfg.gguf_quantization)
        model.save_pretrained_gguf(
            cfg.gguf_output_dir,
            tokenizer,
            quantization_method=cfg.gguf_quantization,
        )
        logger.info("training.gguf_exported", path=cfg.gguf_output_dir)

    # ── Step 9: (Optional) Push to HuggingFace Hub ─────────────
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
    parser = argparse.ArgumentParser(description="AegisAI QLoRA Fine-Tuning")
    parser.add_argument("--model", default=TrainingConfig.model_name, help="Base model name")
    parser.add_argument("--prompt-format", default=TrainingConfig.prompt_format, choices=["chatml", "alpaca"], help="Prompt template format ('chatml' or 'alpaca')")
    parser.add_argument("--chat-template", default=TrainingConfig.chat_template, help="Chat template name for Unsloth get_chat_template (e.g. 'qwen2.5')")
    parser.add_argument("--system-prompt", default=None, help="Custom security analysis system prompt")
    parser.add_argument("--epochs", type=int, default=TrainingConfig.num_train_epochs)
    parser.add_argument("--max-steps", type=int, default=TrainingConfig.max_steps, help="Max training steps (-1 to train full epochs)")
    parser.add_argument("--logging-steps", type=int, default=TrainingConfig.logging_steps, help="Logging steps for loss printing")
    parser.add_argument("--save-strategy", default=TrainingConfig.save_strategy, choices=["steps", "epoch", "no"], help="Save strategy ('steps' recommended)")
    parser.add_argument("--save-steps", type=int, default=TrainingConfig.save_steps, help="Save checkpoint every N steps")
    parser.add_argument("--save-total-limit", type=int, default=TrainingConfig.save_total_limit, help="Max checkpoints to keep on disk")
    parser.add_argument("--lora-r", type=int, default=TrainingConfig.lora_r, help="LoRA rank (16 or 32)")
    parser.add_argument("--lora-alpha", type=int, default=None, help="LoRA alpha (defaults to match lora-r)")
    parser.add_argument("--batch-size", type=int, default=TrainingConfig.per_device_train_batch_size, help="Per-device train batch size (1 recommended for stability)")
    parser.add_argument("--grad-accum", type=int, default=TrainingConfig.gradient_accumulation_steps, help="Gradient accumulation steps")
    parser.add_argument("--learning-rate", type=float, default=TrainingConfig.learning_rate)
    parser.add_argument("--dataset", default=TrainingConfig.dataset_path)
    parser.add_argument("--val-set-size", type=float, default=TrainingConfig.val_set_size)
    parser.add_argument("--output-dir", default=TrainingConfig.output_dir)
    parser.add_argument("--no-resume", action="store_true", help="Disable auto-resuming from existing checkpoints")
    parser.add_argument("--merge", action="store_true", help="Merge LoRA + base in 16-bit after training")
    parser.add_argument("--export-gguf", action="store_true", help="Export to GGUF format for Ollama deployment")
    parser.add_argument("--gguf-quantization", default=TrainingConfig.gguf_quantization, help="GGUF quantization (e.g. q4_k_m, q5_k_m)")
    parser.add_argument("--report-to", default=TrainingConfig.report_to, help="Experiment tracker ('none' or 'wandb')")
    parser.add_argument("--push-to-hub", action="store_true")
    args = parser.parse_args()

    lora_alpha = args.lora_alpha if args.lora_alpha is not None else args.lora_r

    config = TrainingConfig(
        model_name=args.model,
        prompt_format=args.prompt_format,
        chat_template=args.chat_template,
        system_prompt=args.system_prompt,
        num_train_epochs=args.epochs,
        max_steps=args.max_steps,
        logging_steps=args.logging_steps,
        save_strategy=args.save_strategy,
        save_steps=args.save_steps,
        save_total_limit=args.save_total_limit,
        lora_r=args.lora_r,
        lora_alpha=lora_alpha,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        learning_rate=args.learning_rate,
        dataset_path=args.dataset,
        val_set_size=args.val_set_size,
        output_dir=args.output_dir,
        resume=not args.no_resume,
        save_merged_model=args.merge,
        save_gguf=args.export_gguf,
        gguf_quantization=args.gguf_quantization,
        report_to=args.report_to,
        push_to_hub=args.push_to_hub,
    )

    train(config)
