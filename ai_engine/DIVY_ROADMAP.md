# Divy's Roadmap & Task Tracker (AegisAI)

This document serves as the master checklist and roadmap for **Divy (AI Engine & Semantic Reasoning Lead)**. It outlines everything you need to do to fine-tune the model, build the LangGraph workflow, and evaluate the system's performance.

---

## 🚀 Phase 1: At Home Development & Staging

*The goal of this phase is to build the initial datasets and get the LangGraph workflow running locally.*

### 1. Dataset Preparation
- [x] Curate and format the **1,500+ OWASP BOLA (Broken Object Level Authorization) dataset**.
- [x] Ensure the dataset maps vulnerable code patterns to business logic errors.
- [x] Save the dataset locally (e.g., as `formatted_train.json`) in Alpaca, ChatML, or ShareGPT format.

### 2. LangGraph Multi-Agent Workflow
- [x] Develop the LangGraph state machine inside the `ai_engine/multi_agent/state_graph.py` file.
- [x] Design the prompt templates for the **Recon Agent**, **Reasoning Agent**, and **Verifier Agent** (`ai_engine/multi_agent/prompts.py`).
- [x] **Crucial Integration Step:** Work with Vedant and Shahad to define the exact JSON input formats (AST Data from Vedant, Endpoint Data from Shahad) that the graph will ingest.

### 3. Local SLM Testing (Offline)
- [x] Test the LangGraph workflow locally using Ollama and a base 7B/8B model.
- [x] Verify that the Reasoning Agent can synthesize exploit payloads based on mock JSON data.
- [x] Debug the Unsloth QLoRA training scripts locally to ensure they run without syntax errors before moving to the lab GPU.

---

## ⚡ Phase 2: Comprehensive Lab GPU Execution

*This phase takes place on the College Lab Workstation (12GB Dedicated GPU).*

### 1. Infrastructure & Tokenization
- [x] Clone the AegisAI monorepo and pull the local JSON dataset onto the NVMe SSD.
- [x] Install PyTorch (CUDA 12.1) and Unsloth.
- [x] Apply the ShareGPT/ChatML formatting templates and tokenize the dataset (`max_seq_length = 2048`).

### 2. QLoRA Fine-Tuning
- [x] Load the base model (**Qwen2.5 Coder-7B**) in 4-bit precision.
- [x] Inject the target LoRA modules (Rank 16/32).
- [x] Execute the training loop (3-4 Epochs, Batch Size = 2, Gradient Accumulation = 4).
- [x] Monitor training progress and loss convergence (eval loss 0.344 at checkpoint-576).

### 3. Evaluation & Export
- [x] Test the fine-tuned model against the unseen Validation Dataset (`ai_engine/evaluation/evaluate_ablation.py`).
- [x] Verify that the model can successfully read AST data and output syntactically correct Git patches.
- [x] Configure LoRA fusion script (`ai_engine/training/merge_lora.py`) to merge adapters into base model.
- [x] Configure GGUF export script (`ai_engine/training/export_gguf.py`) and Ollama Modelfile (`Modelfile.aegisai`).
- [x] Push the weights to Hugging Face Hub ([Divy2712/aegisai-security-7b](https://huggingface.co/Divy2712/aegisai-security-7b)) and save them to a USB Drive.

---

## 🔗 Phase 3: End-to-End Integration (Semantic Reasoning)

*This phase happens when you integrate your AI engine with Vedant's FastAPI backend.*

- [x] Wrap your LangGraph state graph in an async Python function that Vedant can call from his Celery background tasks (`backend/app/services/ai_engine_service.py`).
- [x] Ensure the **Reasoning Agent** correctly receives the combined AST + Crawler data and successfully deduces BOLA flaws (`backend/app/api/scan_router.py`).
- [x] Ensure the **Exploit Synthesis** accurately crafts the cross-tenant attack payload and passes it securely to Shahad's Verifier Agent.

---

## 🏁 Phase 4: Metrics, Ablation & Final Delivery

*The final evaluation phase to prove the system works for the project defense.*

- [x] **Confusion Matrix:** Calculate Precision, Recall, and False Positive Rate (FPR) for the system (`ai_engine/evaluation/evaluate_ablation.py`).
- [x] **Model Ablation Study:** Run tests to prove the performance difference between the Base 7B model and your Fine-Tuned 7B model.
- [x] **Latency Benchmarks:** Measure and document the token generation speed and overall scan duration.
- [x] Deliver these metrics to Vedant so they can be displayed on the final Next.js Dashboard report (`ai_engine/evaluation/benchmark_report.json`).

