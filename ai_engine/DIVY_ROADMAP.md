# Divy's Roadmap & Task Tracker (AegisAI)

This document serves as the master checklist and roadmap for **Divy (AI Engine & Semantic Reasoning Lead)**. It outlines everything you need to do to fine-tune the model, build the LangGraph workflow, and evaluate the system's performance.

---

## 🚀 Phase 1: At Home Development & Staging

*The goal of this phase is to build the initial datasets and get the LangGraph workflow running locally.*

### 1. Dataset Preparation
- [ ] Curate and format the **1,500+ OWASP BOLA (Broken Object Level Authorization) dataset**.
- [ ] Ensure the dataset maps vulnerable code patterns to business logic errors.
- [ ] Save the dataset locally (e.g., as `formatted_train.json`) in Alpaca, ChatML, or ShareGPT format.

### 2. LangGraph Multi-Agent Workflow
- [ ] Develop the LangGraph state machine inside the `ai_engine/multi_agent/state_graph.py` file.
- [ ] Design the prompt templates for the **Recon Agent**, **Reasoning Agent**, and **Verifier Agent** (`ai_engine/multi_agent/prompts.py`).
- [ ] **Crucial Integration Step:** Work with Vedant and Shahad to define the exact JSON input formats (AST Data from Vedant, Endpoint Data from Shahad) that the graph will ingest.

### 3. Local SLM Testing (Offline)
- [ ] Test the LangGraph workflow locally using Ollama and a base 7B/8B model.
- [ ] Verify that the Reasoning Agent can synthesize exploit payloads based on mock JSON data.
- [ ] Debug the Unsloth QLoRA training scripts locally to ensure they run without syntax errors before moving to the lab GPU.

---

## ⚡ Phase 2: Comprehensive Lab GPU Execution

*This phase takes place on the College Lab Workstation (12GB Dedicated GPU).*

### 1. Infrastructure & Tokenization
- [ ] Clone the AegisAI monorepo and pull the local JSON dataset onto the NVMe SSD.
- [ ] Install PyTorch (CUDA 12.1) and Unsloth.
- [ ] Apply the ShareGPT/ChatML formatting templates and tokenize the dataset (`max_seq_length = 2048`).

### 2. QLoRA Fine-Tuning
- [ ] Load the base model (**Qwen2.5 Coder-7B**) in 4-bit precision.
- [ ] Inject the target LoRA modules (Rank 16/32).
- [ ] Execute the training loop (3-4 Epochs, Batch Size = 2, Gradient Accumulation = 4).
- [ ] Monitor training using WandB.

### 3. Evaluation & Export
- [ ] Test the fine-tuned model against the unseen Validation Dataset.
- [ ] Verify that the model can successfully read AST data and output syntactically correct Git patches.
- [ ] If metrics pass, merge the LoRA adapters into the base model.
- [ ] Export the final model to **GGUF format** (`q4_k_m` and `q5_k_m`).
- [ ] Push the weights to Hugging Face Hub and save them to a USB Drive.

---

## 🔗 Phase 3: End-to-End Integration (Semantic Reasoning)

*This phase happens when you integrate your AI engine with Vedant's FastAPI backend.*

- [ ] Wrap your LangGraph state graph in an async Python function that Vedant can call from his Celery background tasks.
- [ ] Ensure the **Reasoning Agent** correctly receives the combined AST + Crawler data and successfully deduces BOLA flaws.
- [ ] Ensure the **Exploit Synthesis** accurately crafts the cross-tenant attack payload and passes it securely to Shahad's Verifier Agent.

---

## 🏁 Phase 4: Metrics, Ablation & Final Delivery

*The final evaluation phase to prove the system works for the project defense.*

- [ ] **Confusion Matrix:** Calculate Precision, Recall, and False Positive Rate (FPR) for the system.
- [ ] **Model Ablation Study:** Run tests to prove the performance difference between the Base 7B model and your Fine-Tuned 7B model.
- [ ] **Latency Benchmarks:** Measure and document the token generation speed and overall scan duration.
- [ ] Deliver these metrics to Vedant so they can be displayed on the final Next.js Dashboard report.
