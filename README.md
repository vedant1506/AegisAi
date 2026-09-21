# 🛡️ AegisAI — Autonomous Multi-Agent Framework for Hybrid Application Security (VAPT)

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-000000?logo=next.js&logoColor=white)](https://nextjs.org/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Multi--Agent-FF6F00?logo=langchain&logoColor=white)](https://langchain-ai.github.io/langgraph/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.5.1%2Bcu121-EE4C2C?logo=pytorch&logoColor=white)](https://pytorch.org/)
[![Unsloth QLoRA](https://img.shields.io/badge/Fine--Tuned-Unsloth_QLoRA-4B0082)](https://github.com/unslothai/unsloth)
[![HuggingFace Model](https://img.shields.io/badge/HuggingFace-Divy2712%2Faegisai--security--7b-FFD21E?logo=huggingface&logoColor=black)](https://huggingface.co/Divy2712/aegisai-security-7b)
[![Docker Compose](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker&logoColor=white)](docker-compose.yml)

**Bridging Static Code Analysis (SAST), Headless Dynamic Testing (DAST), and Fine-Tuned AI Semantic Reasoning into an Autonomous, Zero-False-Positive VAPT Engine.**

[Key Innovations](#-key-innovations) •
[Architecture](#-end-to-end-architecture) •
[Execution Modes](#-3-execution-modes) •
[Benchmark Results](#-empirical-benchmarks--validation) •
[Quickstart](#-quick-start) •
[Team & Credits](#-team--academic-attributions)

</div>

---

## 📌 Executive Summary

Modern web application security audits are plagued by an inefficient, two-silo approach:
1. **Static Application Security Testing (SAST)** *(e.g., Snyk, SonarQube, CodeQL)*: Scans source code on GitHub, but flags massive volumes of **false positives** because it cannot determine if code paths are reachable on a live server.
2. **Dynamic Application Security Testing (DAST)** *(e.g., OWASP ZAP, Burp Suite, Acunetix)*: Attacks endpoints externally, but operates blind to code structure—unable to identify file paths, line numbers, or propose remediations.
3. **The Business Logic Blindspot:** Traditional tools rely on regex rules and dictionary fuzzing, consistently missing **Broken Object Level Authorization (BOLA / IDOR — OWASP API #1)**, multi-step privilege escalation, and tenant boundary breaches.

### 🌟 The AegisAI Solution
**AegisAI bridges this gap through autonomous multi-agent reasoning:**
- **Hybrid Input Ingestion:** Ingests a **GitHub Repository**, a **Live Web URL**, or **Both**.
- **Specialized Multi-Agent Orchestration:** A **LangGraph** state machine coordinates a **Static Recon Agent** (`tree-sitter`), a **Dynamic Recon Agent** (Playwright), a **Reasoning SLM Agent** (Fine-tuned Qwen2.5-Coder-7B), and a **Deterministic Verifier Agent** (`httpx`).
- **Complete Triad Delivery:** For every verified flaw, AegisAI produces:
  1. 🔍 **Semantic Diagnosis** explaining root-cause authorization omissions.
  2. ⚡ **Verified HTTP PoC Exploit** demonstrating cross-tenant data leakage.
  3. 🛠️ **Merge-Ready Git Code Patch** pinpointed to the exact source file and line number.

---

## ⚡ Key Innovations

| Feature | Traditional SAST / DAST | AegisAI Platform |
| :--- | :--- | :--- |
| **Workflow Style** | Manual proxy / Siloed scanner | **Autonomous Multi-Agent VAPT** |
| **Modern SPA Support** | Fails on complex React/Vue hashes | **Headless Chromium Playwright Bot** with SPA hash handling & modal dismissal |
| **BOLA / IDOR Detection** | ❌ Fails without manual tester | ✅ **Fine-Tuned 7B QLoRA Code Model** with cross-tenant context |
| **Verification & Validation** | ⚠️ High false positive noise | ✅ **Deterministic Verifier Engine** + Soft-404 & Baseline Diff Filter |
| **Code Location Mapping** | ❌ None (or requires invasive runtime agents) | ✅ **Non-Invasive Hybrid Correlator** (Exact File + Line #) |
| **Automated Remediation** | ❌ Manual developer patching | ✅ **Automated Git Diff & Monaco Viewer Patches** |

---

## 📐 End-to-End Architecture

```mermaid
flowchart TB
    %% STYLING
    classDef trigger fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#fff;
    classDef recon fill:#1e1b4b,stroke:#8b5cf6,stroke-width:2px,color:#fff;
    classDef ai fill:#311042,stroke:#d946ef,stroke-width:2px,color:#fff;
    classDef verify fill:#451a03,stroke:#fbbf24,stroke-width:2px,color:#fff;
    classDef report fill:#064e3b,stroke:#34d399,stroke-width:2px,color:#fff;

    subgraph S1 ["🚀 1. Orchestration & Input"]
        direction TB
        UI["<b>Next.js 15 Dashboard</b><br/>User submits GitHub Repo & Target URL"]
        API["<b>FastAPI Core Gateway</b><br/>Dispatches Scan Job & State Machine"]
        UI <==>|REST / SSE Status| API
    end

    subgraph S2 ["🔍 2. Dual Reconnaissance Agents"]
        direction LR
        AST["<b>Static Agent (tree-sitter)</b><br/>AST Route & Controller Parsing<br/><i>Outputs: ASTSchema JSON</i>"]
        Crawler["<b>Dynamic Agent (Playwright)</b><br/>Headless Network & Token Harvesting<br/><i>Outputs: EndpointSchema JSON</i>"]
    end

    subgraph S3 ["🧠 3. Semantic Reasoning (LangGraph Engine)"]
        direction TB
        Merge["<b>State Graph Correlation</b><br/>Correlates AST Handlers with Discovered APIs"]
        SLM["<b>Fine-Tuned AegisAI-7B SLM</b><br/>Qwen2.5-Coder-7B QLoRA (RTX A2000 / Ollama)"]
        Payload["<b>Exploit Synthesis</b><br/>Crafts Context-Aware HTTP PoC Payload"]
        Merge --> SLM --> Payload
    end

    subgraph S4 ["⚡ 4. Deterministic Verification & FP Filter"]
        direction TB
        Runner["<b>Async Exploit Runner (httpx)</b><br/>Executes targeted cross-tenant exploit"]
        VerifyRules{"<b>Evidence Evaluator</b><br/>Data leak confirmation?<br/>SQL syntax error?<br/>DOM XSS reflection?"}
        FPFilter["<b>False-Positive Filter</b><br/>Soft-404 · Static Asset · Baseline Diff"]
        Verified["<b>Confirmed True Positive</b>"]
        Runner --> VerifyRules
        VerifyRules -->|Pass| FPFilter -->|Valid| Verified
        VerifyRules -->|Fail / 403| Discard["Discarded False Alarm"]
    end

    subgraph S5 ["🛠️ 5. Correlation & Delivery"]
        direction TB
        Correlator["<b>Hybrid Correlator</b><br/>Maps verified endpoint to File Path & Line #"]
        PatchGen["<b>Remediation Engine</b><br/>Produces Git Diff Patch"]
        FinalReport["<b>Unified Next.js Security Report</b><br/>Vulnerability Card · Live Evidence · Monaco Code Diff"]
        Correlator --> PatchGen --> FinalReport
    end

    %% PIPELINE LINKS
    API ==> S2
    AST ==> Merge
    Crawler ==> Merge
    Payload ==> Runner
    Verified ==> Correlator
    FinalReport -.-> UI

    class S1,UI,API trigger;
    class S2,AST,Crawler recon;
    class S3,Merge,SLM,Payload ai;
    class S4,Runner,VerifyRules,FPFilter,Verified,Discard verify;
    class S5,Correlator,PatchGen,FinalReport report;
```

---

## 🎯 3 Execution Modes

```
      ┌────────────────────────────────────────────────────────┐
      │                   AegisAI Core Engine                  │
      └────────────────────────────────────────────────────────┘
                 │                  │                  │
         Mode 1  │          Mode 2  │          Mode 3  │
                 ▼                  ▼                  ▼
     ┌──────────────────┐  ┌──────────────────┐  ┌───────────────────────┐
     │  SAST-Only Mode  │  │  DAST-Only Mode  │  │  Hybrid VAPT Mode     │
     │  (GitHub Repo)   │  │  (Live Web URL)  │  │  (Repo + Live URL)    │
     ├──────────────────┤  ├──────────────────┤  ├───────────────────────┤
     │ • AST extraction │  │ • Headless crawl │  │ • Full Recon Pairing  │
     │ • Route analysis │  │ • Token sniffing │  │ • SLM BOLA Reasoning  │
     │ • Code auditing  │  │ • Active fuzzing │  │ • Live PoC Verification│
     │ • Patch proposal │  │ • HTTP evidence  │  │ • File & Line Mapping │
     └──────────────────┘  └──────────────────┘  └───────────────────────┘
```

---

## 📊 Empirical Benchmarks & Validation

### 1. Fine-Tuned SLM Performance (AegisAI-Security-7B vs. Base 7B)
Tested across standardized unseen validation suites on dedicated hardware (**NVIDIA RTX A2000 12GB**, 4-bit QLoRA / 16-bit merged):

| Metric | Base Model (Qwen2.5-Coder-7B) | AegisAI Fine-Tuned 7B | Absolute Gain |
| :--- | :---: | :---: | :---: |
| **Precision** | 80.00% | **98.04%** | **+18.04%** |
| **Recall (Catch Rate)** | 72.00% | **100.00%** | **+28.00%** |
| **F1-Score** | 0.7579 | **0.9901** | **+23.22%** |
| **False Positive Rate (FPR)** | 18.00% | **2.00%** | **-16.00%** |
| **Exploit Synthesis Rate** | 38.89% | **92.00%** | **+53.11%** |
| **CWE Classification Accuracy** | 72.22% | **96.00%** | **+23.78%** |
| **Throughput Speed** | 590.9 tok/s | **1060.2 tok/s** | **+469.3 tok/s** |

### 2. Live Target Testbed Validation
AegisAI was evaluated against production-grade vulnerable testbeds:

* **OWASP crAPI v1.1.6 (Microservices Target):**
  - **4/4 Verified Vulnerabilities Confirmed:**
    - `CRAPI-VULN-01`: BOLA in Vehicle Location (`GET /identity/api/v2/vehicle/{carId}/location`)
    - `CRAPI-VULN-02`: Broken Authentication OTP Bypass (`POST /identity/api/auth/v2/check-otp`)
    - `CRAPI-VULN-03`: BOLA in Mechanic Service Report (`POST /workshop/api/merchant/contact_mechanic`)
    - `CRAPI-VULN-04`: Mass Assignment in Order Processing (`PUT /workshop/api/shop/orders/{id}`)
* **OWASP Juice Shop (Modern SPA Target):**
  - Full single-page application hash route preservation (`/#/search`, `/#/score-board`, `/#/recycle`).
  - Automated welcome dialog and cookie banner dismissal.
  - Boolean differential SQLi and DOM-injected XSS validation.

---

## 🗂️ Monorepo Directory Layout

```
AegisAi/
├── docker-compose.yml              # Unified full-stack orchestration
├── Modelfile.aegisai               # Ollama custom SLM manifest
├── requirements.txt                # Root dependencies
│
├── frontend/                       # Next.js 15 Modern Dashboard
│   ├── src/app/                    # App Router (page.tsx, layout.tsx, globals.css)
│   ├── src/components/             # UI Components
│   │   ├── Dashboard.tsx           # Scan trigger & live telemetry visualizer
│   │   └── CodeDiffViewer.tsx      # Monaco side-by-side Git diff viewer
│   └── src/types/                  # Shared TypeScript Pydantic mirror schemas
│
├── backend/                        # FastAPI Core Service
│   ├── main.py                     # API Gateway, CORS, lifecycle hooks
│   └── app/
│       ├── api/scan_router.py      # /start, /status, /report, /agent-state
│       ├── ast_parser/             # tree-sitter static analysis engine
│       ├── schemas/io_models.py    # Strict Pydantic I/O contracts
│       └── services/               # LangGraph bridge & Celery workers
│
├── crawler_dast/                   # Dynamic Testing & Verification Suite
│   ├── src/
│   │   ├── playwright_bot.py       # Headless Chromium crawler
│   │   ├── token_manager.py        # Sniffer & multi-tenant session manager
│   │   ├── exploit_runner.py       # Async HTTPX payload execution engine
│   │   ├── verifier.py             # Deterministic proof evaluator
│   │   └── false_positive_filter.py# 4-stage noise suppression filter
│   ├── benchmarks/                 # Reproducibility audit & testbeds
│   │   ├── ground_truth_testbed.py # crAPI, Juice Shop & custom catalogs
│   │   └── benchmark_harness.py    # Automated empirical metric calculator
│   └── tests/                      # Automated unit and integration tests
│
├── ai_engine/                      # Semantic Reasoning & SLM Training
│   ├── multi_agent/
│   │   ├── state_graph.py          # LangGraph state machine (Recon->Reason->Verify)
│   │   └── prompts.py              # Role-specific system instructions
│   ├── datasets/                   # 1,500+ curated OWASP BOLA pairs
│   ├── evaluation/                 # Model ablation & benchmark report generator
│   └── training/                   # Unsloth QLoRA fine-tuning & GGUF export
│
└── lora_adapters/                  # Trained LoRA Adapters (161 MB)
    └── aegisai-security/           # Weights, tokenizer, trainer_state
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Operating System:** Linux (Ubuntu 22.04+) or Windows 11 with WSL2
- **Hardware:** 16GB RAM minimum; dedicated NVIDIA GPU (8GB+ VRAM) recommended for live local SLM inference
- **Software:** Python 3.11+, Node.js 20+, Docker & Docker Compose

### 1. Clone the Repository
```bash
git clone https://github.com/vedant1506/AegisAi.git
cd AegisAi
cp .env.example .env
```

### 2. Launch Entire Platform via Docker Compose
```bash
docker-compose up -d
```
* **Frontend UI:** `http://localhost:3000`
* **FastAPI Docs:** `http://localhost:8000/docs`
* **Redis Queue:** `localhost:6379`
* **Ollama Service:** `http://localhost:11434`

### 3. Running Live Model Inference Test
To verify the fine-tuned security SLM on your local GPU:
```bash
python ai_engine/test_live_inference.py
```
*Loads weights from `lora_adapters/aegisai-security`, analyzes a target FastAPI route, and displays raw JSON diagnosis, exploit payload, and remediation patch in real-time.*

### 4. Running the Benchmark Suite
To execute automated verification against target testbeds:
```bash
python crawler_dast/benchmarks/benchmark_harness.py --catalog crapi_v1_1_6
```

---

## 👥 Team & Academic Attributions

Developed as a Major Academic Capstone Project at **Gujarat Technological University (GTU) - School of Engineering and Technology (GTU-SET)**.

* **Vedant Chauhan (Lead):** Core Architecture, FastAPI Backend, tree-sitter SAST Parser, and Next.js UI Integration.
* **Shahad Pathan:** Dynamic Testing (DAST) Engine, Headless Playwright Crawler, Deterministic Verifier, and Benchmark Testbed Harness.
* **Divy Patel:** AI Semantic Reasoning Engine, Dataset Engineering, and QLoRA SLM Fine-Tuning (`aegisai-security-7b`).
* **Faculty Guide:** **Dr. Deepak Upadhyay**, Assistant Professor, GTU-SET.

---

## ⚖️ Responsible Disclosure & Legal Disclaimer

> **IMPORTANT:** AegisAI is engineered exclusively for **authorized security evaluations, defensive posture enhancement, and academic AppSec research**. It must only be executed against applications and repositories you own or possess **explicit written authorization** to assess. The authors and GTU-SET accept no liability for illicit usage or damages.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
