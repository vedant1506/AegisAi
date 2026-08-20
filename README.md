# 🛡️ AegisAI — Autonomous Multi-Agent Framework for Hybrid Application Security (VAPT)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![Next.js 15](https://img.shields.io/badge/Next.js-15-black?logo=next.js)](https://nextjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![LangGraph](https://img.shields.io/badge/LangGraph-Agent-orange)](https://langchain-ai.github.io/langgraph/)

> AegisAI combines **Static Analysis (SAST)**, **Dynamic Testing (DAST)**, and **AI-driven exploit reasoning** into a unified autonomous security platform. A multi-agent LangGraph pipeline orchestrates reconnaissance, vulnerability reasoning, and exploit verification — all surfaced through a modern Next.js dashboard.

---

## 📐 Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Next.js 15 Frontend                  │
│          Dashboard · CodeDiffViewer · Reports           │
└────────────────────────┬────────────────────────────────┘
                         │ REST / SSE
┌────────────────────────▼────────────────────────────────┐
│                   FastAPI Backend                       │
│     /api/v1/scan  ·  /api/v1/report  ·  WebSocket      │
└──────┬──────────────────────────┬───────────────────────┘
       │                          │
┌──────▼──────────┐   ┌───────────▼──────────────────────┐
│  AST Parser     │   │       AI Engine (LangGraph)      │
│  tree-sitter    │   │  Recon → Reason → Verify Agents  │
│  (SAST)         │   │  Fine-tuned 7B LLM (Unsloth)    │
└──────┬──────────┘   └───────────┬──────────────────────┘
       │                          │
┌──────▼──────────────────────────▼───────────────────────┐
│              Crawler / DAST Engine                      │
│       Playwright Bot  ·  Token Manager  ·  httpx        │
│              OWASP Juice Shop (target)                  │
└─────────────────────────────────────────────────────────┘
```

---

## 🗂️ Monorepo Structure

```
aegis-ai/
├── .gitignore
├── .env.example
├── docker-compose.yml
├── README.md
│
├── frontend/              # Next.js 15 App Router UI
│   ├── src/app/           # Pages & layouts
│   ├── src/components/    # Dashboard, CodeDiffViewer
│   └── src/types/         # Shared TypeScript schemas
│
├── backend/               # FastAPI service
│   ├── main.py            # App init, CORS, routers
│   └── app/
│       ├── api/           # Route handlers
│       ├── ast_parser/    # tree-sitter SAST engine
│       └── schemas/       # Pydantic I/O models
│
├── crawler_dast/          # Playwright + httpx DAST
│   ├── src/
│   │   ├── playwright_bot.py
│   │   ├── token_manager.py
│   │   └── exploit_runner.py
│   └── target_docker/     # OWASP Juice Shop compose
│
└── ai_engine/             # LangGraph + Unsloth
    ├── datasets/          # Training data
    ├── training/          # QLoRA fine-tune script
    └── multi_agent/       # LangGraph state graph & prompts
```

---

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 20+
- Ollama (for local LLM inference)

### 1. Clone & Configure
```bash
git clone https://github.com/your-org/aegis-ai.git
cd aegis-ai
cp .env.example .env
# Edit .env with your values
```

### 2. Start All Services
```bash
docker-compose up -d
```

### 3. Backend (FastAPI)
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### 4. Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```

### 5. Launch Target (OWASP Juice Shop)
```bash
cd crawler_dast/target_docker
docker-compose up -d
```

### 6. Run DAST Crawler
```bash
cd crawler_dast
pip install -r requirements.txt
python src/playwright_bot.py
```

---

## 🤖 AI Engine

The `ai_engine/` module contains:

| Component | Description |
|-----------|-------------|
| `multi_agent/state_graph.py` | LangGraph orchestration: Recon → Reason → Verify |
| `multi_agent/prompts.py` | System prompt templates for each agent role |
| `training/train_qlora.py` | Unsloth QLoRA fine-tuning boilerplate (7B model) |
| `datasets/formatted_train_dummy.json` | Sample Alpaca-format training data |

---

## 🔒 Security Notice

This tool is intended for **authorized penetration testing** and **security research** only.  
Use only against systems you own or have **explicit written permission** to test.  
The authors are not responsible for any misuse.

---

## 📄 License

MIT © 2024 AegisAI Contributors
