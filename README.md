# ?? IPsec Security Analyzer

> An AI-powered IPsec traffic analysis and security assessment platform. Upload PCAP files, extract network features, run NIST-based security evaluations, and simulate attacker scenarios — all in one pipeline.

![Next.js](https://img.shields.io/badge/Next.js-16.3.3-black)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green)
![Python](https://img.shields.io/badge/Python-3.10+-blue)

---

## ?? Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Local Development Setup](#local-development-setup)
- [Environment Variables](#environment-variables)
- [Project Structure](#project-structure)
- [Deploying to Render](#deploying-to-render)
- [API Reference](#api-reference)

---

## Overview

IPsec Security Analyzer is a full-stack web application for network security professionals. It provides an end-to-end pipeline:

1. **Upload** a `.pcap` / `.pcapng` / `.cap` capture file
2. **Analyze** packets using TShark dissection
3. **Extract** features (encryption ciphers, key exchange, tunnel parameters)
4. **Assess** security posture against NIST SP 800-77r1 guidelines
5. **Simulate** attacker scenarios using an AI-powered attack model
6. **Harden** your VPN configuration with AI-generated recommendations

---

## Features

| Feature | Description |
|---|---|
| ?? PCAP Upload | Drag-and-drop or file picker for `.pcap`, `.pcapng`, `.cap` files |
| ?? Packet Analysis | TShark-powered deep packet inspection for IPsec/IKE traffic |
| ?? Feature Extraction | Automated extraction of cipher suites, key lifetimes, tunnel parameters |
| ??? Security Assessment | NIST SP 800-77r1 rules engine with RAG-augmented AI analysis |
| ?? AI Threat Analysis | Groq LLM integration for contextual threat intelligence |
| ?? Attacker Simulation | Simulated adversarial test commands generated from the security report |
| ?? IPsec Testbed | Virtual network testbed for VPN configuration testing |
| ?? Report Generation | Downloadable security assessment reports |

---

## Architecture

```
+----------------------------------------------+
¦              Next.js Frontend                ¦
¦  Dashboard ? Analysis ? Features ?           ¦
¦  Assessment ? Testbed ? Attacker Sim         ¦
+----------------------------------------------+
                  ¦  HTTP REST API
                  ?
+----------------------------------------------+
¦              FastAPI Backend                 ¦
¦  TShark Extractor | NIST Engine | Groq LLM  ¦
¦  RAG Engine       | Attacker Analyzer        ¦
+----------------------------------------------+
```

---

## Tech Stack

### Frontend
- **Next.js 16.3.3** with App Router + TypeScript
- **Tailwind CSS v4** + **shadcn/ui** components
- **Lucide React** icons

### Backend
- **FastAPI** + **Uvicorn** (ASGI)
- **Scapy** — Packet analysis
- **TShark** — Packet dissection
- **Groq SDK** — AI/LLM integration
- **Pydantic v2** — Data validation

---

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Node.js | = 18.x | https://nodejs.org |
| pnpm | = 8.x | `npm i -g pnpm` |
| Python | = 3.10 | https://python.org |
| TShark | latest | Installed with Wireshark |
| Git | any | https://git-scm.com |

---

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/ip-sec-security-analyzer.git
cd ip-sec-security-analyzer
```

### 2. Configure Environment

```bash
cp .env.example .env.local
# Edit .env.local and fill in your GROQ_API_KEY
```

### 3. Install Frontend Dependencies

```bash
pnpm install
```

### 4. Set Up Python Backend

```bash
cd backend

# Create virtualenv
python -m venv venv

# Activate (Windows)
venv\Scripts\activate
# Activate (Linux/macOS)
# source venv/bin/activate

pip install -r requirements.txt
cd ..
```

### 5. Start the Backend

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

- API: http://localhost:8000  
- Swagger UI: http://localhost:8000/docs

### 6. Start the Frontend

In a **separate terminal**:

```bash
pnpm dev
```

App: http://localhost:3000

---

## Environment Variables

### `.env.local` (at project root)

| Variable | Description | Example |
|---|---|---|
| `NEXT_PUBLIC_ANALYZER_API_URL` | FastAPI backend URL | `http://localhost:8000` |
| `NEXT_PUBLIC_USE_MOCK_API` | Use mock data (`true`/`false`) | `false` |
| `GROQ_API_KEY` | Groq API key (server-side only) | `gsk_...` |
| `GROQ_MODEL` | Groq model name | `groq/compound` |

> ?? `GROQ_API_KEY` is **never** exposed to the browser.

**Getting a Groq API Key:**
1. Go to https://console.groq.com
2. Sign in ? **API Keys** ? **Create API Key**
3. Copy the key starting with `gsk_...`

---

## Project Structure

```
ip-sec-security-analyzer/
+-- app/                          # Next.js App Router
¦   +-- layout.tsx
¦   +-- page.tsx
¦   +-- globals.css
+-- components/analyzer/          # Page components
¦   +-- analyzer-shell.tsx        # Navigation shell
¦   +-- dashboard-page.tsx        # PCAP upload
¦   +-- analysis-page.tsx         # Packet inspection
¦   +-- features-page.tsx         # Feature extraction
¦   +-- security-page.tsx         # Security assessment
¦   +-- testbed-page.tsx          # IPsec testbed
¦   +-- attacker-simulation-page.tsx
¦   +-- hardening-page.tsx
¦   +-- user-guide-page.tsx
¦   +-- report-modal.tsx
¦   +-- vpn-test-terminal.tsx
+-- hooks/
¦   +-- use-analyzer.ts           # Central state hook
+-- backend/
¦   +-- main.py                   # FastAPI entry point
¦   +-- requirements.txt
¦   +-- groq_analyzer.py          # Groq LLM integration
¦   +-- security_engine.py        # NIST rules engine
¦   +-- attacker_analyzer.py      # Attack simulation logic
¦   +-- rag_engine.py             # RAG retrieval
¦   +-- testbed_router.py         # Testbed routes
¦   +-- extractor/
¦       +-- features.py
¦       +-- tshark.py
+-- render.yaml                   # Render deployment config
+-- .env.example
+-- README.md
```

---

## Deploying to Render

This app uses **two Render services**:

| Service | Type | Port |
|---|---|---|
| `ipsec-backend` | Python Web Service | auto |
| `ipsec-frontend` | Node.js Web Service | auto |

---

### Step 1 — Push to GitHub

```bash
git add .
git commit -m "chore: ready for Render deployment"
git push origin main
```

---

### Step 2 — Deploy Backend (FastAPI)

1. Go to https://render.com ? **New ? Web Service**
2. Connect your GitHub repo
3. Fill in these settings:

| Setting | Value |
|---|---|
| Name | `ipsec-backend` |
| Branch | `main` |
| Root Directory | `backend` |
| Runtime | `Python 3` |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn main:app --host 0.0.0.0 --port $PORT` |

4. Add **Environment Variables**:

| Key | Value |
|---|---|
| `GROQ_API_KEY` | `gsk_your_key_here` |
| `GROQ_MODEL` | `groq/compound` |

5. Click **Create Web Service** — note the URL (e.g. `https://ipsec-backend.onrender.com`)

---

### Step 3 — Deploy Frontend (Next.js)

1. **New ? Web Service** again, same repo
2. Fill in:

| Setting | Value |
|---|---|
| Name | `ipsec-frontend` |
| Branch | `main` |
| Root Directory | *(leave empty)* |
| Runtime | `Node` |
| Build Command | `npm install -g pnpm && pnpm install && pnpm build` |
| Start Command | `pnpm start` |

3. Add **Environment Variables**:

| Key | Value |
|---|---|
| `NEXT_PUBLIC_ANALYZER_API_URL` | `https://ipsec-backend.onrender.com` |
| `NEXT_PUBLIC_USE_MOCK_API` | `false` |
| `GROQ_API_KEY` | `gsk_your_key_here` |
| `GROQ_MODEL` | `groq/compound` |
| `NODE_VERSION` | `20` |

4. Click **Create Web Service**

---

### Step 4 — Verify

Once both show **Live** status:
- ?? Frontend: `https://ipsec-frontend.onrender.com`
- ?? Backend docs: `https://ipsec-backend.onrender.com/docs`

> ?? **Free tier**: Services spin down after 15 min of inactivity. First cold-start request may take ~30s. Upgrade to a paid plan for always-on.

---

### Using render.yaml (Recommended — Deploy Both at Once)

A `render.yaml` Blueprint file is included. To use it:

1. Push to GitHub (Step 1 above)
2. Render dashboard ? **New ? Blueprint**
3. Connect your repo — Render auto-detects `render.yaml` and provisions both services

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Health check |
| `POST` | `/upload` | Upload PCAP file |
| `GET` | `/packets/{session_id}` | Get dissected packets |
| `GET` | `/features/{session_id}` | Get extracted features |
| `GET` | `/security/{session_id}` | Run NIST assessment |
| `POST` | `/ai-analysis/{session_id}` | Groq AI threat analysis |
| `POST` | `/attacker/analyze` | Attacker simulation commands |
| `GET` | `/testbed/status` | Testbed status |
| `POST` | `/testbed/start` | Start IPsec testbed |

Full interactive docs: `http://localhost:8000/docs`

---

## License

MIT © 2024 — IPsec Security Analyzer

> Built for network security professionals. Powered by FastAPI, Next.js, and Groq AI.
