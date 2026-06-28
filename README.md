# HyperPlane

> **Redefining Threat Intelligence via Dual Domain Agentic SIEM**

A multi-agent Security Information & Event Management system that ingests logs from **both IT and OT/IoT domains**, enriches them with threat intelligence, correlates cross-domain attacks, and produces autonomous incident reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Stack: FastAPI + React + LangGraph](https://img.shields.io/badge/stack-FastAPI%20%2B%20React%20%2B%20LangGraph-blue)]()

---

## 🎤 60-second pitch

> Every company gets hacked eventually. The thing that decides whether they survive it is how fast their security system spots the attack and explains what happened.
>
> Modern systems do this for normal IT — emails, logins, servers. But factories and power plants also have computers — PLCs, sensors, Modbus devices — and those get attacked too, often through the IT network first.
>
> HyperPlane is a SIEM that watches both worlds. Six small AI agents cooperate like a security team — one sorts noise from real attacks, one looks up known-bad IPs, one adds context like location and asset owner, one looks for attacks that span IT *and* OT, and one writes the incident report.
>
> The interesting part is **cross-domain correlation** — spotting that an IT brute-force at 09:14 and an anomalous PLC command at 09:17 are the same attack. That's the research contribution.

---

## ✨ Features

- 🤖 **Six cooperating AI agents** built with LangGraph — Supervisor, Triage, Threat Intel, Enrichment, Detection & Correlation, Response
- 🌍 **Dual-domain ingestion** — syslog/EVTX from IT, Modbus/MQTT/OPC UA from OT/IoT
- 🔗 **Cross-domain correlation** — detects attack chains that span IT and OT
- 📜 **Auditable agent traces** — every agent's input and output is recorded (powers the Trace Viewer)
- 🔌 **Pluggable LLM** — runs offline with Ollama (default), or swap in OpenAI/Anthropic
- 🐳 **One-command deployment** — Docker Compose brings up Postgres, Elasticsearch, the backend, and the dashboard

---

## 🚀 Quickstart

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) and `git`.

```bash
git clone https://github.com/Manupathak07/hyperplane.git
cd hyperplane
docker compose up -d --build
```

Once everything is healthy:

| Service | URL |
|---|---|
| API (FastAPI + Swagger UI) | http://localhost:8000/docs |
| Dashboard (React + Vite) | http://localhost:5173 |
| Elasticsearch | http://localhost:9200 |

Seed a sample incident to see the dashboard in action:

```bash
docker exec hyperplane-backend python -m scripts.seed
curl -L http://localhost:8000/incidents/ | python -m json.tool
```

---

## 🏗️ Architecture

```
   IT logs  ──┐
              │
   OT/IoT  ──┼──▶  6 AI agents cooperate  ──▶  incident report
   logs      │    (Triage, Threat Intel,        │
              │     Enrichment, Detection,       ▼
              │     Response, Supervisor)     Dashboard
```

The agent pipeline runs once per event, regardless of source domain:

```
Supervisor → Triage → Threat Intel → Enrichment → Detection → Response → Supervisor (finalize)
```

Each invocation lands in the `agent_traces` table — this is what powers the **Agent Trace Viewer** in the dashboard.

---

## 🧰 Stack

| Layer | Choice | Why |
|---|---|---|
| Backend | FastAPI | Async-native, Pydantic v2, auto OpenAPI |
| Agent engine | LangGraph | Stateful graph with explicit control flow + loops |
| Database | PostgreSQL 16 | Transactional metadata, JSONB for flexibility |
| Search | Elasticsearch 8.15 | Full-text log search |
| Frontend | React + Vite | Industry standard, fast HMR |
| Deployment | Docker Compose | Single-host, simple |
| LLM | Ollama (default) | Offline-capable for viva |

---

## 📁 Repo layout

```
hyperplane/
├── docker-compose.yml       # Postgres + ES + backend + frontend
├── LICENSE                  # MIT
├── README.md                # this file
├── backend/                 # FastAPI app (Python)
│   ├── app/                 # main, config, db, models, schemas, routes
│   ├── alembic/             # DB migrations
│   ├── scripts/             # entrypoint.sh, seed.py
│   └── Dockerfile
├── frontend/                # React + Vite dashboard (Week 3+)
├── data/                    # bundled datasets (BETH/LogHub)
├── scripts/                 # log generators
└── docs/                    # architecture diagrams, viva prep
```

---

## 📅 Project status

Final-year major project, 12-week timeline.

- [x] Week 1 — Docker stack, Postgres + ES + placeholder backend
- [x] Week 2 — FastAPI skeleton + Alembic migrations + seed data (verified)
- [ ] Week 3 — React + Vite dashboard
- [ ] Weeks 4–5 — Ingestion + rules + log generator
- [ ] Weeks 6–7 — Supervisor + Triage + Threat Intel agents
- [ ] Weeks 8–9 — Enrichment + Detection agents + cross-domain correlation
- [ ] Weeks 10–11 — Response + report generation + Agent Trace Viewer
- [ ] Week 12 — Docs, demo, viva prep

---

## 👤 Author

**Manu Pathak** — Final-year engineering student
GitHub: [@Manupathak07](https://github.com/Manupathak07)

---

## 📄 License

[MIT](./LICENSE) — free for any use, including commercial. Just keep the copyright line.