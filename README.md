# 🔐 AI Privacy Firewall

A personal AI-powered digital privacy device that monitors DNS requests, detects tracking behavior, and gives you control over your digital footprint. Combines network-level data collection, FastAPI-based backend processing, and a web dashboard for real-time insights.

---

## 📦 Features

- 🧠 Local DNS traffic monitoring via Pi-hole
- 📡 Backend API for log collection and domain classification
- 🔍 Privacy-focused dashboard with alerts and summaries
- 🛡️ Plans for AI-driven privacy assistant and opt-out automation
- 💻 Optional deployment to Raspberry Pi for real-world testing

---

## 🧱 Project Structure

```bash
.
├── backend/         # FastAPI app for data ingestion and logic
├── dns_monitor/     # Scripts to parse Pi-hole or DNS logs
├── dashboard/       # Local web UI for visualizing activity
├── device/          # Raspberry Pi setup, shell scripts, hardware
├── data/            # Blocklists, log data, threat classification
├── docs/            # Architecture docs, phase checklists
├── tests/           # API and pipeline tests
├── .env.example     # API keys / config
├── requirements.txt
└── README.md
