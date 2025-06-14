# 🏗️ Architecture Overview

## Core Components

- **Backend (FastAPI)**: Handles log ingestion, analysis, storage, and classification
- **DNS Monitor**: Parses DNS logs (e.g. Pi-hole) for real-time insights
- **Dashboard**: Local web UI for user-facing data visualization and alerts
- **Device Module**: (Future) Raspberry Pi configuration and integration
- **AI Module**: (Future) Classifies and detects privacy threats using ML

## Data Flow

## Data Flow

[Device or Pi-hole] → [dns_monitor] → [FastAPI Backend] → [Database] → [Dashboard]


## Tech Stack

- Python 3.10+
- FastAPI
- SQLite (or PostgreSQL later)
- Playwright (optional for scraping)
- JavaScript (dashboard, future)