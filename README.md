# Rakshak-AI


## DFIR-Based Attack Chain Reconstruction and Dynamic Blast-Radius Assessment Using Graph Analysis and Local LLMs

Rakshak-AI is a local-first cybersecurity and Digital Forensics and Incident Response (DFIR) platform designed to reconstruct attack chains from forensic telemetry, correlate evidence, visualize incidents as graphs, and dynamically assess the potential blast radius of a compromised asset.

## Contents

- [Project Status](#project-status)
- [Core Architecture](#core-architecture)
- [Technology Stack](#technology-stack)
- [Setup and Usage](#setup-and-usage)
- [Workspaces and Analysis](#workspaces-and-analysis)
- [Testing and Verification](#testing-and-verification)
- [Security and Persistence](#security-and-persistence)


The project is being developed in two major parts.

---

## Project Status

### Part 1 — Deterministic DFIR Pipeline

**Part 1 is the currently implemented stage of the project.**

The current system focuses on deterministic and explainable processing of forensic telemetry:

- Raw forensic log ingestion
- Parser-specific event extraction
- Event normalization
- OCSF-aligned event representation
- Suspicious event detection
- Sigma/MITRE ATT&CK-aligned analysis
- Evidence correlation
- Incident reconstruction
- Attack-chain / compromise graph generation
- Graph-based blast-radius assessment
- Incident triage and investigation
- Demo and live data provenance separation
- Offline link-loss and replay handling
- Local SQLite persistence
- Metrics and analytical views

Part 1 is designed to work without requiring a Large Language Model.

The current investigation/copilot functionality is deterministic and does not represent a production AI/LLM system.

### Part 2 — Local AI Investigation

**Part 2 will be implemented later.**

The planned Part 2 will introduce local LLM capabilities using Ollama.

Planned capabilities include:

- AI-assisted incident investigation
- Evidence summarization
- Attack-chain explanation
- Contextual interpretation of forensic evidence
- Analyst-oriented investigation assistance
- Investigation report generation
- Recommended next steps
- Natural-language interaction with reconstructed incidents

Ollama is therefore **not required for Part 1**.

---

# Core Architecture

```text
                   RAW FORENSIC LOGS
                           |
                           v
                       PARSERS
                           |
                           v
                NORMALIZATION / OCSF
                           |
                           v
             DETECTION / SIGMA / MITRE
                           |
                           v
                  EVIDENCE CORRELATION
                           |
                           v
                 INCIDENT RECONSTRUCTION
                           |
                  +--------+--------+
                  |                 |
                  v                 v
           INCIDENT GRAPH      BLAST-RADIUS
                  |              ANALYSIS
                  |                 |
                  +--------+--------+
                           |
                           v
                        FASTAPI
                           |
                           v
                     NEXT.JS UI


Technology Stack
### Backend
Python 3.11
FastAPI
Uvicorn
SQLModel
SQLite
NetworkX
pySigma
Pydantic
### Frontend
Next.js
React
TypeScript
React Flow
npm
### Security / Detection / Analysis Concepts
OCSF-aligned event normalization
Sigma-based detection concepts
MITRE ATT&CK technique mapping
Evidence correlation
Incident reconstruction
Graph traversal
BFS / DFS concepts
Weighted graph analysis
Blast-radius scoring

Rakshak/
|
+-- app/
|   +-- incidents/
|   +-- ...
|
+-- backend/
|   +-- app/
|   |   +-- routes/
|   |   +-- services/
|   |   +-- models.py
|   |   +-- schemas.py
|   |   +-- database.py
|   |   +-- main.py
|   |
|   +-- tests/
|   +-- requirements.txt
|   +-- rakshak.db
|
+-- components/
|   +-- DashboardShell.tsx
|   +-- AttackPathGraph.tsx
|   +-- BlastRadiusNetworkView.tsx
|   +-- BlastRadiusReadout.tsx
|   +-- LogIngestionModal.tsx
|   +-- ScenarioControls.tsx
|   +-- ...
|
+-- lib/
|   +-- api.ts
|   +-- types.ts
|   +-- validation.ts
|   +-- forceLayout.ts
|   +-- ...
|
+-- package.json
+-- package-lock.json
+-- README.md
+-- .gitignore

## Setup and Usage

### Prerequisites
Install the following before running the project:

Python 3.11
Node.js
npm
Git

Part 1 does not require Ollama.

### Backend Setup
Open PowerShell in the project directory.

cd backend
py -3.11 -m pip install -r requirements.txt
cd ..

A Python virtual environment is recommended.

cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3.11 -m pip install -r requirements.txt
cd ..
### Frontend Setup
From the project root:

npm install

package-lock.json should remain in version control so that frontend dependencies can be reproduced consistently.

### Running the Project
Rakshak-AI currently uses two local development processes.
#### 1. Start the Backend
Open a PowerShell terminal:

cd "D:\Hackathon PS projects\Rakshak\backend"
py -3.11 -m uvicorn app.main:app --reload --port 8000

The backend will be available at:

http://localhost:8000
#### 2. Start the Frontend
Open a second PowerShell terminal:

cd "D:\Hackathon PS projects\Rakshak"
npm run dev

The frontend will be available at:

http://localhost:3000

Open the application in a browser:

http://localhost:3000
### Quick Start
A root-level start.bat convenience launcher is intended to automate the local startup process.

The launcher will start:

FastAPI backend
Next.js frontend
Local browser

The launcher should use paths relative to the project directory and must not depend on a specific developer machine path.

Until start.bat is present, use the manual commands above.

## Workspaces and Analysis

### Main Tactical Workspaces
Rakshak-AI currently provides four main tactical workspaces.
#### 1. Overview / Triage
Provides a high-level operational view of:

Total events
Active incidents
Severity
Risk indicators
Triage queue
Scenario controls
Campaign correlation
Telemetry status
#### 2. Incident Investigation
Provides detailed investigation of a selected incident:

Reconstructed attack path
Incident graph
Evidence relationships
Timeline
Deterministic investigation analysis
Response-action simulation
Incident evidence references
#### 3. Topology / Blast Radius
Provides dynamic blast-radius assessment for a compromised target:

Target host selection
Surrounding topology
Impact categories
Contributing nodes
Weighted impact values
Blast-radius score
Visual containment / impact zone

The blast-radius contribution score represents analytical impact and must not be confused with an actual evidence-backed network relationship.
#### 4. Metrics & Analytics
Provides analytical views such as:

Live telemetry
Event distribution
ATT&CK technique distribution
High-risk entities
Analytical summaries
### Scenario / Demo System
The project contains deterministic demo scenarios for testing and presentation.

Scenarios are used to demonstrate:

Attack-chain reconstruction
Incident creation
Graph generation
Blast-radius analysis
Cross-site correlation
Replay behavior
Link-loss behavior

Demo data and live data are required to remain provenance-aware and must not silently overwrite each other.

### Live Log Ingestion
Part 1 includes a local forensic log ingestion pipeline.

The general flow is:

Raw Log
   |
   v
Parser
   |
   v
Normalization
   |
   v
Detection
   |
   v
Deduplication
   |
   v
Correlation
   |
   v
Incident / Graph Update

The current implementation includes parser-specific support for the forensic telemetry formats implemented in the backend.

Examples include:

Windows Sysmon-style event input
Linux auditd EXECVE-style input
Supported raw JSON/XML/text telemetry

The ingestion interface allows raw telemetry to be pasted or uploaded depending on the supported parser implementation.

Native EVTX parsing should not be assumed unless an EVTX parser is explicitly implemented.

### Ingestion Provenance
Rakshak-AI distinguishes between:

demo
live

Demo telemetry is used for deterministic scenarios and demonstrations.

Live telemetry is processed through the live ingestion pipeline.

The system should preserve provenance through:

ingestion
   ->
events
   ->
incidents
   ->
correlation
   ->
graphs

Live and demo data should not silently contaminate each other.

### Offline / Link-Loss Mode
The application contains a local replay flow intended to simulate loss of connectivity between the frontend and backend.

The flow supports:

Link Loss
    |
    v
Offline Queue
    |
    v
Replay / Restore
    |
    v
Backend Processing

The purpose is to demonstrate that queued telemetry can be restored without silently losing or duplicating events.

### Incident Graph
Incident graphs reconstruct relationships between forensic entities involved in an attack.

Example semantic node categories may include:

Attacker
Host
User / Process
Payload
Decoy
Site or environment context

The graph represents evidence-backed relationships and should not invent relationships solely for visualization.

### Blast-Radius Analysis
Blast-radius assessment evaluates the potential impact of a compromised node using graph structure and weighted contributing nodes.

Conceptually:

Compromised Node
      |
      +---- Neighbor / Asset
      |
      +---- Infrastructure Dependency
      |
      +---- High-Value System
      |
      +---- Remote / Cross-Site Relationship

The visual blast zone is an analytical representation of potential impact.

A node contributing to a blast-radius score does not automatically mean that a direct network relationship exists between that node and the compromised system.

### Deterministic Investigation
Part 1 investigation is deterministic.

The current system can provide:

Incident reconstruction
Evidence correlation
Attack-path visualization
ATT&CK-aligned interpretation
Blast-radius scoring
Deterministic investigation summaries

This should not be interpreted as an LLM-generated investigation.

The local LLM layer belongs to Part 2.

### Part 2 — Planned AI Layer
The planned Part 2 architecture is:

Reconstructed Incident
        |
        v
Relevant Evidence
        |
        v
Retrieval / Context
        |
        v
Local Ollama Model
        |
        v
Investigation / Report

The future AI layer is intended to remain local-first and should not require sending forensic data to an external hosted AI service.

## Testing and Verification

### Testing
### Backend Tests
From the backend directory:

cd backend
pytest
cd ..
### Frontend TypeScript Check
From the project root:

npx tsc --noEmit
### Production Build
From the project root:

npm run build
### Development Verification
Before considering a change complete, the following flows should be checked:

Application startup
Overview page
Incident Investigation page
Topology / Blast Radius page
Metrics / Analytics page
Demo replay
Campaign replay
Link-loss simulation
Restore link
Clear demo data
Open Full Incident
Live log ingestion
Duplicate ingestion handling
Incident graph rendering
Blast-radius rendering
Browser console
Backend API errors
Database persistence

## Security and Persistence

### Local Database
Rakshak-AI uses SQLite for local persistence.

The runtime database is:

backend/rakshak.db

This database is intentionally excluded from version control.

A developer should allow the application to create or migrate its local database as required.

The database should never contain production credentials or real confidential forensic data in a public repository.

### Security Notes
This project is intended for local development, demonstration, and controlled testing.

Do not commit:

API keys
passwords
authentication tokens
private keys
.env files
local SQLite databases
Python bytecode
generated build artifacts
local exported codebase snapshots

Use .env.example for documenting required environment variables without storing real secrets.

### Current Part 1 Implementation
The current Part 1 implementation includes:

Tactical cockpit
Overview / Triage
Incident Investigation
Attack-path graph visualization
Blast-radius visualization
Metrics / Analytics
Scenario replay
Offline link-loss workflow
Restore/replay workflow
Demo-data clearing
Live log ingestion
SQLite persistence
Deterministic investigation analysis
Cross-site campaign correlation
### Planned Part 2 Implementation
Planned capabilities include:

Ollama integration
Local LLM investigation
Evidence summarization
Attack-chain explanation
Context-aware investigation assistance
Investigation report generation
Analyst recommendations
Natural-language incident interaction

Part 2 will be developed after the Part 1 deterministic DFIR pipeline and visual workflow are stable.
