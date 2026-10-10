# Rakshak-AI

**DFIR-Based Attack Chain Reconstruction and Dynamic Blast-Radius Assessment Using Graph Analysis and Local LLMs**

Rakshak-AI is a local-first cybersecurity and Digital Forensics and Incident Response (DFIR) platform designed to reconstruct attack chains from forensic telemetry, correlate evidence, visualize incidents as deterministic graphs, and dynamically assess the potential blast radius of a compromised asset.

## 1. Project Overview
Rakshak-AI provides security analysts with a powerful, deterministic pipeline to ingest logs, extract meaningful events, and map them to known MITRE ATT&CK techniques. It builds relational graphs of incidents, enabling visual comprehension of complex attack paths and the subsequent topological exposure of infrastructure.

## 2. Problem Statement / Motivation
Modern DFIR requires correlating disparate forensic logs into a coherent narrative. Manual correlation is slow and prone to missing latent relationships, while traditional SIEM tools often produce alert fatigue without context. There is a need for a local, privacy-preserving tool that translates raw evidence directly into causal attack graphs and impact assessments.

## 3. Core Objective
To deterministically process forensic telemetry into actionable, structured incident graphs that immediately communicate how an asset was compromised (attack chain) and what else is at risk (blast radius), paving the way for AI-assisted response.

## 4. Part 1 vs Part 2
**Part 1 (Current State):** A fully operational deterministic DFIR pipeline. It handles log ingestion, normalization, Sigma/MITRE detection, graph construction, and dynamic visualization. 
**Part 2 (Planned State):** An integration of local LLMs (Ollama) to provide natural-language insights, automated investigation reports, and context-aware mitigation recommendations without sending data to the cloud.

## 5. Technical Architecture
The system consists of a backend data processing engine that feeds a highly interactive frontend workspace. Data flows linearly from ingestion to graph representation.

## 6. Data Flow
Raw forensic telemetry → Parser-specific extraction → Normalization (OCSF alignment) → Detection (Sigma/MITRE mapping) → Evidence correlation → Incident reconstruction → Attack-chain graph → Blast-radius assessment → Analyst investigation workspace.

## 7. Technology Stack
### Backend
- Python 3.11
- FastAPI
- Uvicorn
- SQLModel
- SQLite
- NetworkX
- pySigma
- Pydantic

### Frontend
- Next.js
- React
- TypeScript
- React Flow

### Security / DFIR Methodologies
- OCSF-aligned normalization
- Sigma-based detection
- MITRE ATT&CK mapping
- Evidence correlation
- Incident reconstruction
- Graph traversal
- Weighted graph analysis
- Dynamic blast-radius assessment

## 8. Design Methodologies
The architecture strictly isolates deterministic data processing from subjective analysis. This ensures that the foundational graph is mathematically verifiable and strictly evidence-backed before any AI or human interpretation is applied.

## 9. Detection Methodology
Detection relies on pySigma for evaluating normalized logs against industry-standard Sigma rules. This maps suspicious activity directly to MITRE ATT&CK techniques, providing a standardized vocabulary for threat behaviors.

## 10. Evidence Correlation Methodology
Correlation temporally and semantically links disjointed events. If an attacker logs in via SSH (event A) and spawns a malicious process (event B), the system identifies shared entities (e.g., source IP, user, target host) to join them into a single incident.

## 11. Attack-Chain Reconstruction Methodology
Incident reconstruction takes grouped events and builds a causal chain (DAG). It represents exactly how a threat actor moved through the environment, translating individual log lines into a continuous narrative.

## 12. Graph Analysis Methodology
Using NetworkX on the backend and React Flow on the frontend, the platform models entities as nodes and evidence as edges. This visual representation instantly highlights choke points, root causes, and primary vectors of compromise.

## 13. Blast-Radius Methodology & Limitations
Blast-radius analysis estimates potential impact by evaluating the topological proximity of high-value assets to a confirmed compromised host $h$.

### Mathematical Formula
$$BlastRadius(h) = \sum_{n \in Reachable(h)} w(n) \cdot \frac{1}{1 + d_{min}(h, n)}$$

- **$h$**: Confirmed compromised host identified from the causal incident graph.
- **$Reachable(h)$**: Assets reachable within a cutoff of 4 hops via the separate environmental trust/topology graph (SSH keys, AD group memberships, SMB shares).
- **$w(n)$**: Asset criticality weight ($1$ to $5$, where $5$ represents crown-jewel assets such as databases and SCADA historians).
- **$d_{min}(h, n)$**: Shortest-path hop distance computed via NetworkX `single_source_shortest_path_length(G, h, cutoff=4)`. The compromised host itself ($d=0$) is excluded to avoid double-counting.

### Target Canonicalization & Alias Normalization
Raw telemetry and forensic log sources often refer to infrastructure via diverse identifiers (e.g., Linux auditd logs using `target-linux-01`, syslog using `edge-fw-01`, or FQDNs). Rakshak-AI deterministically canonicalizes host identifiers against the environmental trust topology prior to graph traversal.

### Material Limitations
1. **Trust Topology vs. Attack Chain:** The blast-radius calculation uses the separate infrastructure trust topology (credentials, network trusts), not the causal attack chain. Evidence of compromise on host $A$ does not prove that an attacker has already reached host $B$.
2. **Path Multiplicity:** Path multiplicity weighting (accounting for multiple redundant trust paths between assets) is currently out of scope and documented as future work.
3. **Unmapped / Isolated Assets:** If an asset is not registered in the environmental topology or has zero outbound trust edges, Rakshak-AI returns an explicit descriptive status (`Target host is not mapped to the configured topology` or `Target exists in topology but has no evidence-backed reachable nodes`), never fabricating artificial connections.

## 14. Frontend Architecture
The Next.js frontend delivers a set of specialized DFIR workspaces. It relies heavily on local state and React Flow for complex data visualization, presenting technical information in a clean, high-contrast, dark-mode environment.

## 15. Backend Architecture
The FastAPI backend serves as the deterministic engine. It handles database transactions, executes parsing and normalization pipelines, runs the detection engine, calculates graph topologies, and exposes a RESTful API.

## 16. Data Provenance / Demo vs Live
Rakshak-AI strictly isolates data origins. "Demo" telemetry allows for safe, repeatable testing of complex scenarios (e.g., coordinated campaigns), while "Live" telemetry represents actively ingested forensic logs. The two data sources never silently contaminate each other.

## 17. Offline Replay / Link-Loss Workflow
To guarantee reliability in unstable network conditions, the frontend can queue events offline and deterministically replay them when the connection is restored, ensuring zero data loss during critical DFIR operations.

## 18. Log Ingestion
The local telemetry pipeline allows analysts to ingest raw sysmon, auditd, or other forensic logs directly via the UI. The pipeline detects duplicates, handles partial errors, and correlates new data into existing incidents in real-time.

## 19. Project Structure
- `backend/`: FastAPI application, Python dependencies, SQLModel schemas, detection engine, SQLite database.
- `components/`: React UI components, workspaces, React Flow implementations.
- `lib/`: TypeScript utilities, API clients, schema definitions.
- `app/`: Next.js routing and page layouts.

## 20. Installation Prerequisites
- Python 3.11
- Node.js
- npm
- Git

## 21. Backend Setup
```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
py -3.11 -m pip install -r requirements.txt
```

## 22. Frontend Setup
```powershell
npm install
```

## 23. start.bat Usage
You can launch the entire application seamlessly using the root-level `start.bat` convenience launcher.
```powershell
.\start.bat
```
The launcher will automatically verify prerequisites, activate the Python environment, start the backend and frontend in separate persistent windows, and open the browser once the UI is ready.

## 24. Manual Startup
If preferred, start the backend manually:
```powershell
cd backend
py -3.11 -m uvicorn app.main:app --reload --port 8000
```
And start the frontend in a new terminal:
```powershell
npm run dev
```

## 25. API / Service Overview
The RESTful backend exposes endpoints for metrics gathering, log ingestion, incident querying, offline replay synchronization, graph layout generation, and dynamic blast-radius calculation.

## 26. Testing
Backend tests ensure pipeline integrity:
```powershell
cd backend
pytest
```
Frontend validation ensures type safety and build correctness:
```powershell
npx tsc --noEmit
npm run build
```

## 27. Security / Development Considerations
This is a local-first application designed for safe forensic analysis. The SQLite database is excluded from version control to prevent exposing sensitive telemetry. Standard security practices apply: do not commit `.env` secrets or raw forensic data to the repository.

## 28. Current Part 1 Capabilities
- Full deterministic analysis pipeline
- Four tactical DFIR workspaces (Overview, Investigation, Topology, Analytics)
- Attack-chain graph visualization
- Force-directed blast-radius topology
- Local offline queuing and restoration
- Demo scenario replay and live log ingestion

## 29. Future Part 2 AI Capabilities
Part 2 will introduce an Ollama-powered local LLM to interpret the deterministic graphs. It will provide human-readable summaries, contextualize missing evidence, and suggest safe containment actions—all while preserving the strict privacy and local execution environment established in Part 1.
