# DNS Tunneling Detection and Data Exfiltration Monitoring System

## Project Description

A rule-based DNS tunneling detection system that analyzes PCAP/PCAPNG files to extract DNS traffic and identify potential data exfiltration attempts. This system uses explainable rule-based analysis - **no machine learning** is used.

## Problem Statement

DNS tunneling is a technique used by attackers to encode data from compromised systems into DNS queries and responses, bypassing traditional security controls. Since DNS is typically allowed through firewalls, it provides a covert channel for data exfiltration and command-and-control communication.

## Solution

This system provides:
- Real PCAP/PCAPNG file ingestion and DNS packet extraction
- Local SQLite storage for DNS queries and analysis sessions
- REST API for frontend communication
- Cybersecurity-focused dashboard for analysis
- Rule-based detection engine with explainable risk scoring

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Frontend      │     │    Backend      │     │   Database      │
│   (React)       │────▶│   (FastAPI)     │────▶│   (SQLite)      │
│                 │     │                 │     │                 │
│ • Dashboard     │     │ • PCAP Upload   │     │ • Sessions      │
│ • Upload Page   │     │ • DNS Parser    │     │ • DNS Queries   │
│ • Analysis View │     │ • Feature Extr. │     │ • Detection Res.│
│ • Detection UI  │     │ • Rule Engine   │     │ • Indicators    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Technology Stack

### Backend
- **Python 3.11+**
- **FastAPI** - Modern, fast web framework
- **Scapy** - Packet manipulation library for PCAP parsing
- **SQLAlchemy** - ORM for database access
- **Pydantic** - Data validation and serialization
- **SQLite** - Local database (easily replaceable with PostgreSQL)

### Frontend
- **React 18** - UI library
- **Vite** - Fast build tool
- **Tailwind CSS** - Utility-first CSS framework
- **Recharts** - Charting library
- **Axios** - HTTP client
- **Lucide React** - Icon library

## Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- npm or yarn

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
```

### Database Setup

The database is automatically initialized on first run. SQLite file will be created at `data/dns_tunneling.db`.

## Running the Application

### Start Backend

```bash
cd backend
source venv/bin/activate  # On Windows: venv\Scripts\activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Backend will be available at `http://localhost:8000`
API documentation at `http://localhost:8000/docs`

### Start Frontend

```bash
cd frontend
npm run dev
```

Frontend will be available at `http://localhost:5173`

## How to Capture Real DNS Traffic

To test the system with real data:

1. **Open Wireshark** on your machine or authorized lab network
2. **Select your network interface** (Wi-Fi, Ethernet, etc.)
3. **Start capture** with display filter: `dns`
4. **Generate normal DNS traffic** by:
   - Visiting legitimate websites
   - Running `nslookup example.com`
   - Running `dig google.com`
   - Using `ping` commands
5. **Stop the capture** after generating traffic
6. **Save the capture** as `.pcapng` (File → Save As → PCAPNG)
7. **Upload the file** to this application via the Upload page

**Important**: Only capture traffic on networks you own or have explicit authorization to monitor.

## How to Upload a PCAP

1. Navigate to **Upload PCAP** page in the frontend
2. Drag and drop a `.pcap` or `.pcapng` file, or click to browse
3. Click **Upload & Analyze**
4. Wait for processing to complete
5. View results on the **Analysis** page
6. Click **Run Detection** to score the extracted queries with the rule-based engine
7. Expand each activity group to inspect matched indicators, observed values, and explanations

## API Documentation

### Health Check
```
GET /api/health
```

### Upload PCAP
```
POST /api/pcap/upload
Content-Type: multipart/form-data
Body: file (pcap/pcapng)

Response:
{
  "session_id": "uuid",
  "filename": "stored_filename.pcap",
  "original_filename": "original.pcap",
  "total_packets": 100,
  "dns_packets": 50,
  "queries_extracted": 50,
  "processing_status": "completed",
  "processing_duration_ms": 1500
}
```

### List Sessions
```
GET /api/sessions?skip=0&limit=100
```

### Get Session Details
```
GET /api/sessions/{session_id}
```

### Get DNS Queries
```
GET /api/dns/queries?session_id=1&skip=0&limit=100
```

### Run Detection
Runs the rule-based detection engine over the DNS queries stored for a completed session and persists the results.
```
POST /api/analysis/{session_uuid}/detect

Response:
{
  "success": true,
  "message": "Detection completed. Found 1 activity group(s).",
  "results_count": 1,
  "results": [
    {
      "id": 1,
      "session_id": 1,
      "source_ip": "192.168.1.100",
      "base_domain": "example.com",
      "detection_status": "HIGH_RISK",
      "total_queries": 60,
      "unique_subdomains": 61,
      "avg_label_length": 32.4,
      "max_label_length": 56,
      "avg_entropy": 4.12,
      "max_entropy": 4.75,
      "encoding_detected": true,
      "encoding_types": ["base32"],
      "queries_per_minute": 1220.3,
      "txt_query_count": 11,
      "null_query_count": 0,
      "nxdomain_count": 0,
      "nxdomain_ratio": 0.0,
      "burst_detected": true,
      "matched_rules_count": 7,
      "risk_score": 89.7,
      "indicators": [
        {
          "rule_id": "DNS-001",
          "indicator_name": "Long Subdomain",
          "matched": true,
          "severity": "medium",
          "weight": 15.0,
          "threshold": 50.0,
          "observed_value": 56.0,
          "explanation": "..."
        }
      ]
    }
  ]
}
```

### Get Detection Results
Returns previously stored detection results for a session (does not re-run detection).
```
GET /api/analysis/{session_uuid}/detection

Response:
{
  "results": [ ... same structure as above ... ],
  "total": 1
}
```

## Current Implementation Status

### ✅ Completed (Module 1 - Foundation)
- [x] Project structure and configuration
- [x] FastAPI backend with CORS
- [x] SQLite database with SQLAlchemy models
- [x] PCAP/PCAPNG upload endpoint
- [x] Scapy-based DNS packet parsing
- [x] DNS query extraction (timestamp, IPs, query name, type, response code, etc.)
- [x] Database persistence for sessions and DNS queries
- [x] React frontend with Tailwind CSS
- [x] Dashboard with empty state handling
- [x] Upload page with drag-and-drop
- [x] Analysis page with query table and pagination
- [x] Health check endpoint
- [x] Comprehensive test suite
- [x] Error handling for invalid/corrupted files

### ✅ Completed (Module 2 - Detection Engine)
- [x] Feature extraction:
  - [x] Subdomain length analysis
  - [x] Shannon entropy calculation
  - [x] Encoding detection (Base64, Base32, Hex)
  - [x] Query frequency analysis (queries/minute)
  - [x] Unique subdomain counting
  - [x] DNS record type analysis (TXT/NULL)
  - [x] NXDOMAIN ratio calculation
  - [x] Burst behavior detection
- [x] Rule engine with 8 configurable rules (DNS-001 ... DNS-008)
- [x] Risk scoring (0-100) with detection status (NORMAL / SUSPICIOUS / HIGH_RISK)
- [x] Persistence of detection results and per-rule indicators
- [x] Detection API endpoints (`POST /detect`, `GET /detection`)
- [x] Frontend detection analysis UI (run detection, risk score, indicators)
- [x] Comprehensive detection engine test suite (feature extraction, rules, scoring, service, API)

### 📋 Future Modules
- [ ] Live DNS traffic capture
- [ ] Zeek/Bro log ingestion
- [ ] MITRE ATT&CK mapping
- [ ] Threat intelligence integration
- [ ] Export capabilities (JSON, CSV, STIX)
- [ ] Multi-user support with authentication

## Testing

### Backend Tests
```bash
cd backend
source venv/bin/activate
pytest tests/ -v
```

### Test Coverage
- DNS packet parsing (queries, responses, various types)
- PCAP file processing (valid, empty, no DNS, corrupted)
- API endpoints (upload, sessions, queries, detection, health)
- Database operations (CRUD, pagination)
- Detection engine:
  - Feature extraction (entropy, encoding, burst, grouping, metrics)
  - All 8 rules (matched and non-matched paths)
  - Risk scoring and detection status thresholds
  - Detection service persistence and retrieval
  - Detection API endpoints (run, retrieve, error cases)
- Error handling

## Detection Engine

The detection engine is **purely rule-based and explainable** - no machine learning. It groups
DNS queries by `(source_ip, base_domain)` and evaluates the following indicators for each group:

| Rule | Indicator | Threshold | Severity | Weight |
|------|-----------|-----------|----------|--------|
| DNS-001 | Long Subdomain | max label length > 50 | medium | 15 |
| DNS-002 | High Entropy | max entropy > 4.5 | high | 25 |
| DNS-003 | Encoding Pattern Detected | Hex/Base32/Base64 | high | 30 |
| DNS-004 | High Query Frequency | queries/min > 100 | medium | 20 |
| DNS-005 | Excessive Unique Subdomains | unique subdomains > 50 | medium | 15 |
| DNS-006 | Unusual DNS Record Types | TXT+NULL queries > 10 | low | 10 |
| DNS-007 | High NXDOMAIN Ratio | ratio > 0.60 | medium | 15 |
| DNS-008 | DNS Burst Behavior | >= 20 queries in 10s | medium | 15 |

### Risk Scoring

- Risk score = (sum of matched rule weights / sum of all rule weights) × 100
- **HIGH_RISK**: score >= 70
- **SUSPICIOUS**: score >= 30 and < 70
- **NORMAL**: score < 30

Thresholds are configurable in `backend/app/dns/feature_extractor.py`
(`ExtractionConfig`). Each matched indicator stores its rule ID, observed value, threshold,
severity, weight, and a human-readable explanation for transparency.

## Configuration

Environment variables (`.env` file in backend directory):
```
DEBUG=true
DATABASE_URL=sqlite:///./data/dns_tunneling.db
SECRET_KEY=your-secret-key-here
MAX_UPLOAD_SIZE=104857600
```

## Security Considerations

- File type validation (only .pcap/.pcapng)
- File size limits (default 100MB)
- Secure filename generation (UUID-based)
- Path traversal prevention
- No execution of uploaded files
- CORS configured for local development
- No hardcoded secrets

## License

This project is for educational and authorized security testing purposes only.

## Disclaimer

**This application does not use Machine Learning. DNS tunneling detection will be performed using explainable rule-based analysis.**

Only use this tool on networks you own or have explicit written authorization to monitor. Unauthorized network monitoring may violate laws and regulations.