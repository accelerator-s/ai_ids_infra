

# AI-IDS-Infrastructure

## Project Overview

AI-IDS-Infrastructure is a lightweight network intrusion detection system designed for HTTP plaintext traffic. The system acquires network traffic through real-time packet capture and offline PCAP analysis. It detects common Web attacks and anomalous access behaviors, and provides operational interfaces, alert displays, and visual statistics via a WebUI.

The system targets 8 common types of network attacks: SQL injection, XSS attacks, command injection, path traversal, sensitive file probing, DDoS/high-frequency access, brute force attacks, and Web scanner behavior. The rule detection module performs keyword matching and risk scoring on individual requests. Requests exceeding the alert threshold generate direct alerts, while those falling into an ambiguous range are forwarded to AI for assisted analysis. The behavior detection module uses a sliding time window to statistically analyze requests from the same source IP, generating direct alerts when thresholds are exceeded. Upon task completion, the AI also aggregates and analyzes the detection results to generate an evaluation report.

## Project Objectives

1. Support real-time traffic capture and analysis for specified IPs or domains.
2. Support reading or uploading PCAP traffic files for offline analysis.
3. Parse source IP, destination IP, port, protocol, HTTP request path, parameters, headers, User-Agent, and other information from network packets.
4. Establish a feature library for common network attacks, covering 8 categories: SQL injection, XSS, command injection, path traversal, sensitive file probing, DDoS/high-frequency access, brute force, and Web scanner behavior.
5. Detect and risk-score attack behaviors in HTTP plaintext traffic by combining rule matching and behavior statistics.
6. Integrate a large AI model to assist in analyzing requests with suspicious features but risk scores below the direct alert threshold.
7. Perform AI evaluation on the alerts and statistical results of analysis tasks, generating reports containing risk overviews, major threats, and disposal recommendations.
8. Provide a WebUI interface supporting capture task configuration, PCAP file analysis, alert viewing, AI evaluation reports, and statistical chart displays.

## Core Detection Scope

The system focuses on detecting the following 8 common types of attacks and anomalous behaviors.

| No. | Detection Type | Detection Method | Example Features |
| --- | --- | --- | --- |
| 1 | SQL Injection | HTTP content rule matching | `or 1=1`, `union select`, `sleep()` |
| 2 | XSS (Cross-Site Scripting) | HTTP content rule matching | `<script>`, `onerror=`, `javascript:` |
| 3 | Command Injection | HTTP content rule matching | `;`, `&&`, `whoami`, `cat /etc/passwd` |
| 4 | Path Traversal | URL / parameter rule matching | `../`, `..\\`, `/etc/passwd` |
| 5 | Sensitive File Probing | Request path detection | `/.env`, `/.git/config`, `/backup.zip` |
| 6 | DDoS / High-Frequency Access | Traffic behavior statistics | Large volume of requests in a short time |
| 7 | Brute Force | Login behavior statistics | Multiple login failures, frequent access to login endpoints |
| 8 | Web Scanner Behavior | User-Agent + behavior detection | `sqlmap`, `nikto`, numerous 404s |

## Operation Modes

The system is designed with two traffic analysis modes, corresponding to different usage scenarios.

### 1. Real-time Packet Capture Analysis Mode

The real-time packet capture analysis mode is used to monitor HTTP plaintext traffic for a specified target. Users can configure the monitoring network interface, target IP, or target domain in the WebUI. The system starts the capture task based on the configuration, and performs real-time parsing and detection on the captured packets.

When an IP is specified, the system directly filters traffic based on that IP; when a domain is specified, the system first resolves the domain to an IP address, then filters and analyzes traffic for the resolved IP.

Real-time capture analysis flow:

```text
User inputs IP / Domain / Network Interface
        │
        ▼
Resolve domain to IP address
        │
        ▼
Generate packet capture filter conditions
        │
        ▼
PyShark captures traffic
        │
        ▼
Parse plaintext HTTP requests
        │
        ▼
┌───────────────────┬───────────────────┐
│     Rule Detection       │     Behavior Detection      │
│  Keyword matching per    │  Statistical analysis for   │
│  single request          │  requests from same IP      │
└────────┬──────────┘└────────┬──────────┘
         │                    │
         ▼                    ▼
    Risk Score Grading     Direct alert if threshold
    ├─ 70+ Direct Alert         exceeded
    └─ 20-69 AI Assisted Analysis
         │
         ▼
Generate alerts and AI evaluation reports, displayed in WebUI
```

### 2. PCAP Offline Analysis Mode

The PCAP offline analysis mode is used to detect traffic from existing packet capture files. Users can upload PCAP files via the WebUI, and the system reads the packets in the file, parsing and detecting them in chronological order.

PCAP offline analysis flow:

```text
User uploads PCAP file
        │
        ▼
Read PCAP packets
        │
        ▼
Parse IP / TCP / HTTP information
        │
        ▼
Extract HTTP request path, parameters, headers, body, etc.
        │
        ▼
┌───────────────────┬───────────────────┐
│     Rule Detection       │     Behavior Detection      │
│  Keyword matching per    │  Statistical analysis for   │
│  single request          │  requests from same IP      │
└────────┬──────────┘└────────┬──────────┘
         │                    │
         ▼                    ▼
    Risk Score Grading     Direct alert if threshold
    ├─ 70+ Direct Alert         exceeded
    └─ 20-69 AI Assisted Analysis
         │
         ▼
Generate offline analysis results and AI evaluation report
```

## System Architecture

The system adopts a layered architecture, separating traffic acquisition, protocol parsing, attack detection, AI-assisted analysis, data storage, AI evaluation reports, and frontend display, facilitating development, testing, and future expansion.

```text
┌─────────────────────────────────────────────┐
│                  WebUI Frontend              │
│  Task Config / PCAP Upload / Alerts / AI Reports / Stats │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│               Backend API Service           │
│    Tasks / Files / Alerts / Reports / Stats APIs   │
└──────────────────────┬──────────────────────┘
                       │
          ┌────────────┴────────────┐
          ▼                         ▼
┌───────────────────┐       ┌───────────────────┐
│  Live Traffic Capture Module │  PCAP Offline Analysis Module │
│  IP / Domain filter capture  │  Read traffic capture files   │
└─────────┬─────────┘       └─────────┬─────────┘
          │                           │
          └────────────┬──────────────┘
                       ▼
┌─────────────────────────────────────────────┐
│          Packet & HTTP Parsing Module       │
│     IP / TCP / HTTP Path / Params / Headers  │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│               Detection & Analysis Module   │
│  Rule Detection / Behavior Detection / Risk Scoring / AI Assisted Analysis │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│        Data Storage & Alert Module          │
│        Alert Records / Traffic Summaries / Stats Results │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│             AI Evaluation Report Module     │
│      Result Aggregation / Risk Analysis / Disposal Recommendations │
└──────────────────────┬──────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────┐
│                 WebUI Display               │
│  Alert Details / Attack Distribution / Risk Trends / AI Reports │
└─────────────────────────────────────────────┘
```

## Functional Module Design

### 1. WebUI Operation and Visualization Module

The WebUI serves as the primary operational interface for configuring packet capture, performing PCAP analysis, viewing results, and visualizing data.

Page Structure:

```text
Overview: Module readiness, alert statistics, attack type / risk level distribution, high-frequency source IPs, recent alerts
Live Capture: Network interface selection, target IP / domain configuration, task start/stop
Offline Analysis: PCAP upload, analysis task list
Alert Center: Filter by attack type / risk level / source IP, view matched rules and detection reasons
AI Reports: Select task to generate evaluation report, view historical reports, display reasons for failed reports
System Configuration: Service port, large model integration parameters
```

### 2. Backend API Service Module

The backend API connects the frontend, capture tasks, detection modules, and database.

Key Functions:

```text
System Status Query: Reports module readiness based on self-checks, runtime dependencies, and required configurations
Runtime Config R/W: Service port, large model parameters, saved in the settings table
Large Model Integration: Model list retrieval, connectivity testing
Tasks & Alerts: Create, update, filter, and query
Statistics & Aggregation: Attack type / risk level distribution, high-frequency source IPs, recent alerts
AI Evaluation Reports: Aggregate task alerts and call the large model to generate reports
Runtime Condition Checks: Verify tshark for capture/analysis, verify large model config for AI features
```

Route definitions and request examples are uniformly maintained in [API.md](API.md) at the repository root.

### 3. Real-time Traffic Acquisition Module

This module captures network packets from a specified network interface and supports filtering by IP or domain.

Key Functions:

```text
Retrieve list of available local network interfaces
Accept user-input target IP or domain
Resolve domain to IP address
Generate BPF capture filter expression
Invoke PyShark for real-time capture
Forward captured packets to the parsing module
```

Example filter conditions:

```text
host 192.168.1.10 and tcp port 80
host 93.184.216.34 and tcp port 80
```

### 4. PCAP Offline Analysis Module

This module reads existing traffic capture files and analyzes each packet sequentially.

Key Functions:

```text
Receive user-uploaded PCAP files
Read local PCAP files
Parse packets in chronological order
Extract plaintext HTTP request information
Forward parsing results to the detection module
Generate offline analysis results and statistical reports
```

### 5. Packet and HTTP Protocol Parsing Module

This module converts raw packets into structured HTTP request data ready for system detection.

Key Parsed Fields:

```text
Source IP
Destination IP
Source Port
Destination Port
Protocol Type
Request Method
Request Path
Query Parameters
Header Information
User-Agent
Request Body Content
Response Status Code
Timestamp
```

Structured Request Example:

```json
{
  "src_ip": "192.168.1.20",
  "dst_ip": "192.168.1.10",
  "src_port": 53421,
  "dst_port": 80,
  "protocol": "HTTP",
  "method": "GET",
  "path": "/login",
  "query": "username=admin' or '1'='1",
  "headers": {
    "User-Agent": "Mozilla/5.0"
  },
  "body": "",
  "status": 200,
  "timestamp": "2026-07-08 10:00:00"
}
```

### 6. Rule Feature Library Module

The rule feature library stores detection rules for different attack types, facilitating future maintenance and expansion.

Rule Example:

```json
{
  "id": "sqli-001",
  "attack_type": "SQL Injection",
  "level": "high",
  "score": 70,
  "target_fields": ["query", "body"],
  "patterns": [
    "sleep\\s*\\(",
    "extractvalue\\s*\\(",
    "information_schema"
  ],
  "description": "SQL injection-specific functions/keywords that do not appear in normal traffic"
}
```

### 7. Rule Detection Module

The rule detection module matches parsed HTTP request content against the rule library.

Key Functions:

```text
Load JSON rule library
Match rules against request paths, parameters, headers, and body
Detect content-based attacks: SQL injection, XSS, command injection, path traversal
Detect sensitive file probing and scanner User-Agents
Output matched rules, attack type, risk level, and detection reason
```

### 8. Behavior Detection Module

The behavior detection module identifies anomalies that are not obvious in individual packets but are recognizable through access behavior patterns.

Key Functions:

```text
Count requests from the same IP within a time window
Detect DDoS / high-frequency access behavior
Count accesses and failures on login endpoints
Detect brute force behavior
Count distinct paths accessed by the same IP
Detect Web scanner batch probing behavior
Count accesses to sensitive paths
Count 404 response quantities
```

Example Rules:

```text
Same IP makes over 100 requests within 60 seconds → flag as suspected high-frequency access.
Same IP has over 10 login failures within 5 minutes → flag as suspected brute force.
Same IP accesses over 30 distinct paths within 1 minute → flag as suspected scanning behavior.
```

### 9. Risk Scoring Module

The risk scoring module only processes rule detection results, aggregating scores from multiple matched rules into a final risk score and level. Behavior detection bypasses this module and directly generates alerts upon exceeding thresholds.

Scoring Formula:

```text
Final Score = max(Individual Rule Scores) + sum(Other Matched Rule Scores × 0.2)
```

Risk Level Design:

| Level | Score Range | Handling Method |
| --- | --- | --- |
| normal | 0 - 19 | No obvious anomaly, no action taken |
| low | 20 - 39 | Minor anomaly, forwarded to AI for assisted analysis |
| medium | 40 - 69 | Suspected attack, forwarded to AI for assisted analysis |
| high | 70 - 89 | Clear attack signature, direct alert generated |
| critical | 90 and above | Severe attack signature, direct high-risk alert generated |

Rule Scoring Principles:

```text
Features impossible in normal traffic (e.g., sleep(), extractvalue(), <script>): 70 points, single match triggers alert
Rare features in normal traffic (e.g., union, drop, chmod): 30-35 points
Features possibly present in normal traffic (e.g., single quotes, comment symbols, event handlers): 25 points
Common English words (e.g., select, or, and): 10-15 points, used only for auxiliary weighting
```

### 10. AI Assisted Analysis Module

The AI assisted analysis module performs secondary analysis only on ambiguous requests generated by rule detection. When the rule detection risk score falls between 20 and 69, the system forwards the HTTP request content, matched rules, and risk score to the AI, which provides an assisted analysis result based on request context. Behavior detection alerts are determined by statistical thresholds and do not undergo AI assisted analysis.

Rule Detection Assisted Analysis Flow:

```text
Rule Detection → Risk Scoring
        │
        ├── Score ≥ 70: Direct alert generation
        │
        ├── Score 20 - 69: Forwarded to AI assisted analysis
        │                     │
        │                     ├── Judged as attack: Generate alert
        │                     └── Judged as normal: Retain analysis record
        │
        └── Score < 20: AI analysis not triggered
```

AI Output Example:

```json
{
  "ai_judgement": "malicious",
  "attack_type": "SQL Injection",
  "confidence": 0.87,
  "reason": "The conditional expression in the request parameters combined with abnormal comment symbols clearly indicates SQL injection intent"
}
```

If the AI call times out, returns malformed data, or fails to complete the analysis, the system retains the original risk score and rule match results, marks the request for manual review, and should not default to treating it as a normal request.

### 11. AI Evaluation Report Module

The AI evaluation report module performs aggregate analysis on completed detection tasks. The system compiles task summaries, attack type distributions, risk level distributions, high-frequency source IPs, and typical alerts as AI input, from which the AI generates a risk overview, major threats, and disposal recommendations.

The evaluation report and single-request assisted analysis are independent. The report module only reads saved detection and analysis results without modifying risk scores or alert statuses. If the AI report call fails, existing detection results and alert data remain unchanged, and the reason for the report generation failure is logged.

Report Generation Flow:

```text
Complete live capture or PCAP analysis task
        │
        ▼
Aggregate task info, statistical results, and typical alerts
        │
        ▼
Assemble AI input according to Prompt template
        │
        ▼
AI generates structured evaluation report
        │
        ▼
Save report and display in WebUI
```

Report Content:

```text
Task basic info and traffic overview
Total alerts and risk level distribution
Major attack types and high-frequency source IPs
Typical alerts and their matched rules
Overall risk overview
Threats requiring priority attention
Disposal and protection recommendations
```

AI Output Example:

```json
{
  "summary": "This task analyzed 86 HTTP requests and generated 12 alerts.",
  "risk_assessment": "Alerts are primarily SQL injection and sensitive file probing, with an overall risk level of high.",
  "key_findings": [
    "192.168.1.20 accessed sensitive paths multiple times in a short period",
    "Multiple SQL injection rule matches occurred on the login endpoint"
  ],
  "recommendations": [
    "Verify access logs for high-frequency source IPs",
    "Implement parameterized queries and rate limiting for the login endpoint"
  ]
}
```

### 12. Data Storage and Alert Module

This module stores alerts, traffic summaries, AI assisted analysis records, statistical results, and AI evaluation reports generated during the detection process.

Recommended Alert Fields:

```text
Alert ID
Source IP
Destination IP
Source Port
Destination Port
Request Method
Request Path
Attack Type
Risk Level
Risk Score
Matched Rules
AI Assisted Analysis Flag
AI Analysis Result
AI Analysis Reason
Detection Reason
Timestamp
Processing Status
```

## Tech Stack

| Module | Implementation |
| --- | --- |
| Backend Service | Python FastAPI + Uvicorn |
| Packet Capture & Traffic Parsing | PyShark + tshark |
| Rule Detection | Python Regular Expressions + JSON Rule Library |
| Behavior Statistics | Python Time Window Statistics |
| Data Storage | SQLite + SQLAlchemy |
| Runtime Configuration | WebUI Config Panel + settings table |
| AI Assisted Analysis & Evaluation Reports | OpenAI-compatible Large Model API + JSON Structured Output |
| Frontend | Native HTML + CSS + JavaScript |
| Visualization Charts | Custom CSS / SVG Charts |
| Test Traffic | HTTP plaintext PCAP samples |

## Project Structure

`/api/status` reports module readiness based on actual self-checks, runtime dependencies, and required configurations.

```text
ai_ids_infra/
├── README.md
├── API.md                          # Backend route definitions and runtime conditions
├── requirements.txt
├── app/
│   ├── main.py                     # Service entry: python -m app.main
│   ├── config.py                   # Paths, risk thresholds, and default config values
│   ├── api/
│   │   └── routes.py               # All API routes
│   ├── services/
│   │   └── llm.py                  # OpenAI-compatible API client
│   ├── capture/
│   │   ├── live_capture.py         # Real-time packet capture
│   │   └── pcap_analyzer.py        # PCAP offline analysis
│   ├── protocol/
│   │   └── packet_parser.py        # Protocol parsing
│   ├── detection/
│   │   ├── rule_engine.py          # Rule detection
│   │   ├── risk_score.py           # Risk scoring
│   │   └── behavior_detector.py    # Behavior detection
│   ├── ai/
│   │   ├── request_analyzer.py     # AI assisted analysis
│   │   └── report_generator.py     # AI evaluation report
│   └── database/
│       ├── db.py                   # Engine and session
│       ├── models.py               # tasks / alerts / settings tables
│       └── crud.py                 # CRUD operations and statistics
├── data/
│   └── ids.db                      # SQLite database (auto-created on first startup)
├── rules/                          # JSON rule libraries for six attack categories
│   ├── sql_injection_rules.json
│   ├── xss_rules.json
│   ├── command_injection_rules.json
│   ├── path_traversal_rules.json
│   ├── sensitive_path_rules.json
│   └── scanner_rules.json
├── frontend/                       # WebUI, statically served by the backend
│   ├── index.html
│   ├── app.js                      # Component mounting, routing, and health polling
│   ├── core/                       # Themes, API wrappers, event bus, icons
│   ├── components/                 # One component directory per page (html + js + css)
│   │   ├── rail/  topbar/  state-card/
│   │   ├── overview/  capture/  pcap/
│   │   └── alerts/  reports/  config/
│   └── resources/icons/            # Inline SVG icons
└── docs/
    ├── images
        ├── 攻击检测模块功能逻辑图.png
        ├── 结果展示模块功能逻辑图.png
        ├── 流量采集模块功能逻辑图.png
        ├── 系统总体功能逻辑图.png
        ├── 协议解析模块功能逻辑图.png
        └── AI分析模块功能逻辑图.png
    ├── 总体设计报告模板.docx
    ├── 结题报告模板.doc
    └── 选题表.doc
```

## API Interface Design

Interface definitions, request/response examples, and runtime conditions are uniformly maintained in [API.md](API.md).
Route implementations are in `app/api/routes.py`, kept in sync with the documentation.

## WebUI Pages

The WebUI implements six pages, switchable via the left navigation bar, with light/dark theme support.

### 1. Overview

```text
Module readiness donut chart and readiness status of 9 modules
Total alerts, analysis task count, high/critical alert count, loaded rule count
Attack type distribution, risk level distribution, high-frequency source IPs
Recent alerts list, with links to the Alert Center
```

### 2. Live Capture

```text
Select monitoring network interface
Enter target IP or domain
Select port, default HTTP 80
Start/Stop capture tasks
Explicitly display "Missing Runtime Dependency" if tshark is unavailable
```

### 3. Offline Analysis

```text
Upload PCAP file and start analysis
View analysis task list and progress
Display total packet count, HTTP request count, and alert count
```

### 4. Alert Center

```text
Filter by attack type, risk level, source IP, with pagination
View single alert details
View matched rules, detection reasons, and AI assisted analysis results
```

### 5. AI Evaluation Reports

```text
Select an analysis task to synchronously generate an evaluation report
View report task overview, risk assessment, key findings, and disposal recommendations
View historical reports; failed reports display the failure reason
```

### 6. System Configuration

```text
Service port configuration (saved to DB, takes effect after service restart)
Large model service URL, access key, model selection, and generation temperature/randomness
Fetch model list, test connectivity, then save
```

## Database Design

SQLite is used to store tasks, alerts, runtime configurations, and evaluation reports. Tables are automatically created on first startup.
The `alerts`, `tasks`, `settings`, `reports`, and `ai_reviews` tables are all created.

### alerts Table

| Field | Description |
| --- | --- |
| id | Alert ID |
| task_id | Associated analysis task ID |
| src_ip | Source IP |
| dst_ip | Destination IP |
| src_port | Source Port |
| dst_port | Destination Port |
| method | HTTP Method |
| path | Request Path |
| query | Request Parameters |
| attack_type | Attack Type |
| risk_level | Risk Level |
| score | Risk Score |
| matched_rules | Matched Rules |
| ai_judgement | AI Assisted Analysis Result |
| ai_confidence | AI Analysis Confidence |
| ai_reason | AI Analysis Reason |
| created_at | Alert Timestamp |

### tasks Table

| Field | Description |
| --- | --- |
| id | Task ID |
| task_type | Task type, live capture or PCAP analysis |
| target | Target IP, domain, or PCAP filename |
| status | Task status |
| packet_count | Packet count |
| http_count | HTTP request count |
| alert_count | Alert count |
| created_at | Creation time |
| finished_at | Completion time |

### settings Table

| Field | Description |
| --- | --- |
| key | Configuration key, e.g., `server.port`, `llm.base_url` |
| value | JSON-encoded configuration value |

### ai_reviews Table

| Field | Description |
| --- | --- |
| id | Analysis record ID |
| task_id | Associated analysis task ID |
| alert_id | Associated alert ID, empty if no alert generated |
| request_summary | Summary of the request to be analyzed |
| original_score | Original risk score from rule and behavior detection |
| matched_rules | Matched rules |
| judgement | AI analysis result |
| attack_type | AI-identified attack type |
| confidence | AI analysis confidence |
| reason | AI analysis reason |
| status | Analysis or manual review status |
| created_at | Creation time |

### reports Table

| Field | Description |
| --- | --- |
| id | Report ID |
| task_id | Associated analysis task ID |
| status | Report generation status |
| model | Model name |
| prompt_version | Prompt version |
| summary | Task overview |
| risk_assessment | Overall risk assessment |
| key_findings | Key findings |
| recommendations | Disposal recommendations |
| error_message | Report generation failure reason |
| created_at | Creation time |

## System Environment Dependencies

1. Python 3.10 or above, dependencies listed in `requirements.txt`.
2. Real-time capture and PCAP offline analysis are implemented and invoke `tshark` via PyShark.
   Wireshark / `tshark` must be installed before using these features, and the `tshark` command must be accessible:

```bash
tshark -v
```

## System Execution

```bash
# Install dependencies
pip install -r requirements.txt

# Start service (default 127.0.0.1, port read from DB config, initial 8000)
python -m app.main

# Or temporarily specify listen address and port
python -m app.main --host 0.0.0.0 --port 8080
```

After startup, open a browser and visit `http://127.0.0.1:8000` to access the WebUI.

All runtime configurations (service port, large model integration parameters) are modified in the "System Configuration" page of the WebUI, saved in the SQLite `settings` table. The project does not use `.env` or other configuration files. Port changes require restarting the service process to take effect.
