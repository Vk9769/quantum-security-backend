# 🛡️ QuantumSentinel

### AI-Powered Quantum-Safe Attack Surface Management Platform

🚀 **PNB Cybersecurity Hackathon 2026 Submission**
👨‍💻 Team: **TCODE**
🏫 Institute: **IIT Bombay**

---

## 📌 Overview

**QuantumSentinel** is a next-generation cybersecurity platform designed to **secure enterprise systems against future quantum computing threats**.

It provides a centralized solution for:

* 🔍 Attack Surface Discovery
* 🔐 Cryptographic Analysis
* ⚛️ Quantum Risk Detection
* 📊 AI-Based Risk Scoring
* 📑 CBOM (Cryptographic Bill of Materials)

💡 The platform ensures organizations are not just secure today—but **quantum-ready for tomorrow**.

---

## 🚨 Problem Statement

### ❓ Why this problem exists:

* Rapid digitalization exposes **APIs, domains, VPNs**
* Traditional crypto (**RSA, ECC**) vulnerable to quantum attacks
* Rising **Harvest Now, Decrypt Later (HNDL)** threat
* No centralized **cryptographic visibility (CBOM)**

### 👥 Who is affected:

* Banks (PNB, financial systems)
* Cybersecurity teams
* Compliance auditors (CERT-In, NIST)
* End users (data privacy risk)

### ⚠️ Consequences:

* Data breaches & financial fraud
* Regulatory non-compliance
* Long-term quantum decryption risk
* No visibility → delayed response

---

## 💡 Proposed Solution

QuantumSentinel provides an **end-to-end intelligent security platform**:

### 🔹 Core Capabilities

* 🌐 Complete Attack Surface Visibility
* 📊 Cryptographic Inventory (CBOM)
* ⚛️ Quantum Readiness Assessment
* 🤖 AI Risk Intelligence
* 📈 Real-Time Dashboard & Alerts

---

## 🧠 Key Innovations

🔥 What makes QuantumSentinel unique:

1. **Quantum + Attack Surface Integration**
2. **Advanced API Discovery (Hidden endpoints)**
3. **CERT-In aligned CBOM generation**
4. **AI-driven risk prioritization**
5. **Quantum vulnerability detection (future-ready)**
6. **Digital Trust Labels (Quantum Safe / PQC Ready / Risk)**

---

## ⚙️ System Workflow

```
User Login
   ↓
Enter Domain
   ↓
Asset Discovery (Subdomains, APIs, Ports)
   ↓
TLS & Certificate Scanning
   ↓
Cryptographic Analysis
   ↓
CBOM Generation
   ↓
Quantum Risk Analysis
   ↓
AI Risk Scoring
   ↓
Dashboard + Alerts + Reports
```
<img width="558" height="554" alt="image" src="https://github.com/user-attachments/assets/046112a8-ede1-404a-8ef4-d19856e7ae8d" />

---

## 🏗️ Enterprise Architecture
<img width="442" height="593" alt="image" src="https://github.com/user-attachments/assets/65a80be8-ad2b-4966-b0c4-418c51811308" />

### 🔹 Layered Architecture

1. **Presentation Layer**

   * Dashboard UI
   * Visualization & reporting

2. **Application Layer**

   * FastAPI backend
   * Authentication & APIs

3. **Security Scanning Layer**

   * Subdomain discovery
   * Port scanning
   * TLS analysis

4. **AI Risk Layer**

   * Quantum vulnerability detection
   * Risk scoring engine

5. **Data Layer**

   * PostgreSQL → core data
   * Neo4j → relationships
   * Redis → caching

6. **Integration Layer**

   * REST APIs
   * External system integration

7. **Security Layer**

   * RBAC
   * JWT authentication
   * TLS encryption

---

## 🔍 Core Features

### 1️⃣ Asset & API Discovery

* Subdomains, APIs, endpoints
* Hidden services detection
* Full attack surface mapping

---

### 2️⃣ Cryptographic Analysis

* TLS versions & cipher suites
* Certificate validation
* Weak crypto detection

---

### 3️⃣ Quantum Risk Detection ⚛️

* Identifies vulnerable algorithms
* Evaluates PQC readiness
* Classifies assets:

  * ✅ Quantum Safe
  * ⚠️ PQC Ready
  * ❌ Not Safe

---

### 4️⃣ CBOM Generation 📑

* Structured cryptographic inventory
* CERT-In compliant
* Includes:

  * Algorithms
  * Keys
  * Protocols
  * Certificates

---

### 5️⃣ AI Risk Scoring 🤖

* Risk levels: High / Medium / Low
* Anomaly detection
* Real-time updates

---

### 6️⃣ AI Attack Simulation (Advanced)

* Simulates real-world attacks
* Finds hidden vulnerabilities
* Suggests remediation

---

### 7️⃣ Dashboard & Reporting 📊

* Real-time visualization
* Alerts & notifications
* Export reports (JSON, CSV)

---

## 🗄️ Tech Stack

### 🔧 Backend

* Python
* FastAPI

### 🎨 Frontend

* React.js

### 🔍 Scanning Tools

* Nmap, Masscan
* Subfinder, Amass
* Katana, LinkFinder
* Nuclei
* OpenSSL, ZGrab

### 🤖 AI/ML

* LLaMA, Mistral, DeepSeek
* Python ML libraries

### 🗃️ Databases

* PostgreSQL
* Neo4j
* Redis
* Elasticsearch
* ClickHouse

### ⚙️ DevOps

* Docker
* Kafka
* GitHub

---

## 📁 Backend Structure
```
app/
│
├── main.py                 # Entry point
├── config.py               # App configuration
├── dependencies.py         # Dependency injection
│
├── api/                    # API Routes (FastAPI)
│   └── v1/                 # Versioned APIs
│
├── core/                   # Auth, permissions, rate limiting
│
├── db/                     # Database connections
│   ├── postgres.py
│   ├── neo4j.py
│   ├── redis.py
│   ├── clickhouse.py
│   └── elasticsearch.py
│
├── models/                 # Database models (ORM)
├── schemas/                # Pydantic schemas
│
├── services/               # Business logic layer
│
├── scanners/               # Security scanning modules
│   ├── TLS, DNS, Port, API, Vulnerability
│
├── ai/                     # AI & Quantum Intelligence
│   ├── agents/             # AI agents (attack, crypto, pqc)
│   ├── models/             # ML models
│   ├── reasoning/          # Attack graph & recommendations
│   ├── simulators/         # Quantum attack simulations
│   └── llm/                # LLM routing & prompts
│
├── workers/                # Background workers (Kafka आधारित)
│
├── utils/                  # Helper utilities
│
└── logs/                   # Runtime logs (if enabled)
```

## 🔐 Security Features

* 🔒 TLS Encryption (HTTPS)
* 🔑 JWT Authentication
* 👥 Role-Based Access Control (RBAC)
* 📜 Audit Logging
* 🛡️ Secure API communication

---

## ⚡ Performance & Scalability

* Kafka-based async processing
* Distributed scanning
* Redis caching
* Parallel asset scanning

---

## 📊 Impact & Benefits

### 🎯 Cybersecurity Impact

* Early detection of weak crypto
* Quantum readiness preparation
* Reduced attack surface risk

### 💼 Business Benefits

* Cost reduction via automation
* Faster risk response
* Compliance support (CERT-In, NIST)

---

## 🧪 Feasibility

### ✔️ Technical

* Built using proven technologies
* No special hardware required

### ✔️ Operational

* Easy-to-use dashboard
* API integration support

### ✔️ Economic

* Uses open-source tools
* Scalable cloud deployment

---

## 📈 Scalability

* Microservices architecture
* Kafka for high throughput
* Supports enterprise-scale assets
* Future PQC integration ready

---

## ⚠️ Challenges & Mitigation

| Challenge                | Solution                 |
| ------------------------ | ------------------------ |
| Cryptographic complexity | Updated PQC standards    |
| Large-scale scanning     | Distributed architecture |
| Performance issues       | Kafka + Redis            |
| Integration              | REST APIs                |
| Security risks           | RBAC + TLS               |

---

---

## 🚀 Future Scope

QuantumSentinel is designed to evolve into a **comprehensive next-generation cybersecurity platform**. The following enhancements are planned:

### 🔍 Advanced API Discovery
- Deep API endpoint discovery using:
  - Katana
  - Kiterunner
  - httpx
  - Amass
- Detection of hidden, undocumented, and shadow APIs
- Full API attack surface mapping

---

### 🌐 IoT & Device Security Analysis
- Extend scanning to **IoT and smart devices**
- Identify weak cryptographic implementations in embedded systems
- Evaluate whether IoT devices are **PQC-ready or vulnerable**

---

### ⚛️ Enhanced PQC Readiness Engine
- Advanced classification of cryptographic algorithms
- Real-time PQC compliance monitoring
- Automated suggestions for migration to **Post-Quantum Cryptography**

---

### 🛡️ Advanced Vulnerability Detection
- Integration with modern tools:
  - Nuclei (template-based scanning)
  - Katana (crawler)
  - Kiterunner (API fuzzing)
  - httpx (HTTP probing)
- Automated detection of:
  - Misconfigurations
  - Exposed services
  - Weak TLS setups

---

### 🤖 AI Chatbot & Virtual Assistant
- AI-powered security assistant for:
  - Querying scan results
  - Explaining vulnerabilities
  - Providing remediation steps
- Natural language interface for analysts:
  > "Show high-risk assets"  
  > "Which systems are not PQC ready?"

---

### ☁️ Platform as a Service (PaaS)
- Offer QuantumSentinel as a **cloud-based API service**
- External integration via:
  - REST APIs
  - Webhooks
- Enable enterprises to integrate into their **SIEM / SOC pipelines**

---

### 🖥️ CLI Mode (Developer Friendly)
- Lightweight CLI tool for:
  - Running scans directly from terminal
  - Generating CBOM reports
  - Automating security workflows
- Example:
```bash
qs scan example.com
qs report --cbom
```

🔗 SIEM & Enterprise Integration
Integration with tools like:
Splunk
ELK Stack
Microsoft Sentinel
Real-time alert forwarding and monitoring
📊 Predictive Risk Intelligence
AI models to predict future vulnerabilities
Trend analysis on cryptographic posture
Risk forecasting for proactive security

💡 Vision:

Transform QuantumSentinel into a fully autonomous, AI-driven, quantum-aware cybersecurity platform capable of securing both current and future digital infrastructures.

# ⚙️ Installation & Setup Guide

Follow these steps to run **QuantumSentinel** locally.

---

## 📦 1. Clone Repositories

### Backend

```bash
git clone https://github.com/Vk9769/quantum-security-backend.git
cd quantum-security-backend
```

### Frontend

```bash
git clone https://github.com/Vk9769/quantum-sentinel.git
cd quantum-sentinel
```

---

## 🐍 2. Create Python Virtual Environment (Python 3.11)

```bash
python3.11 -m venv venv
```

### Activate:

**Windows**

```bash
venv\Scripts\activate
```

**Linux/Mac**

```bash
source venv/bin/activate
```

---

## 📥 3. Install Dependencies

```bash
pip install -r requirements-core.txt
pip install -r requirements-ai.txt
```

---

## 🤖 4. Setup AI Models (Ollama)

### Install Ollama

👉 https://ollama.com/download

### Pull Models

```bash
ollama pull deepseek
ollama pull mistral
ollama pull llama3
```

---

## ⚙️ 5. Environment Configuration

Create a `.env` file in the backend root:

```env
# PostgreSQL
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=security_db
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=

# Kafka
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password

# ClickHouse
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123

# Elasticsearch
ELASTIC_HOST=http://localhost:9200

# APIs (⚠️ Replace with your own keys)
CENSYS_API_TOKEN=your_censys_token
SHODAN_API_KEY=your_shodan_key
IPINFO_TOKEN=your_ipinfo_token
VT_API_KEY=your_virustotal_key

# Email
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
```

⚠️ **Security Note:**

* Never push `.env` to GitHub
* Add `.env` to `.gitignore`

---

## 🐳 6. Start Services using Docker

You already have a `docker-compose.yml`, so run:

```bash
docker-compose up --build
```

This will start:

* PostgreSQL
* Redis
* Kafka
* Neo4j
* ClickHouse
* Elasticsearch

---

## 🚀 7. Run Backend

```bash
uvicorn app.main:app --reload
```

Backend will run at:
👉 http://127.0.0.1:8000

---

## 🎨 8. Run Frontend

```bash
cd quantum-sentinel
npm install
npm run dev
```

Frontend will run at:
👉 http://localhost:8080

---

## 🧪 9. Verify Setup

* Open Dashboard → http://localhost:8080
* Trigger scan on any domain
* Check:

  * TLS scan results
  * CBOM data
  * Risk score

---

## ⚠️ Common Issues & Fixes

### ❌ Ollama not working

```bash
ollama serve
```

### ❌ Kafka not connecting

* Ensure Docker containers are running
* Check `localhost:9092`

### ❌ DB connection error

* Verify `.env` credentials
* Ensure PostgreSQL container is running

---

## ✅ Final Setup Summary

| Component          | Status |
| ------------------ | ------ |
| Backend (FastAPI)  | ✅      |
| Frontend (React)   | ✅      |
| AI Models (Ollama) | ✅      |
| Databases          | ✅      |
| Docker Services    | ✅      |

---


## 🎥 Demo video 

https://drive.google.com/file/d/1fKSD-W6L6430D0kLLTZ6fVG9dz57pcFp/view?usp=sharing

---

## 👥 Team

* **Vaibhav Kothare** – Team Lead & Backend
* **Rishabh Kori** – Frontend
* **Juned Beg** – Database

---

## 🏆 Why QuantumSentinel?

✔️ Future-proof security (Quantum-ready)
✔️ AI-powered decision making
✔️ Full attack surface visibility
✔️ Enterprise-grade architecture

---

## 🔐 Final Statement

> **“Secure Today. Be Quantum-Ready Tomorrow.”**
