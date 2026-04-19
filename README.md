# 🛡️ QuantumSentinel

### AI-Powered Quantum-Safe Attack Surface Management Platform

🚀 **PSB Cybersecurity Hackathon 2026 Submission**
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

---

## 🏗️ Enterprise Architecture

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
 ├── models/
 ├── services/
 ├── api/
 ├── scanners/
 ├── pqc/
 ├── db/
```

---

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

## 🚀 Deployment

### Docker

```bash
docker-compose up --build
```

### Local Run

```bash
pip install -r requirements.txt
uvicorn main:app --reload
```

---

## 🎥 Demo

👉 Add your 60-sec video link here

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
