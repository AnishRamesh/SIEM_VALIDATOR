# 🛡️ Threat Intelligence & MITRE ATT&CK® Correlation Rule Validator

An enterprise-grade, high-fidelity Security Operations (SecOps) web terminal designed to bridge the gap between SIEM alert correlation rules and threat coverage mapping. This full-stack application allows security architects and SOC operators to import, audit, and systematically map security rules against the **MITRE ATT&CK® Framework** to identify detection gaps and prevent analytical blindspots.

---

## 🎨 Key Features

### 🖥️ 1. MITRE ATT&CK® Coverage Heatmap
* **Dynamic Visualization**: Highlights active tactic coverage with high-contrast, density-based color grading.
* **Interactive Cells**: Drill down into specific techniques (e.g., Initial Access, Persistence) to see which rules map to them.
* **Progress Snapshots**: Graph historical improvements in coverage over time to report maturity metrics to stakeholders.

### 📋 2. Advanced Rule Validation Queue
* **Intelligent Recommendations**: Automatic mapping suggestions using heuristic matching.
* **Granular Filters**: Audit rules by MITRE status (Mapped, Missing Technique, Unmapped), Use Case category, or **Severity Level (Critical, High, Medium, Low)**.
* **Bulk Export**: Download fully evaluated rule books instantly in CSV, JSON, or YAML formats.

### 👥 3. Database-Backed Role Access Management
* **Multi-Role Registry**: Enforces secure role-based terminal access using standard `Admin` and `User` privileges.
* **Admin Privilege Control**: Only designated Administrators (defaulting to `admin@wipro.com`) can authorize new credentials, assign user roles, or revoke operational access from the active database.
* **Read-Only Safeguards**: Standard users are granted complete analytical capabilities with administrative settings securely locked.

### 🔌 4. Resilient Backend Storage & Connectors
* **Dual-Layer Failover Engine**: Built with native MongoDB (`MongoClient`) connection protocols. If the database server is undergoing maintenance, the backend automatically fails over to high-integrity localized JSON schemas.
* **Active Status Telemetry**: Live ping checks reporting database and API health statistics directly inside the interface.

---

## 🛠️ Technology Stack

* **Frontend**: React 18+, TypeScript, Vite, Tailwind CSS, Lucide React (Icons), Recharts & D3 (Data Visualizations), Framer Motion (Transitions)
* **Backend**: Node.js, Express, TSX (TypeScript Engine)
* **Storage**: MongoDB (Native Client with JSON failover schemas)

---

## 🚀 Local Installation & Quick Start

### 📋 Prerequisites
Ensure you have the following installed on your machine:
* **Node.js** (v18.0.0 or higher)
* **npm** (v9.0.0 or higher)
* *Optional*: A local MongoDB instance or a MongoDB Atlas connection string.

### 1. Clone & Extract
Extract the project ZIP file to your preferred local development directory:
```bash
cd threat-correlation-validator
