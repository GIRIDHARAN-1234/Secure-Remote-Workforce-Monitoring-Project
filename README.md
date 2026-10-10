# 🛡️ SentinelEdge – Secure Remote Workforce Monitoring Framework

> **Hackathon Track:** Threat Detection & Security Monitoring  
> **Concept:** Continuous Zero Trust (ZTNA) Endpoint Posture & Threat Detection Console

---

## 📖 1. Overview & Problem Context
In modern remote work environments, employees connect to corporate services from home routers, coffee shops, and personal (BYOD) devices. Traditional perimeter security fails because access is often granted without checking whether endpoint security controls (Antivirus, EDR, Disk Encryption, OS Patching) are enabled and operational.

**SentinelEdge** replaces implicit trust with **Continuous Zero Trust Verification**:
- Collects and evaluates 25+ endpoint telemetry signals.
- Evaluates devices against 19 compliance baselines in real time using a vectorized policy engine.
- Computes an **explainable risk score** with toxic combination detection.
- Provides a real-time **Zero Trust Access (ZTNA) Simulator** (`ALLOW`, `STEP-UP MFA`, `RESTRICT`, `BLOCK`).
- Maps security alerts directly to the **MITRE ATT&CK** matrix.
- Generates prioritized, high-ROI remediation plans with one-click fixes.

---

## 🚀 2. Quick Start

### Start the Application
Open a terminal in the project root directory and run:
```powershell
python run.py
```
*(Or alternatively: `uvicorn app.main:app --reload`)*

* **Web Console:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive API Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Alternative API Docs:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

## 🔑 3. Demo Credentials

The platform automatically seeds 3 role-based demo accounts:

| Role | Email | Password | Permissions |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin@sentineledge.io` | `Admin@12345!` | Full control: policy tuning, user management, ZTNA simulation, remote fixes |
| **SOC Analyst** | `analyst@sentineledge.io` | `Analyst@12345!` | Operational security: alert triage, device inspections, applying fixes |
| **Viewer / Auditor** | `viewer@sentineledge.io` | `Viewer@12345!` | Read-only visibility into posture dashboards and fleet compliance |

> *Tip: The login page provides 1-click quick-fill buttons for all three accounts.*

---

## 🧭 4. Simplified & Explainable Navigation

The console is organized into **3 distinct, easy-to-understand categories**:

### 1. 📊 Daily Monitoring (Core)
* **Posture Dashboard:** Fleet-wide letter grade (A–F), composite risk score, and real-time threat charts.
* **Colleague Devices:** Live directory of all 200 monitored endpoints with 1-click quick filters.
* **Security Alerts:** Active incidents mapped to MITRE ATT&CK techniques with status triage (`Open` → `Investigating` → `Resolved`).

### 2. 🛡️ Security Controls & Fixes (Actions)
* **Remediation Plans:** 1-click fixes ranked by effort vs. risk-reduction ROI.
* **Security Policies:** 19 compliance rules governing patching, BitLocker encryption, and antivirus.
* **Access Simulator (ZTNA):** Test bench to evaluate if a colleague's machine can safely access corporate apps (e.g., ERP, GitHub).

### 3. ⚙️ Reports & Management (Admin)
* **Ingestion & Reports:** Import CSV telemetry and download Executive PDF reports.
* **Users & Roles:** Manage operator accounts and role permissions.
* **Security Audit Log:** Tamper-evident trail of logins, policy modifications, and remediations.
* **Profile & 2FA:** User security settings and TOTP Authenticator setup.

---

## 🔍 5. How to Check a Colleague's Antivirus Status

To check whether a fellow colleague's machine has antivirus installed and active:

1. Click **Colleague Devices** in the sidebar.
2. Click the **`🛡️ ⚠️ Missing Antivirus`** 1-click preset chip to instantly view all machines with missing or disabled protection.
3. Or search the colleague's name/email in the search bar.
4. Click on the device or the **Drawer ➔** button to open the **Endpoint Telemetry Specs**:
   - **Antivirus & Sig Age:** Shows `Active (X days old)` or `Disabled ⚠`.
   - **EDR Agent:** Shows `Running & Healthy` or `Offline / Stopped ⚠`.
   - **Policy Checklist:** Verify `POL-05 (Antivirus Active)` and `POL-06 (Signatures < 7 Days)`.
   - **1-Click Fix:** Click **"Remediate Endpoint"** to remotely deploy/enable protection!

---

## 🧪 6. Automated Testing

All tests verify authentication, account lockout, TOTP MFA, vectorized policies, toxic combinations, ZTNA verdicts, and export engines:

```powershell
# Run the complete test suite (15 unit/integration tests)
python -m pytest -v

# Run the 14-step live end-to-end integration test against the running server
python verify_e2e.py
```

---

## 🏗️ 7. Architecture & Tech Stack

* **Backend:** Python 3.11+, FastAPI, Uvicorn, SQLAlchemy + SQLite, Pandas, NumPy, Pydantic v2
* **Authentication:** Bcrypt password hashing, JWT HttpOnly cookies, Account Lockout (5 attempts), TOTP MFA (PyOTP + QRCode)
* **Frontend:** Single Page App (SPA) served by FastAPI from `/static` using Vanilla JS, Tailwind CSS (CDN), and Chart.js (CDN)
* **Reports:** ReportLab PDF generation, Pandas CSV ingestion/export
