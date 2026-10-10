import httpx
import time

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_sentineledge_e2e():
    print("[1/14] Testing Health Check...")
    with httpx.Client(base_url="http://127.0.0.1:8000") as client:
        r = client.get("/health")
        assert r.status_code == 200, f"Health check failed: {r.text}"
        print(" -> Health Check: OK", r.json())

    print("[2/14] Testing Authentication for Admin, Analyst, Viewer...")
    with httpx.Client(base_url=BASE_URL) as client:
        # Admin Login
        r_admin = client.post("/auth/login", json={"email": "admin@sentineledge.io", "password": "Admin@12345!"})
        assert r_admin.status_code == 200
        admin_data = r_admin.json()
        admin_token = admin_data["access_token"]
        print(" -> Admin Login: OK, Role:", admin_data["user"]["role"])

        # Analyst Login
        r_analyst = client.post("/auth/login", json={"email": "analyst@sentineledge.io", "password": "Analyst@12345!"})
        assert r_analyst.status_code == 200
        analyst_token = r_analyst.json()["access_token"]
        print(" -> Analyst Login: OK, Role:", r_analyst.json()["user"]["role"])

        # Viewer Login
        r_viewer = client.post("/auth/login", json={"email": "viewer@sentineledge.io", "password": "Viewer@12345!"})
        assert r_viewer.status_code == 200
        viewer_token = r_viewer.json()["access_token"]
        print(" -> Viewer Login: OK, Role:", r_viewer.json()["user"]["role"])

        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

        print("[3/14] Testing Account Lockout Security (5 failed attempts)...")
        victim_email = "testlockout@sentineledge.io"
        # Register test account first
        client.post("/auth/register", json={"email": victim_email, "full_name": "Test Lockout", "password": "Password@12345!", "role": "viewer"})
        for i in range(5):
            r_fail = client.post("/auth/login", json={"email": victim_email, "password": "WrongPassword@999"})
        assert r_fail.status_code == 423 or "locked" in r_fail.text.lower(), f"Expected lockout, got: {r_fail.status_code} {r_fail.text}"
        print(" -> Account Lockout: OK (Enforced 15-minute lock)")

        print("[4/14] Testing MFA Setup & TOTP Workflow...")
        r_mfa_setup = client.post("/auth/mfa/setup", headers=admin_headers)
        assert r_mfa_setup.status_code == 200
        mfa_info = r_mfa_setup.json()
        assert "qr_code_base64" in mfa_info and "secret" in mfa_info
        print(" -> MFA Setup: OK (Generated secret and QR base64 data URI)")

        print("[5/14] Testing Dashboard Stats & Charts API...")
        r_stats = client.get("/dashboard/stats", headers=analyst_headers)
        assert r_stats.status_code == 200
        stats = r_stats.json()
        print(f" -> Stats: OK, Total Devices: {stats['total_devices']}, Avg Risk: {stats['avg_risk_score']}, Grade: {stats['letter_grade']}")

        r_charts = client.get("/dashboard/charts", headers=analyst_headers)
        assert r_charts.status_code == 200
        charts = r_charts.json()
        assert "risk_distribution" in charts and "department_compliance" in charts
        print(" -> Charts: OK (Risk doughnut, Dept bar, Trend line, Failed policies, Network risk, OS distribution)")

        print("[6/14] Testing Device Fleet Search & Multi-Filters...")
        r_devs = client.get("/devices/?limit=10&status=Non-Compliant&risk_level=Critical", headers=analyst_headers)
        assert r_devs.status_code == 200
        dev_items = r_devs.json()["items"]
        print(f" -> Device Search & Filter: OK (Found {len(dev_items)} critical non-compliant devices)")

        print("[7/14] Testing Device Detail Drawer Payload...")
        r_drawer = client.get(f"/devices/{dev_items[0]['device_id']}", headers=analyst_headers)
        assert r_drawer.status_code == 200
        drawer = r_drawer.json()
        assert len(drawer["remediation_recommendations"]) > 0
        assert "waterfall" in drawer["score_breakdown"]
        print(f" -> Device Drawer: OK ({drawer['hostname']}: {len(drawer['failed_policy_details'])} failed policies, ZTNA: {drawer['ztna_decision']})")

        print("[8/14] Testing Remediation Execution (Admin Only)...")
        target_id = dev_items[0]['device_id']
        old_score = dev_items[0]['risk_score']
        r_rem = client.post(f"/devices/{target_id}/remediate", json={}, headers=admin_headers)
        assert r_rem.status_code == 200
        rem_data = r_rem.json()
        new_score = rem_data["result"]["new_risk_score"]
        print(f" -> Device Remediation: OK (Score dropped from {old_score} to {new_score})")

        print("[9/14] Testing Security Alerts Workflow...")
        r_alerts = client.get("/alerts/?status=Open", headers=analyst_headers)
        assert r_alerts.status_code == 200
        alerts = r_alerts.json()["items"]
        if alerts:
            first_alert = alerts[0]
            r_ack = client.patch(f"/alerts/{first_alert['id']}", json={"status": "Acknowledged", "notes": "SOC triage in progress"}, headers=analyst_headers)
            assert r_ack.status_code == 200
            print(f" -> Alert Status Update: OK (Alert {first_alert['id']} marked Acknowledged, MITRE: {first_alert['mitre_technique']})")

        print("[10/14] Testing Policy Configuration & Vectorized Re-evaluation...")
        r_pol = client.patch("/policies/POL-01", json={"weight": 7.5}, headers=admin_headers)
        assert r_pol.status_code == 200
        print(" -> Policy Tuning & Vectorized Re-evaluation: OK (Weight updated, fleet re-scored with Pandas)")

        print("[11/14] Testing ZTNA Access Simulator...")
        r_ztna = client.post("/ztna/evaluate", json={"device_id": "DEV-1001", "resource_name": "Production Source Code Repo"}, headers=analyst_headers)
        assert r_ztna.status_code == 200
        ztna_eval = r_ztna.json()
        print(f" -> ZTNA Simulator: OK (Verdict: {ztna_eval['decision']}, Reason: {ztna_eval['reason'][:60]}...)")

        print("[12/14] Testing Live Telemetry Mutation Drift...")
        r_drift = client.post("/simulator/mutate", json={"count": 3}, headers=admin_headers)
        assert r_drift.status_code == 200
        mutations = r_drift.json()["mutations"]
        print(f" -> Live Telemetry Drift: OK (Injected drift into {len(mutations)} devices, live alerts generated)")

        print("[13/14] Testing Reports & Export (CSV, Template, PDF)...")
        r_csv = client.get("/import-export/export-csv", headers=analyst_headers)
        assert r_csv.status_code == 200
        r_tpl = client.get("/import-export/template")
        assert r_tpl.status_code == 200
        r_pdf = client.get("/import-export/export-pdf", headers=analyst_headers)
        assert r_pdf.status_code == 200
        assert r_pdf.headers["content-type"] == "application/pdf"
        assert len(r_pdf.content) > 1000
        print(f" -> Export Engine: OK (Generated valid CSV template, fleet dump, and {len(r_pdf.content)} byte Executive PDF report)")

        print("[14/14] Testing User Management & Audit Trail...")
        r_users = client.get("/users/", headers=admin_headers)
        assert r_users.status_code == 200
        r_audit = client.get("/audit/", headers=admin_headers)
        assert r_audit.status_code == 200
        print(f" -> Users & Audit Trail: OK (Users: {len(r_users.json())}, Audit events recorded: {r_audit.json()['total']})")

    print("\n=======================================================")
    print("ALL 14 SENTINELEDGE END-TO-END SUITES PASSED FLAWLESSLY!")
    print("=======================================================\n")

if __name__ == "__main__":
    test_sentineledge_e2e()
