import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_login_demo_accounts():
    # Admin
    resp_admin = client.post("/api/v1/auth/login", json={
        "email": "admin@sentineledge.io",
        "password": "Admin@12345!"
    })
    assert resp_admin.status_code == 200
    data = resp_admin.json()
    assert data["user"]["role"] == "admin"
    assert "access_token" in data

    # Analyst
    resp_analyst = client.post("/api/v1/auth/login", json={
        "email": "analyst@sentineledge.io",
        "password": "Analyst@12345!"
    })
    assert resp_analyst.status_code == 200
    assert resp_analyst.json()["user"]["role"] == "analyst"

    # Viewer
    resp_viewer = client.post("/api/v1/auth/login", json={
        "email": "viewer@sentineledge.io",
        "password": "Viewer@12345!"
    })
    assert resp_viewer.status_code == 200
    assert resp_viewer.json()["user"]["role"] == "viewer"

def test_dashboard_stats_and_charts():
    # Login as analyst
    login = client.post("/api/v1/auth/login", json={
        "email": "analyst@sentineledge.io",
        "password": "Analyst@12345!"
    })
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Stats
    resp_stats = client.get("/api/v1/dashboard/stats", headers=headers)
    assert resp_stats.status_code == 200
    stats = resp_stats.json()
    assert stats["total_devices"] >= 200
    assert 0 <= stats["avg_risk_score"] <= 100
    assert stats["letter_grade"] in ["A", "B", "C", "D", "F"]

    # Charts
    resp_charts = client.get("/api/v1/dashboard/charts", headers=headers)
    assert resp_charts.status_code == 200
    charts = resp_charts.json()
    assert "risk_distribution" in charts
    assert "department_compliance" in charts
    assert "risk_trend" in charts
    assert "top_failed_policies" in charts

def test_rbac_enforcement():
    # 1. Viewer token
    resp_viewer = client.post("/api/v1/auth/login", json={
        "email": "viewer@sentineledge.io",
        "password": "Viewer@12345!"
    })
    viewer_token = resp_viewer.json()["access_token"]
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # Viewer CAN view devices
    dev_resp = client.get("/api/v1/devices/", headers=viewer_headers)
    assert dev_resp.status_code == 200

    # Viewer CANNOT update policy (403 Forbidden)
    pol_resp = client.patch("/api/v1/policies/POL-01", json={"weight": 8.0}, headers=viewer_headers)
    assert pol_resp.status_code == 403

    # Viewer CANNOT remediate device (403 Forbidden)
    rem_resp = client.post("/api/v1/devices/DEV-1001/remediate", json={}, headers=viewer_headers)
    assert rem_resp.status_code == 403

    # Viewer CANNOT list users (403 Forbidden)
    users_resp = client.get("/api/v1/users/", headers=viewer_headers)
    assert users_resp.status_code == 403

    # 2. Admin token
    resp_admin = client.post("/api/v1/auth/login", json={
        "email": "admin@sentineledge.io",
        "password": "Admin@12345!"
    })
    admin_token = resp_admin.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin CAN update policy
    pol_admin_resp = client.patch("/api/v1/policies/POL-01", json={"weight": 6.5}, headers=admin_headers)
    assert pol_admin_resp.status_code == 200

    # Admin CAN view users
    admin_users_resp = client.get("/api/v1/users/", headers=admin_headers)
    assert admin_users_resp.status_code == 200

def test_ztna_simulator_endpoint():
    # Login
    login = client.post("/api/v1/auth/login", json={
        "email": "analyst@sentineledge.io",
        "password": "Analyst@12345!"
    })
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    resp = client.post("/api/v1/ztna/evaluate", json={
        "device_id": "DEV-1001",
        "resource_name": "Core Financial ERP System"
    }, headers=headers)
    assert resp.status_code == 200
    res = resp.json()
    assert res["decision"] in ["ALLOW", "ALLOW_WITH_STEP_UP_MFA", "RESTRICT", "BLOCK"]
    assert len(res["rule_path"]) > 0
    assert "reason" in res
