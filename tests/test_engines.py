import pytest
import pandas as pd
import json
from types import SimpleNamespace

from app.services.policy_engine import evaluate_policy_vectorized, evaluate_fleet_compliance, DEFAULT_POLICIES
from app.models import Policy
from app.services.risk_engine import evaluate_single_device_risk, detect_toxic_combinations
from app.services.ztna import evaluate_ztna_access
from app.services.importer import validate_and_import_telemetry
from app.database import SessionLocal

def test_vectorized_policy_evaluation():
    data = {
        "days_since_patch": [10, 45],
        "pending_critical_patches": [0, 2],
        "disk_encryption": [True, False],
        "firewall_enabled": [True, False],
        "antivirus_enabled": [True, False],
        "antivirus_signature_age_days": [2, 15],
        "edr_agent_running": [True, False],
        "screen_lock_enabled": [True, False],
        "secure_boot": [True, False],
        "tpm_present": [True, False],
        "jailbroken_or_rooted": [False, True],
        "mdm_enrolled": [True, False],
        "mfa_enabled": [True, False],
        "wifi_security": ["WPA3", "open"],
        "network_type": ["home", "public_wifi"],
        "access_sensitivity": ["low", "critical"],
        "vpn_connected": [False, False],
        "dns_security": ["DoH", "suspicious"],
        "os_version": ["Windows 11 23H2", "Windows 7 SP1 (EOL)"],
        "impossible_travel_flag": [False, True],
        "failed_login_count_24h": [0, 5],
        "installed_risky_apps": [0, 2]
    }
    df = pd.DataFrame(data)

    # Test POL-01 (Patch within 30 days)
    res_pol01 = evaluate_policy_vectorized(df, "POL-01", {"max_patch_age_days": 30})
    assert res_pol01.tolist() == [True, False]

    # Test POL-03 (Disk encryption)
    res_pol03 = evaluate_policy_vectorized(df, "POL-03", {})
    assert res_pol03.tolist() == [True, False]

    # Test POL-07 (EDR running)
    res_pol07 = evaluate_policy_vectorized(df, "POL-07", {})
    assert res_pol07.tolist() == [True, False]

    # Test POL-10 (Not jailbroken)
    res_pol10 = evaluate_policy_vectorized(df, "POL-10", {})
    assert res_pol10.tolist() == [True, False]

    # Test POL-13 (Wi-Fi security)
    res_pol13 = evaluate_policy_vectorized(df, "POL-13", {"prohibited_protocols": ["open", "none", "WPA"]})
    assert res_pol13.tolist() == [True, False]

def test_risk_scoring_known_inputs():
    # Pristine device -> should be Low risk (< 25)
    healthy_device = SimpleNamespace(
        days_since_patch=5,
        pending_critical_patches=0,
        disk_encryption=True,
        edr_agent_running=True,
        antivirus_enabled=True,
        antivirus_signature_age_days=1,
        firewall_enabled=True,
        jailbroken_or_rooted=False,
        secure_boot=True,
        tpm_present=True,
        network_type="corporate_vpn",
        wifi_security="WPA3",
        vpn_connected=True,
        dns_security="DoH",
        privileged_account=False,
        role_level="employee",
        mfa_enabled=True,
        failed_login_count_24h=0,
        impossible_travel_flag=False,
        access_sensitivity="low",
        ownership="corporate",
        installed_risky_apps=0,
        mdm_enrolled=True,
        screen_lock_enabled=True
    )
    res = evaluate_single_device_risk(healthy_device)
    assert res["final_score"] < 25.0
    assert res["risk_level"] == "Low"

    # Compromised device -> should be Critical risk (>= 75)
    compromised_device = SimpleNamespace(
        days_since_patch=120,
        pending_critical_patches=4,
        disk_encryption=False,
        edr_agent_running=False,
        antivirus_enabled=False,
        antivirus_signature_age_days=30,
        firewall_enabled=False,
        jailbroken_or_rooted=True,
        secure_boot=False,
        tpm_present=False,
        network_type="public_wifi",
        wifi_security="open",
        vpn_connected=False,
        dns_security="suspicious",
        privileged_account=True,
        role_level="admin",
        mfa_enabled=False,
        failed_login_count_24h=6,
        impossible_travel_flag=True,
        access_sensitivity="critical",
        ownership="BYOD",
        installed_risky_apps=3,
        mdm_enrolled=False,
        screen_lock_enabled=False
    )
    res = evaluate_single_device_risk(compromised_device)
    assert res["final_score"] >= 75.0
    assert res["risk_level"] == "Critical"

def test_toxic_combination_detection():
    # Unencrypted + Public Wi-Fi + Critical Access
    bad_device = SimpleNamespace(
        disk_encryption=False,
        network_type="public_wifi",
        access_sensitivity="critical",
        privileged_account=False,
        mfa_enabled=True,
        edr_agent_running=True,
        pending_critical_patches=0,
        impossible_travel_flag=False,
        failed_login_count_24h=0,
        jailbroken_or_rooted=False
    )
    boost, reasons = detect_toxic_combinations(bad_device)
    assert boost >= 25.0
    assert any("Public Wi-Fi" in r for r in reasons)

def test_ztna_access_decisions():
    # Pristine device accessing sensitive system -> ALLOW
    good_dev = SimpleNamespace(
        device_id="DEV-GOOD",
        risk_score=12.0,
        compliance_percentage=98.0,
        jailbroken_or_rooted=False,
        edr_agent_running=True,
        disk_encryption=True,
        wifi_security="WPA3",
        vpn_connected=True,
        network_type="corporate_vpn",
        ownership="corporate",
        mfa_enabled=True,
        impossible_travel_flag=False
    )
    eval_good = evaluate_ztna_access(good_dev, "Production Source Code Repo")
    assert eval_good["decision"] == "ALLOW"

    # Rooted device accessing anything -> BLOCK
    rooted_dev = SimpleNamespace(
        device_id="DEV-ROOT",
        risk_score=60.0,
        compliance_percentage=70.0,
        jailbroken_or_rooted=True,
        edr_agent_running=False,
        disk_encryption=True,
        wifi_security="WPA2",
        vpn_connected=False,
        network_type="home",
        ownership="BYOD",
        mfa_enabled=True,
        impossible_travel_flag=False
    )
    eval_rooted = evaluate_ztna_access(rooted_dev, "Corporate Email & Slack")
    assert eval_rooted["decision"] == "BLOCK"
    assert "Rooted/jailbroken" in eval_rooted["reason"]

def test_csv_import_validation():
    db = SessionLocal()
    try:
        # Invalid CSV with missing mandatory columns
        bad_csv = b"device_id,hostname\nDEV-999,TestHost\n"
        result = validate_and_import_telemetry(db, bad_csv)
        assert len(result["errors"]) > 0
        assert "Missing required telemetry columns" in result["errors"][0]

        # Valid CSV
        valid_csv = (
            b"device_id,hostname,owner_name,owner_email,department,role_level,device_type,os_name,os_version,"
            b"days_since_patch,pending_critical_patches,disk_encryption,firewall_enabled,antivirus_enabled,"
            b"edr_agent_running,ownership,network_type,wifi_security,mfa_enabled,access_sensitivity\n"
            b"DEV-8888,TEST-LAP-88,Test Owner,test@sentineledge.io,Engineering,employee,laptop,Windows,Windows 11,"
            b"5,0,True,True,True,True,corporate,home,WPA3,True,low\n"
        )
        result_valid = validate_and_import_telemetry(db, valid_csv)
        assert len(result_valid["errors"]) == 0
        assert result_valid["total_rows"] == 1
    finally:
        db.close()
