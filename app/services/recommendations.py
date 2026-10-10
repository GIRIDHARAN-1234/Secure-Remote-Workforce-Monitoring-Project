import json
import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from app.models import Device, Alert, Policy
from app.services.risk_engine import evaluate_single_device_risk
from app.services.policy_engine import evaluate_fleet_compliance, DEFAULT_POLICIES
from app.services.ztna import evaluate_ztna_access

POLICY_REMEDIATION_MAP = {
    "POL-01": {
        "title": "Install Pending OS Security Updates",
        "category": "Patch",
        "priority": "P2",
        "estimated_effort": "15 mins",
        "risk_reduction_points": 15.0,
        "action": "Trigger automated OS patch deployment via MDM/WSUS agent.",
        "apply_fix": lambda d: setattr(d, "days_since_patch", 2)
    },
    "POL-02": {
        "title": "Deploy Critical Zero-Day CVE Patches",
        "category": "Patch",
        "priority": "P1",
        "estimated_effort": "20 mins",
        "risk_reduction_points": 25.0,
        "action": "Force immediate reboot and installation of out-of-band security bulletins.",
        "apply_fix": lambda d: setattr(d, "pending_critical_patches", 0)
    },
    "POL-03": {
        "title": "Enable BitLocker / FileVault Full Disk Encryption",
        "category": "Encryption",
        "priority": "P1",
        "estimated_effort": "10 mins",
        "risk_reduction_points": 22.0,
        "action": "Provision hardware TPM encryption key and turn on BitLocker/FileVault.",
        "apply_fix": lambda d: setattr(d, "disk_encryption", True)
    },
    "POL-04": {
        "title": "Enable Host Firewall Filtering",
        "category": "Endpoint Protection",
        "priority": "P3",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 12.0,
        "action": "Enforce baseline host firewall policy via group policy or MDM.",
        "apply_fix": lambda d: setattr(d, "firewall_enabled", True)
    },
    "POL-05": {
        "title": "Enable Antivirus Real-Time Protection",
        "category": "Endpoint Protection",
        "priority": "P1",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 20.0,
        "action": "Restart endpoint security daemon and re-enable real-time file monitoring.",
        "apply_fix": lambda d: setattr(d, "antivirus_enabled", True)
    },
    "POL-06": {
        "title": "Update Antivirus Definition Signatures",
        "category": "Endpoint Protection",
        "priority": "P3",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 8.0,
        "action": "Initiate signature update sync with cloud threat intelligence repository.",
        "apply_fix": lambda d: setattr(d, "antivirus_signature_age_days", 1)
    },
    "POL-07": {
        "title": "Restart Enterprise Detection & Response (EDR) Agent",
        "category": "Endpoint Protection",
        "priority": "P1",
        "estimated_effort": "10 mins",
        "risk_reduction_points": 30.0,
        "action": "Re-install or start the background EDR telemetry agent service.",
        "apply_fix": lambda d: setattr(d, "edr_agent_running", True)
    },
    "POL-08": {
        "title": "Configure Inactivity Screen Lock",
        "category": "Device Integrity",
        "priority": "P4",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 6.0,
        "action": "Enforce 5-minute idle screen lock policy with password requirement.",
        "apply_fix": lambda d: setattr(d, "screen_lock_enabled", True)
    },
    "POL-09": {
        "title": "Enable UEFI Secure Boot & Hardware TPM",
        "category": "Device Integrity",
        "priority": "P2",
        "estimated_effort": "15 mins",
        "risk_reduction_points": 14.0,
        "action": "Enable UEFI Secure Boot in firmware and initialize TPM 2.0 security chip.",
        "apply_fix": lambda d: (setattr(d, "secure_boot", True), setattr(d, "tpm_present", True))
    },
    "POL-10": {
        "title": "Re-image Compromised / Jailbroken Device",
        "category": "Device Integrity",
        "priority": "P1",
        "estimated_effort": "45 mins",
        "risk_reduction_points": 35.0,
        "action": "Perform clean OS wipe and flash trusted OEM firmware image.",
        "apply_fix": lambda d: setattr(d, "jailbroken_or_rooted", False)
    },
    "POL-11": {
        "title": "Enroll Device into MDM / UEM",
        "category": "Device Integrity",
        "priority": "P2",
        "estimated_effort": "15 mins",
        "risk_reduction_points": 12.0,
        "action": "Send MDM enrollment invitation profile to device owner.",
        "apply_fix": lambda d: setattr(d, "mdm_enrolled", True)
    },
    "POL-12": {
        "title": "Enforce Multi-Factor Authentication (MFA)",
        "category": "Identity",
        "priority": "P1",
        "estimated_effort": "10 mins",
        "risk_reduction_points": 25.0,
        "action": "Enforce mandatory FIDO2 / Authenticator MFA on Identity Provider.",
        "apply_fix": lambda d: setattr(d, "mfa_enabled", True)
    },
    "POL-13": {
        "title": "Disconnect from Insecure Open Wi-Fi",
        "category": "Network",
        "priority": "P2",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 16.0,
        "action": "Switch connection to authenticated WPA3/WPA2 Wi-Fi network.",
        "apply_fix": lambda d: setattr(d, "wifi_security", "WPA3")
    },
    "POL-14": {
        "title": "Connect Always-On Corporate VPN Tunnel",
        "category": "Network",
        "priority": "P1",
        "estimated_effort": "2 mins",
        "risk_reduction_points": 18.0,
        "action": "Establish secure IPsec / WireGuard VPN tunnel for remote traffic.",
        "apply_fix": lambda d: setattr(d, "vpn_connected", True)
    },
    "POL-15": {
        "title": "Enable DNS-over-HTTPS (DoH)",
        "category": "Network",
        "priority": "P3",
        "estimated_effort": "5 mins",
        "risk_reduction_points": 8.0,
        "action": "Configure encrypted DNS resolvers across endpoint adapters.",
        "apply_fix": lambda d: setattr(d, "dns_security", "DoH")
    },
    "POL-16": {
        "title": "Upgrade EOL Operating System to Supported Version",
        "category": "Device Integrity",
        "priority": "P2",
        "estimated_effort": "60 mins",
        "risk_reduction_points": 16.0,
        "action": "Upgrade device operating system to currently supported build.",
        "apply_fix": lambda d: setattr(d, "os_version", "Windows 11 23H2" if "Windows" in d.os_name else "macOS Sonoma 14.4")
    },
    "POL-17": {
        "title": "Revoke Compromised Session / Investigate Geolocation",
        "category": "Identity",
        "priority": "P1",
        "estimated_effort": "10 mins",
        "risk_reduction_points": 28.0,
        "action": "Terminate rogue concurrent sessions and force user credential reset.",
        "apply_fix": lambda d: setattr(d, "impossible_travel_flag", False)
    },
    "POL-18": {
        "title": "Clear Lockout & Reset Account Credentials",
        "category": "Identity",
        "priority": "P2",
        "estimated_effort": "10 mins",
        "risk_reduction_points": 14.0,
        "action": "Verify employee identity, clear brute-force lockout, and reset password.",
        "apply_fix": lambda d: setattr(d, "failed_login_count_24h", 0)
    },
    "POL-19": {
        "title": "Uninstall Blacklisted Risky Applications",
        "category": "Endpoint Protection",
        "priority": "P2",
        "estimated_effort": "15 mins",
        "risk_reduction_points": 18.0,
        "action": "Remotely uninstall unapproved peer-to-peer or unauthorized software.",
        "apply_fix": lambda d: setattr(d, "installed_risky_apps", 0)
    }
}

def get_device_recommendations(device: Device) -> Tuple[List[Dict[str, Any]], float]:
    """
    Returns prioritized remediation recommendations for a device,
    along with projected post-remediation risk score.
    """
    failed_pols = []
    try:
        failed_pols = json.loads(device.failed_policies) if device.failed_policies else []
    except Exception:
        pass

    recommendations = []
    total_potential_reduction = 0.0

    for pol_id in failed_pols:
        if pol_id in POLICY_REMEDIATION_MAP:
            info = POLICY_REMEDIATION_MAP[pol_id]
            recommendations.append({
                "policy_id": pol_id,
                "title": info["title"],
                "category": info["category"],
                "priority": info["priority"],
                "estimated_effort": info["estimated_effort"],
                "risk_reduction_points": info["risk_reduction_points"],
                "action": info["action"]
            })
            total_potential_reduction += info["risk_reduction_points"]

    # Priority sorting: P1 before P2 before P3 before P4
    priority_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
    recommendations.sort(key=lambda x: priority_order.get(x["priority"], 5))

    # Projected post-remediation risk score
    current_score = float(device.risk_score or 0.0)
    projected_score = max(0.0, round(current_score - min(current_score, total_potential_reduction * 0.75), 1))

    return recommendations, projected_score

def get_fleet_recommendations(devices: List[Device]) -> List[Dict[str, Any]]:
    """
    Aggregates top fleet-level actions ranked by total risk point reduction.
    """
    fleet_map = {}

    for d in devices:
        failed_pols = []
        try:
            failed_pols = json.loads(d.failed_policies) if d.failed_policies else []
        except Exception:
            pass

        for pol_id in failed_pols:
            if pol_id in POLICY_REMEDIATION_MAP:
                info = POLICY_REMEDIATION_MAP[pol_id]
                if pol_id not in fleet_map:
                    fleet_map[pol_id] = {
                        "policy_id": pol_id,
                        "title": info["title"],
                        "category": info["category"],
                        "priority": info["priority"],
                        "affected_devices_count": 0,
                        "total_risk_reduction_points": 0.0,
                        "estimated_effort": info["estimated_effort"],
                        "action_description": info["action"]
                    }
                fleet_map[pol_id]["affected_devices_count"] += 1
                fleet_map[pol_id]["total_risk_reduction_points"] += info["risk_reduction_points"]

    fleet_recommendations = list(fleet_map.values())
    fleet_recommendations.sort(key=lambda x: x["total_risk_reduction_points"], reverse=True)
    return fleet_recommendations[:10]

def apply_remediation_to_device(db: Session, device: Device, policy_ids: List[str] = None) -> Dict[str, Any]:
    """
    Applies simulated remediation to a device for specific policies or all failed policies.
    Recalculates risk score, compliance %, and ZTNA decision.
    Resolves related alerts.
    """
    failed_pols = []
    try:
        failed_pols = json.loads(device.failed_policies) if device.failed_policies else []
    except Exception:
        pass

    target_pols = policy_ids if policy_ids else failed_pols
    remediated_count = 0

    for pol_id in target_pols:
        if pol_id in POLICY_REMEDIATION_MAP:
            fix_fn = POLICY_REMEDIATION_MAP[pol_id]["apply_fix"]
            fix_fn(device)
            remediated_count += 1

    # Recalculate device risk
    new_risk = evaluate_single_device_risk(device)
    device.risk_score = new_risk["final_score"]
    device.risk_level = new_risk["risk_level"]
    device.score_breakdown = json.dumps(new_risk)

    # Recalculate policies
    policies = db.query(Policy).all()
    remaining_failed = []
    for pol in policies:
        if not pol.enabled:
            continue
        params = pol.get_params()
        # Create a single-row dataframe for evaluation
        import pandas as pd
        d_dict = {col.name: getattr(device, col.name) for col in device.__table__.columns}
        row_df = pd.DataFrame([d_dict])
        from app.services.policy_engine import evaluate_policy_vectorized
        passed = evaluate_policy_vectorized(row_df, pol.id, params).iloc[0]
        if not passed:
            remaining_failed.append(pol.id)

    total_enabled = len([p for p in policies if p.enabled]) or 1
    device.failed_policies = json.dumps(remaining_failed)
    device.compliance_percentage = round(((total_enabled - len(remaining_failed)) / total_enabled) * 100.0, 1)
    if device.compliance_percentage >= 90.0:
        device.compliance_status = "Compliant"
    elif device.compliance_percentage >= 70.0:
        device.compliance_status = "At Risk"
    else:
        device.compliance_status = "Non-Compliant"

    # Recalculate ZTNA decision
    ztna_res = evaluate_ztna_access(device)
    device.ztna_decision = ztna_res["decision"]

    # Auto-resolve alerts for remediated policies
    open_alerts = db.query(Alert).filter(Alert.device_id == device.device_id, Alert.status == "Open").all()
    for alert in open_alerts:
        # Check if corresponding failure is resolved
        if device.risk_score < 75.0 and "Risk Score Reached Critical" in alert.title:
            alert.status = "Resolved"
            alert.notes = "Auto-resolved following security remediation."
        elif device.edr_agent_running and "EDR" in alert.title:
            alert.status = "Resolved"
        elif device.disk_encryption and "Encryption" in alert.title:
            alert.status = "Resolved"
        elif not device.jailbroken_or_rooted and "Jailbroken" in alert.title:
            alert.status = "Resolved"
        elif not device.impossible_travel_flag and "Impossible Travel" in alert.title:
            alert.status = "Resolved"
        elif device.pending_critical_patches == 0 and "Unpatched Critical" in alert.title:
            alert.status = "Resolved"

    device.updated_at = datetime.datetime.utcnow()
    db.commit()

    return {
        "device_id": device.device_id,
        "remediated_count": remediated_count,
        "new_risk_score": device.risk_score,
        "new_risk_level": device.risk_level,
        "new_compliance": device.compliance_percentage,
        "new_ztna_decision": device.ztna_decision
    }
