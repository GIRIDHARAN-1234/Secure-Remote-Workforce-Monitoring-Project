import json
from typing import Dict, Any, List

RESOURCE_SENSITIVITY_MAP = {
    "Production Source Code Repo": "critical",
    "Core Financial ERP System": "critical",
    "HR Employee Database": "high",
    "Customer Support Portal": "medium",
    "Corporate Email & Slack": "medium",
    "Internal Knowledge Base / Wiki": "low",
}

def evaluate_ztna_access(device, resource_name: str = None) -> Dict[str, Any]:
    """
    Evaluates Zero Trust Network Access (ZTNA) policy dynamically based on
    device risk score, posture compliance, network context, and resource sensitivity.
    """
    if not resource_name or resource_name not in RESOURCE_SENSITIVITY_MAP:
        resource_name = "Core Financial ERP System"

    sensitivity = RESOURCE_SENSITIVITY_MAP.get(resource_name, "high")
    risk_score = float(getattr(device, "risk_score", 0.0))
    compliance = float(getattr(device, "compliance_percentage", 100.0))
    
    jailbroken = getattr(device, "jailbroken_or_rooted", False)
    edr_running = getattr(device, "edr_agent_running", True)
    disk_encrypted = getattr(device, "disk_encryption", True)
    wifi_sec = getattr(device, "wifi_security", "WPA3")
    vpn_connected = getattr(device, "vpn_connected", False)
    net_type = getattr(device, "network_type", "home")
    ownership = getattr(device, "ownership", "corporate")
    mfa_enabled = getattr(device, "mfa_enabled", True)
    impossible_travel = getattr(device, "impossible_travel_flag", False)

    rule_path = []
    remediations = []
    decision = "ALLOW"
    reason = "All Zero Trust validation criteria passed. Device health and network trust verify access."

    # Rule 1: Device Integrity Check
    rule_path.append({
        "rule_id": "ZTNA-01",
        "name": "Hardware & Kernel Integrity",
        "passed": not jailbroken,
        "detail": "Device is not jailbroken or rooted." if not jailbroken else "FAILED: Compromised root/jailbreak detected."
    })
    if jailbroken:
        decision = "BLOCK"
        reason = f"BLOCKED: Rooted/jailbroken kernel integrity breach. Access to '{resource_name}' denied."
        remediations.append("Restore standard operating system firmware and unroot device.")
        return build_ztna_result(device, resource_name, sensitivity, decision, reason, rule_path, remediations)

    # Rule 2: Geolocation Anomaly Check
    rule_path.append({
        "rule_id": "ZTNA-02",
        "name": "Identity & Impossible Travel Validation",
        "passed": not impossible_travel,
        "detail": "No anomalous geolocation concurrent sessions." if not impossible_travel else "FAILED: Concurrent logins from geographically impossible locations."
    })
    if impossible_travel:
        decision = "BLOCK"
        reason = f"BLOCKED: Impossible travel alert active. Potential compromised credentials accessing '{resource_name}'."
        remediations.append("Re-authenticate with hardware MFA key and notify Security Operations.")
        return build_ztna_result(device, resource_name, sensitivity, decision, reason, rule_path, remediations)

    # Rule 3: Critical Asset Protection
    if sensitivity == "critical":
        crit_pass = (
            disk_encrypted and
            edr_running and
            (wifi_sec not in ["open", "none"]) and
            (net_type != "public_wifi" or vpn_connected)
        )
        rule_path.append({
            "rule_id": "ZTNA-03",
            "name": "Critical Asset Safeguards (Disk Encryption, EDR, Safe Network)",
            "passed": crit_pass,
            "detail": "Meets baseline criteria for Critical asset access." if crit_pass else "FAILED: Missing disk encryption, EDR agent, or using unencrypted Wi-Fi."
        })
        if not crit_pass:
            decision = "BLOCK"
            failed_elements = []
            if not disk_encrypted:
                failed_elements.append("unencrypted disk")
                remediations.append("Enable BitLocker or FileVault disk encryption.")
            if not edr_running:
                failed_elements.append("EDR agent offline")
                remediations.append("Start and register the enterprise EDR security agent.")
            if wifi_sec in ["open", "none"]:
                failed_elements.append("open/insecure Wi-Fi")
                remediations.append("Switch to a secure WPA2/WPA3 network.")
            if net_type == "public_wifi" and not vpn_connected:
                failed_elements.append("public Wi-Fi without VPN")
                remediations.append("Connect to Corporate VPN.")

            reason = f"BLOCKED: Critical asset '{resource_name}' requires pristine endpoint posture. Deficiencies: {', '.join(failed_elements)}."
            return build_ztna_result(device, resource_name, sensitivity, decision, reason, rule_path, remediations)

    # Rule 4: Risk Score & Compliance Threshold Evaluation
    rule_path.append({
        "rule_id": "ZTNA-04",
        "name": "Fleet Risk & Posture Compliance Score",
        "passed": risk_score < 75 and compliance >= 70,
        "detail": f"Risk Score: {risk_score} (Threshold <75), Compliance: {compliance}% (Threshold >=70%)"
    })

    if risk_score >= 75.0 or compliance < 60.0:
        decision = "BLOCK"
        reason = f"BLOCKED: Excessive endpoint risk score ({risk_score}/100) or low compliance ({compliance}%). Quarantined from '{resource_name}'."
        remediations.append("Resolve open high/critical policy violations before reconnecting.")
    elif risk_score >= 50.0 or compliance < 75.0:
        if sensitivity in ["high", "critical"]:
            decision = "RESTRICT"
            reason = f"RESTRICTED: Elevated risk ({risk_score}/100). Granted limited read-only/quarantine access to '{resource_name}'."
            remediations.append("Update pending operating system security patches.")
            remediations.append("Ensure corporate VPN is connected.")
        else:
            decision = "ALLOW_WITH_STEP_UP_MFA"
            reason = f"STEP-UP MFA REQUIRED: Moderate device risk ({risk_score}/100). Step-up authentication needed for '{resource_name}'."
            remediations.append("Perform second-factor biometric/TOTP verification.")
    elif risk_score >= 25.0:
        if sensitivity in ["high", "critical"] and not mfa_enabled:
            decision = "ALLOW_WITH_STEP_UP_MFA"
            reason = f"STEP-UP MFA REQUIRED: High sensitivity resource accessed from moderate risk endpoint."
            remediations.append("Enforce multi-factor authentication (MFA).")
        else:
            decision = "ALLOW"
            reason = f"ALLOWED: Device posture satisfies Zero Trust security baseline for '{resource_name}'."
    else:
        decision = "ALLOW"
        reason = f"ALLOWED: Low risk score ({risk_score}/100) with verified security controls."

    return build_ztna_result(device, resource_name, sensitivity, decision, reason, rule_path, remediations)

def build_ztna_result(device, resource_name, sensitivity, decision, reason, rule_path, remediations):
    return {
        "device_id": getattr(device, "device_id", "UNKNOWN"),
        "resource_name": resource_name,
        "resource_sensitivity": sensitivity,
        "decision": decision,
        "reason": reason,
        "risk_score": float(getattr(device, "risk_score", 0.0)),
        "risk_level": getattr(device, "risk_level", "Low"),
        "rule_path": rule_path,
        "remediation_suggestions": remediations or ["No critical remediations required. Endpoint is compliant."]
    }
