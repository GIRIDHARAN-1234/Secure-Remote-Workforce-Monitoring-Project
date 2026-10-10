import json
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple, List

def calculate_device_health_component(row) -> float:
    score = 0.0
    # Patches
    days_patch = getattr(row, "days_since_patch", 0)
    if days_patch > 90:
        score += 35.0
    elif days_patch > 60:
        score += 25.0
    elif days_patch > 30:
        score += 15.0

    pending_critical = getattr(row, "pending_critical_patches", 0)
    score += min(30.0, pending_critical * 15.0)

    # Disk Encryption
    if not getattr(row, "disk_encryption", True):
        score += 30.0

    # Endpoint Security
    if not getattr(row, "edr_agent_running", True):
        score += 35.0
    if not getattr(row, "antivirus_enabled", True):
        score += 25.0
    else:
        sig_age = getattr(row, "antivirus_signature_age_days", 0)
        if sig_age > 14:
            score += 15.0
        elif sig_age > 7:
            score += 8.0

    if not getattr(row, "firewall_enabled", True):
        score += 15.0

    # Integrity
    if getattr(row, "jailbroken_or_rooted", False):
        score += 45.0
    if not getattr(row, "secure_boot", True) or not getattr(row, "tpm_present", True):
        score += 15.0

    return min(100.0, score)

def calculate_network_trust_component(row) -> float:
    score = 0.0
    net_type = getattr(row, "network_type", "home")
    if net_type == "public_wifi":
        score += 45.0
    elif net_type == "mobile_hotspot":
        score += 25.0
    elif net_type == "home":
        score += 15.0
    elif net_type == "corporate_vpn":
        score += 0.0

    wifi_sec = getattr(row, "wifi_security", "WPA3")
    if wifi_sec in ["open", "none"]:
        score += 40.0
    elif wifi_sec == "WPA":
        score += 25.0
    elif wifi_sec == "WPA2":
        score += 10.0
    elif wifi_sec == "WPA3":
        score += 0.0

    # VPN evaluation
    vpn = getattr(row, "vpn_connected", False)
    if not vpn and net_type in ["public_wifi", "home"]:
        score += 20.0

    # DNS Security
    dns_sec = getattr(row, "dns_security", "DoH")
    if dns_sec == "suspicious":
        score += 35.0
    elif dns_sec == "standard":
        score += 15.0

    return min(100.0, score)

def calculate_user_access_component(row) -> float:
    score = 0.0
    if getattr(row, "privileged_account", False):
        score += 25.0

    role = getattr(row, "role_level", "employee")
    if role == "admin":
        score += 20.0
    elif role == "contractor":
        score += 15.0
    elif role == "manager":
        score += 10.0

    if not getattr(row, "mfa_enabled", True):
        score += 35.0

    failed_logins = getattr(row, "failed_login_count_24h", 0)
    score += min(35.0, failed_logins * 10.0)

    if getattr(row, "impossible_travel_flag", False):
        score += 40.0

    sensitivity = getattr(row, "access_sensitivity", "medium")
    if sensitivity == "critical":
        score += 30.0
    elif sensitivity == "high":
        score += 20.0
    elif sensitivity == "medium":
        score += 10.0

    if getattr(row, "ownership", "corporate") == "BYOD":
        score += 15.0

    return min(100.0, score)

def calculate_behavioral_modifier_component(row) -> float:
    score = 0.0
    risky_apps = getattr(row, "installed_risky_apps", 0)
    score += min(50.0, risky_apps * 25.0)

    if not getattr(row, "mdm_enrolled", True):
        score += 25.0

    if not getattr(row, "screen_lock_enabled", True):
        score += 20.0

    return min(100.0, score)

def detect_toxic_combinations(row) -> Tuple[float, List[str]]:
    boost = 0.0
    reasons = []

    # 1. Unencrypted + Public Wi-Fi + Critical Access
    if (not getattr(row, "disk_encryption", True) and
        getattr(row, "network_type", "") == "public_wifi" and
        getattr(row, "access_sensitivity", "") == "critical"):
        boost += 25.0
        reasons.append("Toxic Combo: Unencrypted drive accessing Critical asset over Public Wi-Fi (+25)")

    # 2. Privileged Account + No MFA
    if (getattr(row, "privileged_account", False) and
        not getattr(row, "mfa_enabled", True)):
        boost += 20.0
        reasons.append("Toxic Combo: Privileged account accessing systems without MFA (+20)")

    # 3. No EDR + Pending Critical Patches
    if (not getattr(row, "edr_agent_running", True) and
        getattr(row, "pending_critical_patches", 0) > 0):
        boost += 20.0
        reasons.append("Toxic Combo: Unprotected endpoint (No EDR) with unpatched Critical CVEs (+20)")

    # 4. Impossible Travel + Failed Logins >= 3
    if (getattr(row, "impossible_travel_flag", False) and
        getattr(row, "failed_login_count_24h", 0) >= 3):
        boost += 15.0
        reasons.append("Toxic Combo: Geolocation impossible travel with multiple failed logins (+15)")

    # 5. Jailbroken/Rooted + High/Critical Access
    if (getattr(row, "jailbroken_or_rooted", False) and
        getattr(row, "access_sensitivity", "") in ["high", "critical"]):
        boost += 25.0
        reasons.append("Toxic Combo: Compromised / Rooted kernel accessing High/Critical assets (+25)")

    return boost, reasons

def evaluate_single_device_risk(device) -> Dict[str, Any]:
    health_raw = calculate_device_health_component(device)
    net_raw = calculate_network_trust_component(device)
    user_raw = calculate_user_access_component(device)
    behav_raw = calculate_behavioral_modifier_component(device)

    # Weights: 40% health, 25% net, 25% user, 10% behav
    health_weighted = health_raw * 0.40
    net_weighted = net_raw * 0.25
    user_weighted = user_raw * 0.25
    behav_weighted = behav_raw * 0.10

    base_score = health_weighted + net_weighted + user_weighted + behav_weighted
    toxic_boost, toxic_reasons = detect_toxic_combinations(device)

    final_score = round(min(100.0, max(0.0, base_score + toxic_boost)), 1)

    if final_score >= 75.0:
        level = "Critical"
    elif final_score >= 50.0:
        level = "High"
    elif final_score >= 25.0:
        level = "Medium"
    else:
        level = "Low"

    waterfall = [
        {"name": "Device Health Risk (40%)", "value": round(health_weighted, 1), "raw": round(health_raw, 1)},
        {"name": "Network Trust Risk (25%)", "value": round(net_weighted, 1), "raw": round(net_raw, 1)},
        {"name": "User/Access Risk (25%)", "value": round(user_weighted, 1), "raw": round(user_raw, 1)},
        {"name": "Behavioral Modifiers (10%)", "value": round(behav_weighted, 1), "raw": round(behav_raw, 1)},
        {"name": "Toxic Combination Boost", "value": round(toxic_boost, 1), "details": toxic_reasons},
        {"name": "Total Composite Score", "value": final_score}
    ]

    return {
        "final_score": final_score,
        "risk_level": level,
        "health_score": round(health_raw, 1),
        "health_weighted": round(health_weighted, 1),
        "network_score": round(net_raw, 1),
        "network_weighted": round(net_weighted, 1),
        "user_score": round(user_raw, 1),
        "user_weighted": round(user_weighted, 1),
        "behavioral_score": round(behav_raw, 1),
        "behavioral_weighted": round(behav_weighted, 1),
        "toxic_boost": round(toxic_boost, 1),
        "toxic_combinations": toxic_reasons,
        "waterfall": waterfall
    }

def batch_calculate_fleet_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Vectorized / batch risk calculation for high-performance fleet scoring."""
    if df.empty:
        return df

    health_scores = []
    net_scores = []
    user_scores = []
    behav_scores = []
    toxic_boosts = []
    final_scores = []
    risk_levels = []
    breakdowns = []

    for _, row in df.iterrows():
        eval_res = evaluate_single_device_risk(row)
        health_scores.append(eval_res["health_score"])
        net_scores.append(eval_res["network_score"])
        user_scores.append(eval_res["user_score"])
        behav_scores.append(eval_res["behavioral_score"])
        toxic_boosts.append(eval_res["toxic_boost"])
        final_scores.append(eval_res["final_score"])
        risk_levels.append(eval_res["risk_level"])
        breakdowns.append(json.dumps(eval_res))

    df["risk_score"] = final_scores
    df["risk_level"] = risk_levels
    df["score_breakdown"] = breakdowns
    return df
