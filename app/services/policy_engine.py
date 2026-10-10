import json
from typing import List, Dict, Any, Tuple
import pandas as pd
from app.models import Policy

DEFAULT_POLICIES = [
    {
        "id": "POL-01",
        "name": "OS Patched Within 30 Days",
        "description": "Operating system security patches must be installed within the last 30 days.",
        "category": "Patch",
        "severity": "high",
        "weight": 6.0,
        "enabled": True,
        "parameters": {"max_patch_age_days": 30}
    },
    {
        "id": "POL-02",
        "name": "No Pending Critical Patches",
        "description": "Zero pending critical CVE or zero-day security updates allowed.",
        "category": "Patch",
        "severity": "critical",
        "weight": 9.0,
        "enabled": True,
        "parameters": {"max_pending_critical": 0}
    },
    {
        "id": "POL-03",
        "name": "Full Disk Encryption Active",
        "description": "Full disk encryption (BitLocker, FileVault, LUKS) must be active to protect data at rest.",
        "category": "Encryption",
        "severity": "critical",
        "weight": 9.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-04",
        "name": "Host Firewall Enabled",
        "description": "Local host-based firewall must be active and filtering inbound/outbound ports.",
        "category": "Endpoint Protection",
        "severity": "high",
        "weight": 6.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-05",
        "name": "Antivirus Real-Time Protection Active",
        "description": "Antivirus agent must be installed, active, and real-time scanning enabled.",
        "category": "Endpoint Protection",
        "severity": "high",
        "weight": 7.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-06",
        "name": "Antivirus Signatures < 7 Days",
        "description": "Antivirus virus definition signatures must be updated within the past 7 days.",
        "category": "Endpoint Protection",
        "severity": "medium",
        "weight": 5.0,
        "enabled": True,
        "parameters": {"max_signature_age_days": 7}
    },
    {
        "id": "POL-07",
        "name": "EDR Agent Running & Reporting",
        "description": "Enterprise Detection & Response (EDR) agent must be actively communicating with the console.",
        "category": "Endpoint Protection",
        "severity": "critical",
        "weight": 10.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-08",
        "name": "Screen Lock Enforced with Timeout",
        "description": "Screen lock must require biometric/PIN/password after 5 minutes of inactivity.",
        "category": "Device Integrity",
        "severity": "medium",
        "weight": 4.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-09",
        "name": "Hardware TPM 2.0 and Secure Boot Active",
        "description": "Hardware Trusted Platform Module and UEFI Secure Boot must be validated.",
        "category": "Device Integrity",
        "severity": "high",
        "weight": 6.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-10",
        "name": "Device Not Jailbroken or Rooted",
        "description": "Mobile and desktop OS kernel integrity check must confirm no root/jailbreak bypasses.",
        "category": "Device Integrity",
        "severity": "critical",
        "weight": 10.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-11",
        "name": "MDM / UEM Enrolled",
        "description": "Device must be enrolled under Unified Endpoint Management (Intune, Jamf, Workspace ONE).",
        "category": "Device Integrity",
        "severity": "medium",
        "weight": 5.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-12",
        "name": "Multi-Factor Authentication (MFA) Active",
        "description": "User account identity must enforce strong MFA (FIDO2, Authenticator App).",
        "category": "Identity",
        "severity": "critical",
        "weight": 8.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-13",
        "name": "Secure Wi-Fi Protocol Enforced",
        "description": "Prohibit open unencrypted Wi-Fi or deprecated WEP/WPA encryption protocols.",
        "category": "Network",
        "severity": "high",
        "weight": 7.0,
        "enabled": True,
        "parameters": {"prohibited_protocols": ["open", "none", "WPA"]}
    },
    {
        "id": "POL-14",
        "name": "VPN Required for Remote Sensitive Access",
        "description": "Encrypted corporate VPN required when accessing High/Critical assets from untrusted or home Wi-Fi.",
        "category": "Network",
        "severity": "high",
        "weight": 8.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-15",
        "name": "Secure DNS (DoH / DoT) Enforced",
        "description": "DNS queries must use DNS-over-HTTPS (DoH) to prevent spoofing and eavesdropping.",
        "category": "Network",
        "severity": "medium",
        "weight": 4.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-16",
        "name": "Supported & Non-EOL Operating System",
        "description": "Legacy and end-of-life OS versions (e.g., Windows 7, Windows 8, old Android) are barred.",
        "category": "Device Integrity",
        "severity": "high",
        "weight": 6.0,
        "enabled": True,
        "parameters": {"eol_keywords": ["Windows 7", "Windows 8", "Windows XP", "Android 9", "Android 10", "10.14", "10.15"]}
    },
    {
        "id": "POL-17",
        "name": "No Impossible Travel Geolocation Anomalies",
        "description": "Concurrent sessions from physically incompatible geographic regions are prohibited.",
        "category": "Identity",
        "severity": "critical",
        "weight": 9.0,
        "enabled": True,
        "parameters": {}
    },
    {
        "id": "POL-18",
        "name": "Failed Login Attempts Within Threshold",
        "description": "Anomalous failed login rate (< 5 in 24h) to protect against credential stuffing/brute force.",
        "category": "Identity",
        "severity": "high",
        "weight": 6.0,
        "enabled": True,
        "parameters": {"max_failed_logins": 4}
    },
    {
        "id": "POL-19",
        "name": "No High-Risk / Blacklisted Applications",
        "description": "Endpoints must have 0 high-risk unapproved applications installed (torrent, p2p, hacking tools).",
        "category": "Endpoint Protection",
        "severity": "high",
        "weight": 7.0,
        "enabled": True,
        "parameters": {"max_risky_apps": 0}
    }
]

def evaluate_policy_vectorized(df: pd.DataFrame, policy_id: str, params: dict) -> pd.Series:
    """Evaluates a single policy against a Pandas DataFrame of devices."""
    if policy_id == "POL-01":
        max_age = params.get("max_patch_age_days", 30)
        return df["days_since_patch"] <= max_age
    elif policy_id == "POL-02":
        max_pending = params.get("max_pending_critical", 0)
        return df["pending_critical_patches"] <= max_pending
    elif policy_id == "POL-03":
        return df["disk_encryption"] == True
    elif policy_id == "POL-04":
        return df["firewall_enabled"] == True
    elif policy_id == "POL-05":
        return df["antivirus_enabled"] == True
    elif policy_id == "POL-06":
        max_sig = params.get("max_signature_age_days", 7)
        return df["antivirus_signature_age_days"] <= max_sig
    elif policy_id == "POL-07":
        return df["edr_agent_running"] == True
    elif policy_id == "POL-08":
        return df["screen_lock_enabled"] == True
    elif policy_id == "POL-09":
        return (df["secure_boot"] == True) & (df["tpm_present"] == True)
    elif policy_id == "POL-10":
        return df["jailbroken_or_rooted"] == False
    elif policy_id == "POL-11":
        return df["mdm_enrolled"] == True
    elif policy_id == "POL-12":
        return df["mfa_enabled"] == True
    elif policy_id == "POL-13":
        prohibited = params.get("prohibited_protocols", ["open", "none", "WPA"])
        return ~df["wifi_security"].str.lower().isin([p.lower() for p in prohibited])
    elif policy_id == "POL-14":
        # VPN required if on public wifi or home AND accessing high/critical data
        is_sensitive = df["access_sensitivity"].isin(["high", "critical"])
        is_untrusted_net = df["network_type"].isin(["public_wifi", "home"])
        requires_vpn = is_sensitive & is_untrusted_net
        # Pass if doesn't require vpn OR vpn is connected
        return (~requires_vpn) | (df["vpn_connected"] == True)
    elif policy_id == "POL-15":
        return df["dns_security"] == "DoH"
    elif policy_id == "POL-16":
        eol_keywords = params.get("eol_keywords", ["Windows 7", "Windows 8", "Windows XP", "Android 9", "Android 10", "10.14", "10.15"])
        eol_pattern = "|".join([k.replace(".", r"\.") for k in eol_keywords])
        return ~df["os_version"].astype(str).str.contains(eol_pattern, case=False, regex=True)
    elif policy_id == "POL-17":
        return df["impossible_travel_flag"] == False
    elif policy_id == "POL-18":
        max_failed = params.get("max_failed_logins", 4)
        return df["failed_login_count_24h"] <= max_failed
    elif policy_id == "POL-19":
        max_risky = params.get("max_risky_apps", 0)
        return df["installed_risky_apps"] <= max_risky
    else:
        # Default pass for unknown policies
        return pd.Series([True] * len(df), index=df.index)

def evaluate_fleet_compliance(df: pd.DataFrame, policies: List[Policy]) -> pd.DataFrame:
    """
    Vectorized compliance evaluation across fleet.
    Adds 'passed_policies', 'failed_policies', 'compliance_percentage', 'compliance_status' columns.
    """
    if df.empty:
        return df

    enabled_policies = [p for p in policies if p.enabled]
    if not enabled_policies:
        df["passed_policies"] = "[]"
        df["failed_policies"] = "[]"
        df["compliance_percentage"] = 100.0
        df["compliance_status"] = "Compliant"
        return df

    results = {}
    weights = {}
    total_weight = sum([p.weight for p in enabled_policies]) or 1.0

    for pol in enabled_policies:
        params = pol.get_params()
        passed_series = evaluate_policy_vectorized(df, pol.id, params)
        results[pol.id] = passed_series
        weights[pol.id] = pol.weight

    passed_df = pd.DataFrame(results, index=df.index)

    # Calculate weighted compliance
    weighted_scores = pd.Series(0.0, index=df.index)
    for pol_id, pol_weight in weights.items():
        weighted_scores += passed_df[pol_id].astype(float) * pol_weight

    compliance_percentages = (weighted_scores / total_weight) * 100.0
    compliance_percentages = compliance_percentages.round(1).clip(0.0, 100.0)

    # Determine passed and failed policy lists per row
    def get_policy_lists(row):
        passed = [pid for pid in passed_df.columns if row[pid]]
        failed = [pid for pid in passed_df.columns if not row[pid]]
        return json.dumps(passed), json.dumps(failed)

    lists = passed_df.apply(get_policy_lists, axis=1)
    df["passed_policies"] = [x[0] for x in lists]
    df["failed_policies"] = [x[1] for x in lists]
    df["compliance_percentage"] = compliance_percentages

    # Compliance Status categories
    def determine_status(score):
        if score >= 90.0:
            return "Compliant"
        elif score >= 70.0:
            return "At Risk"
        else:
            return "Non-Compliant"

    df["compliance_status"] = df["compliance_percentage"].apply(determine_status)
    return df
