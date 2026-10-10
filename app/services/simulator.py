import random
import datetime
import json
import numpy as np
import pandas as pd
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models import Device, Policy, RiskSnapshot, Alert
from app.services.policy_engine import evaluate_fleet_compliance, DEFAULT_POLICIES
from app.services.risk_engine import batch_calculate_fleet_risk
from app.services.ztna import evaluate_ztna_access
from app.services.alerts import generate_alerts_for_device

DEPARTMENTS = ["Engineering", "Finance", "Human Resources", "Sales & Marketing", "Legal & Compliance", "Product & Design", "Executive"]
ROLES = ["employee", "manager", "admin", "contractor"]
DEVICE_TYPES = ["laptop", "desktop", "mobile"]
OS_CONFIGS = [
    ("Windows", "Windows 11 23H2"),
    ("Windows", "Windows 10 22H2"),
    ("Windows", "Windows 7 SP1 (EOL)"),
    ("macOS", "macOS Sonoma 14.4"),
    ("macOS", "macOS Ventura 13.6"),
    ("macOS", "macOS Catalina 10.15 (EOL)"),
    ("Linux", "Ubuntu 22.04 LTS"),
    ("iOS", "iOS 17.4"),
    ("Android", "Android 14"),
    ("Android", "Android 9.0 (EOL)"),
]
COUNTRIES = ["United States", "United Kingdom", "Germany", "India", "Canada", "Singapore", "Australia", "Japan", "Brazil", "Netherlands"]

FIRST_NAMES = ["Alex", "Jordan", "Taylor", "Morgan", "Sam", "Chris", "Pat", "Robin", "Casey", "Riley", "Jamie", "Drew", "Logan", "Avery", "Cameron", "Quinn", "Skyler", "Jesse", "Dakota", "Reese"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"]

def generate_endpoint_telemetry_dataset(num_devices: int = 200, seed: int = 42) -> List[Dict[str, Any]]:
    """Generates a realistic synthetic telemetry dataset for remote endpoints."""
    random.seed(seed)
    np.random.seed(seed)

    devices = []
    now = datetime.datetime.utcnow()

    for i in range(1, num_devices + 1):
        dev_id = f"DEV-{1000 + i}"
        fn = random.choice(FIRST_NAMES)
        ln = random.choice(LAST_NAMES)
        owner_name = f"{fn} {ln}"
        dept = random.choice(DEPARTMENTS)
        owner_email = f"{fn.lower()}.{ln.lower()}@sentineledge.io"
        
        # Role distribution
        role_roll = random.random()
        if role_roll < 0.10:
            role = "admin"
            is_priv = True
        elif role_roll < 0.25:
            role = "manager"
            is_priv = False
        elif role_roll < 0.40:
            role = "contractor"
            is_priv = False
        else:
            role = "employee"
            is_priv = False

        dev_type = random.choice(DEVICE_TYPES)
        if dev_type == "mobile":
            os_name, os_version = random.choice([c for c in OS_CONFIGS if c[0] in ["iOS", "Android"]])
        else:
            os_name, os_version = random.choice([c for c in OS_CONFIGS if c[0] in ["Windows", "macOS", "Linux"]])

        hostname = f"{dept[:3].upper()}-{dev_type[:3].upper()}-{100 + i}"
        ownership = "BYOD" if (role == "contractor" or random.random() < 0.30) else "corporate"

        # Determine posture tier: 60% Healthy, 25% Moderate issues, 15% Badly non-compliant
        tier_roll = random.random()
        
        if tier_roll < 0.60:
            # Healthy Profile
            days_since_patch = random.randint(1, 25)
            pending_critical = 0
            disk_encryption = True
            firewall_enabled = True
            antivirus_enabled = True
            av_sig_age = random.randint(1, 4)
            edr_running = True
            screen_lock = True
            secure_boot = True
            tpm_present = True
            jailbroken = False
            mdm_enrolled = True if ownership == "corporate" else random.choice([True, False])
            failed_logins = random.randint(0, 1)
            network_type = random.choice(["corporate_vpn", "home", "home"])
            vpn_connected = True if network_type == "corporate_vpn" else random.choice([True, False])
            wifi_sec = random.choice(["WPA3", "WPA2"])
            dns_sec = "DoH"
            impossible_travel = False
            access_sensitivity = random.choice(["low", "medium", "high"])
            mfa_enabled = True
            installed_risky = 0
        elif tier_roll < 0.85:
            # Moderate Issues Profile
            days_since_patch = random.randint(28, 65)
            pending_critical = random.choice([0, 1])
            disk_encryption = random.choice([True, True, False])
            firewall_enabled = random.choice([True, True, False])
            antivirus_enabled = True
            av_sig_age = random.randint(5, 14)
            edr_running = random.choice([True, True, False])
            screen_lock = random.choice([True, True, False])
            secure_boot = True
            tpm_present = True
            jailbroken = False
            mdm_enrolled = random.choice([True, False])
            failed_logins = random.randint(1, 3)
            network_type = random.choice(["home", "mobile_hotspot", "public_wifi"])
            vpn_connected = random.choice([False, True])
            wifi_sec = random.choice(["WPA2", "WPA"])
            dns_sec = random.choice(["standard", "DoH"])
            impossible_travel = False
            access_sensitivity = random.choice(["medium", "high", "critical"])
            mfa_enabled = random.choice([True, True, False])
            installed_risky = random.choice([0, 1])
        else:
            # Dramatic Non-Compliant Profile
            days_since_patch = random.randint(70, 200)
            pending_critical = random.randint(2, 5)
            disk_encryption = False
            firewall_enabled = False
            antivirus_enabled = random.choice([False, True])
            av_sig_age = random.randint(15, 45)
            edr_running = False
            screen_lock = False
            secure_boot = random.choice([False, True])
            tpm_present = random.choice([False, True])
            jailbroken = True if dev_type == "mobile" and random.random() < 0.50 else False
            mdm_enrolled = False
            failed_logins = random.randint(3, 8)
            network_type = random.choice(["public_wifi", "public_wifi", "mobile_hotspot"])
            vpn_connected = False
            wifi_sec = random.choice(["open", "none", "WPA"])
            dns_sec = random.choice(["suspicious", "standard"])
            impossible_travel = True if random.random() < 0.40 else False
            access_sensitivity = random.choice(["high", "critical"])
            mfa_enabled = False
            installed_risky = random.randint(1, 4)

        # 3 Deliberately dramatic test cases as specified in prompt:
        if i == 1:
            # Unencrypted BYOD on open Wi-Fi accessing critical data with no EDR
            hostname = "EXEC-BYOD-CRITICAL"
            owner_name = "Marcus Vance (CEO)"
            owner_email = "marcus.vance@sentineledge.io"
            role = "admin"
            is_priv = True
            ownership = "BYOD"
            disk_encryption = False
            network_type = "public_wifi"
            wifi_sec = "open"
            vpn_connected = False
            edr_running = False
            access_sensitivity = "critical"
            mfa_enabled = False
            days_since_patch = 120
            pending_critical = 3
            installed_risky = 2
        elif i == 2:
            # Jailbroken phone accessing financial system
            hostname = "FIN-MOBILE-JAILBREAK"
            owner_name = "Evelyn Reed"
            dept = "Finance"
            dev_type = "mobile"
            os_name = "iOS"
            os_version = "iOS 16.1 (Jailbroken)"
            jailbroken = True
            access_sensitivity = "critical"
            ownership = "BYOD"
            mdm_enrolled = False
        elif i == 3:
            # Impossible travel credential anomaly
            hostname = "ENG-DEV-TRAVEL"
            owner_name = "Dmitri Volkov"
            dept = "Engineering"
            impossible_travel = True
            geo_country = "Brazil"
            failed_logins = 6
            access_sensitivity = "critical"

        last_patch_date = (now - datetime.timedelta(days=days_since_patch)).strftime("%Y-%m-%d")
        last_seen = now - datetime.timedelta(minutes=random.randint(2, 180))

        devices.append({
            "device_id": dev_id,
            "hostname": hostname,
            "owner_name": owner_name,
            "owner_email": owner_email,
            "department": dept,
            "role_level": role,
            "device_type": dev_type,
            "os_name": os_name,
            "os_version": os_version,
            "last_patch_date": last_patch_date,
            "days_since_patch": days_since_patch,
            "pending_critical_patches": pending_critical,
            "disk_encryption": disk_encryption,
            "firewall_enabled": firewall_enabled,
            "antivirus_enabled": antivirus_enabled,
            "antivirus_signature_age_days": av_sig_age,
            "edr_agent_running": edr_running,
            "screen_lock_enabled": screen_lock,
            "secure_boot": secure_boot,
            "tpm_present": tpm_present,
            "jailbroken_or_rooted": jailbroken,
            "mdm_enrolled": mdm_enrolled,
            "ownership": ownership,
            "failed_login_count_24h": failed_logins,
            "vpn_connected": vpn_connected,
            "network_type": network_type,
            "wifi_security": wifi_sec,
            "dns_security": dns_sec,
            "geo_country": random.choice(COUNTRIES) if not (i == 3) else "Brazil",
            "impossible_travel_flag": impossible_travel,
            "access_sensitivity": access_sensitivity,
            "mfa_enabled": mfa_enabled,
            "privileged_account": is_priv,
            "last_seen": last_seen,
            "installed_risky_apps": installed_risky
        })

    return devices

def seed_simulation_data(db: Session, force: bool = False):
    """Initializes policies, devices, alerts, and historical trend data."""
    # 1. Policies
    existing_policies = db.query(Policy).count()
    if existing_policies == 0 or force:
        if force:
            db.query(Policy).delete()
        for p in DEFAULT_POLICIES:
            pol = Policy(
                id=p["id"],
                name=p["name"],
                description=p["description"],
                category=p["category"],
                severity=p["severity"],
                weight=p["weight"],
                enabled=p["enabled"],
                parameters=json.dumps(p["parameters"])
            )
            db.add(pol)
        db.commit()

    policies = db.query(Policy).all()

    # 2. Devices
    existing_devices = db.query(Device).count()
    if existing_devices == 0 or force:
        if force:
            db.query(Alert).delete()
            db.query(Device).delete()

        raw_telemetry = generate_endpoint_telemetry_dataset(num_devices=200, seed=42)
        df = pd.DataFrame(raw_telemetry)

        # Vectorized Policy Evaluation
        df = evaluate_fleet_compliance(df, policies)
        # Vectorized Risk Scoring
        df = batch_calculate_fleet_risk(df)

        # Insert devices into DB
        for _, row in df.iterrows():
            d_dict = row.to_dict()
            # Evaluate ZTNA decision
            ztna_res = evaluate_ztna_access(row)
            d_dict["ztna_decision"] = ztna_res["decision"]

            # Exclude extra keys if any
            valid_keys = {col.name for col in Device.__table__.columns}
            filtered_dict = {k: v for k, v in d_dict.items() if k in valid_keys}
            
            dev = Device(**filtered_dict)
            db.add(dev)
        db.commit()

        # 3. Generate Initial Alerts
        all_devices = db.query(Device).all()
        for dev in all_devices:
            failed_pols = json.loads(dev.failed_policies) if dev.failed_policies else []
            generate_alerts_for_device(db, dev, failed_pols)
        db.commit()

        # 4. Generate 30 Days of Historical Risk Snapshots for Trend Chart
        existing_snapshots = db.query(RiskSnapshot).count()
        if existing_snapshots == 0 or force:
            if force:
                db.query(RiskSnapshot).delete()
            
            now = datetime.datetime.utcnow()
            base_risk = 34.5
            for day in range(30, 0, -1):
                snap_time = now - datetime.timedelta(days=day)
                # Realistic trend: gradual posture improvement with occasional fluctuations
                fluctuation = np.sin(day / 4.0) * 4.5 + np.random.normal(0, 1.2)
                day_risk = round(max(20.0, min(55.0, base_risk + fluctuation)), 1)
                
                snap = RiskSnapshot(
                    timestamp=snap_time,
                    avg_risk_score=day_risk,
                    compliant_count=int(200 * (1 - day_risk / 100)),
                    at_risk_count=int(200 * (day_risk / 200)),
                    non_compliant_count=int(200 * (day_risk / 300)),
                    critical_device_count=int(day_risk / 3.5),
                    open_alerts_count=int(day_risk * 1.2)
                )
                db.add(snap)
            db.commit()

def mutate_live_telemetry(db: Session, count: int = 5) -> List[Dict[str, Any]]:
    """Mutates a random subset of devices to simulate live drift and produce dashboard updates."""
    devices = db.query(Device).all()
    if not devices:
        return []

    targets = random.sample(devices, min(count, len(devices)))
    mutations = []
    policies = db.query(Policy).all()

    for dev in targets:
        drift_type = random.choice([
            "patch_drift", "av_stopped", "wifi_switch", "failed_logins", "risky_app"
        ])
        before_score = dev.risk_score

        if drift_type == "patch_drift":
            dev.days_since_patch += random.randint(15, 30)
            dev.pending_critical_patches += random.randint(1, 2)
            desc = f"Patch drift: {dev.days_since_patch} days since patch, {dev.pending_critical_patches} pending CVEs"
        elif drift_type == "av_stopped":
            dev.antivirus_enabled = False
            dev.antivirus_signature_age_days += 10
            desc = "Antivirus real-time protection deactivated"
        elif drift_type == "wifi_switch":
            dev.network_type = "public_wifi"
            dev.wifi_security = "open"
            dev.vpn_connected = False
            desc = "Switched to unencrypted public Wi-Fi without VPN"
        elif drift_type == "failed_logins":
            dev.failed_login_count_24h += 4
            desc = f"Spike in failed logins ({dev.failed_login_count_24h} in 24h)"
        else:
            dev.installed_risky_apps += 1
            desc = "Unapproved peer-to-peer / torrent client detected"

        dev.last_seen = datetime.datetime.utcnow()

        # Recalculate single device
        d_dict = {col.name: getattr(dev, col.name) for col in dev.__table__.columns}
        row_df = pd.DataFrame([d_dict])
        evaluated_df = evaluate_fleet_compliance(row_df, policies)
        scored_df = batch_calculate_fleet_risk(evaluated_df)
        
        dev.risk_score = scored_df["risk_score"].iloc[0]
        dev.risk_level = scored_df["risk_level"].iloc[0]
        dev.compliance_percentage = scored_df["compliance_percentage"].iloc[0]
        dev.compliance_status = scored_df["compliance_status"].iloc[0]
        dev.failed_policies = scored_df["failed_policies"].iloc[0]
        dev.score_breakdown = scored_df["score_breakdown"].iloc[0]

        ztna_res = evaluate_ztna_access(dev)
        dev.ztna_decision = ztna_res["decision"]

        # Alert generation
        failed_list = json.loads(dev.failed_policies) if dev.failed_policies else []
        generate_alerts_for_device(db, dev, failed_list)

        mutations.append({
            "device_id": dev.device_id,
            "hostname": dev.hostname,
            "drift_type": drift_type,
            "description": desc,
            "old_risk_score": before_score,
            "new_risk_score": dev.risk_score,
            "risk_level": dev.risk_level
        })

    db.commit()
    return mutations
