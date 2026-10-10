import io
import json
import datetime
from typing import Dict, Any, List, Tuple
import pandas as pd
from sqlalchemy.orm import Session
from app.models import Device, Policy, Alert
from app.services.policy_engine import evaluate_fleet_compliance
from app.services.risk_engine import batch_calculate_fleet_risk
from app.services.ztna import evaluate_ztna_access
from app.services.alerts import generate_alerts_for_device

REQUIRED_COLUMNS = [
    "device_id", "hostname", "owner_name", "owner_email", "department",
    "role_level", "device_type", "os_name", "os_version", "days_since_patch",
    "pending_critical_patches", "disk_encryption", "firewall_enabled",
    "antivirus_enabled", "edr_agent_running", "ownership", "network_type",
    "wifi_security", "mfa_enabled", "access_sensitivity"
]

OPTIONAL_DEFAULTS = {
    "last_patch_date": lambda: datetime.datetime.utcnow().strftime("%Y-%m-%d"),
    "antivirus_signature_age_days": 1,
    "screen_lock_enabled": True,
    "secure_boot": True,
    "tpm_present": True,
    "jailbroken_or_rooted": False,
    "mdm_enrolled": True,
    "failed_login_count_24h": 0,
    "vpn_connected": False,
    "dns_security": "DoH",
    "geo_country": "United States",
    "impossible_travel_flag": False,
    "privileged_account": False,
    "installed_risky_apps": 0,
    "last_seen": lambda: datetime.datetime.utcnow()
}

def validate_and_import_telemetry(db: Session, file_content: bytes, is_json: bool = False) -> Dict[str, Any]:
    """
    Validates CSV/JSON telemetry using Pandas and upserts into database.
    Performs policy evaluation, risk scoring, ZTNA decision, and alert creation.
    """
    errors = []
    
    try:
        if is_json:
            df = pd.read_json(io.BytesIO(file_content))
        else:
            df = pd.read_csv(io.BytesIO(file_content))
    except Exception as e:
        return {
            "total_rows": 0,
            "created": 0,
            "updated": 0,
            "errors": [f"Malformed file parsing error: {str(e)}"]
        }

    if df.empty:
        return {
            "total_rows": 0,
            "created": 0,
            "updated": 0,
            "errors": ["File contains no data rows."]
        }

    # 1. Missing columns check
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append(f"Missing required telemetry columns: {', '.join(missing)}")
        return {
            "total_rows": len(df),
            "created": 0,
            "updated": 0,
            "errors": errors
        }

    # 2. Fill optional defaults if absent
    for col, default_val in OPTIONAL_DEFAULTS.items():
        if col not in df.columns:
            val = default_val() if callable(default_val) else default_val
            df[col] = val

    # 3. Clean and convert boolean columns
    bool_cols = [
        "disk_encryption", "firewall_enabled", "antivirus_enabled",
        "edr_agent_running", "screen_lock_enabled", "secure_boot",
        "tpm_present", "jailbroken_or_rooted", "mdm_enrolled",
        "vpn_connected", "impossible_travel_flag", "mfa_enabled", "privileged_account"
    ]
    for b_col in bool_cols:
        if b_col in df.columns:
            df[b_col] = df[b_col].astype(str).str.lower().isin(["true", "1", "t", "yes", "y"])

    # 4. Clean numeric columns
    num_cols = ["days_since_patch", "pending_critical_patches", "antivirus_signature_age_days", "failed_login_count_24h", "installed_risky_apps"]
    for n_col in num_cols:
        if n_col in df.columns:
            df[n_col] = pd.to_numeric(df[n_col], errors="coerce").fillna(0).astype(int)

    # 5. Check for null device_id
    if df["device_id"].isnull().any():
        errors.append("Dataset contains rows with missing device_id identifiers.")
        return {
            "total_rows": len(df),
            "created": 0,
            "updated": 0,
            "errors": errors
        }

    # 6. Evaluate Policies and Risk
    policies = db.query(Policy).all()
    evaluated_df = evaluate_fleet_compliance(df, policies)
    scored_df = batch_calculate_fleet_risk(evaluated_df)

    created_count = 0
    updated_count = 0

    valid_keys = {col.name for col in Device.__table__.columns}

    for _, row in scored_df.iterrows():
        dev_id = str(row["device_id"]).strip()
        existing = db.query(Device).filter(Device.device_id == dev_id).first()

        row_dict = row.to_dict()
        ztna_eval = evaluate_ztna_access(row)
        row_dict["ztna_decision"] = ztna_eval["decision"]

        filtered_dict = {k: v for k, v in row_dict.items() if k in valid_keys}
        filtered_dict["updated_at"] = datetime.datetime.utcnow()

        if existing:
            for k, v in filtered_dict.items():
                setattr(existing, k, v)
            updated_count += 1
            dev_target = existing
        else:
            dev_target = Device(**filtered_dict)
            db.add(dev_target)
            created_count += 1

        # Generate alerts
        failed_list = json.loads(dev_target.failed_policies) if dev_target.failed_policies else []
        generate_alerts_for_device(db, dev_target, failed_list)

    db.commit()

    return {
        "total_rows": len(scored_df),
        "created": created_count,
        "updated": updated_count,
        "errors": []
    }
