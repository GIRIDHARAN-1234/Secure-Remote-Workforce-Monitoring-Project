import json
import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import pandas as pd

from app.database import get_db
from app.models import Policy, Device, AuditLog, User
from app.auth.deps import get_current_user, require_role, get_client_ip
from app.schemas import PolicyResponse, PolicyUpdate
from app.services.policy_engine import evaluate_fleet_compliance, DEFAULT_POLICIES
from app.services.risk_engine import batch_calculate_fleet_risk
from app.services.ztna import evaluate_ztna_access
from app.services.alerts import generate_alerts_for_device

router = APIRouter(prefix="/policies", tags=["Policies"])

def trigger_fleet_reevaluation(db: Session):
    """Vectorized re-evaluation of entire device fleet across active policies."""
    policies = db.query(Policy).all()
    devices = db.query(Device).all()
    if not devices:
        return

    # Convert to DataFrame
    raw_list = [{col.name: getattr(d, col.name) for col in Device.__table__.columns} for d in devices]
    df = pd.DataFrame(raw_list)

    evaluated_df = evaluate_fleet_compliance(df, policies)
    scored_df = batch_calculate_fleet_risk(evaluated_df)

    valid_cols = ["risk_score", "risk_level", "compliance_percentage", "compliance_status", "passed_policies", "failed_policies", "score_breakdown"]

    for _, row in scored_df.iterrows():
        dev_id = row["device_id"]
        dev = db.query(Device).filter(Device.device_id == dev_id).first()
        if dev:
            for c in valid_cols:
                setattr(dev, c, row[c])
            ztna_res = evaluate_ztna_access(dev)
            dev.ztna_decision = ztna_res["decision"]
            dev.updated_at = datetime.datetime.utcnow()

            # Alerts
            f_list = json.loads(dev.failed_policies) if dev.failed_policies else []
            generate_alerts_for_device(db, dev, f_list)

    db.commit()

@router.get("/", response_model=List[PolicyResponse])
def list_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    policies = db.query(Policy).order_by(Policy.id.asc()).all()
    res = []
    for p in policies:
        res.append(PolicyResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            category=p.category,
            severity=p.severity,
            weight=p.weight,
            enabled=p.enabled,
            parameters=p.get_params(),
            created_at=p.created_at,
            updated_at=p.updated_at
        ))
    return res

@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found.")
    return PolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        category=p.category,
        severity=p.severity,
        weight=p.weight,
        enabled=p.enabled,
        parameters=p.get_params(),
        created_at=p.created_at,
        updated_at=p.updated_at
    )

@router.patch("/{policy_id}", response_model=PolicyResponse)
def update_policy(
    policy_id: str,
    update_data: PolicyUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    p = db.query(Policy).filter(Policy.id == policy_id).first()
    if not p:
        raise HTTPException(status_code=404, detail=f"Policy {policy_id} not found.")

    client_ip = get_client_ip(request)

    if update_data.name is not None:
        p.name = update_data.name
    if update_data.description is not None:
        p.description = update_data.description
    if update_data.severity is not None:
        p.severity = update_data.severity
    if update_data.weight is not None:
        p.weight = update_data.weight
    if update_data.enabled is not None:
        p.enabled = update_data.enabled
    if update_data.parameters is not None:
        p.set_params(update_data.parameters)

    p.updated_at = datetime.datetime.utcnow()
    db.commit()

    # Vectorized fleet re-evaluation
    trigger_fleet_reevaluation(db)

    # Log audit
    audit = AuditLog(
        user_email=current_user.email,
        action="POLICY_UPDATED",
        target=p.id,
        details=f"Policy {p.id} ({p.name}) updated. Vectorized fleet re-evaluation completed.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return PolicyResponse(
        id=p.id,
        name=p.name,
        description=p.description,
        category=p.category,
        severity=p.severity,
        weight=p.weight,
        enabled=p.enabled,
        parameters=p.get_params(),
        created_at=p.created_at,
        updated_at=p.updated_at
    )

@router.post("/reevaluate")
def reevaluate_fleet(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    client_ip = get_client_ip(request)
    trigger_fleet_reevaluation(db)

    audit = AuditLog(
        user_email=current_user.email,
        action="FLEET_REEVALUATION",
        target="All Endpoints",
        details="Admin requested full fleet posture re-evaluation across all active policies.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "Full fleet policy re-evaluation and risk scoring completed."}

@router.post("/reset-defaults")
def reset_policy_defaults(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin"]))
):
    client_ip = get_client_ip(request)
    for p_def in DEFAULT_POLICIES:
        pol = db.query(Policy).filter(Policy.id == p_def["id"]).first()
        if pol:
            pol.name = p_def["name"]
            pol.description = p_def["description"]
            pol.category = p_def["category"]
            pol.severity = p_def["severity"]
            pol.weight = p_def["weight"]
            pol.enabled = p_def["enabled"]
            pol.parameters = json.dumps(p_def["parameters"])
            pol.updated_at = datetime.datetime.utcnow()
    db.commit()

    trigger_fleet_reevaluation(db)

    audit = AuditLog(
        user_email=current_user.email,
        action="POLICY_DEFAULTS_RESET",
        target="All Policies",
        details="Reset all policy definitions, weights, and parameters to default baselines.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {"message": "All policies reset to factory defaults and fleet re-evaluated."}
