import json
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Device, Alert, Policy, RiskSnapshot, User
from app.auth.deps import get_current_user
from app.schemas import DashboardStatsResponse

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).all()
    total_devices = len(devices)

    if total_devices == 0:
        return DashboardStatsResponse(
            total_devices=0,
            compliance_percentage=100.0,
            avg_risk_score=0.0,
            critical_devices_count=0,
            high_devices_count=0,
            medium_devices_count=0,
            low_devices_count=0,
            open_alerts_count=0,
            byod_percentage=0.0,
            unpatched_percentage=0.0,
            security_posture_score=100.0,
            letter_grade="A"
        )

    avg_risk = round(sum([d.risk_score for d in devices]) / total_devices, 1)
    compliance_avg = round(sum([d.compliance_percentage for d in devices]) / total_devices, 1)

    critical_count = len([d for d in devices if d.risk_level == "Critical"])
    high_count = len([d for d in devices if d.risk_level == "High"])
    medium_count = len([d for d in devices if d.risk_level == "Medium"])
    low_count = len([d for d in devices if d.risk_level == "Low"])

    open_alerts_count = db.query(Alert).filter(Alert.status.in_(["Open", "Investigating"])).count()
    byod_count = len([d for d in devices if d.ownership == "BYOD"])
    byod_pct = round((byod_count / total_devices) * 100.0, 1)

    unpatched_count = len([d for d in devices if d.days_since_patch > 30 or d.pending_critical_patches > 0])
    unpatched_pct = round((unpatched_count / total_devices) * 100.0, 1)

    # Posture score: 100 - avg_risk (with minor penalty for critical devices)
    posture_score = max(0.0, min(100.0, round(100.0 - avg_risk - (critical_count * 0.2), 1)))

    if posture_score >= 85:
        letter_grade = "A"
    elif posture_score >= 70:
        letter_grade = "B"
    elif posture_score >= 55:
        letter_grade = "C"
    elif posture_score >= 40:
        letter_grade = "D"
    else:
        letter_grade = "F"

    return DashboardStatsResponse(
        total_devices=total_devices,
        compliance_percentage=compliance_avg,
        avg_risk_score=avg_risk,
        critical_devices_count=critical_count,
        high_devices_count=high_count,
        medium_devices_count=medium_count,
        low_devices_count=low_count,
        open_alerts_count=open_alerts_count,
        byod_percentage=byod_pct,
        unpatched_percentage=unpatched_pct,
        security_posture_score=posture_score,
        letter_grade=letter_grade
    )

@router.get("/charts")
def get_dashboard_charts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).all()
    
    # 1. Risk Level Distribution (doughnut)
    risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for d in devices:
        risk_counts[d.risk_level] = risk_counts.get(d.risk_level, 0) + 1

    # 2. Compliance by Department (bar)
    dept_map = {}
    for d in devices:
        if d.department not in dept_map:
            dept_map[d.department] = []
        dept_map[d.department].append(d.compliance_percentage)
    
    dept_labels = list(dept_map.keys())
    dept_scores = [round(sum(vals) / len(vals), 1) for vals in dept_map.values()]

    # 3. Risk Trend Over Time (line, from snapshots)
    snapshots = db.query(RiskSnapshot).order_by(RiskSnapshot.timestamp.asc()).all()
    trend_labels = [s.timestamp.strftime("%b %d") for s in snapshots]
    trend_scores = [round(s.avg_risk_score, 1) for s in snapshots]

    # 4. Top Failed Policies (horizontal bar)
    failed_counts = {}
    for d in devices:
        try:
            f_list = json.loads(d.failed_policies) if d.failed_policies else []
            for p_id in f_list:
                failed_counts[p_id] = failed_counts.get(p_id, 0) + 1
        except Exception:
            pass

    policies = {p.id: p.name for p in db.query(Policy).all()}
    top_failed_sorted = sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)[:8]
    policy_labels = [f"{pid}: {policies.get(pid, pid)[:25]}..." for pid, _ in top_failed_sorted]
    policy_counts = [cnt for _, cnt in top_failed_sorted]

    # 5. Network Type Risk Distribution
    net_map = {}
    for d in devices:
        if d.network_type not in net_map:
            net_map[d.network_type] = []
        net_map[d.network_type].append(d.risk_score)
    net_labels = [k.replace("_", " ").title() for k in net_map.keys()]
    net_scores = [round(sum(v) / len(v), 1) for v in net_map.values()]

    # 6. Operating System Distribution
    os_counts = {}
    for d in devices:
        os_counts[d.os_name] = os_counts.get(d.os_name, 0) + 1

    return {
        "risk_distribution": {
            "labels": ["Low (0-24)", "Medium (25-49)", "High (50-74)", "Critical (75-100)"],
            "data": [risk_counts["Low"], risk_counts["Medium"], risk_counts["High"], risk_counts["Critical"]],
            "colors": ["#10b981", "#f59e0b", "#f97316", "#ef4444"]
        },
        "department_compliance": {
            "labels": dept_labels,
            "data": dept_scores
        },
        "risk_trend": {
            "labels": trend_labels,
            "data": trend_scores
        },
        "top_failed_policies": {
            "labels": policy_labels,
            "data": policy_counts
        },
        "network_risk": {
            "labels": net_labels,
            "data": net_scores
        },
        "os_distribution": {
            "labels": list(os_counts.keys()),
            "data": list(os_counts.values())
        }
    }

@router.get("/riskiest")
def get_riskiest_devices(
    limit: int = 10,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).order_by(Device.risk_score.desc()).limit(limit).all()
    return [
        {
            "device_id": d.device_id,
            "hostname": d.hostname,
            "owner_name": d.owner_name,
            "owner_email": d.owner_email,
            "department": d.department,
            "role_level": d.role_level,
            "os_name": d.os_name,
            "network_type": d.network_type,
            "ownership": d.ownership,
            "risk_score": d.risk_score,
            "risk_level": d.risk_level,
            "compliance_percentage": d.compliance_percentage,
            "ztna_decision": d.ztna_decision,
            "pending_critical_patches": d.pending_critical_patches,
            "edr_agent_running": d.edr_agent_running
        }
        for d in devices
    ]

@router.get("/geo-anomalies")
def get_geo_anomalies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).filter(
        (Device.impossible_travel_flag == True) | (Device.geo_country.in_(["Brazil", "Singapore", "Australia"]))
    ).all()

    return [
        {
            "device_id": d.device_id,
            "hostname": d.hostname,
            "owner_name": d.owner_name,
            "geo_country": d.geo_country,
            "impossible_travel": d.impossible_travel_flag,
            "risk_score": d.risk_score,
            "risk_level": d.risk_level,
            "last_seen": d.last_seen
        }
        for d in devices
    ]
