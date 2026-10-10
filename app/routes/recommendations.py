from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, User
from app.auth.deps import get_current_user
from app.schemas import FleetRecommendation, DeviceRecommendation
from app.services.recommendations import get_fleet_recommendations, get_device_recommendations

router = APIRouter(prefix="/recommendations", tags=["Recommendations"])

@router.get("/fleet", response_model=List[FleetRecommendation])
def get_fleet_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    devices = db.query(Device).all()
    fleet_recs = get_fleet_recommendations(devices)
    return [FleetRecommendation(**r) for r in fleet_recs]

@router.get("/device/{device_id}")
def get_device_recommendations_route(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.device_id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {device_id} not found.")

    recs, projected_score = get_device_recommendations(device)
    return {
        "device_id": device.device_id,
        "hostname": device.hostname,
        "current_risk_score": device.risk_score,
        "projected_risk_score": projected_score,
        "potential_reduction": round(max(0.0, device.risk_score - projected_score), 1),
        "recommendations": recs
    }
