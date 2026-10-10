from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Device, User
from app.auth.deps import get_current_user
from app.schemas import ZTNAEvaluationRequest, ZTNAEvaluationResponse
from app.services.ztna import evaluate_ztna_access, RESOURCE_SENSITIVITY_MAP

router = APIRouter(prefix="/ztna", tags=["Zero Trust Access"])

@router.get("/resources")
def list_resources(current_user: User = Depends(get_current_user)):
    return [
        {
            "name": name,
            "sensitivity": sens,
            "description": f"{sens.upper()} sensitivity corporate enterprise asset"
        }
        for name, sens in RESOURCE_SENSITIVITY_MAP.items()
    ]

@router.post("/evaluate", response_model=ZTNAEvaluationResponse)
def evaluate_access(
    req: ZTNAEvaluationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    device = db.query(Device).filter(Device.device_id == req.device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail=f"Device {req.device_id} not found.")

    res = evaluate_ztna_access(device, req.resource_name)
    return ZTNAEvaluationResponse(**res)
