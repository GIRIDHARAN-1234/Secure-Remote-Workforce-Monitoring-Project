from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AuditLog, User
from app.auth.deps import get_current_user, require_role, get_client_ip
from app.services.simulator import mutate_live_telemetry

router = APIRouter(prefix="/simulator", tags=["Live Simulator"])

@router.post("/mutate")
def trigger_telemetry_drift(
    count: int = 5,
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    mutations = mutate_live_telemetry(db, count=count)
    client_ip = get_client_ip(request)

    audit = AuditLog(
        user_email=current_user.email,
        action="SIMULATOR_DRIFT_TRIGGERED",
        target=f"{len(mutations)} devices",
        details=f"Live telemetry drift injected into {len(mutations)} endpoints.",
        ip_address=client_ip
    )
    db.add(audit)
    db.commit()

    return {
        "message": f"Successfully simulated live telemetry drift on {len(mutations)} endpoints.",
        "mutations": mutations
    }
