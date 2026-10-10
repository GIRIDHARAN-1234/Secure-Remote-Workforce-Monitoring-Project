import os
import json
from pathlib import Path
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.database import engine, Base, SessionLocal
from app.models import User
from app.auth.security import get_password_hash
from app.services.simulator import seed_simulation_data, generate_endpoint_telemetry_dataset
from app.services.reports import generate_devices_csv

# Import route modules
from app.auth.routes import router as auth_router
from app.routes.dashboard import router as dashboard_router
from app.routes.devices import router as devices_router
from app.routes.alerts import router as alerts_router
from app.routes.policies import router as policies_router
from app.routes.recommendations import router as recommendations_router
from app.routes.ztna import router as ztna_router
from app.routes.import_export import router as import_export_router
from app.routes.users import router as users_router
from app.routes.audit import router as audit_router
from app.routes.simulator import router as simulator_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# ----------------- Security Headers Middleware -----------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # CSP allowing Tailwind CDN, Chart.js CDN, Google Fonts, and inline scripts for SPA
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com data:; "
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:;"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# ----------------- CORS Middleware -----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Include API Routers -----------------
api_v1 = settings.API_V1_STR
app.include_router(auth_router, prefix=api_v1)
app.include_router(dashboard_router, prefix=api_v1)
app.include_router(devices_router, prefix=api_v1)
app.include_router(alerts_router, prefix=api_v1)
app.include_router(policies_router, prefix=api_v1)
app.include_router(recommendations_router, prefix=api_v1)
app.include_router(ztna_router, prefix=api_v1)
app.include_router(import_export_router, prefix=api_v1)
app.include_router(users_router, prefix=api_v1)
app.include_router(audit_router, prefix=api_v1)
app.include_router(simulator_router, prefix=api_v1)

# ----------------- Database Initialization & Seeding -----------------
def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        # Seed Demo Users
        demo_users = [
            ("admin@sentineledge.io", "Admin Security Lead", "Admin@12345!", "admin"),
            ("analyst@sentineledge.io", "Alex Hunter (SOC Analyst)", "Analyst@12345!", "analyst"),
            ("viewer@sentineledge.io", "Sam Auditor (Viewer)", "Viewer@12345!", "viewer"),
        ]
        for email, full_name, raw_pwd, role in demo_users:
            existing = db.query(User).filter(User.email == email).first()
            if not existing:
                u = User(
                    email=email,
                    full_name=full_name,
                    hashed_password=get_password_hash(raw_pwd),
                    role=role,
                    is_active=True,
                    is_locked=False,
                    mfa_enabled=False
                )
                db.add(u)
        db.commit()

        # Seed Policies, Devices, Alerts, Snapshots
        seed_simulation_data(db)

        # Export sample CSV to data/
        data_dir = settings.DATA_DIR
        data_dir.mkdir(parents=True, exist_ok=True)
        csv_sample_path = data_dir / "sample_telemetry.csv"
        if not csv_sample_path.exists():
            from app.models import Device
            all_devs = db.query(Device).all()
            if all_devs:
                csv_sample_path.write_text(generate_devices_csv(all_devs[:50]), encoding="utf-8")
    finally:
        db.close()

@app.on_event("startup")
def on_startup():
    seed_database()

# ----------------- Static Files & Single Page App -----------------
static_path = settings.STATIC_DIR
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

@app.get("/")
def serve_index():
    index_file = settings.STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return HTMLResponse("<h1>SentinelEdge is starting up... Please refresh in a moment.</h1>")

@app.get("/health")
def health_check():
    return {"status": "ok", "app": settings.PROJECT_NAME, "version": settings.VERSION}
