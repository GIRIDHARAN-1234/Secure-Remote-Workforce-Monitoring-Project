import datetime
import json
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="viewer")  # admin, analyst, viewer
    is_active = Column(Boolean, default=True)
    is_locked = Column(Boolean, default=False)
    failed_logins = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    mfa_secret = Column(String(100), nullable=True)
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(255), unique=True, index=True, nullable=False)
    user_email = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)

class Policy(Base):
    __tablename__ = "policies"

    id = Column(String(50), primary_key=True)  # POL-01
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100), nullable=False)  # Patch, Encryption, Endpoint Protection, Network, Identity, Device Integrity
    severity = Column(String(50), nullable=False)  # low, medium, high, critical
    weight = Column(Float, default=5.0)
    enabled = Column(Boolean, default=True)
    parameters = Column(Text, default="{}")  # JSON string
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    def get_params(self):
        try:
            return json.loads(self.parameters) if self.parameters else {}
        except Exception:
            return {}

    def set_params(self, params_dict):
        self.parameters = json.dumps(params_dict)

class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String(50), primary_key=True, index=True)
    hostname = Column(String(100), nullable=False)
    owner_name = Column(String(100), nullable=False)
    owner_email = Column(String(150), nullable=False)
    department = Column(String(100), nullable=False)
    role_level = Column(String(50), nullable=False)  # employee, manager, admin, contractor
    device_type = Column(String(50), nullable=False)  # laptop, desktop, mobile
    os_name = Column(String(50), nullable=False)  # Windows, macOS, Linux, iOS, Android
    os_version = Column(String(50), nullable=False)
    last_patch_date = Column(String(50), nullable=False)
    days_since_patch = Column(Integer, default=0)
    pending_critical_patches = Column(Integer, default=0)
    disk_encryption = Column(Boolean, default=True)
    firewall_enabled = Column(Boolean, default=True)
    antivirus_enabled = Column(Boolean, default=True)
    antivirus_signature_age_days = Column(Integer, default=1)
    edr_agent_running = Column(Boolean, default=True)
    screen_lock_enabled = Column(Boolean, default=True)
    secure_boot = Column(Boolean, default=True)
    tpm_present = Column(Boolean, default=True)
    jailbroken_or_rooted = Column(Boolean, default=False)
    mdm_enrolled = Column(Boolean, default=True)
    ownership = Column(String(50), default="corporate")  # corporate, BYOD
    failed_login_count_24h = Column(Integer, default=0)
    vpn_connected = Column(Boolean, default=False)
    network_type = Column(String(50), default="home")  # home, public_wifi, corporate_vpn, mobile_hotspot
    wifi_security = Column(String(50), default="WPA3")  # WPA3, WPA2, WPA, open, none
    dns_security = Column(String(50), default="DoH")  # DoH, standard, suspicious
    geo_country = Column(String(100), default="United States")
    impossible_travel_flag = Column(Boolean, default=False)
    access_sensitivity = Column(String(50), default="medium")  # low, medium, high, critical
    mfa_enabled = Column(Boolean, default=True)
    privileged_account = Column(Boolean, default=False)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    installed_risky_apps = Column(Integer, default=0)

    # Evaluated risk and posture values
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(50), default="Low")  # Low, Medium, High, Critical
    compliance_percentage = Column(Float, default=100.0)
    compliance_status = Column(String(50), default="Compliant")  # Compliant, At Risk, Non-Compliant
    ztna_decision = Column(String(50), default="ALLOW")  # ALLOW, ALLOW_WITH_STEP_UP_MFA, RESTRICT, BLOCK
    score_breakdown = Column(Text, default="{}")  # JSON representation of risk components
    failed_policies = Column(Text, default="[]")  # JSON list of failed policy IDs
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(50), primary_key=True, index=True)
    device_id = Column(String(50), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)  # low, medium, high, critical
    category = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(50), default="Open")  # Open, Acknowledged, Investigating, Resolved, False Positive
    mitre_technique = Column(String(100), nullable=True)  # e.g., T1562 Impair Defenses
    assigned_to = Column(String(150), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    device = relationship("Device", back_populates="alerts")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(255), nullable=True)
    details = Column(Text, default="{}")
    ip_address = Column(String(100), default="127.0.0.1")
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class RiskSnapshot(Base):
    __tablename__ = "risk_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    avg_risk_score = Column(Float, default=0.0)
    compliant_count = Column(Integer, default=0)
    at_risk_count = Column(Integer, default=0)
    non_compliant_count = Column(Integer, default=0)
    critical_device_count = Column(Integer, default=0)
    open_alerts_count = Column(Integer, default=0)
