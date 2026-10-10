import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field

# ----------------- Auth Schemas -----------------
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]

class TokenPayload(BaseModel):
    sub: str
    role: str
    jti: str
    exp: int
    type: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str
    totp_code: Optional[str] = None

class UserRegister(BaseModel):
    email: EmailStr
    full_name: str
    password: str
    role: Optional[str] = "analyst"

class UserResponse(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    is_locked: bool
    mfa_enabled: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class MFASetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_base64: str

class MFAVerifyRequest(BaseModel):
    code: str

class UserUpdateRole(BaseModel):
    role: str

class UserToggleActive(BaseModel):
    is_active: bool

# ----------------- Policy Schemas -----------------
class PolicyBase(BaseModel):
    id: str
    name: str
    description: str
    category: str
    severity: str
    weight: float
    enabled: bool
    parameters: Optional[Dict[str, Any]] = None

class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    weight: Optional[float] = None
    enabled: Optional[bool] = None
    parameters: Optional[Dict[str, Any]] = None

class PolicyResponse(PolicyBase):
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

# ----------------- Device Schemas -----------------
class DeviceResponse(BaseModel):
    device_id: str
    hostname: str
    owner_name: str
    owner_email: str
    department: str
    role_level: str
    device_type: str
    os_name: str
    os_version: str
    last_patch_date: str
    days_since_patch: int
    pending_critical_patches: int
    disk_encryption: bool
    firewall_enabled: bool
    antivirus_enabled: bool
    antivirus_signature_age_days: int
    edr_agent_running: bool
    screen_lock_enabled: bool
    secure_boot: bool
    tpm_present: bool
    jailbroken_or_rooted: bool
    mdm_enrolled: bool
    ownership: str
    failed_login_count_24h: int
    vpn_connected: bool
    network_type: str
    wifi_security: str
    dns_security: str
    geo_country: str
    impossible_travel_flag: bool
    access_sensitivity: str
    mfa_enabled: bool
    privileged_account: bool
    last_seen: datetime.datetime
    installed_risky_apps: int
    risk_score: float
    risk_level: str
    compliance_percentage: float
    compliance_status: str
    ztna_decision: str
    score_breakdown: Optional[str] = None
    failed_policies: Optional[str] = None

    class Config:
        from_attributes = True

class DeviceDetailResponse(DeviceResponse):
    failed_policy_details: List[Dict[str, Any]] = []
    passed_policy_details: List[Dict[str, Any]] = []
    remediation_recommendations: List[Dict[str, Any]] = []
    active_alerts: List[Dict[str, Any]] = []
    ztna_explanation: Dict[str, Any] = {}

class DeviceRemediateRequest(BaseModel):
    policy_ids: Optional[List[str]] = None  # None = fix all failed policies

# ----------------- Alert Schemas -----------------
class AlertResponse(BaseModel):
    id: str
    device_id: Optional[str]
    title: str
    severity: str
    category: str
    description: str
    status: str
    mitre_technique: Optional[str]
    assigned_to: Optional[str]
    notes: Optional[str]
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

class AlertUpdateStatus(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None

class AlertBulkUpdate(BaseModel):
    alert_ids: List[str]
    status: str
    assigned_to: Optional[str] = None

# ----------------- ZTNA Schemas -----------------
class ZTNAEvaluationRequest(BaseModel):
    device_id: str
    resource_name: str  # e.g., "HR Database", "Source Code", "Finance ERP", "Email", "Internal Wiki"

class ZTNAEvaluationResponse(BaseModel):
    device_id: str
    resource_name: str
    resource_sensitivity: str
    decision: str  # ALLOW, ALLOW_WITH_STEP_UP_MFA, RESTRICT, BLOCK
    reason: str
    risk_score: float
    risk_level: str
    rule_path: List[Dict[str, Any]]
    remediation_suggestions: List[str]

# ----------------- Recommendations Schemas -----------------
class FleetRecommendation(BaseModel):
    policy_id: str
    title: str
    category: str
    priority: str
    affected_devices_count: int
    total_risk_reduction_points: float
    estimated_effort: str
    action_description: str

class DeviceRecommendation(BaseModel):
    policy_id: str
    title: str
    priority: str
    risk_reduction_points: float
    estimated_effort: str
    action: str

# ----------------- Dashboard & Audit Schemas -----------------
class DashboardStatsResponse(BaseModel):
    total_devices: int
    compliance_percentage: float
    avg_risk_score: float
    critical_devices_count: int
    high_devices_count: int
    medium_devices_count: int
    low_devices_count: int
    open_alerts_count: int
    byod_percentage: float
    unpatched_percentage: float
    security_posture_score: float
    letter_grade: str

class AuditLogResponse(BaseModel):
    id: int
    user_email: str
    action: str
    target: Optional[str]
    details: str
    ip_address: str
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class ImportSummaryResponse(BaseModel):
    total_rows: int
    created: int
    updated: int
    errors: List[str]
