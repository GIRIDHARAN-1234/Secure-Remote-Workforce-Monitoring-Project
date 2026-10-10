import re
import io
import base64
import time
import uuid
import datetime
from typing import Optional, Tuple, Dict, Any
from passlib.context import CryptContext
from jose import jwt, JWTError
import pyotp
import qrcode
from app.config import settings

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def validate_password_strength(password: str) -> Tuple[bool, str]:
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special symbol (!@#$%^&*...)."
    return True, "Strong password."

# JWT Tokens
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (
        expires_delta or datetime.timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "type": "access", "jti": jti})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict, expires_delta: Optional[datetime.timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + (
        expires_delta or datetime.timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    jti = str(uuid.uuid4())
    to_encode.update({"exp": expire, "type": "refresh", "jti": jti})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None

# MFA TOTP Utilities
def generate_mfa_secret() -> str:
    return pyotp.random_base32()

def generate_totp_qr_code(email: str, secret: str) -> Tuple[str, str]:
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="SentinelEdge")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=3,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    data_uri = f"data:image/png;base64,{img_b64}"
    
    return provisioning_uri, data_uri

def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code.strip(), valid_window=1)

# In-Memory Rate Limiter & Lockout Management
class InMemorySecurityLimiter:
    def __init__(self):
        self.failed_attempts: Dict[str, list] = {}  # email -> list of timestamps
        self.lockouts: Dict[str, float] = {}        # email -> lock expiry timestamp
        self.rate_limits: Dict[str, list] = {}      # ip -> list of timestamps

    def check_rate_limit(self, client_ip: str, max_requests: int = 30, window_seconds: int = 60) -> bool:
        now = time.time()
        timestamps = [t for t in self.rate_limits.get(client_ip, []) if now - t < window_seconds]
        if len(timestamps) >= max_requests:
            return False
        timestamps.append(now)
        self.rate_limits[client_ip] = timestamps
        return True

    def is_locked_out(self, email: str) -> Tuple[bool, int]:
        now = time.time()
        expiry = self.lockouts.get(email.lower())
        if expiry and now < expiry:
            return True, int(expiry - now)
        elif expiry:
            # Lock expired
            del self.lockouts[email.lower()]
            self.failed_attempts.pop(email.lower(), None)
        return False, 0

    def record_failed_login(self, email: str) -> Tuple[int, bool]:
        now = time.time()
        email_clean = email.lower()
        attempts = [t for t in self.failed_attempts.get(email_clean, []) if now - t < settings.LOCKOUT_DURATION_MINUTES * 60]
        attempts.append(now)
        self.failed_attempts[email_clean] = attempts
        
        if len(attempts) >= settings.MAX_FAILED_LOGINS:
            self.lockouts[email_clean] = now + (settings.LOCKOUT_DURATION_MINUTES * 60)
            return len(attempts), True
        return len(attempts), False

    def reset_failed_logins(self, email: str):
        email_clean = email.lower()
        self.failed_attempts.pop(email_clean, None)
        self.lockouts.pop(email_clean, None)

security_limiter = InMemorySecurityLimiter()
