import datetime
import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, TokenBlacklist, PasswordResetToken, AuditLog
from app.schemas import (
    UserLogin, UserRegister, UserResponse, PasswordChange,
    ForgotPasswordRequest, ResetPasswordRequest,
    MFASetupResponse, MFAVerifyRequest
)
from app.auth.security import (
    verify_password, get_password_hash, validate_password_strength,
    create_access_token, create_refresh_token, decode_token,
    generate_mfa_secret, generate_totp_qr_code, verify_totp_code,
    security_limiter
)
from app.auth.deps import get_current_user, get_client_ip
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

def log_audit(db: Session, email: str, action: str, details: str, ip: str, target: Optional[str] = None):
    try:
        audit = AuditLog(
            user_email=email,
            action=action,
            target=target or email,
            details=details,
            ip_address=ip
        )
        db.add(audit)
        db.commit()
    except Exception:
        db.rollback()

@router.post("/login")
def login(
    login_data: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # 1. Rate Limiting Check
    if not security_limiter.check_rate_limit(client_ip, max_requests=settings.RATE_LIMIT_REQUESTS_PER_MINUTE):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Too many requests from your IP, please slow down.",
        )
        
    email_clean = login_data.email.lower().strip()
    
    # 2. Account Lockout Check
    is_locked, remaining_seconds = security_limiter.is_locked_out(email_clean)
    if is_locked:
        mins = max(1, remaining_seconds // 60)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account locked due to 5 consecutive failed login attempts. Try again in {mins} minute(s).",
        )
        
    user = db.query(User).filter(User.email == email_clean).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        attempts, locked_now = security_limiter.record_failed_login(email_clean)
        log_audit(db, email_clean, "LOGIN_FAILED", f"Failed login attempt from {client_ip} (Attempt {attempts}/{settings.MAX_FAILED_LOGINS})", client_ip)
        
        if locked_now:
            if user:
                user.is_locked = True
                user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                db.commit()
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account has been locked for {settings.LOCKOUT_DURATION_MINUTES} minutes due to {settings.MAX_FAILED_LOGINS} consecutive failed attempts.",
            )
            
        remaining = settings.MAX_FAILED_LOGINS - attempts
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid email or password. {remaining} attempt(s) remaining before account lockout.",
        )
        
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Please contact your security administrator.",
        )
        
    # Check if DB-level lock has expired
    if user.is_locked:
        if user.locked_until and datetime.datetime.utcnow() > user.locked_until:
            user.is_locked = False
            user.locked_until = None
            user.failed_logins = 0
            db.commit()
        else:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is administratively locked.",
            )

    # 3. TOTP MFA Check
    if user.mfa_enabled and user.mfa_secret:
        if not login_data.totp_code:
            return {
                "mfa_required": True,
                "message": "Two-factor authentication code required.",
                "email": user.email
            }
        
        if not verify_totp_code(user.mfa_secret, login_data.totp_code):
            log_audit(db, email_clean, "LOGIN_MFA_FAILED", f"Invalid TOTP MFA token from {client_ip}", client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid two-factor authentication code. Please check your authenticator app.",
            )

    # Login Success
    security_limiter.reset_failed_logins(email_clean)
    user.failed_logins = 0
    db.commit()

    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.email, "role": user.role})

    # Set HttpOnly, SameSite=Strict cookies
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False  # allow localhost testing without https
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        secure=False
    )

    log_audit(db, user.email, "LOGIN_SUCCESS", f"User logged in successfully with role {user.role}", client_ip)

    return {
        "mfa_required": False,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "mfa_enabled": user.mfa_enabled
        }
    }

@router.post("/register")
def register(
    register_data: UserRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # Validate password strength
    is_strong, msg = validate_password_strength(register_data.password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)
        
    email_clean = register_data.email.lower().strip()
    existing = db.query(User).filter(User.email == email_clean).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )
        
    # Restrict arbitrary registration role (default to analyst or viewer)
    assigned_role = register_data.role if register_data.role in ["analyst", "viewer"] else "analyst"

    user = User(
        email=email_clean,
        full_name=register_data.full_name.strip(),
        hashed_password=get_password_hash(register_data.password),
        role=assigned_role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit(db, user.email, "USER_REGISTERED", f"New user registered with role {user.role}", client_ip)

    return {
        "message": "User registered successfully. You may now log in.",
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.post("/refresh")
def refresh_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    token = request.cookies.get("refresh_token")
    if not token:
        # Also check Authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    payload = decode_token(token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    jti = payload.get("jti")
    if jti:
        blacklisted = db.query(TokenBlacklist).filter(TokenBlacklist.jti == jti).first()
        if blacklisted:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has been revoked",
            )

    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.is_active or user.is_locked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User session is no longer active",
        )

    new_access_token = create_access_token({"sub": user.email, "role": user.role})

    response.set_cookie(
        key="access_token",
        value=new_access_token,
        httponly=True,
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=False
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)

    # Blacklist current tokens if possible
    for cookie_name in ["access_token", "refresh_token"]:
        token = request.cookies.get(cookie_name)
        if token:
            payload = decode_token(token)
            if payload and "jti" in payload:
                exp = datetime.datetime.utcfromtimestamp(payload.get("exp", 0))
                db.add(TokenBlacklist(jti=payload["jti"], expires_at=exp))
    db.commit()

    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    log_audit(db, current_user.email, "LOGOUT", "User logged out and session revoked", client_ip)

    return {"message": "Logged out successfully. Tokens revoked."}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.post("/change-password")
def change_password(
    data: PasswordChange,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    is_strong, msg = validate_password_strength(data.new_password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    current_user.hashed_password = get_password_hash(data.new_password)
    db.commit()

    log_audit(db, current_user.email, "PASSWORD_CHANGED", "User successfully changed password", client_ip)

    return {"message": "Password updated successfully."}

@router.post("/forgot-password")
def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    email_clean = data.email.lower().strip()
    user = db.query(User).filter(User.email == email_clean).first()
    
    # Always return a message for security; if user exists, create token
    reset_token = secrets.token_urlsafe(32)
    if user:
        expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        db.add(PasswordResetToken(token=reset_token, user_email=user.email, expires_at=expiry))
        db.commit()
        log_audit(db, user.email, "PASSWORD_RESET_REQUESTED", f"Reset token generated: {reset_token}", client_ip)

    # Return reset_token directly in response for demo hackathon convenience
    return {
        "message": "If this email exists, a password reset link has been dispatched.",
        "demo_reset_token": reset_token if user else None,
        "note": "In this demo environment without SMTP server, use the demo_reset_token to complete reset."
    }

@router.post("/reset-password")
def reset_password(
    data: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    token_record = db.query(PasswordResetToken).filter(
        PasswordResetToken.token == data.token,
        PasswordResetToken.used == False
    ).first()

    if not token_record or datetime.datetime.utcnow() > token_record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token is invalid or has expired.",
        )

    is_strong, msg = validate_password_strength(data.new_password)
    if not is_strong:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    user = db.query(User).filter(User.email == token_record.user_email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    user.hashed_password = get_password_hash(data.new_password)
    user.is_locked = False
    user.failed_logins = 0
    token_record.used = True
    db.commit()

    log_audit(db, user.email, "PASSWORD_RESET_SUCCESS", "Password reset successfully completed", client_ip)

    return {"message": "Password has been reset successfully. You can now log in with your new password."}

@router.post("/mfa/setup", response_model=MFASetupResponse)
def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Generate temporary secret or keep existing
    secret = generate_mfa_secret()
    current_user.mfa_secret = secret
    db.commit()

    uri, qr_b64 = generate_totp_qr_code(current_user.email, secret)

    return {
        "secret": secret,
        "otpauth_url": uri,
        "qr_code_base64": qr_b64
    }

@router.post("/mfa/verify")
def verify_mfa_setup(
    data: MFAVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initiated. Please run setup first.",
        )

    if not verify_totp_code(current_user.mfa_secret, data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is incorrect. Please try again.",
        )

    current_user.mfa_enabled = True
    db.commit()

    log_audit(db, current_user.email, "MFA_ENABLED", "Two-factor authentication successfully enabled", client_ip)

    return {"message": "Two-factor authentication (TOTP) has been successfully verified and enabled!"}

@router.post("/mfa/disable")
def disable_mfa(
    data: MFAVerifyRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = get_client_ip(request)
    if not current_user.mfa_enabled:
        return {"message": "MFA is already disabled."}

    # Verify code before disabling
    if not verify_totp_code(current_user.mfa_secret, data.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is incorrect. Cannot disable MFA.",
        )

    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()

    log_audit(db, current_user.email, "MFA_DISABLED", "Two-factor authentication disabled", client_ip)

    return {"message": "Two-factor authentication disabled successfully."}
