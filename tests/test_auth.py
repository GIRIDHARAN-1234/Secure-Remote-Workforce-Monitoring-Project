import pytest
from app.auth.security import (
    verify_password, get_password_hash, validate_password_strength,
    create_access_token, decode_token, InMemorySecurityLimiter,
    generate_mfa_secret, verify_totp_code
)
import pyotp

def test_password_hashing():
    raw = "CyberSec@2026!"
    hashed = get_password_hash(raw)
    assert hashed != raw
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False

def test_password_strength():
    # Weak: too short
    valid, msg = validate_password_strength("Short1!")
    assert valid is False
    assert "at least 10 characters" in msg

    # Weak: no uppercase
    valid, msg = validate_password_strength("lowercase1234!")
    assert valid is False
    assert "uppercase" in msg

    # Weak: no symbol
    valid, msg = validate_password_strength("StrongPass12345")
    assert valid is False
    assert "symbol" in msg

    # Strong
    valid, msg = validate_password_strength("Admin@12345!")
    assert valid is True

def test_jwt_tokens():
    payload = {"sub": "analyst@sentineledge.io", "role": "analyst"}
    token = create_access_token(payload)
    decoded = decode_token(token)
    assert decoded is not None
    assert decoded["sub"] == "analyst@sentineledge.io"
    assert decoded["role"] == "analyst"
    assert decoded["type"] == "access"

def test_account_lockout_after_five_attempts():
    limiter = InMemorySecurityLimiter()
    test_email = "victim@sentineledge.io"

    # 4 failed attempts -> not locked yet
    for i in range(4):
        attempts, locked = limiter.record_failed_login(test_email)
        assert locked is False
        assert attempts == i + 1

    # 5th failed attempt -> locked out!
    attempts, locked = limiter.record_failed_login(test_email)
    assert locked is True
    assert attempts == 5

    # Check lockout status
    is_locked, remaining = limiter.is_locked_out(test_email)
    assert is_locked is True
    assert remaining > 0

    # Reset
    limiter.reset_failed_logins(test_email)
    is_locked, remaining = limiter.is_locked_out(test_email)
    assert is_locked is False

def test_totp_mfa_verification():
    secret = generate_mfa_secret()
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    assert verify_totp_code(secret, current_code) is True
    assert verify_totp_code(secret, "000000") is False
