import secrets 
import hashlib
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from common.config.settings import get_settings
from common.utils.crypto import encryp_payload, decrypt_payload

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

# ---- Access Token ----
def create_acces_token(
        user_id: str, 
        email: str,
        phone: str,
        display_name: str,
        unique_session_id: str
        ) -> tuple[str, str]:
    
    settings = get_settings()
    now = _utcnow()
    jti = secrets.token_hex(16)
    exp = now + timedelta(minutes=settings.access_token_expire_minutes)

    inner_claims = {
        "sub": user_id,
        "email": email,
        "uid": unique_session_id,
        "phone": phone,
        "display_name": display_name,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "type": "access"
    }

    encrypted_claims = encryp_payload(inner_claims)

    outer_claims = {
        "enc": encrypted_claims,
        "jti": jti,
        "exp": int(exp.timestamp())
    }

    token = jwt.encode(outer_claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return token, jti


# ---- Refresh Token ----
def create_refresh_token(
        user_id: str,
        unique_session_id: str
        ) -> tuple[str, str, str]:
    
    settings = get_settings()
    now = _utcnow()
    jti = secrets.token_hex(16)
    exp = now + timedelta(days=settings.refresh_token_expire_days)

    inner_claims = {
        "sub": user_id,
        "uid": unique_session_id, 
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti
    }

    encrypted_claims = encryp_payload(inner_claims)
    outer_claims = {
        "enc": encrypted_claims,
        "jti": jti,
        "exp": int(exp.timestamp())
    }

    token = jwt.encode(outer_claims, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, jti, token_hash

# --- Decode & Verify ---
def decode_token(token: str) -> dict:
    settings = get_settings()
    try:
        outer = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        return decrypt_payload(outer["enc"])
    except JWTError:
        raise
    except Exception as e:
        raise JWTError(f"Token decoding failed: {e}") from e

def decode_refresh_token(token: str) -> dict:
    try:
        settings = get_settings()
        outer = jwt.decode(
            token, 
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": True}
        )
        return decrypt_payload(outer["enc"])
    except Exception as e:
        return None
    
def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()