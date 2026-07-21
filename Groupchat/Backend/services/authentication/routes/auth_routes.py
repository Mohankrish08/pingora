from fastapi import APIRouter, HTTPException, status

from common.config.redis_client import get_redis_client
from common.security.password import hash_password, verify_password
from common.utils.otp import generate_totp_secret, get_totp_provisioning_uri, create_sms_otp
from common.utils.crypto import aes_encrypt


from schema.auth_schemas import RegisterRequest, RegisterResponse
from repositories.user_repository import find_by_email_or_phone, create_user

router = APIRouter(tags=["auth"])

async def _send_sms(phone_number: str, otp: str) -> None:
    print("f[DEV ONLY] need to send SMS to {phone_number} with OTP: {otp}")

@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest):
   

    # 1. Check if email or phone number is already registered
    existing = find_by_email_or_phone(payload.email, payload.phone_number)

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone number already exists"
        )

    # 2. Password Hash
    password_hash = hash_password(payload.password)

    # 3. Generate TOTP secret and encrypt it
    totp_secret = generate_totp_secret()
    encrypted_totp_secret = aes_encrypt(totp_secret)
    provisioning_uri = get_totp_provisioning_uri(totp_secret, payload.email)

    # 4. Create the user in the database
    try:
        # user = create_user(
        #     email=payload.email,
        #     phone_number=payload.phone_number,
        #     password_hash=password_hash,
        #     display_name=payload.display_name,
        #     encrypted_totp_secret=encrypted_totp_secret
        # )
        print("PAYLOAD: ", payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Failed to create user: {e}"
        )
    
   # 5. Generate OTP and send it via SMS
    redis = get_redis_client()
    otp = await create_sms_otp(redis, identifier=payload.phone_number)
    await _send_sms(payload.phone_number, otp)

    return RegisterResponse(
        user_id=user["id"],
        email=user["email"],
        phone_number=user["phone_number"],
        totp_provisioning_uri=provisioning_uri,
        email_verified=False,
        phone_verified=False
    )
    