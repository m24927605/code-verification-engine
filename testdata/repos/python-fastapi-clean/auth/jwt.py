import os
import jwt

SECRET_KEY = os.environ.get("JWT_SECRET", "")

def verify_token(token: str) -> dict:
    """Verify a JWT token and return claims."""
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
