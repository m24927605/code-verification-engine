from fastapi import Header, HTTPException
from auth.jwt import verify_token

def require_auth(authorization: str = Header(...)):
    """FastAPI dependency for authentication."""
    try:
        return verify_token(authorization)
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")
