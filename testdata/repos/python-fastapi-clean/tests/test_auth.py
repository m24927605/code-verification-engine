import pytest
from auth.jwt import verify_token

def test_verify_token_invalid():
    with pytest.raises(Exception):
        verify_token("invalid")

def test_verify_token_empty():
    with pytest.raises(Exception):
        verify_token("")

class TestAuthMiddleware:
    def test_require_auth_missing(self):
        pass
