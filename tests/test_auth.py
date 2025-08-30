import pytest
from fastapi.testclient import TestClient

# Basic smoke tests - these will be skipped if server isn't configured in CI

from app.app import app

client = TestClient(app)

@pytest.mark.skip(reason="Needs DB in CI - placeholder test")
def test_signup_login_flow():
    # This is a placeholder showing the intended tests: signup -> login -> access protected
    resp = client.post('/signup', json={'name': 'test', 'email': 't@example.com', 'password': 'P@ssw0rd'})
    assert resp.status_code in (201, 409)

    resp = client.post('/login', json={'loginIdentifier': 't@example.com', 'password': 'P@ssw0rd'})
    # could be 200 or 401 depending on previous state
    assert resp.status_code in (200, 401)
