from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.auth import install_api_auth, websocket_token_is_valid


def _app(token=None):
    app = FastAPI()
    install_api_auth(app, token)

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    @app.get("/api/private")
    def private():
        return {"secret": "protected"}

    return app


def test_auth_is_disabled_when_token_is_unset():
    response = TestClient(_app()).get("/api/private")
    assert response.status_code == 200


def test_health_is_public_but_other_api_routes_require_token():
    client = TestClient(_app("local-test-token"))

    assert client.get("/api/health").status_code == 200
    assert client.get("/api/private").status_code == 401
    assert client.get(
        "/api/private", headers={"Authorization": "Bearer wrong"}
    ).status_code == 401
    assert client.get(
        "/api/private", headers={"Authorization": "Bearer local-test-token"}
    ).json() == {"secret": "protected"}
    assert client.get(
        "/api/private", headers={"X-Agent-Firewall-Token": "local-test-token"}
    ).status_code == 200


def test_websocket_token_validation():
    assert websocket_token_is_valid(None, None)
    assert websocket_token_is_valid("local-test-token", "local-test-token")
    assert not websocket_token_is_valid(None, "local-test-token")
    assert not websocket_token_is_valid("wrong", "local-test-token")
