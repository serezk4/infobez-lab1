import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from secure_api import SCHEMA, create_app


@pytest.fixture()
def app(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "JWT_SECRET": secrets.token_hex(32),
        }
    )
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.executescript(SCHEMA)
        for name in ("alice", "bob"):
            db.execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (name, generate_password_hash("test-passphrase-123")),
            )
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


def login_headers(client, username="alice"):
    response = client.post(
        "/auth/login", json={"username": username, "password": "test-passphrase-123"}
    )
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json["access_token"]}


def test_notes_are_private(client):
    headers = login_headers(client)
    assert client.get("/api/data", headers=headers).json == {"data": []}
    response = client.post("/api/data", headers=headers, json={"text": "hello"})
    assert response.status_code == 201
    assert client.get("/api/data", headers=headers).json["data"] == [response.json]
    assert client.get("/api/data", headers=login_headers(client, "bob")).json == {
        "data": []
    }


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("header", ["", "Bearer garbage", "Basic abc", "Bearer"])
def test_unauthorized(client, method, header):
    assert (
        getattr(client, method)(
            "/api/data", headers={"Authorization": header}
        ).status_code
        == 401
    )


@pytest.mark.parametrize(
    "username,password",
    [
        ("alice' OR 1=1 --", "x"),
        ("alice", "' OR 1=1 --"),
        ("alice", "wrong"),
        ("unknown", "wrong"),
    ],
)
def test_login_rejected(client, username, password):
    assert (
        client.post(
            "/auth/login", json={"username": username, "password": password}
        ).status_code
        == 401
    )


def test_xss_and_sql_payload_stored_as_data(client, app):
    headers = login_headers(client)
    payload = '<script>alert("x")</script>\'; DROP TABLE users; --'
    response = client.post("/api/data", headers=headers, json={"text": payload})
    assert response.status_code == 201
    assert "<script>" not in response.json["text"]
    assert "&lt;script&gt;" in response.json["text"]
    assert client.get("/api/data", headers=headers).json["data"][0] == response.json
    with sqlite3.connect(app.config["DATABASE"]) as db:
        assert db.execute("SELECT text FROM notes").fetchone()[0] == payload
        assert db.execute("SELECT count(*) FROM users").fetchone()[0] == 2


@pytest.mark.parametrize(
    "variant",
    [
        "expired",
        "future",
        "signature",
        "algorithm",
        "issuer",
        "audience",
        "missing",
        "unknown",
    ],
)
def test_invalid_jwt(client, app, variant):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "1",
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(minutes=15),
        "iss": "lab1-api",
        "aud": "lab1-client",
        "jti": secrets.token_hex(16),
    }
    key, algorithm = app.config["JWT_SECRET"], "HS256"
    if variant == "expired":
        payload["exp"] = now - timedelta(seconds=10)
    elif variant == "future":
        payload["nbf"] = now + timedelta(minutes=5)
    elif variant == "signature":
        key = secrets.token_hex(32)
    elif variant == "algorithm":
        algorithm = "HS384"
    elif variant == "issuer":
        payload["iss"] = "other"
    elif variant == "audience":
        payload["aud"] = "other"
    elif variant == "missing":
        del payload["exp"]
    elif variant == "unknown":
        payload["sub"] = "999"
    token = jwt.encode(payload, key, algorithm=algorithm)
    assert (
        client.get(
            "/api/data", headers={"Authorization": "Bearer " + token}
        ).status_code
        == 401
    )


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"username": [], "password": "x"},
        {"username": "alice", "password": "x", "extra": 1},
    ],
)
def test_bad_login_input(client, payload):
    response = client.post("/auth/login", json=payload)
    assert response.status_code in (400, 415)


@pytest.mark.parametrize(
    "payload", [{}, [], {"text": ""}, {"text": " "}, {"text": 1}, {"text": "x" * 2001}]
)
def test_bad_note_input(client, payload):
    assert (
        client.post(
            "/api/data", headers=login_headers(client), json=payload
        ).status_code
        == 400
    )


def test_headers_limits_and_content_type(client):
    response = client.get("/api/data")
    assert response.content_type == "application/json"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert (
        client.post("/auth/login", data="x", content_type="text/plain").status_code
        == 415
    )
    assert (
        client.post(
            "/auth/login", data="x" * 17000, content_type="application/json"
        ).status_code
        == 413
    )


def test_password_hash_and_cli(app):
    runner = app.test_cli_runner()
    result = runner.invoke(
        args=["create-user", "charlie"],
        input="new-passphrase-123\nnew-passphrase-123\n",
    )
    assert result.exit_code == 0
    with sqlite3.connect(app.config["DATABASE"]) as db:
        password_hash = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("charlie",)
        ).fetchone()[0]
    assert password_hash.startswith("scrypt:")
    assert check_password_hash(password_hash, "new-passphrase-123")
    assert (
        runner.invoke(args=["create-user", "bad!", "--password", "short"]).exit_code
        != 0
    )


def test_secret_required(tmp_path):
    with pytest.raises(ValueError):
        create_app({"JWT_SECRET": "short", "DATABASE": str(tmp_path / "db")})
