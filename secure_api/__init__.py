"""API личных заметок."""

import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from html import escape
from pathlib import Path

import click
import jwt
from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id),
    text TEXT NOT NULL
);
"""


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        JWT_SECRET=os.environ.get("JWT_SECRET", ""),
        DATABASE=os.environ.get(
            "DATABASE", str(Path(app.instance_path) / "data.sqlite3")
        ),
        JWT_ISSUER="lab1-api",
        JWT_AUDIENCE="lab1-client",
        JWT_TTL=900,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if config:
        app.config.update(config)
    secret = app.config["JWT_SECRET"]
    if not isinstance(secret, str) or len(secret.encode()) < 32:
        raise ValueError(
            "JWT_SECRET must contain at least 32 bytes; generate with secrets.token_hex(32)"
        )
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error):
        connection = g.pop("db", None)
        if connection is not None:
            connection.close()

    @app.cli.command("init-db")
    def init_db():
        get_db().executescript(SCHEMA)
        get_db().commit()
        click.echo("Database initialized.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.password_option(confirmation_prompt=True)
    def create_user(username, password):
        if (
            not re.fullmatch(r"[A-Za-z0-9_]{3,64}", username)
            or not 12 <= len(password) <= 256
        ):
            raise click.ClickException(
                "Username: 3–64 letters/digits/underscore; password: 12–256 characters."
            )
        try:
            get_db().execute(
                "INSERT INTO users(username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password, method="scrypt")),
            )
            get_db().commit()
        except sqlite3.IntegrityError as exc:
            raise click.ClickException("Username already exists.") from exc
        click.echo("User created.")

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    def read_json(fields):
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != set(fields):
            return None
        if not all(isinstance(data[key], str) for key in fields):
            return None
        return data

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            auth = request.headers.get("Authorization", "").split()
            if len(auth) != 2 or auth[0].lower() != "bearer":
                return jsonify(error="Authentication required"), 401
            try:
                payload = jwt.decode(
                    auth[1],
                    app.config["JWT_SECRET"],
                    algorithms=["HS256"],
                    issuer=app.config["JWT_ISSUER"],
                    audience=app.config["JWT_AUDIENCE"],
                    options={
                        "require": ["sub", "exp", "iat", "nbf", "iss", "aud", "jti"]
                    },
                )
                user = (
                    get_db()
                    .execute("SELECT id FROM users WHERE id = ?", (payload["sub"],))
                    .fetchone()
                )
                if user is None:
                    raise jwt.InvalidTokenError("Unknown user")
                g.user_id = user["id"]
            except jwt.InvalidTokenError:
                return jsonify(error="Invalid or expired token"), 401
            return view(*args, **kwargs)

        return wrapped

    # Проверяем scrypt даже для неизвестного логина, чтобы не отвечать быстрее.
    dummy_hash = generate_password_hash(secrets.token_hex(32), method="scrypt")

    @app.post("/auth/login")
    def login():
        data = read_json(["username", "password"])
        if (
            data is None
            or not 1 <= len(data["username"]) <= 64
            or not 1 <= len(data["password"]) <= 256
        ):
            return jsonify(error="Invalid credentials format"), 400
        user = (
            get_db()
            .execute("SELECT * FROM users WHERE username = ?", (data["username"],))
            .fetchone()
        )
        valid = check_password_hash(
            user["password_hash"] if user else dummy_hash, data["password"]
        )
        if user is None or not valid:
            return jsonify(error="Invalid credentials"), 401
        now = datetime.now(timezone.utc)
        token = jwt.encode(
            {
                "sub": str(user["id"]),
                "iat": now,
                "nbf": now,
                "exp": now + timedelta(seconds=app.config["JWT_TTL"]),
                "iss": app.config["JWT_ISSUER"],
                "aud": app.config["JWT_AUDIENCE"],
                "jti": secrets.token_hex(16),
            },
            app.config["JWT_SECRET"],
            algorithm="HS256",
        )
        return jsonify(
            {
                "access_token": token,
                # Bearer — название схемы HTTP, а не пароль.
                "token_type": "Bearer",  # nosec B105
                "expires_in": app.config["JWT_TTL"],
            }
        )

    @app.get("/api/data")
    @login_required
    def get_data():
        rows = (
            get_db()
            .execute(
                "SELECT id, text FROM notes WHERE owner_id = ? ORDER BY id",
                (g.user_id,),
            )
            .fetchall()
        )
        return jsonify(
            data=[
                {"id": row["id"], "text": escape(row["text"], quote=True)}
                for row in rows
            ]
        )

    @app.post("/api/data")
    @login_required
    def add_data():
        data = read_json(["text"])
        if data is None or not data["text"].strip() or len(data["text"]) > 2000:
            return jsonify(error="Text must contain 1–2000 characters"), 400
        cursor = get_db().execute(
            "INSERT INTO notes(owner_id, text) VALUES (?, ?)", (g.user_id, data["text"])
        )
        get_db().commit()
        return jsonify(id=cursor.lastrowid, text=escape(data["text"], quote=True)), 201

    return app
