"""Реальные HTTP-запросы curl к временному серверу; токены не записываются в лог."""

import json
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server
from secure_api import SCHEMA, create_app


def main():
    with tempfile.TemporaryDirectory() as directory:
        app = create_app(
            {"JWT_SECRET": secrets.token_hex(32), "DATABASE": directory + "/db.sqlite3"}
        )
        password = secrets.token_urlsafe(24)
        with sqlite3.connect(app.config["DATABASE"]) as db:
            db.executescript(SCHEMA)
            for username in ("demo", "other"):
                db.execute(
                    "INSERT INTO users(username,password_hash) VALUES (?,?)",
                    (username, generate_password_hash(password)),
                )
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        log = ["HTTP-проверки через curl. Временная база данных; пароли и JWT скрыты."]
        cases = []

        def call(method, path, expected, data=None, token=None, label=""):
            args = [
                "curl",
                "--silent",
                "--show-error",
                "--max-time",
                "10",
                "-X",
                method,
                base + path,
                "-w",
                "\n%{http_code}",
            ]
            if data is not None:
                body_path = Path(directory) / "request.json"
                body_path.write_text(json.dumps(data))
                args += [
                    "-H",
                    "Content-Type: application/json",
                    "--data-binary",
                    "@" + str(body_path),
                ]
            curl_config = ""
            if token:
                # Заголовок передаётся через stdin, чтобы JWT не попал в список процессов.
                args += ["--config", "-"]
                curl_config = f'header = "Authorization: Bearer {token}"\n'
            result = subprocess.run(
                args, input=curl_config, capture_output=True, text=True, check=True
            )
            content, status = result.stdout.rsplit("\n", 1)
            assert int(status) == expected, result.stdout
            response = json.loads(content)
            safe_response = response.copy()
            if "access_token" in safe_response:
                safe_response["access_token"] = "[REDACTED]"
            request_data = dict(data) if data is not None else None
            if request_data is not None and "password" in request_data:
                request_data["password"] = "[REDACTED]"
            cases.append(
                {
                    "case": label,
                    "method": method,
                    "path": path,
                    "request": request_data,
                    "authenticated": bool(token),
                    "status": int(status),
                    "response": safe_response,
                }
            )
            log.append(
                f"{label}\n{method} {path} -> {status}\n{json.dumps(safe_response, ensure_ascii=False)}"
            )
            return response

        try:
            call("GET", "/api/data", 401, label="Без токена")
            call(
                "POST",
                "/auth/login",
                401,
                {"username": "demo' OR 1=1 --", "password": "wrong"},
                label="SQL-инъекция",
            )
            call(
                "POST",
                "/auth/login",
                401,
                {"username": "demo", "password": "wrong"},
                label="Неверный пароль",
            )
            token = call(
                "POST",
                "/auth/login",
                200,
                {"username": "demo", "password": password},
                label="Вход",
            )["access_token"]
            call(
                "POST",
                "/api/data",
                201,
                {"text": "Моя первая заметка"},
                token,
                "Создание заметки",
            )
            response = call(
                "GET", "/api/data", 200, token=token, label="Чтение своих заметок"
            )
            assert response["data"] == [{"id": 1, "text": "Моя первая заметка"}]
            response = call(
                "POST",
                "/api/data",
                201,
                {"text": "<script>alert(1)</script>"},
                token,
                "XSS-нагрузка",
            )
            assert response["text"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
            response = call(
                "GET",
                "/api/data",
                200,
                token=token,
                label="Чтение экранированного текста",
            )
            assert (
                response["data"][1]["text"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
            )
            other_token = call(
                "POST",
                "/auth/login",
                200,
                {"username": "other", "password": password},
                label="Вход второго пользователя",
            )["access_token"]
            response = call(
                "GET",
                "/api/data",
                200,
                token=other_token,
                label="Проверка доступа к чужим заметкам",
            )
            assert response["data"] == []
            call(
                "GET",
                "/api/data",
                401,
                token="invalid.token.value",
                label="Неверный JWT",
            )
            now = datetime.now(timezone.utc)
            expired = jwt.encode(
                {
                    "sub": "1",
                    "iat": now - timedelta(hours=1),
                    "nbf": now - timedelta(hours=1),
                    "exp": now - timedelta(seconds=10),
                    "iss": "lab1-api",
                    "aud": "lab1-client",
                    "jti": secrets.token_hex(16),
                },
                app.config["JWT_SECRET"],
                algorithm="HS256",
            )
            call("GET", "/api/data", 401, token=expired, label="Просроченный JWT")
            call("POST", "/api/data", 400, {"text": ""}, token, "Пустая заметка")
            call(
                "POST",
                "/api/data",
                400,
                {"text": "x" * 2001},
                token,
                "Слишком длинная заметка",
            )
            with sqlite3.connect(app.config["DATABASE"]) as db:
                saved_hash = db.execute(
                    "SELECT password_hash FROM users WHERE username = ?", ("demo",)
                ).fetchone()[0]
                hash_evidence = {
                    "method": saved_hash.split("$")[0],
                    "equals_plaintext": saved_hash == password,
                    "users_count": db.execute("SELECT count(*) FROM users").fetchone()[
                        0
                    ],
                }
                assert not hash_evidence["equals_plaintext"]
        finally:
            server.shutdown()
            thread.join(timeout=5)
        output = Path(__file__).resolve().parents[1] / "reports" / "curl.txt"
        output.parent.mkdir(exist_ok=True)
        output.write_text("\n\n".join(log) + "\n")
        (output.parent / "http-cases.json").write_text(
            json.dumps(
                {"cases": cases, "password_storage": hash_evidence},
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
        print(output.read_text())


if __name__ == "__main__":
    main()
