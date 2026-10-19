Лабораторная работа 1 по информационной безопасности

Сервис личных заметок на Flask и SQLite. Пользователь входит по логину и паролю,
получает JWT и может создавать и читать свои заметки.

Запуск

Нужен Python 3.12 или новее. В каталоге проекта выполнить

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements-dev.txt
    export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
    python -m flask --app secure_api init-db
    python -m flask --app secure_api create-user demo
    python -m flask --app secure_api run --port 5000

Пароль задаётся при создании пользователя. Сервер доступен на localhost порту 5000.

API

    POST /auth/login    Вход по username и password
    POST /api/data      Создание заметки с полем text
    GET /api/data       Получение своих заметок

Для работы с заметками нужен заголовок Authorization со значением Bearer и JWT.
Токен действует 15 минут. Пароли хранятся как хэши scrypt, SQL запросы используют
параметры, текст заметок экранируется перед выдачей.

Проверки

    python -m pytest
    python scripts/smoke.py

В GitHub Actions запускаются тесты, Bandit, pip audit и Snyk. Для Snyk нужен
секрет репозитория SNYK_TOKEN в Settings затем Secrets and variables затем Actions.
