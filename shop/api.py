"""Versioned JSON API for the desktop client; no browser cookie or CSRF dependency."""

import re
import sqlite3
from functools import wraps

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from shop.auth_state import (authenticated_api_user, create_api_session, record_failure,
                             revoke_api_session, throttle_key, throttle_remaining)
from shop.database import get_db


def create_api_blueprint(auth_now, dummy_hash):
    api = Blueprint("api", __name__, url_prefix="/api/v1")

    def error(code, message, status, headers=None):
        response = jsonify({"error": {"code": code, "message": message}})
        response.status_code = status
        if headers:
            response.headers.update(headers)
        return response

    def json_object(required, optional=()):
        if not request.is_json:
            return None, error("json_required", "Request body must be a JSON object.", 415)
        payload = request.get_json(silent=True)
        allowed = set(required) | set(optional)
        if (type(payload) is not dict or any(field not in payload for field in required)
                or any(field not in allowed for field in payload)):
            return None, error("invalid_request", "Request fields are invalid.", 400)
        return payload, None

    def bearer_token():
        header = request.headers.get("Authorization", "")
        parts = header.split(" ")
        if len(header) > 256 or len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1]:
            return None
        return parts[1]

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            token = bearer_token()
            g.user = (authenticated_api_user(get_db(), current_app.config["SECRET_KEY"],
                                              token, auth_now()) if token else None)
            if g.user is None:
                return error("unauthorized", "A valid bearer token is required.", 401,
                             {"WWW-Authenticate": "Bearer"})
            g.api_token = token
            return view(*args, **kwargs)
        return wrapped

    def user_json(user):
        return {"id": user["id"], "name": user["name"], "email": user["email"]}

    def product_json(product):
        return {field: product[field] for field in
                ("id", "name", "category", "illustration", "price", "stock", "description")}

    @api.get("/health")
    def health():
        get_db().execute("SELECT 1").fetchone()
        return jsonify({"status": "ok"})

    @api.post("/auth/register")
    def register():
        payload, invalid = json_object(("name", "email", "password"))
        if invalid:
            return invalid
        if any(not isinstance(payload[field], str) for field in ("name", "email", "password")):
            return error("invalid_fields", "Name, email and password must be strings.", 400)
        name = payload["name"].strip()
        email = payload["email"].strip().lower()
        password = payload["password"]
        if (not 2 <= len(name) <= 60 or len(email) > 254
                or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
                or not 12 <= len(password) <= 128):
            return error("invalid_fields", "Name, email or password does not meet the contract.", 400)
        try:
            db = get_db()
            cursor = db.execute("INSERT INTO users(name, email, password_hash) VALUES (?, ?, ?)",
                                (name, email, generate_password_hash(password)))
            db.commit()
            user = db.execute("SELECT id, name, email FROM users WHERE id=?",
                              (cursor.lastrowid,)).fetchone()
        except sqlite3.IntegrityError:
            db.rollback()
            return error("email_unavailable", "An account cannot be created with this email.", 409)
        return jsonify({"user": user_json(user)}), 201

    @api.post("/auth/login")
    def login():
        payload, invalid = json_object(("email", "password"))
        if invalid:
            return invalid
        if not isinstance(payload["email"], str) or not isinstance(payload["password"], str):
            return error("invalid_fields", "Email and password must be strings.", 400)
        email = payload["email"].strip().lower()
        password = payload["password"]
        if len(email) > 254 or len(password) > 128:
            return error("invalid_fields", "Email or password is too long.", 400)
        db = get_db()
        identity = throttle_key(current_app.config["SECRET_KEY"], email)
        remaining = throttle_remaining(db, identity, auth_now())
        if remaining:
            return error("login_throttled", "Login is temporarily unavailable.", 429,
                         {"Retry-After": str(remaining)})
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        valid = check_password_hash(user["password_hash"] if user else dummy_hash, password)
        if not user or not valid:
            remaining = record_failure(
                db, identity, auth_now(), current_app.config["LOGIN_FAILURE_LIMIT"],
                current_app.config["LOGIN_WINDOW_SECONDS"],
                current_app.config["LOGIN_BLOCK_SECONDS"],
                current_app.config["LOGIN_THROTTLE_MAX_ENTRIES"],
            )
            if remaining:
                return error("login_throttled", "Login is temporarily unavailable.", 429,
                             {"Retry-After": str(remaining)})
            return error("invalid_credentials", "Email or password is incorrect.", 401)
        lifetime = int(current_app.permanent_session_lifetime.total_seconds())
        token = create_api_session(
            db, current_app.config["SECRET_KEY"], user["id"], auth_now(), lifetime,
            current_app.config["MAX_API_SESSIONS_PER_USER"], identity,
        )
        return jsonify({"token": token, "token_type": "Bearer", "expires_in": lifetime,
                        "user": user_json(user)})

    @api.get("/me")
    @login_required
    def me():
        return jsonify({"user": user_json(g.user)})

    @api.post("/auth/logout")
    @login_required
    def logout():
        revoke_api_session(get_db(), current_app.config["SECRET_KEY"], g.api_token)
        return "", 204

    @api.get("/products")
    def products():
        query = request.args.get("q", "")
        category = request.args.get("category", "")
        if len(query) > 200 or len(category) > 40:
            return error("invalid_query", "Search query or category is too long.", 400)
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = get_db().execute(
            "SELECT * FROM products WHERE name LIKE ? ESCAPE '\\' "
            "AND (? = '' OR category = ?) ORDER BY id",
            (f"%{escaped}%", category, category),
        ).fetchall()
        return jsonify({"items": [product_json(row) for row in rows]})

    @api.get("/products/<int:product_id>")
    def product(product_id):
        row = get_db().execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        if row is None:
            return error("not_found", "Product was not found.", 404)
        return jsonify({"product": product_json(row)})

    return api
