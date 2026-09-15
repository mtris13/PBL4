import os
import sqlite3
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from shop.app import create_app


class ShopTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "shop.sqlite3")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret-" * 4,
                               "DATABASE": self.path, "SESSION_COOKIE_SECURE": False,
                               "ENABLE_HSTS": False})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def csrf(self, client=None):
        client = client or self.client
        client.get("/login")
        with client.session_transaction() as session:
            return session["csrf"]

    def post(self, path, data=None, client=None):
        client = client or self.client
        return client.post(path, data={"csrf_token": self.csrf(client), **(data or {})})

    def account(self, email="student@example.test", client=None):
        client = client or self.client
        response = self.post("/register", {"name": "Sinh viên", "email": email,
                                            "password": "local-demo-password"}, client)
        self.assertEqual(response.status_code, 303)
        response = self.post("/login", {"email": email, "password": "local-demo-password"}, client)
        self.assertEqual(response.status_code, 303)

    def test_catalog_and_detail(self):
        self.assertIn("Bàn phím Pebble", self.client.get("/").get_data(as_text=True))
        self.assertEqual(self.client.get("/products/1").status_code, 200)
        self.assertEqual(self.client.get("/products/999").status_code, 404)
        health = self.app.test_client().get("/healthz")
        self.assertEqual(health.json, {"status": "ok"})
        self.assertNotIn("Set-Cookie", health.headers)

    def test_register_hash_login_logout(self):
        self.account()
        with closing(sqlite3.connect(self.path)) as db, db:
            password_hash = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertTrue(password_hash.startswith("scrypt:"))
        self.assertNotIn("local-demo-password", password_hash)
        self.assertEqual(self.client.get("/cart").status_code, 200)
        self.assertEqual(self.post("/logout").status_code, 303)
        self.assertEqual(self.client.get("/cart").status_code, 302)

    def test_bad_password_and_sqli_do_not_login(self):
        self.account()
        self.post("/logout")
        for email in ("student@example.test", "' OR 1=1 --"):
            response = self.post("/login", {"email": email, "password": "wrong-password"})
            self.assertEqual(response.status_code, 401)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_csrf_missing_wrong_and_unicode(self):
        self.csrf()
        for token in ("", "incorrect", "tiếng Việt"):
            self.assertEqual(self.client.post("/register", data={"csrf_token": token}).status_code, 400)

    def test_session_rotates_csrf_after_login(self):
        before = self.csrf()
        self.account()
        with self.client.session_transaction() as session:
            self.assertNotEqual(session["csrf"], before)

    def test_login_throttle_persists_and_does_not_store_attempted_email(self):
        clock = [datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)]
        self.app.config.update(AUTH_CLOCK=lambda: clock[0], LOGIN_FAILURE_LIMIT=3,
                               LOGIN_WINDOW_SECONDS=120, LOGIN_BLOCK_SECONDS=60)
        self.account()
        self.post("/logout")
        for _ in range(2):
            response = self.post("/login", {"email": "student@example.test",
                                             "password": "wrong-password"})
            self.assertEqual(response.status_code, 401)

        restarted = create_app({"TESTING": True, "SECRET_KEY": "test-secret-" * 4,
                                "DATABASE": self.path, "SESSION_COOKIE_SECURE": False,
                                "AUTH_CLOCK": lambda: clock[0], "LOGIN_FAILURE_LIMIT": 3,
                                "LOGIN_WINDOW_SECONDS": 120, "LOGIN_BLOCK_SECONDS": 60})
        client = restarted.test_client()
        response = self.post("/login", {"email": "STUDENT@example.test",
                                         "password": "wrong-password"}, client)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "60")
        self.assertIn("Không thể đăng nhập lúc này", response.get_data(as_text=True))
        with closing(sqlite3.connect(self.path)) as db:
            stored = db.execute("SELECT identity_hash FROM login_throttle").fetchone()[0]
        self.assertEqual(len(stored), 64)
        self.assertNotIn("student", stored)

        clock[0] += timedelta(seconds=61)
        response = self.post("/login", {"email": "student@example.test",
                                         "password": "local-demo-password"}, client)
        self.assertEqual(response.status_code, 303)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0], 0)

    def test_login_errors_do_not_enumerate_accounts(self):
        self.app.config.update(LOGIN_FAILURE_LIMIT=2, LOGIN_BLOCK_SECONDS=60)
        self.post("/register", {"name": "Sinh viên", "email": "student@example.test",
                                "password": "local-demo-password"})
        responses = []
        for email in ("student@example.test", "missing@example.test"):
            response = self.post("/login", {"email": email, "password": "wrong-password"})
            self.assertEqual(response.status_code, 401)
            body = response.get_data(as_text=True)
            self.assertIn("Email hoặc mật khẩu không đúng.", body)
            self.assertNotIn(email, body)
            responses.append(response.status_code)
            blocked = self.post("/login", {"email": email, "password": "wrong-password"})
            self.assertEqual(blocked.status_code, 429)
            self.assertIn("Không thể đăng nhập lúc này", blocked.get_data(as_text=True))
            responses.append(blocked.status_code)
        self.assertEqual(responses, [401, 429, 401, 429])

    def test_login_throttle_capacity_is_bounded_and_stale_rows_are_reclaimed(self):
        clock = [datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)]
        self.app.config.update(AUTH_CLOCK=lambda: clock[0], LOGIN_FAILURE_LIMIT=5,
                               LOGIN_WINDOW_SECONDS=60, LOGIN_BLOCK_SECONDS=60,
                               LOGIN_THROTTLE_MAX_ENTRIES=1)
        first = self.post("/login", {"email": "first@example.test", "password": "wrong"})
        self.assertEqual(first.status_code, 401)
        capacity = self.post("/login", {"email": "second@example.test", "password": "wrong"})
        self.assertEqual(capacity.status_code, 429)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0], 1)
        clock[0] += timedelta(seconds=61)
        reclaimed = self.post("/login", {"email": "second@example.test", "password": "wrong"})
        self.assertEqual(reclaimed.status_code, 401)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM login_throttle").fetchone()[0], 1)

    def test_logout_revokes_replayed_cookie_and_database_stores_only_token_hash(self):
        self.account()
        self.assertNotIn("Set-Cookie", self.client.get("/").headers)
        with self.client.session_transaction() as current:
            raw_token = current["auth_token"]
        cookie = self.client.get_cookie("pbl4_session").value
        with closing(sqlite3.connect(self.path)) as db:
            token_hash = db.execute("SELECT token_hash FROM browser_sessions").fetchone()[0]
        self.assertEqual(len(token_hash), 64)
        self.assertNotEqual(token_hash, raw_token)
        self.assertNotIn(raw_token, token_hash)

        self.assertEqual(self.post("/logout").status_code, 303)
        replay = self.app.test_client()
        replay.set_cookie("pbl4_session", cookie)
        self.assertEqual(replay.get("/cart").status_code, 302)
        with replay.session_transaction() as stale:
            self.assertNotIn("user_id", stale)
            self.assertNotIn("auth_token", stale)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()[0], 0)

    def test_session_expiry_and_per_user_capacity_revoke_old_sessions(self):
        clock = [datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)]
        self.app.config.update(AUTH_CLOCK=lambda: clock[0], MAX_SESSIONS_PER_USER=2,
                               PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
        first = self.app.test_client()
        self.account(client=first)
        clock[0] += timedelta(seconds=1)
        second = self.app.test_client()
        self.assertEqual(self.post("/login", {"email": "student@example.test",
                                               "password": "local-demo-password"}, second).status_code, 303)
        clock[0] += timedelta(seconds=1)
        third = self.app.test_client()
        self.assertEqual(self.post("/login", {"email": "student@example.test",
                                               "password": "local-demo-password"}, third).status_code, 303)
        self.assertEqual(first.get("/cart").status_code, 302)
        self.assertEqual(second.get("/cart").status_code, 200)
        self.assertEqual(third.get("/cart").status_code, 200)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()[0], 2)

        clock[0] += timedelta(minutes=31)
        self.assertEqual(third.get("/cart").status_code, 302)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()[0], 1)

    def test_auth_configuration_rejects_boolean_limits_and_naive_clock(self):
        with self.assertRaises(ValueError):
            create_app({"SECRET_KEY": "test-secret-" * 4, "DATABASE": self.path,
                        "LOGIN_FAILURE_LIMIT": True})
        with self.assertRaises(ValueError):
            create_app({"SECRET_KEY": "test-secret-" * 4, "DATABASE": self.path,
                        "ENABLE_HSTS": "yes"})
        with self.assertRaises(ValueError):
            create_app({"TESTING": True, "SECRET_KEY": "test-secret-" * 4,
                        "DATABASE": self.path, "AUTH_CLOCK": datetime.now})
        if os.name == "posix":
            self.assertEqual(Path(self.path).stat().st_mode & 0o777, 0o600)

    def test_register_validation_and_duplicate(self):
        for data in ({"name": "A", "email": "a@b.test", "password": "long-enough-password"},
                     {"name": "Student", "email": "wrong", "password": "long-enough-password"},
                     {"name": "Student", "email": "a@b.test", "password": "short"}):
            self.assertEqual(self.post("/register", data).status_code, 400)
        self.account()
        self.assertEqual(self.post("/register", {"name": "Student", "email": "STUDENT@example.test",
                                                 "password": "long-enough-password"}).status_code, 409)

    def test_search_escapes_xss_and_binds_sql(self):
        response = self.client.get("/", query_string={"q": "<script>alert(1)</script>"})
        html = response.get_data(as_text=True)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertEqual(self.client.get("/", query_string={"q": "' UNION SELECT password_hash FROM users --"}).status_code, 200)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM products").fetchone()[0], 6)

    def test_search_category_and_literal_wildcards(self):
        response = self.client.get("/?category=Thi%E1%BA%BFt+b%E1%BB%8B").get_data(as_text=True)
        self.assertIn("Bàn phím Pebble", response)
        self.assertNotIn("Đèn bàn Arc", response)
        response = self.client.get("/", query_string={"q": "%"}).get_data(as_text=True)
        self.assertNotIn("Bàn phím Pebble", response)

    def test_path_traversal_does_not_read_files(self):
        for path in ("/../../requirements.txt", "/%252e%252e%252frequirements.txt", "/static/../../requirements.txt"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 404)
            self.assertNotIn(b"Flask==", response.data)

    def test_security_headers_and_host_validation(self):
        response = self.client.get("/")
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("HttpOnly", response.headers["Set-Cookie"])
        self.assertIn("SameSite=Lax", response.headers["Set-Cookie"])
        self.assertEqual(self.client.get("/", headers={"Host": "evil.test"}).status_code, 400)
        self.assertEqual(self.client.get("/", headers={"X-Forwarded-Host": "evil.test"}).status_code, 200)

    def test_secure_cookie_default_and_secret_required(self):
        with self.assertRaises(ValueError):
            create_app({"SECRET_KEY": "short", "DATABASE": self.path})
        app = create_app({"SECRET_KEY": "test-secret-" * 4, "DATABASE": self.path})
        response = app.test_client().get("/")
        self.assertIn("Secure", response.headers["Set-Cookie"])
        self.assertEqual(response.headers["Strict-Transport-Security"],
                         "max-age=31536000; includeSubDomains")

    def test_cart_requires_login_and_limits_quantity(self):
        self.assertEqual(self.post("/cart/add/1").status_code, 302)
        self.account()
        for quantity in ("-1", "0", "11", "nan"):
            self.assertEqual(self.post("/cart/add/1", {"quantity": quantity}).status_code, 400)
        self.assertEqual(self.post("/cart/add/999").status_code, 404)

    def test_checkout_transaction_and_duplicate_submit(self):
        self.account()
        self.post("/cart/add/1", {"quantity": "2", "price": "1"})
        self.client.get("/cart")
        with self.client.session_transaction() as session:
            key = session["checkout_key"]
        response = self.post("/checkout", {"checkout_key": key, "total": "1"})
        self.assertEqual(response.status_code, 303)
        order_url = response.headers["Location"]
        self.assertEqual(self.client.get(order_url).status_code, 200)
        repeated = self.post("/checkout", {"checkout_key": key})
        self.assertEqual(repeated.headers["Location"], order_url)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT total FROM orders").fetchone()[0], 1780000)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT stock FROM products WHERE id=1").fetchone()[0], 22)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cart").fetchone()[0], 0)

    def test_order_and_cart_are_owned_by_user(self):
        self.account()
        self.post("/cart/add/1")
        self.client.get("/cart")
        with self.client.session_transaction() as session:
            key = session["checkout_key"]
        order_url = self.post("/checkout", {"checkout_key": key}).headers["Location"]
        second = self.app.test_client()
        self.account("second@example.test", second)
        self.assertEqual(second.get(order_url).status_code, 404)
        self.assertNotIn("Bàn phím Pebble", second.get("/cart").get_data(as_text=True))

    def test_stock_change_prevents_checkout(self):
        self.account()
        self.post("/cart/add/1")
        self.client.get("/cart")
        with self.client.session_transaction() as session:
            key = session["checkout_key"]
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE products SET stock=0 WHERE id=1")
        response = self.post("/checkout", {"checkout_key": key})
        self.assertEqual(response.headers["Location"], "/cart")
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 0)

    def test_oversized_body(self):
        self.assertEqual(self.client.post("/login", data={"password": "x" * 17000}).status_code, 413)
