import sqlite3
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from shop.app import create_app


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.database = str(Path(self.temp.name) / "shop.sqlite3")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "api-test-secret-" * 3,
                               "DATABASE": self.database, "SESSION_COOKIE_SECURE": False,
                               "ENABLE_HSTS": False})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def register(self, email="student@example.test"):
        return self.client.post("/api/v1/auth/register", json={
            "name": "Sinh viên", "email": email, "password": "local-demo-password",
        })

    def login(self, email="student@example.test", password="local-demo-password", client=None):
        return (client or self.client).post("/api/v1/auth/login",
                                            json={"email": email, "password": password})

    @staticmethod
    def authorization(token):
        return {"Authorization": f"Bearer {token}"}

    def test_health_and_products_are_json_without_browser_session(self):
        health = self.client.get("/api/v1/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json, {"status": "ok"})
        self.assertEqual(health.headers["X-API-Version"], "1")
        self.assertNotIn("Set-Cookie", health.headers)

        products = self.client.get("/api/v1/products").json["items"]
        self.assertEqual(len(products), 6)
        self.assertEqual(products[0]["price"], 890000)
        self.assertIsInstance(products[0]["price"], int)
        self.assertEqual(self.client.get("/api/v1/products/1").status_code, 200)
        missing = self.client.get("/api/v1/products/999")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json["error"]["code"], "not_found")

    def test_register_login_me_logout_and_token_hashing(self):
        registered = self.register()
        self.assertEqual(registered.status_code, 201)
        self.assertEqual(registered.json["user"]["email"], "student@example.test")
        self.assertNotIn("Set-Cookie", registered.headers)

        logged_in = self.login(email="STUDENT@example.test")
        self.assertEqual(logged_in.status_code, 200)
        self.assertEqual(logged_in.json["token_type"], "Bearer")
        self.assertEqual(logged_in.json["expires_in"], 7200)
        token = logged_in.json["token"]
        with closing(sqlite3.connect(self.database)) as db:
            stored = db.execute("SELECT token_hash FROM api_sessions").fetchone()[0]
        self.assertEqual(len(stored), 64)
        self.assertNotEqual(stored, token)
        self.assertNotIn(token, stored)

        headers = self.authorization(token)
        self.assertEqual(self.client.get("/api/v1/me", headers=headers).json["user"]["id"], 1)
        self.assertEqual(self.client.post("/api/v1/auth/logout", headers=headers).status_code, 204)
        replay = self.client.get("/api/v1/me", headers=headers)
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(replay.headers["WWW-Authenticate"], "Bearer")

    def test_api_does_not_accept_browser_cookie_as_bearer_token(self):
        csrf_client = self.app.test_client()
        csrf_client.get("/login")
        with csrf_client.session_transaction() as browser_session:
            csrf = browser_session["csrf"]
        csrf_client.post("/register", data={"csrf_token": csrf, "name": "Sinh viên",
                                            "email": "student@example.test",
                                            "password": "local-demo-password"})
        with csrf_client.session_transaction() as browser_session:
            csrf = browser_session["csrf"]
        csrf_client.post("/login", data={"csrf_token": csrf, "email": "student@example.test",
                                         "password": "local-demo-password"})
        with csrf_client.session_transaction() as browser_session:
            browser_token = browser_session["auth_token"]
        response = self.client.get("/api/v1/me", headers=self.authorization(browser_token))
        self.assertEqual(response.status_code, 401)

    def test_login_errors_throttle_and_request_validation_are_consistent(self):
        self.app.config.update(LOGIN_FAILURE_LIMIT=2, LOGIN_BLOCK_SECONDS=60)
        self.register()
        known = self.login(password="wrong-password")
        unknown = self.login(email="missing@example.test", password="wrong-password")
        self.assertEqual(known.status_code, 401)
        self.assertEqual(unknown.status_code, 401)
        self.assertEqual(known.json, unknown.json)
        blocked = self.login(password="wrong-password")
        self.assertEqual(blocked.status_code, 429)
        self.assertEqual(blocked.json["error"]["code"], "login_throttled")
        self.assertEqual(blocked.headers["Retry-After"], "60")

        no_json = self.client.post("/api/v1/auth/login", data="email=x")
        self.assertEqual(no_json.status_code, 415)
        extra = self.client.post("/api/v1/auth/login",
                                 json={"email": "x", "password": "y", "admin": True})
        self.assertEqual(extra.status_code, 400)
        oversized = self.client.post("/api/v1/auth/login",
                                     json={"email": "x", "password": "x" * 17000})
        self.assertEqual(oversized.status_code, 413)
        self.assertEqual(oversized.json["error"]["code"], "payload_too_large")

    def test_api_session_expiry_and_capacity(self):
        clock = [datetime(2026, 9, 24, 9, 0, tzinfo=timezone.utc)]
        self.app.config.update(AUTH_CLOCK=lambda: clock[0], MAX_API_SESSIONS_PER_USER=2,
                               PERMANENT_SESSION_LIFETIME=timedelta(minutes=30))
        self.register()
        tokens = []
        for _ in range(3):
            tokens.append(self.login().json["token"])
            clock[0] += timedelta(seconds=1)
        self.assertEqual(self.client.get("/api/v1/me",
                                         headers=self.authorization(tokens[0])).status_code, 401)
        self.assertEqual(self.client.get("/api/v1/me",
                                         headers=self.authorization(tokens[1])).status_code, 200)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM api_sessions").fetchone()[0], 2)

        clock[0] += timedelta(minutes=31)
        self.assertEqual(self.client.get("/api/v1/me",
                                         headers=self.authorization(tokens[2])).status_code, 401)

    def test_search_escapes_wildcards_and_api_errors_stay_json(self):
        self.assertEqual(self.client.get("/api/v1/products", query_string={"q": "%"}).json,
                         {"items": []})
        wrong_method = self.client.post("/api/v1/products", json={})
        self.assertEqual(wrong_method.status_code, 405)
        self.assertEqual(wrong_method.json["error"]["code"], "method_not_allowed")
        self.assertEqual(wrong_method.headers["X-API-Version"], "1")
        missing = self.client.get("/api/v1/not-a-route")
        self.assertEqual(missing.status_code, 404)
        self.assertEqual(missing.json["error"]["code"], "not_found")


if __name__ == "__main__":
    unittest.main()
