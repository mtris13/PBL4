import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

from shop.app import create_app


class ShopTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "shop.sqlite3")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret-" * 4,
                               "DATABASE": self.path, "SESSION_COOKIE_SECURE": False})
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
        self.assertIn("Secure", app.test_client().get("/").headers["Set-Cookie"])

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
