import sqlite3
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
from shop.app import create_app

class CartOrderTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / "shop.sqlite3")
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-order-secret" * 3,
                               "DATABASE": self.path})
        self.client = self.app.test_client()
        self.a = self.account("a@example.test")
        self.b = self.account("b@example.test")

    def account(self, email):
        self.client.post("/api/v1/auth/register", json={
            "name": "Demo Student", "email": email, "password": "demo-password-123"})
        token = self.client.post("/api/v1/auth/login", json={
            "email": email, "password": "demo-password-123"}).json["token"]
        return {"Authorization": "Bearer " + token}

    def put(self, headers, quantity=2, product=1):
        return self.client.put(f"/api/v1/cart/items/{product}", headers=headers,
                               json={"quantity": quantity})

    def order(self, headers, key="demo-key", client=None):
        return (client or self.client).post("/api/v1/orders",
                                           headers={**headers, "Idempotency-Key": key})

    def test_auth_validation_and_put_is_absolute(self):
        for method, path in (("GET", "/cart"), ("PUT", "/cart/items/1"),
                             ("DELETE", "/cart/items/1"), ("POST", "/orders"),
                             ("GET", "/orders"), ("GET", "/orders/missing")):
            self.assertEqual(self.client.open("/api/v1" + path, method=method).status_code, 401)
        self.assertEqual(self.put(self.a).json["total"], 1780000)
        self.assertEqual(self.put(self.a).json["items"][0]["quantity"], 2)
        self.assertEqual(self.put(self.a, True).status_code, 400)
        for quantity in (0, -1, 11, 100):
            self.assertEqual(self.put(self.a, quantity).status_code, 409)
        self.assertEqual(self.put(self.a, product=999).status_code, 404)
        forged = self.client.put("/api/v1/cart/items/1", headers=self.a,
                                  json={"quantity": 1, "price": 1, "user_id": 2})
        self.assertEqual(forged.status_code, 400)

    def test_ownership_delete_and_order_history(self):
        self.put(self.a)
        self.assertEqual(self.client.get("/api/v1/cart", headers=self.b).json["total"], 0)
        self.client.delete("/api/v1/cart/items/1", headers=self.b)
        self.assertEqual(self.client.get("/api/v1/cart", headers=self.a).json["total"], 1780000)
        order = self.order(self.a)
        self.assertEqual(order.status_code, 201)
        order_id = order.json["order"]["id"]
        self.assertEqual(self.client.get("/api/v1/orders/" + order_id, headers=self.b).status_code, 404)
        self.assertEqual(self.client.get("/api/v1/orders", headers=self.b).json["items"], [])
        self.assertEqual(len(self.client.get("/api/v1/orders", headers=self.a).json["items"]), 1)
        self.assertEqual(self.client.get("/api/v1/cart", headers=self.a).json["total"], 0)
        for _ in range(2):
            self.assertEqual(self.client.delete("/api/v1/cart/items/1", headers=self.a).status_code, 204)

    def test_replay_is_scoped_to_user_and_does_not_consume_new_cart(self):
        self.put(self.a)
        first = self.order(self.a)
        self.put(self.a, 1, 2)
        replay = self.order(self.a)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(first.json, replay.json)
        self.assertEqual(self.client.get("/api/v1/cart", headers=self.a).json["total"], 650000)
        self.put(self.b, 1)
        second_user = self.order(self.b)
        self.assertEqual(second_user.status_code, 201)
        self.assertNotEqual(first.json["order"]["id"], second_user.json["order"]["id"])
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT stock FROM products WHERE id=1").fetchone()[0], 21)

    def test_stock_change_rolls_back_entire_order(self):
        self.put(self.a)
        self.put(self.a, 1, 2)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE products SET stock=1 WHERE id=1")
        response = self.order(self.a)
        self.assertEqual(response.json["error"]["code"], "stock_unavailable")
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM orders").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT stock FROM products WHERE id=2").fetchone()[0], 18)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cart WHERE user_id=1").fetchone()[0], 2)

    def test_invalid_keys_empty_cart_and_client_price_rejected(self):
        for key in ("", "has space", "x" * 101):
            self.assertEqual(self.order(self.a, key).status_code, 400)
        self.assertEqual(self.order(self.a).json["error"]["code"], "empty_cart")
        self.put(self.a)
        forged = self.client.post("/api/v1/orders", headers={**self.a, "Idempotency-Key": "valid"},
                                  json={"total": 1})
        self.assertEqual(forged.status_code, 400)

    def test_simultaneous_replay_creates_one_order(self):
        self.put(self.a)
        def submit(_):
            with self.app.test_client() as client:
                response = self.order(self.a, client=client)
                return response.status_code, response.json["order"]["id"]
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(submit, range(2)))
        self.assertEqual(sorted(status for status, _ in responses), [200, 201])
        self.assertEqual(len({order_id for _, order_id in responses}), 1)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT stock FROM products WHERE id=1").fetchone()[0], 22)

if __name__ == "__main__":
    unittest.main()
