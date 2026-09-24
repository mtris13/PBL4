"""Real HTTP integration of the desktop API adapter and the local server."""
import json
import socket
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from client.api import ApiClient, ApiError, normalize_url
from lab.run import LocalLab

class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory()
        sockets = [socket.socket(), socket.socket()]
        try:
            for sock in sockets:
                sock.bind(("127.0.0.1", 0))
            ports = [sock.getsockname()[1] for sock in sockets]
        finally:
            for sock in sockets:
                sock.close()
        cls.lab = LocalLab({"runtime_dir": cls.temp.name, "proxy_port": ports[0],
                            "backend_port": ports[1], "proxy_source_ip": "127.0.0.2",
                            "trusted_proxies": ["127.0.0.2/32"], "poll_seconds": 0.03})
        cls.lab.start()
        cls.url = f"http://127.0.0.1:{ports[0]}"

    @classmethod
    def tearDownClass(cls):
        cls.lab.close()
        cls.temp.cleanup()

    def test_complete_desktop_flow_through_real_proxy(self):
        api = ApiClient(self.url)
        self.assertEqual(api.request("GET", "/health"), {"status": "ok"})
        self.assertEqual(len(api.products()), 6)
        api.request("POST", "/auth/register", {"name": "Desktop Demo",
                    "email": "desktop@example.test", "password": "desktop-password-123"})
        self.assertEqual(api.login("desktop@example.test", "desktop-password-123")["name"], "Desktop Demo")
        token = api.token
        self.assertEqual(api.request("GET", "/me")["user"]["name"], "Desktop Demo")
        cart = api.request("PUT", "/cart/items/1", {"quantity": 2})
        self.assertEqual(cart["total"], 1780000)
        # Simulate server commit followed by loss of the response at the client.
        original = api.request
        def lose_response(*args, **kwargs):
            original(*args, **kwargs)
            raise ApiError("network")
        with patch.object(api, "request", side_effect=lose_response):
            with self.assertRaises(ApiError):
                api.checkout()
        self.assertIsNotNone(api.pending_order_key)
        order = api.checkout()
        self.assertIsNone(api.pending_order_key)
        self.assertEqual(order["total"], 1780000)
        self.assertEqual(len(api.request("GET", "/orders")["items"]), 1)
        self.assertEqual(api.request("GET", "/orders/" + order["id"])["order"], order)
        self.assertEqual(api.products()[0]["stock"], 22)
        self.assertEqual(api.request("GET", "/cart")["total"], 0)
        api.logout()
        self.assertIsNone(api.token)
        api.token = token
        with self.assertRaises(ApiError) as result:
            api.request("GET", "/me")
        self.assertEqual(result.exception.status, 401)
        log = (Path(self.temp.name) / "access.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(token, log)
        self.assertNotIn("desktop-password-123", log)

    def test_logout_discards_token_even_offline(self):
        api = ApiClient(self.url)
        api.token = "memory-only"
        with patch.object(api, "request", side_effect=ApiError("network")):
            with self.assertRaises(ApiError):
                api.logout()
        self.assertIsNone(api.token)


    def test_pending_order_survives_expiry_and_stays_with_same_account(self):
        api = ApiClient(self.url)
        api.token = "expired"
        api.user_email = "owner@example.test"
        api.pending_order_key = "original-request"
        with patch.object(api, "request", side_effect=ApiError("unauthorized", 401)):
            with self.assertRaises(ApiError):
                api.checkout()
        self.assertEqual(api.pending_order_key, "original-request")
        with self.assertRaises(ValueError):
            api.login("another@example.test", "any-password")
        with patch.object(api, "request", return_value={
                "token": "new", "user": {"email": "owner@example.test"}}):
            api.login("OWNER@example.test", "any-password")
        self.assertEqual(api.pending_order_key, "original-request")


    def test_malformed_checkout_response_keeps_original_key(self):
        api = ApiClient(self.url)
        api.pending_order_key = "keep-this-key"
        with patch.object(api, "request", return_value={}):
            with self.assertRaises(ApiError):
                api.checkout()
        self.assertEqual(api.pending_order_key, "keep-this-key")

    def test_url_validation(self):
        self.assertEqual(normalize_url("192.168.1.20:8080"), "http://192.168.1.20:8080/api/v1")
        self.assertEqual(normalize_url("https://demo.test/api/v1/"), "https://demo.test/api/v1")
        for url in ("file:///etc/passwd", "http://user:pass@example.test",
                    "http://example.test/wrong", "http://example.test?q=x", "http://bad host:80"):
            with self.assertRaises(ValueError):
                normalize_url(url)


    def test_tk_window_connect_cart_checkout_and_logout(self):
        import time
        try:
            import tkinter as tk
            from client.app import ShopWindow
        except ImportError:
            self.skipTest("Tk is not installed on this server")
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Tk requires a graphical display")
        root.withdraw()
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as directory, \
                patch("client.app.CONFIG", Path(directory) / "client.json"), \
                patch("client.app.messagebox.showinfo"), \
                patch("client.app.messagebox.askyesno", return_value=True), \
                patch("client.app.messagebox.showerror") as errors:
            window = ShopWindow(root, self.url)
            def drain():
                deadline = time.monotonic() + 15
                while window.future is not None and time.monotonic() < deadline:
                    root.update()
                    time.sleep(0.01)
                self.assertIsNone(window.future)
                self.assertFalse(errors.called, errors.call_args)
            try:
                window.connect()
                drain()
                self.assertTrue(window.connected)
                self.assertEqual(len(window.catalog.get_children()), 6)
                window.api.request("POST", "/auth/register", {"name": "GUI Demo",
                                   "email": "gui@example.test", "password": "desktop-password-123"})
                window.user = window.api.login("gui@example.test", "desktop-password-123")
                window.update_controls()
                window.catalog.selection_set("2")
                window.quantity.set("2")
                window.add_cart()
                drain()
                self.assertEqual(window.cart.item("2")["values"][2], 2)
                window.checkout()
                drain()
                self.assertEqual(len(window.orders.get_children()), 1)
                self.assertEqual(len(window.cart.get_children()), 0)
                window.logout()
                drain()
                self.assertIsNone(window.user)
                self.assertIsNone(window.api.token)
            finally:
                window.pool.shutdown(wait=True)
                root.destroy()

if __name__ == "__main__":
    unittest.main()
