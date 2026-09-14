import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from deploy.arch.render import build_files
from shop.serve import load_app


class ArchConfigTests(unittest.TestCase):
    def test_proxy_topology_and_policy(self):
        files = build_files("/home/student/projects/PBL4")
        nginx = files["nginx.conf"]
        for port in (8080, 8081, 8082):
            self.assertIn(f"127.0.0.1:{port}", nginx)
        self.assertIn("proxy_bind 127.0.0.2;", nginx)
        self.assertIn("allow 127.0.0.2;", nginx)
        self.assertIn("deny all;", nginx)
        self.assertNotIn("real_ip_header", nginx)
        self.assertNotIn("0.0.0.0", nginx)
        self.assertEqual(json.loads(files["policy.json"])["trusted_proxies"], ["127.0.0.2/32"])

    def test_paths_and_ports_validated(self):
        for path in ("relative", "/home/a b", "/home/a;evil", "/home/$USER", "/home/%h", "/home/../tmp"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                build_files(path)
        for ports in ((80, 8082, 8081), (8080, 8080, 8081), (65536, 8082, 8081), (True, 8082, 8081)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                build_files("/home/student/PBL4", *ports)
        self.assertIn("127.0.0.1:9082", build_files("/home/student/PBL4", 9080, 9082, 9081)["nginx.conf"])

    def test_logs_and_units(self):
        files = build_files("/home/student/PBL4")
        for field in ("$request_body", "$http_cookie", "$http_authorization", "$args"):
            self.assertNotIn(field, files["nginx.conf"])
        self.assertIn("escape=json", files["nginx.conf"])
        for name, text in files.items():
            if name.endswith(".service"):
                self.assertIn("UMask=0077", text)
                self.assertIn("WantedBy=default.target", text)
                self.assertNotIn("User=root", text)
                self.assertNotIn("sudo", text)

    def test_standalone_server(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "session.key").write_text("test-secret-" * 4)
            config = {"port": 8081, "database": str(root / "shop.sqlite3"),
                      "secret_file": str(root / "session.key"), "lab_http": True}
            path = root / "app.json"
            path.write_text(json.dumps(config))
            app, port = load_app(path)
            self.assertEqual(port, 8081)
            self.assertEqual(app.test_client().get("/healthz").status_code, 200)
            self.assertFalse(app.config["SESSION_COOKIE_SECURE"])
            config["lab_http"] = False
            path.write_text(json.dumps(config))
            app, _ = load_app(path)
            self.assertTrue(app.config["SESSION_COOKIE_SECURE"])
