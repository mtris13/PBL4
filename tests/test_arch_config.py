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
        lan = build_files("/home/student/PBL4", lan_address="192.168.10.20")["nginx.conf"]
        self.assertIn("listen 192.168.10.20:8080;", lan)
        self.assertIn("listen 127.0.0.1:8080;", lan)
        for address in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "::1", "not-an-ip"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                build_files("/home/student/PBL4", lan_address=address)

    def test_logs_and_units(self):
        files = build_files("/home/student/PBL4")
        temp_paths = {
            "client_body_temp_path": "client_temp",
            "proxy_temp_path": "proxy_temp",
            "fastcgi_temp_path": "fastcgi_temp",
            "scgi_temp_path": "scgi_temp",
            "uwsgi_temp_path": "uwsgi_temp",
        }
        for directive, directory in temp_paths.items():
            self.assertIn(f"{directive} /home/student/PBL4/runtime/arch/{directory};", files["nginx.conf"])
        for field in ("$request_body", "$http_cookie", "$http_authorization", "$args"):
            self.assertNotIn(field, files["nginx.conf"])
        self.assertIn("escape=json", files["nginx.conf"])
        self.assertIn('map "$request_method:$request_uri" $pbl4_logged_target', files["nginx.conf"])
        self.assertIn('"GET:/healthz" /healthz;', files["nginx.conf"])
        self.assertIn('"request_uri":"$pbl4_logged_target"', files["nginx.conf"])
        for name, text in files.items():
            if name.endswith(".service"):
                self.assertIn("UMask=0077", text)
                self.assertNotIn("User=root", text)
                self.assertNotIn("sudo", text)
                if name != "pbl4-logrotate.service":
                    self.assertIn("WantedBy=default.target", text)
        self.assertIn("--checkpoint /home/student/PBL4/runtime/arch/watcher.checkpoint.json",
                      files["pbl4-security.service"])
        rotate = files["pbl4-logrotate.service"]
        self.assertIn("Type=oneshot", rotate)
        self.assertIn("--max-bytes 5242880 --keep 8", rotate)
        self.assertIn("--nginx-pid /home/student/PBL4/runtime/arch/nginx.pid", rotate)
        timer = files["pbl4-logrotate.timer"]
        self.assertIn("OnCalendar=*:0/15", timer)
        self.assertIn("Persistent=true", timer)
        self.assertIn("WantedBy=timers.target", timer)

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
            self.assertFalse(app.config["ENABLE_HSTS"])
            config["lab_http"] = False
            path.write_text(json.dumps(config))
            app, _ = load_app(path)
            self.assertTrue(app.config["SESSION_COOKIE_SECURE"])

    def test_docker_firewall_lab_is_isolated_and_reversible(self):
        script = (Path(__file__).parents[1] / "deploy" / "arch" /
                  "docker_firewall_lab.sh").read_text(encoding="utf-8")
        self.assertIn('HOST_IP="198.18.0.5"', script)
        self.assertIn('--publish "$HOST_IP:$HOST_PORT:$CONTAINER_PORT/tcp"', script)
        self.assertIn("FROM scratch", script)
        self.assertIn("--network none --pull=false", script)
        self.assertIn('iptables -I DOCKER-USER 1 "${RULE[@]}"', script)
        self.assertIn('iptables -D DOCKER-USER "${RULE[@]}"', script)
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("systemctl is-enabled --quiet ufw.service", script)
        self.assertNotIn("ufw reset", script)
        self.assertNotIn("iptables -F", script)
        self.assertNotIn("0.0.0.0", script)
