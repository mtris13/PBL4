"""Run the storefront, a loopback proxy and the dry-run analyzer together."""

import argparse
import json
import secrets
import threading
from dataclasses import replace
from pathlib import Path

from waitress import create_server

from lab.access_log import AccessLogMiddleware
from lab.proxy import make_proxy
from security.configuration import load_settings
from security.response.base import AddressPolicy
from security.scripts.watch import Watcher
from shop.app import create_app


def read_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    for key in ("proxy_port", "backend_port"):
        if type(config[key]) is not int or not 1024 <= config[key] <= 65535:
            raise ValueError("Use distinct unprivileged ports")
    if config["proxy_port"] == config["backend_port"]:
        raise ValueError("Proxy and backend ports must differ")
    return config


class LocalLab:
    def __init__(self, config):
        self.runtime = Path(config["runtime_dir"]).resolve()
        self.runtime.mkdir(parents=True, exist_ok=True)
        key_path = self.runtime / "session.key"
        try:
            with key_path.open("x", encoding="ascii") as stream:
                stream.write(secrets.token_urlsafe(48))
            key_path.chmod(0o600)
        except FileExistsError:
            pass
        app = create_app({"SECRET_KEY": key_path.read_text(encoding="ascii").strip(),
                          "DATABASE": str(self.runtime / "shop.sqlite3"),
                          "SESSION_COOKIE_SECURE": False, "ENABLE_HSTS": False})
        settings = replace(load_settings(), policy=AddressPolicy(trusted_proxies=config["trusted_proxies"]))
        self.watcher = Watcher(settings, self.runtime / "access.jsonl", self.runtime / "audit.jsonl",
                               config["poll_seconds"], self.runtime / "watcher.checkpoint.json")
        self.backend = create_server(AccessLogMiddleware(app, self.runtime / "access.jsonl"),
                                     host="127.0.0.1", port=config["backend_port"], threads=4,
                                     max_request_body_size=16384,
                                     clear_untrusted_proxy_headers=False)
        # Keep raw XFF for the analyzer; do NOT set Waitress trusted_proxy, which
        # would rewrite REMOTE_ADDR and erase the transport-peer trust boundary.
        try:
            self.proxy = make_proxy(config["proxy_port"], config["backend_port"], config["proxy_source_ip"])
        except Exception:
            self.backend.close()
            self.backend.task_dispatcher.shutdown()
            raise
        self.threads = []

    def start(self):
        for target in (self.backend.run, self.proxy.serve_forever, self.watcher.run):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.threads.append(thread)

    def close(self):
        self.proxy.shutdown()
        self.proxy.server_close()
        self.backend.close()
        self.backend.task_dispatcher.shutdown()
        self.watcher.stop.set()
        for thread in self.threads:
            thread.join(timeout=3)


def main(argv=None):
    parser = argparse.ArgumentParser(description="PBL4 local lab behind a simulated ALB; loopback only")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("local.json"))
    args = parser.parse_args(argv)
    try:
        config = read_config(args.config)
        lab = LocalLab(config)
    except (OSError, ValueError, KeyError, TypeError):
        print("Cannot start lab. Check configuration, runtime permissions and whether ports are already in use.")
        return 2
    lab.start()
    print(f"Storefront: http://127.0.0.1:{config['proxy_port']}", flush=True)
    print(f"Audit: {lab.runtime / 'audit.jsonl'}", flush=True)
    print("Local ALB append-mode emulator; security is DRY-RUN. Ctrl+C to stop.", flush=True)
    try:
        while not lab.watcher.stop.wait(1):
            if lab.watcher.error or not all(thread.is_alive() for thread in lab.threads):
                print("A lab component stopped. Review the local test results before restarting.")
                return 2
    except KeyboardInterrupt:
        pass
    finally:
        lab.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
