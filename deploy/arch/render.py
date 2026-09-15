"""Render Arch lab configuration only; no service install, sudo or firewall calls."""
import argparse
import json
import re
import secrets
import sys
from pathlib import Path, PurePosixPath


def build_files(project, edge_port=8080, origin_port=8082, backend_port=8081):
    if not project.startswith("/") or not re.fullmatch(r"/[A-Za-z0-9_./-]+", project):
        raise ValueError("Use an absolute Linux project path without spaces or special characters")
    if ".." in PurePosixPath(project).parts:
        raise ValueError("Use a normalized path")
    ports = (edge_port, origin_port, backend_port)
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(set(ports)) != 3:
        raise ValueError("Use three distinct unprivileged ports")
    project = project.rstrip("/")
    runtime = f"{project}/runtime/arch"
    python = f"{project}/.venv/bin/python"
    nginx = Path(__file__).with_name("nginx.conf.template").read_text(encoding="utf-8")
    for token, value in {"RUNTIME": runtime, "EDGE": edge_port, "ORIGIN": origin_port, "BACKEND": backend_port}.items():
        nginx = nginx.replace("@" + token + "@", str(value))

    def unit(description, command, extra="", dependencies=""):
        return (f"[Unit]\nDescription={description}\n{dependencies}\n"
                f"[Service]\nType=simple\nWorkingDirectory={project}\nUMask=0077\n"
                f"Environment=PYTHONUNBUFFERED=1\nExecStart={command}\nRestart=on-failure\n"
                f"RestartSec=3\nNoNewPrivileges=yes\n{extra}\n[Install]\nWantedBy=default.target\n")

    def encode(value):
        return json.dumps(value, indent=2) + "\n"

    return {
        "nginx.conf": nginx,
        "app.json": encode({"port": backend_port, "database": f"{runtime}/shop.sqlite3",
                            "secret_file": f"{runtime}/session.key", "lab_http": True}),
        "policy.json": encode({"allowlist": ["127.0.0.0/8", "::1/128"],
                               "trusted_proxies": ["127.0.0.2/32"], "alb_networks": [], "admin_networks": []}),
        "demo.json": encode({"proxy_port": edge_port, "backend_port": backend_port, "runtime_dir": runtime,
                             "proxy_source_ip": "127.0.0.2", "trusted_proxies": ["127.0.0.2/32"], "poll_seconds": 0.2}),
        "pbl4-shop.service": unit("PBL4 storefront local lab", f"{python} -m shop.serve --config {runtime}/app.json"),
        "pbl4-nginx.service": unit("PBL4 isolated Nginx lab", f"/usr/bin/nginx -p {runtime}/ -c {runtime}/nginx.conf",
                                    f"ExecStartPre=/usr/bin/nginx -t -p {runtime}/ -c {runtime}/nginx.conf\nKillSignal=SIGQUIT",
                                    "Wants=pbl4-shop.service\nAfter=pbl4-shop.service"),
        "pbl4-security.service": unit("PBL4 security watcher dry-run",
                                       f"{python} -m security.scripts.watch --input {runtime}/access.jsonl --audit {runtime}/audit.jsonl --policy {runtime}/policy.json",
                                       dependencies="Wants=pbl4-nginx.service\nAfter=pbl4-nginx.service"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Generate local Arch Nginx and user services")
    parser.add_argument("--edge-port", type=int, default=8080)
    parser.add_argument("--origin-port", type=int, default=8082)
    parser.add_argument("--backend-port", type=int, default=8081)
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("Run this on Linux after cloning and creating .venv")
    project = Path(__file__).resolve().parents[2]
    files = build_files(project.as_posix(), args.edge_port, args.origin_port, args.backend_port)
    output = project / "runtime" / "arch"
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    for name in ("client_temp", "proxy_temp", "fastcgi_temp", "scgi_temp", "uwsgi_temp"):
        (output / name).mkdir(exist_ok=True, mode=0o700)
    key = output / "session.key"
    try:
        with key.open("x", encoding="ascii") as stream:
            stream.write(secrets.token_urlsafe(48))
    except FileExistsError:
        pass
    key.chmod(0o600)
    for name, content in files.items():
        (output / name).write_text(content, encoding="utf-8")
    print(f"Rendered {len(files)} files in {output}. Existing secret and database preserved.")
    print("Next: nginx -t -p " + str(output) + "/ -c " + str(output / "nginx.conf"))


if __name__ == "__main__":
    main()
