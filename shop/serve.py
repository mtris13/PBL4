"""Standalone loopback WSGI server; Nginx owns access logs."""
import argparse
import json
from pathlib import Path
from waitress import serve
from shop.app import create_app


def load_app(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    port = config["port"]
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("Invalid backend port")
    if type(config.get("lab_http", False)) is not bool:
        raise ValueError("lab_http must be boolean")
    secret = Path(config["secret_file"]).read_text(encoding="ascii").strip()
    lab_http = config.get("lab_http", False)
    app = create_app({"SECRET_KEY": secret, "DATABASE": config["database"],
                      "SESSION_COOKIE_SECURE": not lab_http, "ENABLE_HSTS": not lab_http})
    return app, port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    app, port = load_app(parser.parse_args().config)
    serve(app, host="127.0.0.1", port=port, threads=4, max_request_body_size=16384)


if __name__ == "__main__":
    main()
