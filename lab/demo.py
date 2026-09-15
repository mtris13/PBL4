"""Small fixed set of harmless HTTP probes against the configured loopback lab."""

import argparse
import http.client
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from lab.run import read_config


def audit_offset(path):
    """Return the start of the unfinished tail, or EOF for complete JSONL."""
    if not path.exists():
        return 0
    data = path.read_bytes()
    return data.rfind(b"\n") + 1


def audit_records_since(path, offset):
    if not path.exists():
        return []
    size = path.stat().st_size
    with path.open("rb") as stream:
        stream.seek(offset if size >= offset else 0)
        data = stream.read()
    records = []
    for row in data.splitlines():
        try:
            records.append(json.loads(row))
        except (UnicodeDecodeError, ValueError):
            continue  # Writer may still be completing the final row.
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run 25 fixed requests against the local lab; no external target option")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("local.json"))
    args = parser.parse_args(argv)
    config = read_config(args.config)
    started = datetime.now(timezone.utc).isoformat()
    path = Path(config["runtime_dir"]) / "audit.jsonl"
    start_offset = audit_offset(path)
    cases = [("benign", "/"), ("sqli", "/?q=UNION+SELECT"),
             ("xss", "/?q=%3Cscript%3Ealert(1)"),
             ("path_traversal", "/%252e%252e%252fetc/passwd")]
    cases += [("request_flood", "/healthz")] * 21
    statuses = []
    try:
        for name, target in cases:
            connection = http.client.HTTPConnection("127.0.0.1", config["proxy_port"], timeout=5)
            try:
                connection.request("GET", target, headers={"X-Forwarded-For": "192.0.2.66"})
                response = connection.getresponse()
                response.read()
                statuses.append({"case": name, "status": response.status})
            finally:
                connection.close()
            time.sleep(0.04)
    except OSError:
        print("Local lab is unavailable. Start python -m lab.run first.")
        return 2
    deadline = time.monotonic() + 5
    detected = set()
    outcomes = set()
    sources = set()
    while time.monotonic() < deadline:
        if path.exists():
            for record in audit_records_since(path, start_offset):
                detection = record.get("detection", {})
                if detection:
                    detected.add(detection["attack_type"])
                    sources.add(detection["source_ip"])
                response = record.get("response", {})
                if response:
                    outcomes.add(response["outcome"])
        if {"sqli", "xss", "path_traversal", "request_flood"} <= detected:
            break
        time.sleep(0.1)
    expected_http = all(item["status"] == (404 if item["case"] == "path_traversal" else 200) for item in statuses)
    passed = (expected_http and len(detected) == 4 and sources == {"127.0.0.1"}
              and "suppressed_protected_address" in outcomes)
    report = {"stage": "local_after_proxy_dry_run", "started_at": started,
              "passed": passed, "requests": len(cases), "http_results": statuses,
              "detected_attack_types": sorted(detected), "detected_sources": sorted(sources),
              "response_outcomes": sorted(outcomes), "aws_tested": False, "firewall_executed": False}
    target = Path(config["runtime_dir"]) / "demo-report.json"
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
