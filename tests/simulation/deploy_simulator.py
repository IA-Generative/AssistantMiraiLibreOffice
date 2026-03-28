#!/usr/bin/env python3
"""Simulate N devices contacting the bootstrap server for update rollout testing.

Usage:
    python tests/simulation/deploy_simulator.py \
        --devices 500 \
        --concurrency 50 \
        --bootstrap-url https://bootstrap.fake-domain.name \
        --campaign-id 1 \
        --failure-rate 0.05 \
        --interval 2 \
        --profile int

Each simulated device:
  1. GET /config/libreoffice/config.json → receives (or not) an update directive
  2. If directive → simulates download (HEAD on artifact_url)
  3. POST /update/status with success (1-failure_rate) or failure (failure_rate)

Output:
  - Real-time progress bar (ASCII)
  - Final JSON report with latencies, success rate, timeline
"""

import argparse
import json
import hashlib
import random
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def _make_uuid(index: int) -> str:
    """Deterministic UUID for device N."""
    return str(uuid.UUID(hashlib.md5(f"sim-device-{index}".encode()).hexdigest()))


def _simulate_device(
    device_index: int,
    bootstrap_url: str,
    profile: str,
    campaign_id: int,
    failure_rate: float,
    plugin_version: str,
):
    """Simulate a single device lifecycle. Returns a result dict."""
    client_uuid = _make_uuid(device_index)
    result = {
        "device_index": device_index,
        "client_uuid": client_uuid,
        "got_directive": False,
        "status": "no_directive",
        "latency_config_ms": 0,
        "latency_update_ms": 0,
        "error": None,
    }

    # Step 1: Fetch config
    config_url = f"{bootstrap_url}/config/libreoffice/config.json?profile={profile}"
    headers = {
        "Accept": "application/json",
        "X-Plugin-Version": plugin_version,
        "X-Platform-Type": "libreoffice",
        "X-Client-UUID": client_uuid,
        "User-Agent": f"MIrAI-Simulator/1.0 device-{device_index}",
    }

    t0 = time.monotonic()
    try:
        req = Request(config_url, headers=headers)
        with urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        result["latency_config_ms"] = round((time.monotonic() - t0) * 1000)
    except (HTTPError, URLError, Exception) as e:
        result["latency_config_ms"] = round((time.monotonic() - t0) * 1000)
        result["status"] = "config_error"
        result["error"] = str(e)
        return result

    # Step 2: Check for update directive
    update = body.get("update")
    if not update or not isinstance(update, dict):
        result["status"] = "no_directive"
        return result

    result["got_directive"] = True
    target_version = update.get("target_version", "")
    artifact_url = update.get("artifact_url", "")

    # Step 3: Simulate download (HEAD only)
    if artifact_url:
        full_url = artifact_url if artifact_url.startswith("http") else bootstrap_url + artifact_url
        try:
            head_req = Request(full_url, method="HEAD", headers={"User-Agent": headers["User-Agent"]})
            urlopen(head_req, timeout=10)
        except Exception:
            pass  # download simulation — don't fail on HEAD errors

    # Step 4: Simulate success or failure
    t1 = time.monotonic()
    if random.random() < failure_rate:
        status = random.choice(["failed", "checksum_error", "download_error"])
        error_detail = f"Simulated {status} for device {device_index}"
    else:
        status = "installed"
        error_detail = ""

    # Step 5: Report status
    status_url = f"{bootstrap_url}/update/status"
    payload = {
        "campaign_id": campaign_id,
        "client_uuid": client_uuid,
        "status": status,
        "version_before": plugin_version,
        "version_after": target_version if status == "installed" else "",
        "error_detail": error_detail,
    }
    try:
        data = json.dumps(payload).encode("utf-8")
        req = Request(status_url, data=data, headers={
            "Content-Type": "application/json",
            "User-Agent": headers["User-Agent"],
        })
        with urlopen(req, timeout=10) as resp:
            resp.read()
    except (HTTPError, URLError, Exception) as e:
        # Status reporting failure is non-fatal
        result["error"] = f"status_report_failed: {e}"

    result["latency_update_ms"] = round((time.monotonic() - t1) * 1000)
    result["status"] = status
    return result


def _progress_bar(done: int, total: int, width: int = 40):
    pct = done / total if total else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    sys.stderr.write(f"\r  [{bar}] {done}/{total} ({pct:.0%})")
    sys.stderr.flush()


def main():
    parser = argparse.ArgumentParser(description="MIrAI deployment simulator")
    parser.add_argument("--devices", type=int, default=100, help="Number of simulated devices")
    parser.add_argument("--concurrency", type=int, default=20, help="Max parallel requests")
    parser.add_argument("--bootstrap-url", required=True, help="Bootstrap server URL")
    parser.add_argument("--campaign-id", type=int, default=1, help="Campaign ID to simulate")
    parser.add_argument("--failure-rate", type=float, default=0.05, help="Simulated failure rate (0-1)")
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between waves")
    parser.add_argument("--profile", default="int", help="Config profile (dev/int/prod)")
    parser.add_argument("--plugin-version", default="0.9.0", help="Simulated current plugin version")
    parser.add_argument("--output", default=None, help="Output JSON report file path")
    args = parser.parse_args()

    print(f"MIrAI Deployment Simulator")
    print(f"  Devices: {args.devices}")
    print(f"  Concurrency: {args.concurrency}")
    print(f"  Bootstrap: {args.bootstrap_url}")
    print(f"  Campaign: {args.campaign_id}")
    print(f"  Failure rate: {args.failure_rate:.0%}")
    print(f"  Profile: {args.profile}")
    print(f"  Plugin version: {args.plugin_version}")
    print()

    results = []
    start_time = time.monotonic()

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {}
        for i in range(args.devices):
            future = pool.submit(
                _simulate_device,
                i, args.bootstrap_url, args.profile,
                args.campaign_id, args.failure_rate, args.plugin_version,
            )
            futures[future] = i
            # Stagger submissions slightly
            if i % args.concurrency == 0 and i > 0:
                time.sleep(args.interval)

        done_count = 0
        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            done_count += 1
            _progress_bar(done_count, args.devices)

    elapsed = time.monotonic() - start_time
    sys.stderr.write("\n\n")

    # Compute stats
    got_directive = [r for r in results if r["got_directive"]]
    installed = [r for r in results if r["status"] == "installed"]
    failed = [r for r in results if r["status"] in ("failed", "checksum_error", "download_error")]
    no_directive = [r for r in results if r["status"] == "no_directive"]
    config_errors = [r for r in results if r["status"] == "config_error"]

    config_latencies = [r["latency_config_ms"] for r in results if r["latency_config_ms"] > 0]
    update_latencies = [r["latency_update_ms"] for r in results if r["latency_update_ms"] > 0]

    def _stats(values):
        if not values:
            return {"min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0}
        s = sorted(values)
        return {
            "min": s[0],
            "max": s[-1],
            "avg": round(sum(s) / len(s)),
            "p50": s[len(s) // 2],
            "p95": s[int(len(s) * 0.95)],
        }

    report = {
        "summary": {
            "total_devices": args.devices,
            "got_directive": len(got_directive),
            "installed": len(installed),
            "failed": len(failed),
            "no_directive": len(no_directive),
            "config_errors": len(config_errors),
            "success_rate": round(len(installed) / len(got_directive), 4) if got_directive else 0,
            "failure_rate_actual": round(len(failed) / len(got_directive), 4) if got_directive else 0,
            "elapsed_seconds": round(elapsed, 1),
        },
        "latencies": {
            "config_ms": _stats(config_latencies),
            "update_ms": _stats(update_latencies),
        },
        "parameters": {
            "bootstrap_url": args.bootstrap_url,
            "campaign_id": args.campaign_id,
            "failure_rate_target": args.failure_rate,
            "profile": args.profile,
            "plugin_version": args.plugin_version,
            "concurrency": args.concurrency,
        },
        "errors": [
            {"device": r["device_index"], "error": r["error"]}
            for r in results if r["error"]
        ][:20],  # cap at 20 errors
    }

    # Print summary
    print("Results:")
    print(f"  Total devices:    {report['summary']['total_devices']}")
    print(f"  Got directive:    {report['summary']['got_directive']}")
    print(f"  Installed:        {report['summary']['installed']}")
    print(f"  Failed:           {report['summary']['failed']}")
    print(f"  No directive:     {report['summary']['no_directive']}")
    print(f"  Config errors:    {report['summary']['config_errors']}")
    print(f"  Success rate:     {report['summary']['success_rate']:.1%}")
    print(f"  Elapsed:          {report['summary']['elapsed_seconds']}s")
    print()
    print(f"  Config latency:   avg={report['latencies']['config_ms']['avg']}ms "
          f"p50={report['latencies']['config_ms']['p50']}ms "
          f"p95={report['latencies']['config_ms']['p95']}ms")
    if update_latencies:
        print(f"  Update latency:   avg={report['latencies']['update_ms']['avg']}ms "
              f"p50={report['latencies']['update_ms']['p50']}ms "
              f"p95={report['latencies']['update_ms']['p95']}ms")

    # Write report
    output_path = args.output or f"tests/simulation/report_{int(time.time())}.json"
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  Report saved to: {output_path}")


if __name__ == "__main__":
    main()
