#!/usr/bin/env python3
"""NetGuard: lightweight aggregate network throughput anomaly monitor."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

import psutil


@dataclass(frozen=True)
class Rate:
    inbound_mbps: float
    outbound_mbps: float


def calculate_rates(previous: dict, current: dict, elapsed: float) -> Dict[str, Rate]:
    """Calculate per-interface Mbps from psutil counter snapshots."""
    if elapsed <= 0:
        raise ValueError("elapsed must be greater than zero")

    rates: Dict[str, Rate] = {}
    for name, now in current.items():
        before = previous.get(name)
        if before is None:
            continue
        # Counter resets (e.g. interface restart) should not create negative rates.
        recv = max(0, now.bytes_recv - before.bytes_recv)
        sent = max(0, now.bytes_sent - before.bytes_sent)
        rates[name] = Rate(
            inbound_mbps=(recv * 8) / elapsed / 1_000_000,
            outbound_mbps=(sent * 8) / elapsed / 1_000_000,
        )
    return rates


def detect_anomalies(
    rates: Dict[str, Rate],
    inbound_threshold_mbps: float,
    outbound_threshold_mbps: float,
) -> Iterable[dict]:
    """Yield anomaly events for rates at or above enabled thresholds."""
    for interface, rate in rates.items():
        if inbound_threshold_mbps > 0 and rate.inbound_mbps >= inbound_threshold_mbps:
            yield {
                "interface": interface,
                "direction": "inbound",
                "rate_mbps": round(rate.inbound_mbps, 3),
                "threshold_mbps": float(inbound_threshold_mbps),
            }
        if outbound_threshold_mbps > 0 and rate.outbound_mbps >= outbound_threshold_mbps:
            yield {
                "interface": interface,
                "direction": "outbound",
                "rate_mbps": round(rate.outbound_mbps, 3),
                "threshold_mbps": float(outbound_threshold_mbps),
            }


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    defaults = {
        "sample_interval_seconds": 2,
        "inbound_threshold_mbps": 100,
        "outbound_threshold_mbps": 50,
        "alert_cooldown_seconds": 60,
        "webhook_url": "",
        "log_file": "netguard-events.jsonl",
        "interfaces": [],
    }
    defaults.update(config)

    if not isinstance(defaults["sample_interval_seconds"], (int, float)) or defaults["sample_interval_seconds"] <= 0:
        raise ValueError("sample_interval_seconds must be greater than zero")
    for key in ("inbound_threshold_mbps", "outbound_threshold_mbps", "alert_cooldown_seconds"):
        if not isinstance(defaults[key], (int, float)) or defaults[key] < 0:
            raise ValueError(f"{key} must be zero or greater")
    if not isinstance(defaults["interfaces"], list):
        raise ValueError("interfaces must be a list")
    return defaults


def send_webhook(url: str, event: dict, timeout: float = 5.0) -> None:
    """POST an event to a configured webhook; raises on delivery failure."""
    if not url:
        return
    body = json.dumps(event).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "NetGuard/1.0"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        if not 200 <= response.status < 300:
            raise RuntimeError(f"webhook returned HTTP {response.status}")


class NetGuard:
    def __init__(self, config: dict):
        self.config = config
        self.last_alert: Dict[tuple, float] = {}
        self.log_path = config["log_file"]

    def snapshot(self) -> dict:
        counters = psutil.net_io_counters(pernic=True)
        allowed = set(self.config["interfaces"])
        return {
            name: counter
            for name, counter in counters.items()
            if not allowed or name in allowed
        }

    def emit(self, event: dict) -> None:
        line = json.dumps(event, sort_keys=True)
        print(line, flush=True)
        if self.log_path:
            with Path(self.log_path).open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def process_rates(self, rates: Dict[str, Rate]) -> None:
        now = time.monotonic()
        for anomaly in detect_anomalies(
            rates,
            self.config["inbound_threshold_mbps"],
            self.config["outbound_threshold_mbps"],
        ):
            key = (anomaly["interface"], anomaly["direction"])
            cooldown = self.config["alert_cooldown_seconds"]
            if key in self.last_alert and now - self.last_alert[key] < cooldown:
                continue

            message = (
                f'{anomaly["direction"].capitalize()} traffic on {anomaly["interface"]} '
                f'reached {anomaly["rate_mbps"]:.2f} Mbps '
                f'(threshold: {anomaly["threshold_mbps"]:.2f} Mbps).'
            )
            event = {
                "source": "netguard",
                "event": "traffic_anomaly",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **anomaly,
                "message": message,
            }
            self.emit(event)
            try:
                send_webhook(self.config["webhook_url"], event)
            except (URLError, TimeoutError, RuntimeError, OSError) as exc:
                print(f"NetGuard: webhook delivery failed: {exc}", file=sys.stderr, flush=True)
            self.last_alert[key] = now

    def run(self, once: bool = False, stop_flag=None) -> None:
        previous = self.snapshot()
        previous_time = time.monotonic()
        print("NetGuard monitoring started. Press Ctrl+C to stop.", flush=True)

        while stop_flag is None or not stop_flag["stop"]:
            time.sleep(self.config["sample_interval_seconds"])
            current = self.snapshot()
            current_time = time.monotonic()
            elapsed = current_time - previous_time
            rates = calculate_rates(previous, current, elapsed)

            for name, rate in rates.items():
                print(
                    f"{name}: ↓ {rate.inbound_mbps:.3f} Mbps | "
                    f"↑ {rate.outbound_mbps:.3f} Mbps",
                    flush=True,
                )
            self.process_rates(rates)
            previous, previous_time = current, current_time
            if once:
                break


def main() -> int:
    parser = argparse.ArgumentParser(description="Lightweight network traffic anomaly monitor")
    parser.add_argument("--config", default="config.json", help="Path to JSON config (default: config.json)")
    parser.add_argument("--list-interfaces", action="store_true", help="List detected network interfaces and exit")
    parser.add_argument("--once", action="store_true", help="Take two samples, report once, and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        for name in psutil.net_io_counters(pernic=True):
            print(name)
        return 0

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config not found: {config_path}. Copy config.example.json to config.json first.", file=sys.stderr)
        return 2

    try:
        config = load_config(config_path)
        guard = NetGuard(config)
        stop_flag = {"stop": False}

        def request_stop(_signum, _frame):
            stop_flag["stop"] = True

        signal.signal(signal.SIGINT, request_stop)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, request_stop)
        guard.run(once=args.once, stop_flag=stop_flag)
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"NetGuard error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
