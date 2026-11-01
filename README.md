# NetGuard

NetGuard is a lightweight, defensive network-traffic monitor. It samples interface byte counters, calculates inbound/outbound throughput, detects configurable traffic spikes, and sends alerts to a webhook.

## Features

- Uses operating-system network interface counters via `psutil` (no packet payload inspection).
- Per-interface inbound and outbound throughput sampling.
- Configurable spike thresholds, sampling interval, cooldown, and webhook URL.
- Console output plus JSON Lines event logging.
- Graceful shutdown with Ctrl+C.
- Unit tests for rate calculation and anomaly detection.

## Requirements

- Python 3.9+
- Linux, macOS, or Windows
- Optional: a webhook endpoint such as Slack, Discord, or your own HTTP service.

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/netguard.git
cd netguard
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
cp config.example.json config.json
python netguard.py --config config.json
```

On Windows, copy `config.example.json` to `config.json` manually if `cp` is unavailable.

## Configuration

Edit `config.json`:

```json
{
  "sample_interval_seconds": 2,
  "inbound_threshold_mbps": 100,
  "outbound_threshold_mbps": 50,
  "alert_cooldown_seconds": 60,
  "webhook_url": "",
  "log_file": "netguard-events.jsonl",
  "interfaces": []
}
```

- `sample_interval_seconds`: time between samples.
- `inbound_threshold_mbps` / `outbound_threshold_mbps`: alert when a measured interface rate is **at or above** the threshold. Set a threshold to `0` to disable that direction.
- `alert_cooldown_seconds`: minimum time between repeated alerts for the same interface and direction.
- `webhook_url`: optional HTTP(S) webhook. Leave empty to disable webhook delivery.
- `log_file`: JSON Lines event log path. Set to an empty string to disable file logging.
- `interfaces`: optional allow-list of interface names. An empty list monitors all interfaces.

Thresholds are intentionally simple baselines, not machine-learning detection. Tune them for the network being monitored to reduce false positives.

## Run options

```bash
python netguard.py --config config.json
python netguard.py --list-interfaces
python netguard.py --once --config config.json
```

`--once` takes two samples and prints one rate report, useful for a quick check. `--list-interfaces` lists interfaces and exits.

## Webhook payload

NetGuard sends a JSON `POST` request containing:

```json
{
  "source": "netguard",
  "event": "traffic_anomaly",
  "timestamp": "2025-01-01T12:00:00+00:00",
  "interface": "eth0",
  "direction": "inbound",
  "rate_mbps": 123.45,
  "threshold_mbps": 100.0,
  "message": "Inbound traffic on eth0 reached 123.45 Mbps (threshold: 100.00 Mbps)."
}
```

Webhook delivery has a short timeout. A failed webhook is reported to the console and does not stop monitoring. Use HTTPS and protect webhook URLs as secrets; do not commit real credentials to source control.

## Run as a service

For production use, run NetGuard under a dedicated service account and a process supervisor such as `systemd`, `launchd`, or Windows Task Scheduler. Restrict write access to the configuration and log files. The tool only reads aggregate interface counters; it does not capture packet contents.

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limitations

- Measures aggregate interface throughput, not per-process or per-connection traffic.
- A high-throughput threshold can flag legitimate backups, updates, or large downloads.
- Some systems may require elevated privileges to enumerate certain interface details, although byte counters are commonly available to normal users.
- This is a monitoring aid, not an intrusion detection system or a replacement for a firewall, endpoint protection, or network telemetry platform.

## License

MIT. See [LICENSE](LICENSE).
