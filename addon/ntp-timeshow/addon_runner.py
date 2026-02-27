#!/usr/bin/env python3
"""Home Assistant add-on runner for NTP scan publishing."""

from __future__ import annotations

import json
import signal
import sys
import time
from pathlib import Path

import paho.mqtt.client as mqtt

import ntp_scan

OPTIONS_PATH = Path("/data/options.json")
STOP = False


def on_signal(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def load_options() -> dict:
    if not OPTIONS_PATH.exists():
        raise RuntimeError(f"Missing add-on options file: {OPTIONS_PATH}")
    with OPTIONS_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_discovery_payload(name: str, object_id: str, state_topic: str, value_template: str, unit: str | None = None) -> dict:
    payload = {
        "name": name,
        "state_topic": state_topic,
        "value_template": value_template,
        "unique_id": f"ntp_timeshow_{object_id}",
        "state_class": "measurement",
    }
    if unit:
        payload["unit_of_measurement"] = unit
    return payload


def publish(client: mqtt.Client, topic: str, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    info = client.publish(topic, data, qos=1, retain=True)
    info.wait_for_publish()


def publish_discovery(client: mqtt.Client, options: dict, state_topic: str) -> None:
    prefix = options["mqtt_discovery_prefix"].strip("/")
    sensors = [
        (
            "NTP Mean Offset",
            "mean_offset_ms",
            "{{ value_json.stats.mean_offset_ms if value_json.stats else none }}",
            "ms",
        ),
        (
            "NTP Max Abs Offset",
            "max_abs_offset_ms",
            "{{ value_json.stats.max_abs_offset_ms if value_json.stats else none }}",
            "ms",
        ),
        (
            "NTP Servers Found",
            "servers",
            "{{ value_json.ntp_servers }}",
            None,
        ),
    ]

    for name, object_id, template, unit in sensors:
        topic = f"{prefix}/sensor/ntp_timeshow/{object_id}/config"
        payload = build_discovery_payload(name, object_id, state_topic, template, unit)
        publish(client, topic, payload)


def scan_once(options: dict) -> dict:
    hosts = ntp_scan.hosts_to_scan(options["network"], options["include_network_broadcast"])
    start = time.time()
    results = []

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=max(1, options["workers"])) as executor:
        futures = [executor.submit(ntp_scan.query_ntp, host, options["timeout"]) for host in hosts]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    elapsed = time.time() - start
    return ntp_scan.build_report(results, scanned=len(hosts), elapsed=elapsed)


def main() -> int:
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    options = load_options()
    topic = options["mqtt_topic"].strip("/")
    interval = max(5, int(options["interval_seconds"]))

    client = mqtt.Client()
    if options.get("mqtt_username"):
        client.username_pw_set(options["mqtt_username"], options.get("mqtt_password", ""))

    client.connect(options["mqtt_host"], int(options["mqtt_port"]), keepalive=max(30, interval))
    client.loop_start()

    try:
        if options.get("mqtt_discovery", True):
            publish_discovery(client, options, topic)

        while not STOP:
            report = scan_once(options)
            publish(client, topic, report)
            print(
                f"Published scan: hosts={report['scanned_hosts']} servers={report['ntp_servers']} "
                f"duration={report['scan_time_s']}s"
            )

            for _ in range(interval):
                if STOP:
                    break
                time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())
