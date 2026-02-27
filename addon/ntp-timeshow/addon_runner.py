#!/usr/bin/env python3
"""Home Assistant add-on runner for NTP scan publishing."""

from __future__ import annotations

import json
import signal
import sys
import threading
import time
from pathlib import Path

import paho.mqtt.client as mqtt

import ntp_scan

OPTIONS_PATH = Path("/data/options.json")
STOP = False
VERBOSE = True


def on_signal(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def log(message: str, force: bool = False) -> None:
    if force or VERBOSE:
        print(message, flush=True)


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
    last_error: Exception | None = None
    for _ in range(3):
        info = client.publish(topic, data, qos=1, retain=True)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            last_error = RuntimeError(f"Publish rejected: rc={info.rc}")
            log(f"MQTT publish rejected for topic '{topic}': rc={info.rc}")
            time.sleep(1)
            continue
        try:
            info.wait_for_publish()
            log(f"MQTT publish success: topic='{topic}' bytes={len(data)}")
            return
        except RuntimeError as exc:
            last_error = exc
            log(f"MQTT publish runtime error for topic '{topic}': {exc}")
            time.sleep(1)
    raise RuntimeError(f"MQTT publish failed after retries: {last_error}")


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
    global VERBOSE
    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    options = load_options()
    VERBOSE = bool(options.get("verbose", True))
    topic = options["mqtt_topic"].strip("/")
    interval = max(5, int(options["interval_seconds"]))
    connected = threading.Event()
    mqtt_host = options["mqtt_host"]
    mqtt_port = int(options["mqtt_port"])
    username = options.get("mqtt_username") or ""
    discovery_enabled = bool(options.get("mqtt_discovery", True))

    log(
        "Add-on configuration: "
        f"network={options['network']} interval={interval}s timeout={options['timeout']} "
        f"workers={options['workers']} mqtt_host={mqtt_host}:{mqtt_port} "
        f"mqtt_username={'set' if username else 'empty'} discovery={discovery_enabled}",
        force=True,
    )

    client = mqtt.Client()
    if username:
        client.username_pw_set(username, options.get("mqtt_password", ""))
        log("MQTT authentication enabled (username provided)")
    else:
        log("MQTT authentication disabled (no username provided)")

    def on_connect(_client: mqtt.Client, _userdata: object, _flags: object, reason_code: object, _properties: object = None) -> None:
        if reason_code == 0:
            connected.set()
            log("MQTT connected successfully", force=True)
        else:
            log(f"MQTT connect failed: reason_code={reason_code}", force=True)

    def on_disconnect(_client: mqtt.Client, _userdata: object, *_args: object) -> None:
        connected.clear()
        log(f"MQTT disconnected args={_args}", force=True)

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.loop_start()
    log(f"Connecting to MQTT broker {mqtt_host}:{mqtt_port}", force=True)
    client.connect(mqtt_host, mqtt_port, keepalive=max(30, interval))

    if not connected.wait(timeout=15):
        raise RuntimeError("MQTT connection was not established within 15 seconds")

    try:
        if discovery_enabled:
            log("Publishing MQTT discovery entities")
            publish_discovery(client, options, topic)

        while not STOP:
            log("Starting NTP scan cycle")
            report = scan_once(options)
            publish(client, topic, report)
            log(
                f"Published scan: hosts={report['scanned_hosts']} servers={report['ntp_servers']} "
                f"duration={report['scan_time_s']}s",
                force=True,
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
