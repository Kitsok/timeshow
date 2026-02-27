# NTP Timeshow Scanner (Home Assistant Add-on)

Scans an IPv4 subnet for NTP servers and publishes per-scan JSON reports to MQTT.

## MQTT Payload

Topic (default): `timeshow/ntp_scan`

Example payload:

```json
{
  "generated_at": 1740690000,
  "scanned_hosts": 254,
  "ntp_servers": 2,
  "scan_time_s": 1.03,
  "servers": [
    {
      "host": "172.20.20.10",
      "stratum": 2,
      "offset_ms": -0.843,
      "delay_ms": 0.912,
      "leap": 0,
      "version": 4
    }
  ],
  "stats": {
    "min_offset_ms": -0.843,
    "max_offset_ms": 1.203,
    "mean_offset_ms": 0.18,
    "median_offset_ms": 0.18,
    "stdev_offset_ms": 1.446,
    "rms_offset_ms": 1.053,
    "mean_abs_offset_ms": 1.023,
    "max_abs_offset_ms": 1.203
  }
}
```

## Configuration options

- `network`: CIDR subnet to scan.
- `interval_seconds`: Period between scans.
- `timeout`: NTP query timeout per host.
- `workers`: Concurrent probes.
- `include_network_broadcast`: Include network/broadcast IPs.
- `mqtt_host`, `mqtt_port`, `mqtt_username`, `mqtt_password`: Broker settings.
- `mqtt_topic`: Topic for report payload.
- `mqtt_discovery`: Publish Home Assistant MQTT discovery entities.
- `mqtt_discovery_prefix`: Discovery prefix (usually `homeassistant`).
- `verbose`: Enable detailed add-on logs for MQTT and scan cycles.
