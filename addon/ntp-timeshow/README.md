# NTP Timeshow Scanner

Home Assistant add-on that scans an IPv4 subnet for NTP servers, calculates offsets and delays, then publishes results to MQTT for dashboards and automations.

## What this add-on does

- Scans a configurable CIDR subnet (for example `172.20.20.0/24`).
- Detects hosts that respond as NTP servers on UDP/123.
- Calculates per-server offset and delay.
- Publishes one JSON payload per scan to a configurable MQTT topic.
- Optionally publishes MQTT Discovery entities so sensors appear automatically in Home Assistant.

## Installation

1. In Home Assistant, open `Settings` -> `Add-ons` -> `Add-on Store`.
2. Open menu (top-right) -> `Repositories`.
3. Add repository URL: `https://github.com/Kitsok/timeshow`.
4. Install `NTP Timeshow Scanner`.
5. Configure options and start the add-on.

## Configuration

Example configuration:

```yaml
network: 172.20.20.0/24
interval_seconds: 300
timeout: 0.5
workers: 64
include_network_broadcast: false
mqtt_host: core-mosquitto
mqtt_port: 1883
mqtt_username: ntp_timeshow
mqtt_password: "change_me"
mqtt_topic: timeshow/ntp_scan
mqtt_discovery: true
mqtt_discovery_prefix: homeassistant
verbose: true
```

Options:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `network` | string | `172.20.20.0/24` | IPv4 CIDR network to scan. |
| `interval_seconds` | int | `300` | Seconds between scan runs. Minimum effective value is 5. |
| `timeout` | float | `0.5` | Per-host NTP timeout in seconds. |
| `workers` | int | `64` | Number of concurrent probe workers. |
| `include_network_broadcast` | bool | `false` | If true, also probes network and broadcast addresses. |
| `mqtt_host` | string | `core-mosquitto` | MQTT hostname or IP. Use `core-mosquitto` for Mosquitto add-on. |
| `mqtt_port` | int | `1883` | MQTT TCP port. |
| `mqtt_username` | string | `""` | MQTT username. |
| `mqtt_password` | string | `""` | MQTT password. |
| `mqtt_topic` | string | `timeshow/ntp_scan` | Topic where scan JSON is published (retained). |
| `mqtt_discovery` | bool | `true` | Publish MQTT Discovery config entities for Home Assistant. |
| `mqtt_discovery_prefix` | string | `homeassistant` | Discovery prefix used by Home Assistant MQTT integration. |
| `verbose` | bool | `true` | Enables detailed runtime logs (connection/publish/scan). |

## MQTT Payload

Default topic: `timeshow/ntp_scan`

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
    },
    {
      "host": "172.20.20.21",
      "stratum": 3,
      "offset_ms": 1.203,
      "delay_ms": 1.870,
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

## Auto-created Home Assistant entities

When `mqtt_discovery: true`, these sensors are published through MQTT Discovery:

- `NTP Mean Offset` (`ms`)
- `NTP Max Abs Offset` (`ms`)
- `NTP Servers Found`

## Suggested dashboard card

```yaml
type: vertical-stack
cards:
  - type: entities
    title: NTP Scan
    show_header_toggle: false
    entities:
      - sensor.ntp_mean_offset
      - sensor.ntp_max_abs_offset
      - sensor.ntp_servers_found
  - type: history-graph
    title: Offset (24h)
    hours_to_show: 24
    refresh_interval: 60
    entities:
      - sensor.ntp_mean_offset
      - sensor.ntp_max_abs_offset
  - type: history-graph
    title: Servers Found (24h)
    hours_to_show: 24
    refresh_interval: 60
    entities:
      - sensor.ntp_servers_found
```

## Troubleshooting

`Message publish failed: The client is not currently connected`
- Verify `mqtt_host`/`mqtt_port`.
- Check broker availability and add-on startup order.
- Keep `verbose: true` to see connect/disconnect diagnostics.

`Client ... disconnected, not authorised` in Mosquitto logs
- Username/password is invalid or missing.
- Create user in Mosquitto add-on and set matching `mqtt_username` and `mqtt_password`.

No sensors appear in Home Assistant
- Ensure MQTT integration is configured and running.
- Ensure `mqtt_discovery: true`.
- Confirm payloads are present in `Developer Tools` -> `MQTT` -> `Listen to topic`.
- Check topic matches `mqtt_topic` in add-on config.
