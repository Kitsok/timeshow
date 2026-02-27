#!/usr/bin/env python3
"""Scan a subnet for NTP servers and report time offset statistics."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import socket
import struct
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

NTP_PORT = 123
NTP_PACKET_LEN = 48
NTP_EPOCH_DELTA = 2208988800  # Seconds between 1900-01-01 and 1970-01-01


@dataclass
class NtpResult:
    host: str
    stratum: int
    offset_ms: float
    delay_ms: float
    leap: int
    version: int


def unix_to_ntp(unix_seconds: float) -> bytes:
    seconds = int(unix_seconds) + NTP_EPOCH_DELTA
    fraction = int((unix_seconds - int(unix_seconds)) * (1 << 32))
    return struct.pack("!II", seconds, fraction)


def ntp_to_unix(ts: bytes) -> float:
    seconds, fraction = struct.unpack("!II", ts)
    return (seconds - NTP_EPOCH_DELTA) + fraction / (1 << 32)


def build_ntp_request(t1_unix: float) -> bytes:
    packet = bytearray(NTP_PACKET_LEN)
    packet[0] = 0x1B  # LI=0, VN=3, Mode=3 (client)
    packet[40:48] = unix_to_ntp(t1_unix)  # Transmit timestamp
    return bytes(packet)


def query_ntp(host: str, timeout: float) -> NtpResult | None:
    t1 = time.time()
    request = build_ntp_request(t1)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(request, (host, NTP_PORT))
            response, _ = sock.recvfrom(512)
            t4 = time.time()
        except (TimeoutError, socket.timeout, OSError):
            return None

    if len(response) < NTP_PACKET_LEN:
        return None

    first = response[0]
    leap = (first >> 6) & 0x3
    version = (first >> 3) & 0x7
    mode = first & 0x7
    stratum = response[1]

    # Mode 4 = server, Mode 5 = broadcast server
    if mode not in (4, 5) or stratum == 0:
        return None

    t2 = ntp_to_unix(response[32:40])  # Server receive timestamp
    t3 = ntp_to_unix(response[40:48])  # Server transmit timestamp

    offset = ((t2 - t1) + (t3 - t4)) / 2
    delay = (t4 - t1) - (t3 - t2)

    return NtpResult(
        host=host,
        stratum=stratum,
        offset_ms=offset * 1000,
        delay_ms=delay * 1000,
        leap=leap,
        version=version,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find NTP servers in a network and print time offset statistics.",
    )
    parser.add_argument(
        "--network",
        default="172.20.20.0/24",
        help="CIDR network to scan (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Per-host timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=64,
        help="Number of concurrent workers (default: %(default)s)",
    )
    parser.add_argument(
        "--include-network-broadcast",
        action="store_true",
        help="Also query network and broadcast addresses",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of text output",
    )
    return parser.parse_args()


def hosts_to_scan(network_cidr: str, include_special: bool) -> list[str]:
    network = ipaddress.ip_network(network_cidr, strict=False)
    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported")

    if include_special:
        addresses = [str(ip) for ip in network]
    else:
        addresses = [str(ip) for ip in network.hosts()]

    if not addresses:
        raise ValueError("Network contains no hosts to scan")
    return addresses


def build_report(results: list[NtpResult], scanned: int, elapsed: float) -> dict:
    report = {
        "generated_at": int(time.time()),
        "scanned_hosts": scanned,
        "ntp_servers": len(results),
        "scan_time_s": round(elapsed, 3),
        "servers": [],
        "stats": None,
    }

    if not results:
        return report

    sorted_results = sorted(results, key=lambda r: abs(r.offset_ms))
    report["servers"] = [
        {
            "host": result.host,
            "stratum": result.stratum,
            "offset_ms": round(result.offset_ms, 3),
            "delay_ms": round(result.delay_ms, 3),
            "leap": result.leap,
            "version": result.version,
        }
        for result in sorted_results
    ]

    offsets = [r.offset_ms for r in results]
    abs_offsets = [abs(v) for v in offsets]
    rms = math.sqrt(sum(v * v for v in offsets) / len(offsets))
    report["stats"] = {
        "min_offset_ms": round(min(offsets), 3),
        "max_offset_ms": round(max(offsets), 3),
        "mean_offset_ms": round(statistics.mean(offsets), 3),
        "median_offset_ms": round(statistics.median(offsets), 3),
        "stdev_offset_ms": round(statistics.stdev(offsets), 3) if len(offsets) > 1 else None,
        "rms_offset_ms": round(rms, 3),
        "mean_abs_offset_ms": round(statistics.mean(abs_offsets), 3),
        "max_abs_offset_ms": round(max(abs_offsets), 3),
    }
    return report


def print_results(results: list[NtpResult], scanned: int, elapsed: float, as_json: bool) -> None:
    report = build_report(results, scanned, elapsed)
    if as_json:
        print(json.dumps(report, separators=(",", ":")))
        return

    print(f"Scanned hosts : {scanned}")
    print(f"NTP servers   : {len(results)}")
    print(f"Scan time     : {elapsed:.2f} s")

    if not results:
        return

    print("\nServers:")
    for result in sorted(results, key=lambda r: abs(r.offset_ms)):
        print(
            f"  {result.host:15} stratum={result.stratum:<2} "
            f"offset={result.offset_ms:+8.3f} ms delay={result.delay_ms:8.3f} ms "
            f"LI={result.leap} VN={result.version}"
        )

    offsets = [r.offset_ms for r in results]
    abs_offsets = [abs(v) for v in offsets]

    print("\nOffset statistics (ms):")
    print(f"  min          : {min(offsets):+.3f}")
    print(f"  max          : {max(offsets):+.3f}")
    print(f"  mean         : {statistics.mean(offsets):+.3f}")
    print(f"  median       : {statistics.median(offsets):+.3f}")
    print(f"  stdev        : {statistics.stdev(offsets):.3f}" if len(offsets) > 1 else "  stdev        : n/a")
    rms = math.sqrt(sum(v * v for v in offsets) / len(offsets))
    print(f"  RMS          : {rms:.3f}")
    print(f"  mean |offset|: {statistics.mean(abs_offsets):.3f}")


def main() -> int:
    args = parse_args()

    try:
        hosts = hosts_to_scan(args.network, args.include_network_broadcast)
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    start = time.time()
    results: list[NtpResult] = []

    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(query_ntp, host, args.timeout) for host in hosts]
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    elapsed = time.time() - start
    print_results(results, scanned=len(hosts), elapsed=elapsed, as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
