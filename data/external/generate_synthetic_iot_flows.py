from __future__ import annotations

import argparse
import csv
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


@dataclass(frozen=True)
class Device:
    device_id: str
    device_type: str
    ip: str


@dataclass(frozen=True)
class ScenarioConfig:
    compromised_camera: str
    attack_scale: float


INTERNAL_DEVICES: list[Device] = [
    Device("cam-001", "camera", "10.10.0.11"),
    Device("cam-002", "camera", "10.10.0.12"),
    Device("cam-003", "camera", "10.10.0.13"),
    Device("router-01", "router", "10.10.0.1"),
    Device("router-02", "router", "10.10.0.2"),
    Device("door-ctrl-01", "door_controller", "10.10.0.21"),
    Device("door-ctrl-02", "door_controller", "10.10.0.22"),
    Device("sensor-01", "sensor", "10.10.0.31"),
    Device("sensor-02", "sensor", "10.10.0.32"),
    Device("sensor-03", "sensor", "10.10.0.33"),
    Device("nvr-01", "nvr", "10.10.0.40"),
    Device("storage-01", "storage_server", "10.10.0.50"),
]

DEVICE_BY_ID: dict[str, Device] = {d.device_id: d for d in INTERNAL_DEVICES}

UNKNOWN_EXTERNAL_IPS = [
    "185.199.110.45",
    "103.44.77.201",
    "45.76.22.19",
    "91.210.186.5",
    "198.251.90.77",
    "172.93.111.64",
]

BENIGN_EXTERNAL_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "13.107.42.14",
]

CSV_FIELDS = [
    "timestamp",
    "src_device",
    "dst_device",
    "device_id",
    "device_type",
    "src_ip",
    "dst_ip",
    "protocol",
    "port",
    "dest_port",
    "packet_rate",
    "byte_volume",
    "flow_duration",
    "unique_dest_ips",
    "tcp_ratio",
    "udp_ratio",
    "phase",
    "is_compromised_source",
    "is_attack",
    "attack_stage",
    "attack_family",
    "attack_path",
]


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def jitter(base: float, rel: float, rng: random.Random) -> float:
    return base * (1.0 + rng.uniform(-rel, rel))


def phase_for_minute(minute_idx: int) -> str:
    if minute_idx < 20:
        return "normal"
    if minute_idx < 40:
        return "camera_compromised"
    return "propagation"


def enrich_row_labels(row: dict[str, str | int | float], config: ScenarioConfig) -> dict[str, str | int | float]:
    phase = str(row.get("phase", "normal"))
    src_device = str(row.get("src_device", ""))
    compromised = int(row.get("is_compromised_source", 0) or 0)

    attack_path = f"{config.compromised_camera}->router-01->door-ctrl-01"
    if compromised == 0 or phase == "normal":
        row["is_attack"] = 0
        row["attack_stage"] = "benign"
        row["attack_family"] = "none"
        row["attack_path"] = ""
        return row

    row["is_attack"] = 1
    row["attack_family"] = "scan_and_propagate"
    row["attack_path"] = attack_path

    if phase == "camera_compromised":
        row["attack_stage"] = "initial_compromise"
    elif src_device == config.compromised_camera:
        row["attack_stage"] = "recon_and_c2"
    elif src_device == "router-01":
        row["attack_stage"] = "lateral_movement"
    elif src_device == "door-ctrl-01":
        row["attack_stage"] = "impact_and_spread"
    else:
        row["attack_stage"] = "propagation"

    return row


def benign_flows_for_second(
    ts: datetime,
    minute_idx: int,
    rng: random.Random,
    config: ScenarioConfig,
) -> list[dict[str, str | int | float]]:
    rows: list[dict[str, str | int | float]] = []
    t_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    phase = phase_for_minute(minute_idx)

    # Cameras stream to NVR (mostly UDP 554, stable high volume).
    # The configured compromised camera stays benign until minute 20, then switches to attack traffic.
    for cam in ("cam-001", "cam-002", "cam-003"):
        if cam == config.compromised_camera and minute_idx >= 20:
            continue
        src = DEVICE_BY_ID[cam]
        dst = DEVICE_BY_ID["nvr-01"]
        packet_rate = jitter(44.0, 0.10, rng)
        flow_duration = jitter(0.95, 0.12, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": dst.device_id,
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst.ip,
            "protocol": "UDP",
            "port": 554,
            "dest_port": 554,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 830.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 2,
            "tcp_ratio": 0.22,
            "udp_ratio": 0.78,
            "phase": phase,
            "is_compromised_source": 0,
        })

    # Sensors send telemetry to router-02 (mostly TCP on 1883)
    for sensor_id in ("sensor-01", "sensor-02", "sensor-03"):
        src = DEVICE_BY_ID[sensor_id]
        dst = DEVICE_BY_ID["router-02"]
        packet_rate = jitter(3.2, 0.14, rng)
        flow_duration = jitter(0.45, 0.18, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": dst.device_id,
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst.ip,
            "protocol": "TCP",
            "port": 1883,
            "dest_port": 1883,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 280.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 1,
            "tcp_ratio": 0.91,
            "udp_ratio": 0.09,
            "phase": phase,
            "is_compromised_source": 0,
        })

    # Door controllers communicate with router-01
    for door_id in ("door-ctrl-01", "door-ctrl-02"):
        src = DEVICE_BY_ID[door_id]
        dst = DEVICE_BY_ID["router-01"]
        packet_rate = jitter(6.4, 0.12, rng)
        flow_duration = jitter(0.60, 0.15, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": dst.device_id,
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst.ip,
            "protocol": "TCP",
            "port": 443,
            "dest_port": 443,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 520.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 2,
            "tcp_ratio": 0.88,
            "udp_ratio": 0.12,
            "phase": phase,
            "is_compromised_source": 0,
        })

    # NVR to storage replication
    src = DEVICE_BY_ID["nvr-01"]
    dst = DEVICE_BY_ID["storage-01"]
    packet_rate = jitter(16.0, 0.15, rng)
    flow_duration = jitter(1.15, 0.16, rng)
    rows.append({
        "timestamp": t_iso,
        "src_device": src.device_id,
        "dst_device": dst.device_id,
        "device_id": src.device_id,
        "device_type": src.device_type,
        "src_ip": src.ip,
        "dst_ip": dst.ip,
        "protocol": "TCP",
        "port": 445,
        "dest_port": 445,
        "packet_rate": round(packet_rate, 3),
        "byte_volume": round(packet_rate * flow_duration * 1300.0, 2),
        "flow_duration": round(flow_duration, 4),
        "unique_dest_ips": 2,
        "tcp_ratio": 0.86,
        "udp_ratio": 0.14,
        "phase": phase,
        "is_compromised_source": 0,
    })

    # Storage heartbeat / sync acknowledgement back to NVR.
    src = DEVICE_BY_ID["storage-01"]
    dst = DEVICE_BY_ID["nvr-01"]
    packet_rate = jitter(7.8, 0.14, rng)
    flow_duration = jitter(0.72, 0.16, rng)
    rows.append({
        "timestamp": t_iso,
        "src_device": src.device_id,
        "dst_device": dst.device_id,
        "device_id": src.device_id,
        "device_type": src.device_type,
        "src_ip": src.ip,
        "dst_ip": dst.ip,
        "protocol": "TCP",
        "port": 2049,
        "dest_port": 2049,
        "packet_rate": round(packet_rate, 3),
        "byte_volume": round(packet_rate * flow_duration * 910.0, 2),
        "flow_duration": round(flow_duration, 4),
        "unique_dest_ips": 1,
        "tcp_ratio": 0.94,
        "udp_ratio": 0.06,
        "phase": phase,
        "is_compromised_source": 0,
    })

    # Routers external benign traffic (DNS + cloud)
    for rid in ("router-01", "router-02"):
        src = DEVICE_BY_ID[rid]
        dst_ip = rng.choice(BENIGN_EXTERNAL_IPS)
        packet_rate = jitter(10.5, 0.18, rng)
        flow_duration = jitter(0.50, 0.20, rng)
        proto = "UDP" if rng.random() < 0.7 else "TCP"
        port = 53 if proto == "UDP" else 443
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": "internet-benign",
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst_ip,
            "protocol": proto,
            "port": port,
            "dest_port": port,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 460.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 3,
            "tcp_ratio": 0.61,
            "udp_ratio": 0.39,
            "phase": phase,
            "is_compromised_source": 0,
        })

    return rows


def attack_flows_camera(
    ts: datetime,
    minute_idx: int,
    rng: random.Random,
    config: ScenarioConfig,
) -> list[dict[str, str | int | float]]:
    if minute_idx < 20:
        return []

    rows: list[dict[str, str | int | float]] = []
    t_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    src = DEVICE_BY_ID[config.compromised_camera]
    phase = phase_for_minute(minute_idx)

    # Persistent C2/external contact with traffic spikes.
    for _ in range(2):
        dst_ip = rng.choice(UNKNOWN_EXTERNAL_IPS)
        packet_rate = jitter((150.0 if minute_idx < 40 else 190.0) * config.attack_scale, 0.22, rng)
        flow_duration = jitter(1.3, 0.25, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": "external-unknown",
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "port": rng.choice([4444, 5555, 8088]),
            "dest_port": rng.choice([4444, 5555, 8088]),
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 950.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 8 if minute_idx < 40 else 10,
            "tcp_ratio": 0.90,
            "udp_ratio": 0.10,
            "phase": phase,
            "is_compromised_source": 1,
        })

    # Port scanning over topology-adjacent/internal reachable targets.
    scan_targets = [
        DEVICE_BY_ID["router-01"],
        DEVICE_BY_ID["router-02"],
        DEVICE_BY_ID["door-ctrl-01"],
        DEVICE_BY_ID["door-ctrl-02"],
        DEVICE_BY_ID["nvr-01"],
        DEVICE_BY_ID["storage-01"],
    ]
    scan_ports = [22, 23, 80, 443, 445, 1883, 3306, 3389, 8080]
    for _ in range(6):
        dst = rng.choice(scan_targets)
        port = rng.choice(scan_ports)
        packet_rate = jitter((85.0 if minute_idx < 40 else 110.0) * config.attack_scale, 0.25, rng)
        flow_duration = jitter(0.25, 0.40, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": src.device_id,
            "dst_device": dst.device_id,
            "device_id": src.device_id,
            "device_type": src.device_type,
            "src_ip": src.ip,
            "dst_ip": dst.ip,
            "protocol": "TCP" if rng.random() < 0.8 else "UDP",
            "port": port,
            "dest_port": port,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 210.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 8 if minute_idx < 40 else 10,
            "tcp_ratio": 0.93,
            "udp_ratio": 0.07,
            "phase": phase,
            "is_compromised_source": 1,
        })

    return rows


def attack_flows_propagated(
    ts: datetime,
    minute_idx: int,
    rng: random.Random,
    config: ScenarioConfig,
) -> list[dict[str, str | int | float]]:
    if minute_idx < 40:
        return []

    rows: list[dict[str, str | int | float]] = []
    t_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    # router-01 compromised after cam-002 pivot, probes core nodes and externals.
    r1 = DEVICE_BY_ID["router-01"]
    for _ in range(4):
        dst = rng.choice([
            DEVICE_BY_ID["door-ctrl-01"],
            DEVICE_BY_ID["door-ctrl-02"],
            DEVICE_BY_ID["storage-01"],
            DEVICE_BY_ID["nvr-01"],
        ])
        port = rng.choice([22, 80, 443, 445, 502, 1883])
        packet_rate = jitter(125.0 * config.attack_scale, 0.24, rng)
        flow_duration = jitter(0.58, 0.30, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": r1.device_id,
            "dst_device": dst.device_id,
            "device_id": r1.device_id,
            "device_type": r1.device_type,
            "src_ip": r1.ip,
            "dst_ip": dst.ip,
            "protocol": "TCP",
            "port": port,
            "dest_port": port,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 540.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 9,
            "tcp_ratio": 0.89,
            "udp_ratio": 0.11,
            "phase": "propagation",
            "is_compromised_source": 1,
        })

    # door-ctrl-01 compromised, starts abnormal outbound and lateral attempts.
    d1 = DEVICE_BY_ID["door-ctrl-01"]
    for _ in range(3):
        if rng.random() < 0.6:
            dst_device = "external-unknown"
            dst_ip = rng.choice(UNKNOWN_EXTERNAL_IPS)
        else:
            dst = rng.choice([DEVICE_BY_ID["door-ctrl-02"], DEVICE_BY_ID["router-02"], DEVICE_BY_ID["storage-01"]])
            dst_device = dst.device_id
            dst_ip = dst.ip
        port = rng.choice([443, 502, 1883, 8888, 9001])
        packet_rate = jitter(98.0 * config.attack_scale, 0.26, rng)
        flow_duration = jitter(0.72, 0.28, rng)
        rows.append({
            "timestamp": t_iso,
            "src_device": d1.device_id,
            "dst_device": dst_device,
            "device_id": d1.device_id,
            "device_type": d1.device_type,
            "src_ip": d1.ip,
            "dst_ip": dst_ip,
            "protocol": "TCP" if rng.random() < 0.85 else "UDP",
            "port": port,
            "dest_port": port,
            "packet_rate": round(packet_rate, 3),
            "byte_volume": round(packet_rate * flow_duration * 480.0, 2),
            "flow_duration": round(flow_duration, 4),
            "unique_dest_ips": 7,
            "tcp_ratio": 0.87,
            "udp_ratio": 0.13,
            "phase": "propagation",
            "is_compromised_source": 1,
        })

    return rows


def generate_dataset(
    output_path: Path,
    seed: int = 42,
    config: ScenarioConfig | None = None,
) -> int:
    rng = random.Random(seed)
    scenario = config or ScenarioConfig(compromised_camera="cam-002", attack_scale=1.0)
    start_ts = datetime(2026, 3, 13, 10, 0, 0, tzinfo=timezone.utc)
    total_rows = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()

        for second in range(60 * 60):
            ts = start_ts + timedelta(seconds=second)
            minute_idx = second // 60

            rows = []
            rows.extend(benign_flows_for_second(ts, minute_idx, rng, scenario))
            rows.extend(attack_flows_camera(ts, minute_idx, rng, scenario))
            rows.extend(attack_flows_propagated(ts, minute_idx, rng, scenario))

            for row in rows:
                row = enrich_row_labels(row, scenario)
                writer.writerow(row)
                total_rows += 1

    return total_rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic IoT telemetry flow dataset.")
    parser.add_argument(
        "--output",
        default="data/external/synthetic_iot_flows_60m_1s.csv",
        help="Output CSV path.",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed for deterministic generation.")
    parser.add_argument(
        "--compromised-camera",
        choices=["cam-001", "cam-002", "cam-003"],
        default="cam-002",
        help="Camera that becomes compromised at minute 21.",
    )
    parser.add_argument(
        "--attack-scale",
        type=float,
        default=1.0,
        help="Multiplier applied to attack-phase packet rates.",
    )
    args = parser.parse_args()

    out_path = Path(args.output)
    rows = generate_dataset(
        out_path,
        seed=args.seed,
        config=ScenarioConfig(
            compromised_camera=args.compromised_camera,
            attack_scale=args.attack_scale,
        ),
    )
    print(f"Generated {rows} rows -> {out_path}")


if __name__ == "__main__":
    main()
