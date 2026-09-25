import math
from typing import Any, Dict, List, Optional, Tuple


def calculate_statistics(numbers: List[float]) -> Dict[str, Optional[float]]:
    """Calculates min, max, mean, and standard deviation for a list of numbers."""
    if not numbers:
        return {"min": None, "max": None, "mean": None, "std_dev": None}
    n = len(numbers)
    min_val = min(numbers)
    max_val = max(numbers)
    mean_val = sum(numbers) / n
    if n > 1:
        variance = sum((x - mean_val) ** 2 for x in numbers) / (n - 1)
        std_dev = math.sqrt(variance)
    else:
        std_dev = 0.0
    return {
        "min": round(min_val, 4),
        "max": round(max_val, 4),
        "mean": round(mean_val, 4),
        "std_dev": round(std_dev, 4),
    }


def extract_bidirectional_flows(packets: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Groups packets into bidirectional network flows and computes flow-level metrics."""
    flow_map: Dict[Tuple[str, str, int, int, str], Dict[str, Any]] = {}
    ordered_keys: List[Tuple[str, str, int, int, str]] = []

    for pkt in packets:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        if not src_ip or not dst_ip:
            continue

        proto = pkt.get("protocol") or str(pkt.get("ip_proto") or "UNKNOWN")
        src_port = pkt.get("src_port") or 0
        dst_port = pkt.get("dst_port") or 0
        pkt_len = pkt.get("frame_len", 0)
        t_epoch = pkt.get("time_epoch")

        fwd_key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)

        if fwd_key in flow_map:
            fl = flow_map[fwd_key]
            fl["forward_packets"] += 1
            fl["forward_bytes"] += pkt_len
            fl["packet_sizes"].append(pkt_len)
            if t_epoch is not None:
                fl["timestamps"].append(t_epoch)
        elif rev_key in flow_map:
            fl = flow_map[rev_key]
            fl["backward_packets"] += 1
            fl["backward_bytes"] += pkt_len
            fl["packet_sizes"].append(pkt_len)
            if t_epoch is not None:
                fl["timestamps"].append(t_epoch)
        else:
            flow_entry = {
                "forward_key": fwd_key,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "forward_packets": 1,
                "backward_packets": 0,
                "forward_bytes": pkt_len,
                "backward_bytes": 0,
                "packet_sizes": [pkt_len],
                "timestamps": [t_epoch] if t_epoch is not None else [],
            }
            flow_map[fwd_key] = flow_entry
            ordered_keys.append(fwd_key)

    flows_result: List[Dict[str, Any]] = []
    total_flow_durations: List[float] = []

    for key in ordered_keys:
        fl = flow_map[key]
        fwd_pkts = fl["forward_packets"]
        bwd_pkts = fl["backward_packets"]
        tot_pkts = fwd_pkts + bwd_pkts

        fwd_bytes = fl["forward_bytes"]
        bwd_bytes = fl["backward_bytes"]
        tot_bytes = fwd_bytes + bwd_bytes

        timestamps = sorted(fl["timestamps"])
        if len(timestamps) >= 2:
            duration = max(0.0, timestamps[-1] - timestamps[0])
            iats = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            iat_stats = calculate_statistics(iats)
        else:
            duration = 0.0
            iat_stats = {"min": None, "max": None, "mean": None, "std_dev": None}

        total_flow_durations.append(duration)

        # Ratios
        fwd_bwd_pkt_ratio = round(fwd_pkts / bwd_pkts, 4) if bwd_pkts > 0 else None
        fwd_bwd_byte_ratio = round(fwd_bytes / bwd_bytes, 4) if bwd_bytes > 0 else None

        # Throughput
        throughput_bps = round((tot_bytes * 8) / duration, 2) if duration > 0 else None
        packet_rate = round(tot_pkts / duration, 2) if duration > 0 else None

        # Burstiness & Entropy
        iat_mean = iat_stats.get("mean")
        iat_std = iat_stats.get("std_dev")
        if iat_mean and iat_mean > 0 and iat_std is not None:
            flow_burstiness = round(min(1.0, iat_std / (iat_mean + 1e-6)), 4)
        else:
            flow_burstiness = 0.0

        flow_burst_count = 0
        if len(timestamps) >= 2 and iat_mean and iat_mean > 0:
            threshold = iat_mean * 0.5
            flow_burst_count = sum(1 for i in range(len(timestamps) - 1) if (timestamps[i + 1] - timestamps[i]) <= threshold)

        # Flow packet size entropy
        flow_entropy = 0.0
        if fl["packet_sizes"]:
            freq: Dict[int, int] = {}
            for v in fl["packet_sizes"]:
                b = v % 256
                freq[b] = freq.get(b, 0) + 1
            tot_p = len(fl["packet_sizes"])
            e_sum = 0.0
            for cnt in freq.values():
                p = cnt / tot_p
                if p > 0:
                    e_sum -= p * math.log2(p)
            flow_entropy = round(min(8.0, e_sum), 4)

        size_stats = calculate_statistics(fl["packet_sizes"])

        flows_result.append({
            "flow_id": f"{fl['src_ip']}:{fl['src_port']} <-> {fl['dst_ip']}:{fl['dst_port']} ({fl['protocol']})",
            "source_ip": fl["src_ip"],
            "destination_ip": fl["dst_ip"],
            "src_ip": fl["src_ip"],
            "dst_ip": fl["dst_ip"],
            "source_port": fl["src_port"],
            "destination_port": fl["dst_port"],
            "src_port": fl["src_port"],
            "dst_port": fl["dst_port"],
            "protocol": fl["protocol"],
            "duration": round(duration, 4),
            "duration_seconds": round(duration, 4),
            "packet_count": tot_pkts,
            "total_packets": tot_pkts,
            "forward_packet_count": fwd_pkts,
            "forward_packets": fwd_pkts,
            "backward_packet_count": bwd_pkts,
            "backward_packets": bwd_pkts,
            "total_bytes": tot_bytes,
            "forward_bytes": fwd_bytes,
            "backward_bytes": bwd_bytes,
            "forward_backward_packet_ratio": fwd_bwd_pkt_ratio,
            "forward_backward_byte_ratio": fwd_bwd_byte_ratio,
            "throughput": throughput_bps,
            "throughput_bps": throughput_bps,
            "packet_rate": packet_rate,
            "inter_arrival_time_seconds": iat_stats,
            "iat_statistics": iat_stats,
            "packet_size_statistics": size_stats,
            "packet_sizes": size_stats,
            "burst_count": flow_burst_count,
            "burstiness": flow_burstiness,
            "packet_size_entropy": flow_entropy,
            "shannon_entropy": flow_entropy,
        })

    flow_summary = {
        "flow_count": len(flows_result),
        "duration_statistics": calculate_statistics(total_flow_durations),
    }

    return flows_result, flow_summary
