import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple


def find_tshark_binary() -> Optional[str]:
    """Finds the tshark executable from PATH or common Windows / Linux locations."""
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    which_path = shutil.which("tshark")
    if which_path:
        return which_path

    base_backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidate_paths = [
        os.path.join(base_backend_dir, "bin", "wireshark", "Wireshark", "tshark.exe"),
        os.path.join(base_backend_dir, "bin", "wireshark", "tshark.exe"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Wireshark\tshark.exe"),
        os.path.expandvars(r"%ProgramFiles%\Wireshark\tshark.exe"),
    ]

    for path in candidate_paths:
        if os.path.isfile(path):
            return path

    return None


def get_tshark_version() -> Optional[str]:
    """Returns the TShark version string if available, else None."""
    binary = find_tshark_binary()
    if not binary:
        return None
    try:
        res = subprocess.run([binary, "-v"], capture_output=True, text=True, timeout=5)
        if res.returncode == 0:
            first_line = res.stdout.splitlines()[0] if res.stdout else ""
            return first_line.strip()
    except Exception:
        pass
    return None


# Verified Wireshark/TShark 4.x field specifications for IPsec, IKEv1, IKEv2, ESP, and AH
TSHARK_FIELDS = [
    ("frame.number", "frame_number"),
    ("frame.time_epoch", "time_epoch"),
    ("frame.len", "frame_len"),
    ("ip.src", "ip_src"),
    ("ip.dst", "ip_dst"),
    ("ipv6.src", "ipv6_src"),
    ("ipv6.dst", "ipv6_dst"),
    ("ip.proto", "ip_proto"),
    ("ipv6.nxt", "ipv6_nxt"),
    ("ip.ttl", "ip_ttl"),
    ("ipv6.hlim", "ipv6_hlim"),
    ("tcp.srcport", "tcp_srcport"),
    ("tcp.dstport", "tcp_dstport"),
    ("udp.srcport", "udp_srcport"),
    ("udp.dstport", "udp_dstport"),
    ("icmp.type", "icmp_type"),
    ("_ws.col.Protocol", "protocol"),
    ("_ws.col.Info", "info"),
    # ESP fields
    ("esp.spi", "esp_spi"),
    ("esp.sequence", "esp_sequence"),
    ("esp.protocol", "esp_protocol"),
    # AH fields
    ("ah.spi", "ah_spi"),
    ("ah.sequence", "ah_sequence"),
    ("ah.next_header", "ah_next_header"),
    # IKE / ISAKMP header & exchange fields
    ("isakmp.ispi", "isakmp_ispi"),
    ("isakmp.rspi", "isakmp_rspi"),
    ("isakmp.version", "isakmp_version"),
    ("isakmp.mjver", "isakmp_mjver"),
    ("isakmp.mnver", "isakmp_mnver"),
    ("isakmp.exchangetype", "isakmp_exchangetype"),
    ("isakmp.typepayload", "isakmp_typepayload"),
    # IKEv2 Transform fields
    ("isakmp.tf.type", "isakmp_tf_type"),
    ("isakmp.tf.id.encr", "isakmp_tf_encr"),
    ("isakmp.ike2.attr.key_length", "isakmp_ike2_key_length"),
    ("isakmp.tf.id.integ", "isakmp_tf_integ"),
    ("isakmp.tf.id.prf", "isakmp_tf_prf"),
    ("isakmp.tf.id.dh", "isakmp_tf_dh"),
    ("isakmp.key_exchange.dh_group", "isakmp_ke_dh"),
    # IKEv1 Transform & Attribute fields
    ("isakmp.trans.id", "isakmp_v1_trans_id"),
    ("isakmp.ike.attr.encryption_algorithm", "isakmp_v1_encr"),
    ("isakmp.ike.attr.key_length", "isakmp_v1_key_length"),
    ("isakmp.ike.attr.prf", "isakmp_v1_prf"),
    ("isakmp.ike.attr.group_type", "isakmp_v1_group"),
    ("isakmp.ike.attr.authentication_method", "isakmp_v1_auth"),
    ("isakmp.ike.attr.life_type", "isakmp_v1_life_type"),
    # Authentication & Notification fields
    ("isakmp.auth.method", "isakmp_auth_method"),
    ("isakmp.notify.msgtype", "isakmp_notify_msgtype"),
    ("isakmp.spi", "isakmp_spi"),
    ("isakmp.ts.type", "isakmp_ts_type"),
]


def extract_packets_with_tshark(pcap_path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Runs TShark on the PCAP file and returns parsed packet dicts and capture execution info.
    Supports all transform occurrences and handles truncated captures (exit code 14) gracefully.
    """
    binary = find_tshark_binary()
    if not binary:
        raise RuntimeError(
            "TShark executable not found. Please install Wireshark / TShark or set the TSHARK_PATH environment variable."
        )

    cmd = [
        binary,
        "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "header=y",
        "-E", "occurrence=a",
        "-E", "aggregator=,",
    ]
    for field_spec, _ in TSHARK_FIELDS:
        cmd.extend(["-e", field_spec])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Capture lines from stdout; partial/truncated captures (code 14) still output all packets
    lines = proc.stdout.splitlines()
    if not lines and proc.returncode != 0:
        raise RuntimeError(f"TShark execution failed (code {proc.returncode}): {proc.stderr.strip()}")

    if not lines:
        return [], {"packet_count": 0, "tshark_version": get_tshark_version()}

    headers = [col.strip() for col in lines[0].split("\t")]
    field_name_map = {spec.lower(): col_name for spec, col_name in TSHARK_FIELDS}

    packets: List[Dict[str, Any]] = []
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = line.split("\t")
        record: Dict[str, Any] = {}
        for h_idx, raw_header in enumerate(headers):
            val = parts[h_idx].strip() if h_idx < len(parts) else ""
            key = field_name_map.get(raw_header.lower(), raw_header)
            record[key] = val

        # Normalize frame number
        try:
            record["frame_number"] = int(record.get("frame_number", "").split(",")[0])
        except (ValueError, KeyError, IndexError):
            record["frame_number"] = len(packets) + 1

        # Normalize time epoch
        try:
            record["time_epoch"] = float(record.get("time_epoch", "").split(",")[0])
        except (ValueError, KeyError, IndexError):
            record["time_epoch"] = None

        # Normalize frame length
        try:
            record["frame_len"] = int(record.get("frame_len", "").split(",")[0])
        except (ValueError, KeyError, IndexError):
            record["frame_len"] = 0

        # Unify source & destination IP
        src_candidate = record.get("ip_src") or record.get("ipv6_src")
        dst_candidate = record.get("ip_dst") or record.get("ipv6_dst")
        record["src_ip"] = src_candidate.split(",")[0] if src_candidate else None
        record["dst_ip"] = dst_candidate.split(",")[0] if dst_candidate else None

        # Unify ports
        src_port_raw = record.get("tcp_srcport") or record.get("udp_srcport")
        dst_port_raw = record.get("tcp_dstport") or record.get("udp_dstport")
        try:
            record["src_port"] = int(src_port_raw.split(",")[0]) if src_port_raw else None
        except (ValueError, IndexError):
            record["src_port"] = None

        try:
            record["dst_port"] = int(dst_port_raw.split(",")[0]) if dst_port_raw else None
        except (ValueError, IndexError):
            record["dst_port"] = None

        packets.append(record)

    tshark_info = {
        "packet_count": len(packets),
        "tshark_version": get_tshark_version(),
        "tshark_binary": binary,
        "warning": proc.stderr.strip() if proc.returncode != 0 else None,
    }
    return packets, tshark_info
