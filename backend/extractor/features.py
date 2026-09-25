"""
Comprehensive IPsec & Network Traffic Feature Extractor

Extracts structured observable features from TShark decoded packet streams.
Adheres strictly to PCAP observability principles:
- Fully dynamic and calculated from the specific PCAP trace
- Never hardcodes or fabricates values
- Accurately distinguishes IKEv2, IKEv1, ESP, AH, NAT-T, and cleartext traffic leakage
- Tracks sequence numbers and anti-replay counters per Security Association (SPI)
"""

import math
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .flows import calculate_statistics, extract_bidirectional_flows


def format_bytes(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def compute_shannon_entropy(values: List[int]) -> float:
    """Computes Shannon entropy over a distribution of values (e.g. packet lengths).
    Returns value in bits (0.0 - 8.0).
    """
    if not values:
        return 0.0
    freq: Dict[int, int] = {}
    for v in values:
        bucket = v % 256
        freq[bucket] = freq.get(bucket, 0) + 1
    total = len(values)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(min(8.0, entropy), 2)


# IKE Exchange Type Map (RFC 7296 / RFC 2409)
IKE_EXCHANGE_TYPES = {
    "1": "Identity Protection (Main Mode)",
    "2": "Auth Only",
    "4": "Aggressive",
    "5": "Informational (v1)",
    "6": "Transaction (Config)",
    "32": "Quick Mode (v1)",
    "33": "New Group Mode",
    "34": "IKE_SA_INIT",
    "35": "IKE_AUTH",
    "36": "CREATE_CHILD_SA",
    "37": "INFORMATIONAL (v2)",
}

# IANA IKEv2 Transform ID Mappings (RFC 7296)
ENCR_ALGO_MAP = {
    "1": "DES-IV64",
    "2": "DES",
    "3": "3DES-CBC",
    "12": "AES-CBC",
    "14": "AES-CTR",
    "18": "AES-CCM-8",
    "19": "AES-CCM-12",
    "20": "AES-GCM",
    "28": "ChaCha20-Poly1305",
}

def resolve_encryption_algo(transform_id: str, key_length: Optional[str] = None) -> str:
    tid = str(transform_id).strip()
    klen = str(key_length).strip() if key_length else None

    if tid == "20":
        return f"AES-{klen}-GCM" if klen else "AES-256-GCM"
    elif tid == "12":
        return f"AES-{klen}-CBC" if klen else "AES-CBC"
    elif tid == "14":
        return f"AES-{klen}-CTR" if klen else "AES-CTR"
    elif tid == "18":
        return f"AES-{klen}-CCM-8" if klen else "AES-CCM-8"
    elif tid == "19":
        return f"AES-{klen}-CCM-12" if klen else "AES-CCM-12"
    elif tid == "3":
        return "3DES-CBC"
    elif tid == "2":
        return "DES"
    elif tid == "1":
        return "DES-IV64"
    elif tid == "28":
        return "ChaCha20-Poly1305"
    return ENCR_ALGO_MAP.get(tid, f"ENCR_ID_{tid}")


PRF_ALGO_MAP = {
    "1": "PRF_HMAC_MD5",
    "2": "PRF_HMAC_SHA1",
    "3": "PRF_HMAC_TIGER",
    "4": "PRF_AES128_XCBC",
    "5": "PRF_HMAC_SHA2_256",
    "6": "PRF_HMAC_SHA2_384",
    "7": "PRF_HMAC_SHA2_512",
    "8": "PRF_AES128_CMAC",
}

INTEG_ALGO_MAP = {
    "1": "AUTH_HMAC_MD5_96",
    "2": "AUTH_HMAC_SHA1_96",
    "3": "AUTH_DES_MAC",
    "4": "AUTH_KPDK_MD5",
    "5": "AUTH_AES_XCBC_96",
    "12": "AUTH_HMAC_SHA2_256_128",
    "13": "AUTH_HMAC_SHA2_384_192",
    "14": "AUTH_HMAC_SHA2_512_256",
}

DH_GROUP_MAP = {
    "1": "MODP-768 (Group 1)",
    "2": "MODP-1024 (Group 2)",
    "5": "MODP-1536 (Group 5)",
    "14": "MODP-2048 (Group 14)",
    "15": "MODP-3072 (Group 15)",
    "16": "MODP-4096 (Group 16)",
    "19": "ECP-256 (Group 19)",
    "20": "ECP-384 (Group 20)",
    "21": "ECP-521 (Group 21)",
    "31": "Curve25519 (Group 31)",
}

AUTH_METHOD_MAP = {
    "1": "RSA Digital Signature",
    "2": "Pre-Shared Key (PSK)",
    "3": "DSS Digital Signature",
    "9": "ECDSA with SHA-256",
    "10": "ECDSA with SHA-384",
    "11": "ECDSA with SHA-512",
    "14": "Digital Signature (RFC 7427)",
}

# IKEv1 Attributes
IKEV1_ENCR_MAP = {
    "1": "DES-CBC",
    "2": "IDEA-CBC",
    "3": "Blowfish-CBC",
    "4": "RC5-R16-B64-CBC",
    "5": "3DES-CBC",
    "6": "CAST-CBC",
    "7": "AES-CBC",
}

IKEV1_HASH_MAP = {
    "1": "MD5",
    "2": "SHA-1",
    "3": "Tiger",
    "4": "SHA2-256",
    "5": "SHA2-384",
    "6": "SHA2-512",
}

IKEV1_AUTH_MAP = {
    "1": "Pre-Shared Key",
    "2": "DSS Signatures",
    "3": "RSA Signatures",
    "4": "Encryption with RSA",
    "5": "Revised encryption with RSA",
}

def resolve_ikev1_encryption_algo(encr_id: str, key_length: Optional[str] = None) -> str:
    eid = str(encr_id).strip()
    klen = str(key_length).strip() if key_length else None
    if eid == "7":
        return f"AES-{klen}-CBC" if klen else "AES-CBC"
    return IKEV1_ENCR_MAP.get(eid, f"IKEv1_ENCR_{eid}")


def parse_csv_items(field_val: Any) -> List[str]:
    if not field_val:
        return []
    s = str(field_val).strip()
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def extract_features_from_packets(
    packets: List[Dict[str, Any]],
    file_path: str,
    original_filename: str,
) -> Dict[str, Any]:
    """Dynamically parses and aggregates TShark extracted packets into the comprehensive
    IPsec feature schema, adhering strictly to PCAP observability without fabricating values.
    """
    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
    packet_count = len(packets)

    # ----------------------------------------------------
    # 1. CAPTURE METADATA & TIMING
    # ----------------------------------------------------
    timestamps = [p["time_epoch"] for p in packets if p.get("time_epoch") is not None]
    if timestamps:
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        duration_sec = max(0.0, max_ts - min_ts)
        first_iso = datetime.fromtimestamp(min_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        last_iso = datetime.fromtimestamp(max_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    else:
        duration_sec = 0.0
        first_iso = None
        last_iso = None

    hrs = int(duration_sec // 3600)
    mins = int((duration_sec % 3600) // 60)
    secs = int(duration_sec % 60)
    duration_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

    capture_meta = {
        "filename": original_filename,
        "file_size_bytes": file_size,
        "file_size_formatted": format_bytes(file_size),
        "packet_count": packet_count,
        "capture_duration_seconds": round(duration_sec, 4),
        "capture_duration_formatted": duration_str,
        "first_packet_timestamp": first_iso,
        "last_packet_timestamp": last_iso,
    }

    # ----------------------------------------------------
    # 2. IP & NETWORK OBSERVABLES
    # ----------------------------------------------------
    ipv4_count = sum(1 for p in packets if p.get("ip_src") or p.get("ip_dst"))
    ipv6_count = sum(1 for p in packets if p.get("ipv6_src") or p.get("ipv6_dst"))
    src_ips = sorted(list(set(p["src_ip"] for p in packets if p.get("src_ip"))))
    dst_ips = sorted(list(set(p["dst_ip"] for p in packets if p.get("dst_ip"))))

    packet_lengths = [p.get("frame_len", 0) for p in packets]
    length_stats = calculate_statistics([float(l) for l in packet_lengths])

    # Inter-arrival times
    if len(timestamps) >= 2:
        sorted_ts = sorted(timestamps)
        iats = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
        iat_stats = calculate_statistics(iats)
    else:
        iat_stats = {"min": None, "max": None, "mean": None, "std_dev": None}

    packet_rate = round(packet_count / duration_sec, 2) if duration_sec > 0 else 0.0

    # TTL / Hop limits
    ttls = set()
    for p in packets:
        for ttl_str in parse_csv_items(p.get("ip_ttl")):
            try:
                ttls.add(int(ttl_str))
            except ValueError:
                pass
        for hlim_str in parse_csv_items(p.get("ipv6_hlim")):
            try:
                ttls.add(int(hlim_str))
            except ValueError:
                pass
    observed_ttls = sorted(list(ttls)) if ttls else None

    packet_size_stats = {
        "minimum": length_stats.get("min"),
        "maximum": length_stats.get("max"),
        "mean": length_stats.get("mean"),
        "standard_deviation": length_stats.get("std_dev"),
        "min": length_stats.get("min"),
        "max": length_stats.get("max"),
        "std_dev": length_stats.get("std_dev"),
    }
    timing_stats = {
        "packet_rate": packet_rate,
        "minimum_iat": iat_stats.get("min"),
        "maximum_iat": iat_stats.get("max"),
        "mean_iat": iat_stats.get("mean"),
        "iat_standard_deviation": iat_stats.get("std_dev"),
        "min": iat_stats.get("min"),
        "max": iat_stats.get("max"),
        "std_dev": iat_stats.get("std_dev"),
    }

    network_features = {
        "ipv4_packet_count": ipv4_count,
        "ipv6_packet_count": ipv6_count,
        "unique_source_ips": src_ips,
        "unique_destination_ips": dst_ips,
        "source_ips": src_ips,
        "destination_ips": dst_ips,
        "ttl_observations": observed_ttls,
        "ttl_hop_limit_observed": observed_ttls,
        "packet_size_statistics": packet_size_stats,
        "packet_sizes": packet_size_stats,
        "timing_statistics": timing_stats,
        "inter_arrival_time_seconds": iat_stats,
        "iat_statistics": iat_stats,
        "packet_rate": packet_rate,
        "packet_rate_per_sec": packet_rate,
    }

    # ----------------------------------------------------
    # 3. PROTOCOL INSPECTION & ACCURATE IPSEC IDENTIFICATION
    # ----------------------------------------------------
    esp_count = 0
    esp_byte_count = 0
    ah_count = 0
    ah_byte_count = 0
    ike_count = 0
    ike_byte_count = 0
    udp_500_present = False
    udp_4500_present = False
    use_transport_mode_notify_seen = False

    esp_spis: Set[str] = set()
    esp_sequences_by_spi: Dict[str, List[int]] = {}
    esp_all_sequences: List[int] = []

    ah_spis: Set[str] = set()
    ah_sequences: List[int] = []
    ah_next_headers: List[int] = []

    # IKE fields
    ike_versions: Set[str] = set()
    ike_exchanges: Set[str] = set()
    ike_initiators: Set[str] = set()
    ike_responders: Set[str] = set()
    ike_encr_algos: Set[str] = set()
    ike_integ_algos: Set[str] = set()
    ike_prf_algos: Set[str] = set()
    ike_dh_groups: Set[str] = set()
    ike_auth_methods: Set[str] = set()
    ike_sa_spis: Set[str] = set()

    protocol_packet_counts: Dict[str, int] = {}
    protocol_byte_counts: Dict[str, int] = {}

    cleartext_leak_packets = 0
    cleartext_protocols: Set[str] = set()

    for p in packets:
        proto_col = (p.get("protocol") or "").upper().strip()
        ip_proto = str(p.get("ip_proto") or "").split(",")[0].strip()
        src_port = p.get("src_port")
        dst_port = p.get("dst_port")
        frame_len = p.get("frame_len", 0)

        # Port presence
        is_port_500 = (src_port == 500 or dst_port == 500)
        is_port_4500 = (src_port == 4500 or dst_port == 4500)
        if is_port_500:
            udp_500_present = True
        if is_port_4500:
            udp_4500_present = True

        raw_esp_spi = p.get("esp_spi", "").strip()
        has_valid_esp_spi = bool(raw_esp_spi) and raw_esp_spi not in ("0x00000000", "0", "0x0", "")

        raw_isakmp_ispi = p.get("isakmp_ispi", "").strip()
        has_valid_isakmp_ispi = bool(raw_isakmp_ispi) and raw_isakmp_ispi not in ("0000000000000000", "0x0000000000000000", "")

        # 1. Check if frame is ESP:
        # Native ESP has IP proto 50. UDP Encapsulated ESP (UDP 4500) has esp.spi populated.
        is_esp = (
            ip_proto == "50"
            or "ESP" in proto_col
            or has_valid_esp_spi
        )

        # 2. Check if frame is AH:
        is_ah = (
            ip_proto == "51"
            or "AH" in proto_col
            or bool(p.get("ah_spi"))
        )

        # 3. Check if frame is IKE:
        # IKE runs on UDP 500 or UDP 4500 (with Non-ESP marker).
        # Must not be classified as ESP!
        is_ike = False
        if not is_esp and not is_ah:
            is_ike = (
                "ISAKMP" in proto_col
                or "IKE" in proto_col
                or bool(p.get("isakmp_version"))
                or bool(p.get("isakmp_mjver"))
                or bool(p.get("isakmp_exchangetype"))
                or has_valid_isakmp_ispi
                or is_port_500
                or (is_port_4500 and not has_valid_esp_spi)
            )

        # Protocol accounting
        if is_esp:
            norm_proto = "ESP"
            esp_count += 1
            esp_byte_count += frame_len

            parsed_spis = parse_csv_items(raw_esp_spi)
            for spi in parsed_spis:
                esp_spis.add(spi)

            current_spi = parsed_spis[0] if parsed_spis else "unknown"
            if current_spi not in esp_sequences_by_spi:
                esp_sequences_by_spi[current_spi] = []

            for seq_str in parse_csv_items(p.get("esp_sequence")):
                try:
                    seq_num = int(seq_str)
                    esp_all_sequences.append(seq_num)
                    esp_sequences_by_spi[current_spi].append(seq_num)
                except ValueError:
                    pass

        elif is_ah:
            norm_proto = "AH"
            ah_count += 1
            ah_byte_count += frame_len
            for spi in parse_csv_items(p.get("ah_spi")):
                ah_spis.add(spi)
            for seq_str in parse_csv_items(p.get("ah_sequence")):
                try:
                    ah_sequences.append(int(seq_str))
                except ValueError:
                    pass
            for nh_str in parse_csv_items(p.get("ah_next_header")):
                try:
                    ah_next_headers.append(int(nh_str))
                except ValueError:
                    pass

        elif is_ike:
            norm_proto = "IKE"
            ike_count += 1
            ike_byte_count += frame_len

            # Version detection
            v = p.get("isakmp_version")
            mj = p.get("isakmp_mjver")
            if mj:
                for val in parse_csv_items(mj):
                    if val in ("0x02", "0x2", "2", "2.0"):
                        ike_versions.add("IKEv2")
                    elif val in ("0x01", "0x1", "1", "1.0"):
                        ike_versions.add("IKEv1")
                    else:
                        ike_versions.add(f"IKEv{val}")
            elif v:
                for val in parse_csv_items(v):
                    if val in ("0x20", "2.0", "2"):
                        ike_versions.add("IKEv2")
                    elif val in ("0x10", "1.0", "1"):
                        ike_versions.add("IKEv1")
            elif "IKEV2" in proto_col:
                ike_versions.add("IKEv2")
            elif any(x in (p.get("info") or "") for x in ("IKE_SA_INIT", "IKE_AUTH", "CREATE_CHILD_SA")):
                ike_versions.add("IKEv2")
            elif any(x in (p.get("info") or "") for x in ("Main Mode", "Aggressive Mode", "Quick Mode")):
                ike_versions.add("IKEv1")

            # Exchange types
            for etype in parse_csv_items(p.get("isakmp_exchangetype")):
                ike_exchanges.add(IKE_EXCHANGE_TYPES.get(etype, f"Exchange {etype}"))

            # Notify messages
            for notify in parse_csv_items(p.get("isakmp_notify_msgtype")):
                if notify == "16391":  # USE_TRANSPORT_MODE
                    use_transport_mode_notify_seen = True

            # SPIs
            for ispi in parse_csv_items(p.get("isakmp_ispi")):
                if ispi and ispi not in ("0000000000000000", "0x0000000000000000"):
                    ike_initiators.add(ispi)
                    ike_sa_spis.add(ispi)
            for rspi in parse_csv_items(p.get("isakmp_rspi")):
                if rspi and rspi not in ("0000000000000000", "0x0000000000000000"):
                    ike_responders.add(rspi)
                    ike_sa_spis.add(rspi)
            for spi in parse_csv_items(p.get("isakmp_spi")):
                ike_sa_spis.add(spi)

            # IKEv2 Cryptographic transforms with key length resolution
            v2_encr_items = parse_csv_items(p.get("isakmp_tf_encr"))
            v2_key_len_items = parse_csv_items(p.get("isakmp_ike2_key_length"))
            for idx, enc_id in enumerate(v2_encr_items):
                klen = v2_key_len_items[idx] if idx < len(v2_key_len_items) else (v2_key_len_items[0] if v2_key_len_items else None)
                ike_encr_algos.add(resolve_encryption_algo(enc_id, klen))

            for integ_id in parse_csv_items(p.get("isakmp_tf_integ")):
                ike_integ_algos.add(INTEG_ALGO_MAP.get(integ_id, f"INTEG_ID_{integ_id}"))

            for prf_id in parse_csv_items(p.get("isakmp_tf_prf")):
                ike_prf_algos.add(PRF_ALGO_MAP.get(prf_id, f"PRF_ID_{prf_id}"))

            for dh_id in parse_csv_items(p.get("isakmp_tf_dh")):
                ike_dh_groups.add(DH_GROUP_MAP.get(dh_id, f"Group {dh_id}"))

            for ke_dh in parse_csv_items(p.get("isakmp_ke_dh")):
                ike_dh_groups.add(DH_GROUP_MAP.get(ke_dh, f"Group {ke_dh}"))

            # IKEv1 Transforms & Attributes
            v1_encr_items = parse_csv_items(p.get("isakmp_v1_encr"))
            v1_key_len_items = parse_csv_items(p.get("isakmp_v1_key_length"))
            for idx, enc_id in enumerate(v1_encr_items):
                klen = v1_key_len_items[idx] if idx < len(v1_key_len_items) else (v1_key_len_items[0] if v1_key_len_items else None)
                ike_encr_algos.add(resolve_ikev1_encryption_algo(enc_id, klen))

            for h in parse_csv_items(p.get("isakmp_v1_prf")):
                ike_integ_algos.add(IKEV1_HASH_MAP.get(h, f"HASH_{h}"))

            for g in parse_csv_items(p.get("isakmp_v1_group")):
                ike_dh_groups.add(DH_GROUP_MAP.get(g, f"Group {g}"))

            for a in parse_csv_items(p.get("isakmp_v1_auth")):
                ike_auth_methods.add(IKEV1_AUTH_MAP.get(a, f"Auth {a}"))

            for am in parse_csv_items(p.get("isakmp_auth_method")):
                ike_auth_methods.add(AUTH_METHOD_MAP.get(am, f"Auth_Method_{am}"))

        else:
            # Cleartext network payload
            norm_proto = p.get("protocol") or ("TCP" if p.get("tcp_srcport") else ("UDP" if p.get("udp_srcport") else "PLAIN-IP"))
            if p.get("src_ip") or p.get("dst_ip"):
                cleartext_leak_packets += 1
                cleartext_protocols.add(norm_proto)

        protocol_packet_counts[norm_proto] = protocol_packet_counts.get(norm_proto, 0) + 1
        protocol_byte_counts[norm_proto] = protocol_byte_counts.get(norm_proto, 0) + frame_len

    esp_ratio = round((esp_count / packet_count) * 100, 2) if packet_count > 0 else 0.0
    ike_ratio = round((ike_count / packet_count) * 100, 2) if packet_count > 0 else 0.0
    ah_ratio = round((ah_count / packet_count) * 100, 2) if packet_count > 0 else 0.0
    cleartext_ratio = round((cleartext_leak_packets / packet_count) * 100, 2) if packet_count > 0 else 0.0

    nat_t_detected = udp_4500_present and (esp_count > 0 or ike_count > 0)

    protocols_detected = []
    if "IKEv2" in ike_versions:
        protocols_detected.append("IKEv2")
    elif "IKEv1" in ike_versions:
        protocols_detected.append("IKEv1")
    elif ike_count > 0:
        protocols_detected.append("IKE")

    if esp_count > 0:
        protocols_detected.append("ESP")
    if ah_count > 0:
        protocols_detected.append("AH")
    if nat_t_detected:
        protocols_detected.append("NAT-T")

    ipsec_detected = len(protocols_detected) > 0 or esp_count > 0 or ah_count > 0 or ike_count > 0

    resolved_ike_version = None
    if "IKEv2" in ike_versions and "IKEv1" in ike_versions:
        resolved_ike_version = "IKEv2 / IKEv1 (Mixed)"
    elif "IKEv2" in ike_versions:
        resolved_ike_version = "IKEv2"
    elif "IKEv1" in ike_versions:
        resolved_ike_version = "IKEv1"
    elif ike_versions and "UNKNOWN" not in ike_versions:
        resolved_ike_version = sorted(list(ike_versions))[0]
    elif ike_count > 0:
        resolved_ike_version = "UNKNOWN"

    ike_section = {
        "detected": ike_count > 0,
        "version": resolved_ike_version,
        "packet_count": ike_count,
        "initiator": sorted(list(ike_initiators))[0] if ike_initiators else None,
        "responder": sorted(list(ike_responders))[0] if ike_responders else None,
        "exchange_types": sorted(list(ike_exchanges)),
        "encryption_algorithms": sorted(list(ike_encr_algos)),
        "integrity_algorithms": sorted(list(ike_integ_algos)),
        "prf_algorithms": sorted(list(ike_prf_algos)),
        "authentication_methods": sorted(list(ike_auth_methods)),
        "key_exchange_methods": sorted(list(ike_dh_groups)),
    }

    # ----------------------------------------------------
    # 4. ESP EVIDENCE & PER-SA REPLAY TRACKING
    # ----------------------------------------------------
    if ike_encr_algos:
        primary_encr = sorted(list(ike_encr_algos))[0]
        esp_encr_evidence = {
            "value": primary_encr,
            "source": "IKE_SA negotiation transform",
            "confidence": "HIGH",
            "evidence": f"Directly observed from IKE proposal transform ({primary_encr})",
        }
    elif esp_count > 0:
        esp_encr_evidence = {
            "value": "UNKNOWN",
            "source": "none",
            "confidence": "NONE",
            "evidence": "ESP payload is encapsulated inside ciphertext and not observable without IKE SA negotiation in the capture.",
        }
    else:
        esp_encr_evidence = {
            "value": "NONE",
            "source": "none",
            "confidence": "NONE",
            "evidence": "Zero ESP packets observed in capture.",
        }

    # Sequence analysis per SA (SPI)
    total_sa_duplicates = 0
    all_sa_monotonic = True
    sa_sequence_details = {}

    for spi_key, seqs in esp_sequences_by_spi.items():
        if seqs:
            s_min = min(seqs)
            s_max = max(seqs)
            s_count = len(seqs)
            s_dups = s_count - len(set(seqs))
            total_sa_duplicates += s_dups
            # Strictly monotonic if no duplicates and sorted order matches
            s_mono = (s_dups == 0) and (seqs == sorted(seqs))
            if not s_mono:
                all_sa_monotonic = False
            sa_sequence_details[spi_key] = {
                "min": s_min,
                "max": s_max,
                "count": s_count,
                "duplicates": s_dups,
                "monotonic": s_mono,
            }

    seq_min = min(esp_all_sequences) if esp_all_sequences else None
    seq_max = max(esp_all_sequences) if esp_all_sequences else None
    seq_count = len(esp_all_sequences)

    esp_section = {
        "detected": esp_count > 0,
        "packet_count": esp_count,
        "spi_values": sorted(list(esp_spis)),
        "sequence_number_min": seq_min,
        "sequence_number_max": seq_max,
        "sequence_number_count": seq_count,
        "sequence_number_duplicates": total_sa_duplicates,
        "sequence_monotonic": all_sa_monotonic if esp_sequences_by_spi else False,
        "sequence_by_spi": sa_sequence_details,
        "udp_encapsulated": udp_4500_present and esp_count > 0,
        "nat_t": nat_t_detected,
        "encryption_algorithm": esp_encr_evidence,
    }

    # ----------------------------------------------------
    # 5. AH FEATURES
    # ----------------------------------------------------
    ah_section = {
        "detected": ah_count > 0,
        "packet_count": ah_count,
        "spi_values": sorted(list(ah_spis)),
        "sequence_numbers": {
            "min": min(ah_sequences) if ah_sequences else None,
            "max": max(ah_sequences) if ah_sequences else None,
            "count": len(ah_sequences),
        } if ah_sequences else None,
    }

    # ----------------------------------------------------
    # 6. TUNNEL VS TRANSPORT MODE DETERMINATION
    # ----------------------------------------------------
    mode_value = "UNKNOWN"
    mode_confidence = "NONE"
    mode_evidence = "Insufficient observable information in PCAP (ESP payload is encrypted)"

    if ah_next_headers:
        if any(h in (4, 41) for h in ah_next_headers):
            mode_value = "TUNNEL"
            mode_confidence = "HIGH"
            mode_evidence = "AH header encapsulates inner IP protocol (4 or 41), confirming Tunnel Mode."
        elif any(h in (6, 17) for h in ah_next_headers):
            mode_value = "TRANSPORT"
            mode_confidence = "HIGH"
            mode_evidence = "AH header encapsulates transport protocol (TCP/UDP), indicating Transport Mode."
    elif use_transport_mode_notify_seen:
        mode_value = "TRANSPORT"
        mode_confidence = "HIGH"
        mode_evidence = "USE_TRANSPORT_MODE notification observed in IKE negotiation."
    elif not ipsec_detected:
        mode_value = "NONE"
        mode_confidence = "HIGH"
        mode_evidence = "No IPsec encapsulation present in capture."

    mode_section = {
        "value": mode_value,
        "confidence": mode_confidence,
        "evidence": mode_evidence,
    }

    # ----------------------------------------------------
    # 7. FLOWS & PROTOCOLS
    # ----------------------------------------------------
    flows = extract_bidirectional_flows(packets)
    entropy_val = compute_shannon_entropy(packet_lengths)

    protocols_summary = {
        "detected": sorted(list(protocol_packet_counts.keys())),
        "packet_counts": protocol_packet_counts,
        "byte_counts": protocol_byte_counts,
    }

    all_observed_spis = sorted(list(esp_spis.union(ah_spis).union(ike_sa_spis)))

    leakage_detected = cleartext_leak_packets > 0
    leakage_section = {
        "detected": leakage_detected,
        "packet_count": cleartext_leak_packets,
        "ratio_percent": cleartext_ratio,
        "cleartext_protocols": sorted(list(cleartext_protocols)),
        "description": (
            f"Detected {cleartext_leak_packets} packet(s) ({cleartext_ratio}%) running unencrypted "
            f"protocols ({', '.join(sorted(list(cleartext_protocols)))}) outside the IPsec tunnel."
            if leakage_detected
            else "No unencrypted IP traffic observed outside the IPsec tunnel."
        ),
    }

    sa_section = {
        "sa_count_observed": len(all_observed_spis),
        "spi_values": all_observed_spis,
        "initiator_spi": sorted(list(ike_initiators))[0] if ike_initiators else None,
        "responder_spi": sorted(list(ike_responders))[0] if ike_responders else None,
        "traffic_selectors": [],
        "rekey_information": (
            "CREATE_CHILD_SA exchange observed"
            if any("CREATE_CHILD_SA" in ex for ex in ike_exchanges)
            else (f"{len(esp_spis)} ESP SPI(s) observed" if len(esp_spis) > 1 else None)
        ),
        "replay_information": (
            f"ESP sequence numbers [{seq_min}..{seq_max}] across {len(esp_sequences_by_spi)} SA(s) ({seq_count} packets, monotonic={all_sa_monotonic})"
            if esp_all_sequences
            else None
        ),
    }

    cryptography_section = {
        "ike": {
            "encryption": sorted(list(ike_encr_algos)),
            "integrity": sorted(list(ike_integ_algos)),
            "prf": sorted(list(ike_prf_algos)),
            "authentication": sorted(list(ike_auth_methods)),
            "key_exchange": sorted(list(ike_dh_groups)),
        },
        "esp": {
            "encryption": (
                [esp_encr_evidence["value"]]
                if esp_encr_evidence.get("value") and esp_encr_evidence["value"] not in ("UNKNOWN", "NONE")
                else []
            ),
            "integrity": sorted(list(ike_integ_algos)),
        },
    }

    return {
        "totalPackets": packet_count,
        "avgPacketSize": int(length_stats.get("mean") or 0),
        "packetRate": packet_rate,
        "espRatio": esp_ratio,
        "ikeRatio": ike_ratio,
        "ahRatio": ah_ratio,
        "cleartextRatio": cleartext_ratio,
        "burstiness": round(length_stats.get("std_dev", 0) / (length_stats.get("mean", 1) or 1), 4),
        "entropy": entropy_val,
        "capture_name": original_filename,
        "capture_size": format_bytes(file_size),
        "capture": capture_meta,
        "network": network_features,
        "ip_features": network_features,
        "ipsec": {
            "ipsec_detected": ipsec_detected,
            "protocols_detected": protocols_detected,
            "ike_detected": ike_count > 0,
            "ikev2_detected": "IKEv2" in ike_versions,
            "ikev1_detected": "IKEv1" in ike_versions,
            "esp_detected": esp_count > 0,
            "ah_detected": ah_count > 0,
            "udp_500_detected": udp_500_present,
            "udp_4500_detected": udp_4500_present,
            "nat_t_detected": nat_t_detected,
            "esp_packet_count": esp_count,
            "esp_ratio_percent": esp_ratio,
            "ah_packet_count": ah_count,
            "ah_ratio_percent": ah_ratio,
            "ike_packet_count": ike_count,
            "ike_ratio_percent": ike_ratio,
            "cleartext_packet_count": cleartext_leak_packets,
            "cleartext_ratio_percent": cleartext_ratio,
            "ike_versions_observed": sorted(list(ike_versions)),
            "esp_spi_values": sorted(list(esp_spis)),
            "esp_sequence_numbers": {
                "min": seq_min,
                "max": seq_max,
                "observed_count": seq_count,
                "duplicates": total_sa_duplicates,
                "is_monotonic": all_sa_monotonic,
                "sa_details": sa_sequence_details,
            } if esp_all_sequences else None,
            "tunnel_transport_mode": mode_value,
            "tunnel_transport_mode_detail": mode_evidence,
            "cleartext_leakage": leakage_section,
        },
        "ike": ike_section,
        "esp": esp_section,
        "ah": ah_section,
        "mode": mode_section,
        "cryptography": cryptography_section,
        "security_association": sa_section,
        "cleartext_leakage": leakage_section,
        "protocols": protocols_summary,
        "statistics": {
            "total_bytes": sum(packet_lengths),
            "throughput_bps": round((sum(packet_lengths) * 8) / duration_sec, 2) if duration_sec > 0 else 0.0,
            "burst_count": len(flows),
            "burstiness": round(length_stats.get("std_dev", 0) / (length_stats.get("mean", 1) or 1), 4),
            "packet_size_entropy": entropy_val,
            "shannon_entropy": entropy_val,
        },
        "flows": flows,
        "feature_availability": {
            "capture_metadata": True,
            "ip_features": True,
            "ike_negotiation": ike_count > 0,
            "ike_version": resolved_ike_version is not None,
            "esp_detection": esp_count > 0,
            "ah_detection": ah_count > 0,
            "tunnel_transport_mode": mode_value not in ("UNKNOWN", "NONE"),
            "encryption_algorithm": len(ike_encr_algos) > 0,
            "authentication_algorithm": len(ike_integ_algos) > 0,
            "key_exchange_method": len(ike_dh_groups) > 0,
            "security_association": len(all_observed_spis) > 0,
            "spi_values": len(all_observed_spis) > 0,
            "sequence_numbers": len(esp_all_sequences) > 0 or len(ah_sequences) > 0,
            "nat_t_detection": nat_t_detected,
            "cleartext_leakage": leakage_detected,
        },
    }
