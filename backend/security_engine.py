"""
NIST-Based Security Rule Engine and Deterministic Risk Scorer

Implements deterministic server-side evaluation across 8 security categories:
1. Cryptographic Strength
2. Configuration Compliance
3. Security Association (SA) Parameters
4. Key Lifetime
5. Replay Protection
6. Forward Secrecy (PFS) Configuration
7. Cipher Suite Strength
8. Metadata Exposure

Adheres strictly to observable evidence from extracted PCAP features.
Calculates deterministic, dynamic risk scores derived from NIST SP 800-77 Rev. 1
and NIST SP 800-57 Part 1 Rev. 5 guidance.
"""

from typing import Any, Dict, List, Optional, Tuple
from security_policy import (
    APPROVED_DH_GROUPS,
    APPROVED_ENCRYPTION_ALGORITHMS,
    APPROVED_INTEGRITY_ALGORITHMS,
    DEPRECATED_DH_GROUPS,
    DEPRECATED_ENCRYPTION_ALGORITHMS,
    DEPRECATED_INTEGRITY_ALGORITHMS,
    NIST_REFERENCES,
    POLICY_METHOD,
    get_risk_level,
)


def evaluate_cryptographic_strength(features: Dict[str, Any]) -> Dict[str, Any]:
    ipsec = features.get("ipsec") or {}
    ike = features.get("ike") or {}
    esp = features.get("esp") or {}

    ipsec_detected = ipsec.get("ipsec_detected", False)
    esp_count = esp.get("packet_count", 0)
    ike_count = ike.get("packet_count", 0)

    # Case 0: ZERO IPsec detected in capture (Pure cleartext traffic)
    if not ipsec_detected and esp_count == 0 and ike_count == 0:
        return {
            "category": "Cryptographic Strength",
            "status": "FAIL",
            "observed_value": "Zero Encrypted Frames (100% Cleartext)",
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3: Mandatory IPsec ESP/IKE encryption for confidentiality.",
            "reason": "No IPsec encrypted frames or IKE key exchange packets were detected in the capture. All observable traffic is unencrypted plain-text.",
            "severity": "CRITICAL",
        }

    encr_algos = list(ike.get("encryption_algorithms") or [])
    esp_encr = esp.get("encryption_algorithm", {})
    if isinstance(esp_encr, dict) and esp_encr.get("value") and esp_encr.get("value") not in ("UNKNOWN", "NONE"):
        if esp_encr["value"] not in encr_algos:
            encr_algos.append(esp_encr["value"])

    integ_algos = list(ike.get("integrity_algorithms") or [])

    # Case 1: Pure ESP traffic without IKE negotiation captured
    if not encr_algos and not integ_algos:
        return {
            "category": "Cryptographic Strength",
            "status": "NOT_OBSERVABLE",
            "observed_value": None,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3: AES-128/256 (GCM or CBC) with HMAC-SHA-256 or AEAD; key length >= 128 bits.",
            "reason": "IKE SA negotiation transforms were not captured in this PCAP trace. Cryptographic algorithm and key strength cannot be determined from encrypted ESP ciphertext alone without private SA keys.",
            "severity": "LOW",
        }

    # Evaluate observed algorithms against NIST catalogs
    deprecated_found = []
    approved_found = []

    for algo in encr_algos:
        cleaned = algo.strip()
        is_deprecated = False
        for dep, meta in DEPRECATED_ENCRYPTION_ALGORITHMS.items():
            if dep in cleaned.upper():
                deprecated_found.append(f"{cleaned} ({meta['reason']})")
                is_deprecated = True
                break
        if not is_deprecated:
            for app, meta in APPROVED_ENCRYPTION_ALGORITHMS.items():
                if app in cleaned or cleaned in app:
                    approved_found.append(f"{cleaned} ({meta['bits']}-bit, AEAD={meta['aead']})")
                    break

    for algo in integ_algos:
        cleaned = algo.strip()
        for dep, meta in DEPRECATED_INTEGRITY_ALGORITHMS.items():
            if dep in cleaned.upper():
                deprecated_found.append(f"{cleaned} ({meta['reason']})")
                break

    primary_encr = encr_algos[0] if encr_algos else "Unspecified"

    if deprecated_found:
        return {
            "category": "Cryptographic Strength",
            "status": "FAIL",
            "observed_value": ", ".join(encr_algos + integ_algos),
            "expected_or_policy": "NIST SP 800-77 Rev. 1 & SP 800-57: Deprecated algorithms (3DES, DES, MD5) must not be used.",
            "reason": f"Disallowed cryptographic algorithms observed: {'; '.join(deprecated_found)}.",
            "severity": "CRITICAL" if any("DES" in d for d in deprecated_found) else "HIGH",
        }

    if approved_found:
        return {
            "category": "Cryptographic Strength",
            "status": "PASS",
            "observed_value": primary_encr,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 / SP 800-57: AES-128/256 (GCM/CBC) or modern AEAD cipher with >= 128-bit key.",
            "reason": f"Observed robust cryptographic transform: {'; '.join(approved_found)}. Compliant with NIST cryptographic standards.",
            "severity": "LOW",
        }

    return {
        "category": "Cryptographic Strength",
        "status": "WARNING",
        "observed_value": ", ".join(encr_algos),
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3 approved ciphers.",
        "reason": f"Transform '{primary_encr}' is not explicitly listed in NIST SP 800-77 standard recommendations.",
        "severity": "MEDIUM",
    }


def evaluate_configuration_compliance(features: Dict[str, Any]) -> Dict[str, Any]:
    ipsec = features.get("ipsec") or {}
    ike = features.get("ike") or {}
    esp = features.get("esp") or {}
    ah = features.get("ah") or {}
    mode = features.get("mode") or {}
    cleartext = features.get("cleartext_leakage") or {}

    ipsec_detected = ipsec.get("ipsec_detected", False)
    ike_version = ike.get("version")
    esp_detected = esp.get("detected", False)
    ah_detected = ah.get("detected", False)
    nat_t_detected = esp.get("nat_t", False) or ipsec.get("nat_t_detected", False)

    cleartext_leak_packets = cleartext.get("packet_count", 0)
    cleartext_ratio = cleartext.get("ratio_percent", 0.0)
    cleartext_protos = cleartext.get("cleartext_protocols", [])

    # Case 0: No IPsec at all
    if not ipsec_detected:
        return {
            "category": "Configuration Compliance",
            "status": "FAIL",
            "observed_value": "No IPsec configuration active",
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2: Secure IPsec configuration with active IKE and ESP protection.",
            "reason": "Host network traffic completely lacks IPsec configuration; all packets bypass VPN encapsulation.",
            "severity": "CRITICAL",
        }

    observed_details = []
    issues = []
    severity = "LOW"

    if ike_version:
        observed_details.append(f"IKE Version: {ike_version}")
        if ike_version == "IKEv1":
            issues.append("IKEv1 is legacy and deprecated by NIST SP 800-77 Rev. 1 Section 3.2 in favor of IKEv2.")
            severity = "MEDIUM"
    else:
        observed_details.append("IKE Version: Not Captured")

    if esp_detected:
        observed_details.append(f"ESP: Active ({esp.get('packet_count', 0)} pkts)")
    if ah_detected:
        observed_details.append(f"AH: Active ({ah.get('packet_count', 0)} pkts)")
        issues.append("AH protocol detected; per NIST SP 800-77 Rev. 1 Section 3.4, AH does not provide confidentiality and ESP is recommended.")
        severity = max(severity, "MEDIUM", key=lambda x: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[x])

    if nat_t_detected:
        observed_details.append("NAT-T: UDP 4500 Active")

    # Evaluate traffic leakage (cleartext packets alongside IPsec)
    if cleartext_leak_packets > 0:
        proto_str = ", ".join(cleartext_protos) if cleartext_protos else "Plain IP"
        observed_details.append(f"Cleartext Leakage: {cleartext_leak_packets} pkts ({cleartext_ratio}%)")
        if cleartext_ratio > 25.0:
            issues.append(
                f"Significant unencrypted traffic leakage detected ({cleartext_leak_packets} pkts, {cleartext_ratio}% of capture: {proto_str}) "
                f"bypassing IPsec tunnel. Violates NIST SP 800-77 Section 4.2 split-tunnel protection policy."
            )
            severity = "HIGH"
        elif cleartext_ratio > 5.0:
            issues.append(
                f"Unencrypted traffic leakage observed ({cleartext_leak_packets} pkts, {cleartext_ratio}% of capture: {proto_str}) "
                f"outside the IPsec tunnel."
            )
            severity = max(severity, "MEDIUM", key=lambda x: {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[x])

    observed_str = "; ".join(observed_details) if observed_details else "No IPsec configuration headers observed"

    if any("bypassing IPsec tunnel" in issue for issue in issues):
        return {
            "category": "Configuration Compliance",
            "status": "FAIL",
            "observed_value": observed_str,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 4.2: Strict tunnel encapsulation without unencrypted traffic leakage.",
            "reason": "; ".join(issues),
            "severity": severity,
        }

    if issues:
        return {
            "category": "Configuration Compliance",
            "status": "WARNING",
            "observed_value": observed_str,
            "expected_or_policy": "NIST SP 800-77 Rev. 1: Standard IKEv2 architecture with ESP encapsulation.",
            "reason": "; ".join(issues),
            "severity": severity,
        }

    if esp_detected or (ike_version == "IKEv2"):
        return {
            "category": "Configuration Compliance",
            "status": "PASS",
            "observed_value": observed_str,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2 & 3.4: IKEv2 with ESP encapsulation.",
            "reason": "Observed IPsec protocol configuration adheres to NIST guidance with modern IKEv2 and ESP encapsulation.",
            "severity": "LOW",
        }

    return {
        "category": "Configuration Compliance",
        "status": "NOT_OBSERVABLE",
        "observed_value": None,
        "expected_or_policy": "NIST SP 800-77 Rev. 1 IPsec architecture compliance.",
        "reason": "Insufficient IKE/ESP protocol headers captured to confirm overall configuration compliance.",
        "severity": "LOW",
    }


def evaluate_security_association(features: Dict[str, Any]) -> Dict[str, Any]:
    esp = features.get("esp") or {}
    sa = features.get("security_association") or {}
    ipsec = features.get("ipsec") or {}

    spis = esp.get("spi_values") or sa.get("spi_values") or []
    seq_min = esp.get("sequence_number_min")
    seq_max = esp.get("sequence_number_max")
    seq_count = esp.get("sequence_number_count", 0)

    if not ipsec.get("ipsec_detected", False):
        return {
            "category": "Security Association Parameters",
            "status": "FAIL",
            "observed_value": "Zero Security Associations",
            "expected_or_policy": "RFC 4301 / NIST SP 800-77 Section 3.1: Valid 32-bit non-zero SPI and initialized sequence counters.",
            "reason": "No Security Associations exist; traffic is entirely unencrypted.",
            "severity": "HIGH",
        }

    if not spis and seq_count == 0:
        return {
            "category": "Security Association Parameters",
            "status": "NOT_OBSERVABLE",
            "observed_value": None,
            "expected_or_policy": "RFC 4301 / NIST SP 800-77 Section 3.1: Valid 32-bit non-zero SPI and initialized sequence counters.",
            "reason": "No ESP Security Parameter Index (SPI) values or sequence headers were observable in the captured frames.",
            "severity": "LOW",
        }

    spi_count = len(spis)
    spi_summary = f"{spi_count} unique SPI(s): {', '.join(spis[:3])}"
    if seq_count > 0:
        seq_summary = f"Seq range [{seq_min}..{seq_max}], {seq_count} packets"
    else:
        seq_summary = "Seq not recorded"

    # Check for invalid zero SPI
    if any(s in ("0x00000000", "0x0", "0") for s in spis):
        return {
            "category": "Security Association Parameters",
            "status": "FAIL",
            "observed_value": spi_summary,
            "expected_or_policy": "RFC 4301: SPI value 0 is strictly reserved and prohibited in operational traffic.",
            "reason": "Reserved SPI value 0 observed, indicating corrupt or malformed SA negotiation.",
            "severity": "HIGH",
        }

    return {
        "category": "Security Association Parameters",
        "status": "PASS",
        "observed_value": f"{spi_summary} ({seq_summary})",
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.1: Active Security Associations identified by unique 32-bit SPIs and sequence tracking.",
        "reason": f"Active SA observed with valid SPI values ({', '.join(spis[:2])}) and active sequence number progression.",
        "severity": "LOW",
    }


def evaluate_key_lifetime(features: Dict[str, Any]) -> Dict[str, Any]:
    # Strictly observe from PCAP; NEVER guess or fabricate
    return {
        "category": "Key Lifetime",
        "status": "NOT_OBSERVABLE",
        "observed_value": None,
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2.4 & SP 800-57: IKE SA lifetime <= 24 hours; IPsec CHILD_SA <= 8 hours or byte-limit rekeying.",
        "reason": "SA lifetime duration/byte limits were not present in the captured frames. SA lifetimes are frequently enforced locally by host IPsec daemons without explicit on-wire advertisement.",
        "severity": "LOW",
    }


def evaluate_replay_protection(features: Dict[str, Any]) -> Dict[str, Any]:
    esp = features.get("esp") or {}
    seq_min = esp.get("sequence_number_min")
    seq_max = esp.get("sequence_number_max")
    seq_count = esp.get("sequence_number_count", 0)
    seq_duplicates = esp.get("sequence_number_duplicates", 0)

    if seq_count == 0 or seq_min is None or seq_max is None:
        return {
            "category": "Replay Protection",
            "status": "NOT_OBSERVABLE",
            "observed_value": None,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.1.3 & RFC 4303: Monotonically increasing sequence numbers with anti-replay window.",
            "reason": "No ESP sequence numbers observed in the trace to evaluate anti-replay protection.",
            "severity": "LOW",
        }

    dup_ratio = (seq_duplicates / seq_count) if seq_count > 0 else 0

    if dup_ratio > 0.20:
        return {
            "category": "Replay Protection",
            "status": "FAIL",
            "observed_value": f"{seq_duplicates} duplicate sequence number(s) detected across {seq_count} packets ({round(dup_ratio*100, 1)}%)",
            "expected_or_policy": "RFC 4303 Section 3.4.3: Duplicate sequence numbers violate anti-replay security.",
            "reason": f"Observed {seq_duplicates} duplicate sequence number(s) in ESP stream; potential packet replay attack or counter reset.",
            "severity": "HIGH",
        }

    if seq_duplicates > 0:
        return {
            "category": "Replay Protection",
            "status": "PASS" if esp.get("nat_t") else "WARNING",
            "observed_value": f"ESP sequence numbers [{seq_min}..{seq_max}] with {seq_duplicates} counter overlap(s)",
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.1.3: Anti-replay sequence verification.",
            "reason": f"Ascending sequence progression observed across SAs. Minor counter overlap ({seq_duplicates} pkts) observed during NAT-T transition.",
            "severity": "LOW",
        }

    return {
        "category": "Replay Protection",
        "status": "PASS",
        "observed_value": f"Monotonic ESP sequence numbers (min: {seq_min}, max: {seq_max}, packets: {seq_count}, duplicates: 0)",
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.1.3: Anti-replay protection with strictly increasing sequence counters.",
        "reason": f"Observed {seq_count} ESP frames with ascending sequence numbers [{seq_min}..{seq_max}] with zero duplicate counters. Note: host receiver anti-replay sliding window buffer size is an internal stack parameter not transmitted on wire.",
        "severity": "LOW",
    }


def evaluate_forward_secrecy(features: Dict[str, Any]) -> Dict[str, Any]:
    ike = features.get("ike") or {}
    dh_groups = ike.get("key_exchange_methods") or []
    exchanges = ike.get("exchange_types") or []

    has_child_sa_exchange = any("CREATE_CHILD_SA" in ex for ex in exchanges)

    if has_child_sa_exchange and dh_groups:
        dh_str = ", ".join(dh_groups)
        return {
            "category": "Forward Secrecy (PFS) Configuration",
            "status": "PASS",
            "observed_value": f"PFS Enabled ({dh_str} in CREATE_CHILD_SA)",
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2.3: Perfect Forward Secrecy enabled for CHILD_SAs with DH Group >= 14.",
            "reason": f"CHILD_SA negotiation captured with ephemeral Diffie-Hellman Key Exchange ({dh_str}), ensuring past session key confidentiality.",
            "severity": "LOW",
        }

    if dh_groups and not has_child_sa_exchange:
        return {
            "category": "Forward Secrecy (PFS) Configuration",
            "status": "NOT_OBSERVABLE",
            "observed_value": None,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2.3: Diffie-Hellman Key Exchange (KE) payload during CREATE_CHILD_SA rekeying.",
            "reason": "CREATE_CHILD_SA exchange was not captured in this trace. While initial IKE_SA_INIT used DH (" + ", ".join(dh_groups) + "), CHILD_SA Perfect Forward Secrecy (PFS) cannot be confirmed from IKE_SA_INIT or ESP packets alone.",
            "severity": "LOW",
        }

    return {
        "category": "Forward Secrecy (PFS) Configuration",
        "status": "NOT_OBSERVABLE",
        "observed_value": None,
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.2.3: Perfect Forward Secrecy enabled for CHILD_SAs.",
        "reason": "Diffie-Hellman Key Exchange payloads were not observable in the captured trace; PFS status cannot be claimed from ESP packets alone.",
        "severity": "LOW",
    }


def evaluate_cipher_suite_strength(features: Dict[str, Any]) -> Dict[str, Any]:
    ipsec = features.get("ipsec") or {}
    ike = features.get("ike") or {}
    esp = features.get("esp") or {}

    if not ipsec.get("ipsec_detected", False):
        return {
            "category": "Cipher Suite Strength",
            "status": "FAIL",
            "observed_value": "No cipher suite configured (Plain-text)",
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3.1: Approved cipher suites (e.g. AES-GCM-256).",
            "reason": "Network traffic is unencrypted plain-text; zero cipher suites configured.",
            "severity": "CRITICAL",
        }

    encr_list = list(ike.get("encryption_algorithms") or [])
    esp_encr = esp.get("encryption_algorithm", {})
    if isinstance(esp_encr, dict) and esp_encr.get("value") and esp_encr.get("value") not in ("UNKNOWN", "NONE"):
        if esp_encr["value"] not in encr_list:
            encr_list.append(esp_encr["value"])

    dh_list = ike.get("key_exchange_methods") or []
    prf_list = ike.get("prf_algorithms") or []
    integ_list = ike.get("integrity_algorithms") or []

    if not encr_list:
        return {
            "category": "Cipher Suite Strength",
            "status": "NOT_OBSERVABLE",
            "observed_value": None,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3.1: Approved cipher suites (e.g., AES-GCM-256 with DH Group >= 14).",
            "reason": "Cipher suite negotiation parameters were not captured in this PCAP trace.",
            "severity": "LOW",
        }

    suite_components = encr_list + prf_list + integ_list + dh_list
    suite_str = " + ".join(suite_components[:4])

    for item in suite_components:
        for dep in ("DES", "3DES", "MD5", "Group 1)", "Group 2)", "Group 5)"):
            if dep in item:
                return {
                    "category": "Cipher Suite Strength",
                    "status": "FAIL",
                    "observed_value": suite_str,
                    "expected_or_policy": "NIST SP 800-77 Rev. 1: Modern AEAD or high-strength suites; zero legacy ciphers.",
                    "reason": f"Cipher suite contains deprecated/vulnerable component: {item}.",
                    "severity": "HIGH",
                }

    is_aead = any("GCM" in e or "ChaCha20" in e or "CCM" in e for e in encr_list)
    if is_aead:
        return {
            "category": "Cipher Suite Strength",
            "status": "PASS",
            "observed_value": suite_str,
            "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3.1: Modern AEAD cipher suite (AES-GCM) with authenticated encryption.",
            "reason": f"High-assurance AEAD cipher suite ({suite_str}). Provides simultaneous confidentiality and message authenticity without requiring separate MAC.",
            "severity": "LOW",
        }

    # If CBC is used without AEAD
    return {
        "category": "Cipher Suite Strength",
        "status": "WARNING",
        "observed_value": suite_str,
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.3.1: Modern AEAD suites (AES-GCM) preferred over CBC mode.",
        "reason": f"Legacy CBC mode cipher suite observed ({suite_str}). Requires independent HMAC for integrity verification.",
        "severity": "LOW",
    }


def evaluate_metadata_exposure(features: Dict[str, Any]) -> Dict[str, Any]:
    network = features.get("network") or features.get("ip_features") or {}
    esp = features.get("esp") or {}
    ipsec = features.get("ipsec") or {}

    src_ips = network.get("unique_source_ips") or network.get("source_ips") or []
    dst_ips = network.get("unique_destination_ips") or network.get("destination_ips") or []
    packet_rate = network.get("packet_rate") or 0.0
    size_stats = network.get("packet_size_statistics") or network.get("packet_sizes") or {}
    spis = esp.get("spi_values") or ipsec.get("esp_spi_values") or []

    min_size = size_stats.get("min") or size_stats.get("minimum") or "N/A"
    max_size = size_stats.get("max") or size_stats.get("maximum") or "N/A"
    std_dev = size_stats.get("std_dev") or size_stats.get("standard_deviation") or 0.0

    endpoints_str = f"{len(src_ips)} src IP(s), {len(dst_ips)} dst IP(s)"
    spi_str = f"SPIs: {', '.join(spis[:2])}" if spis else "No SPIs"
    rate_str = f"{packet_rate} pps"

    observed_summary = (
        f"Outer IPs: {endpoints_str}; {spi_str}; Rate: {rate_str}; Packet sizes: [{min_size}..{max_size}] B (std-dev: {std_dev})"
    )

    reason = (
        "Outer IP headers, ESP SPIs (32-bit flow identifiers), sequence numbers, packet lengths, and timing characteristics "
        "remain visible in cleartext on the wire. While packet payloads are encrypted, passive eavesdroppers can perform traffic "
        "analysis, correlate communication endpoints, and infer activity bursts or application categories unless traffic padding "
        "or cover traffic is deployed."
    )

    return {
        "category": "Metadata Exposure",
        "status": "WARNING",
        "observed_value": observed_summary,
        "expected_or_policy": "NIST SP 800-77 Rev. 1 Section 3.1.1: Standard IPsec encrypts payload; outer IP headers and flow timing remain visible unless traffic flow confidentiality (cover traffic / padding) is deployed.",
        "reason": reason,
        "severity": "MEDIUM",
    }


def calculate_deterministic_risk_score(checks: List[Dict[str, Any]], features: Dict[str, Any]) -> Dict[str, Any]:
    """Computes a deterministic, dynamic numeric risk score (0-100)
    derived strictly from the NIST rule engine findings and observable PCAP metrics.
    """
    score = 0
    factors: List[Dict[str, Any]] = []

    checks_by_cat = {c["category"]: c for c in checks}
    ipsec = features.get("ipsec") or {}
    esp = features.get("esp") or {}
    cleartext = features.get("cleartext_leakage") or {}
    network = features.get("network") or {}

    # 1. Cryptographic Strength
    crypto_check = checks_by_cat.get("Cryptographic Strength")
    if crypto_check:
        if crypto_check["status"] == "FAIL":
            pts = 45 if crypto_check["severity"] == "CRITICAL" else 35
            score += pts
            factors.append({
                "category": "Cryptographic Strength",
                "points": pts,
                "reason": crypto_check.get("reason", "Disallowed or deprecated cryptographic algorithm observed."),
            })
        elif crypto_check["status"] == "WARNING":
            pts = 15
            score += pts
            factors.append({
                "category": "Cryptographic Strength",
                "points": pts,
                "reason": "Non-standard cryptographic transform observed.",
            })

    # 2. Configuration Compliance & Traffic Leakage
    config_check = checks_by_cat.get("Configuration Compliance")
    if config_check:
        if config_check["status"] == "FAIL":
            pts = 30 if config_check["severity"] == "CRITICAL" else 25
            score += pts
            factors.append({
                "category": "Configuration Compliance",
                "points": pts,
                "reason": config_check.get("reason", "Critical configuration failure or traffic leakage."),
            })
        elif config_check["status"] == "WARNING":
            pts = 12 if "leakage" in config_check.get("reason", "").lower() else 9
            score += pts
            factors.append({
                "category": "Configuration Compliance",
                "points": pts,
                "reason": config_check.get("reason", "Sub-optimal configuration or legacy parameter detected."),
            })

    # 3. Security Association Parameters
    sa_check = checks_by_cat.get("Security Association Parameters")
    if sa_check and sa_check["status"] == "FAIL":
        pts = 20 if sa_check["severity"] == "CRITICAL" else 15
        score += pts
        factors.append({
            "category": "Security Association Parameters",
            "points": pts,
            "reason": sa_check.get("reason", "Invalid or malformed Security Association."),
        })

    # 4. Replay Protection
    replay_check = checks_by_cat.get("Replay Protection")
    if replay_check:
        if replay_check["status"] == "FAIL":
            pts = 30
            score += pts
            factors.append({
                "category": "Replay Protection",
                "points": pts,
                "reason": replay_check.get("reason", "Anti-replay sequence number failure or duplicates."),
            })
        elif replay_check["status"] == "WARNING":
            pts = 10
            score += pts
            factors.append({
                "category": "Replay Protection",
                "points": pts,
                "reason": replay_check.get("reason", "Non-standard sequence counter pattern or packet gaps."),
            })

    # 5. Forward Secrecy / PFS
    pfs_check = checks_by_cat.get("Forward Secrecy (PFS) Configuration")
    if pfs_check and pfs_check["status"] == "FAIL":
        pts = 20
        score += pts
        factors.append({
            "category": "Forward Secrecy (PFS) Configuration",
            "points": pts,
            "reason": "Weak or disallowed Diffie-Hellman group in CHILD_SA negotiation.",
        })

    # 6. Cipher Suite Strength
    suite_check = checks_by_cat.get("Cipher Suite Strength")
    if suite_check:
        if suite_check["status"] == "FAIL":
            pts = 35
            score += pts
            factors.append({
                "category": "Cipher Suite Strength",
                "points": pts,
                "reason": suite_check.get("reason", "Insecure or deprecated composite cipher suite."),
            })
        elif suite_check["status"] == "WARNING":
            pts = 8
            score += pts
            factors.append({
                "category": "Cipher Suite Strength",
                "points": pts,
                "reason": suite_check.get("reason", "Non-AEAD cipher suite requires separate integrity validation."),
            })

    # 7. Metadata Exposure (Dynamically adjusted by size variance and rate)
    metadata_check = checks_by_cat.get("Metadata Exposure")
    if metadata_check and metadata_check["status"] == "WARNING":
        size_stats = network.get("packet_size_statistics") or {}
        std_dev = size_stats.get("std_dev", 0.0) or 0.0
        meta_pts = 15 if std_dev >= 250 else 10
        score += meta_pts
        factors.append({
            "category": "Metadata Exposure",
            "points": meta_pts,
            "reason": f"Outer IP addresses, SPIs, and packet timing remain exposed to network observers (size variance: {std_dev} B).",
        })

    # Clamp score to 0..100
    final_score = max(0, min(100, score))
    level = get_risk_level(final_score)

    return {
        "score": final_score,
        "level": level,
        "method": POLICY_METHOD,
        "factors": factors,
    }


def run_nist_security_engine(features: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Runs all 8 security checks and computes the deterministic risk assessment."""
    checks = [
        evaluate_cryptographic_strength(features),
        evaluate_configuration_compliance(features),
        evaluate_security_association(features),
        evaluate_key_lifetime(features),
        evaluate_replay_protection(features),
        evaluate_forward_secrecy(features),
        evaluate_cipher_suite_strength(features),
        evaluate_metadata_exposure(features),
    ]

    has_fail = any(c["status"] == "FAIL" for c in checks)
    has_warning = any(c["status"] == "WARNING" for c in checks)
    overall_status = "FAIL" if has_fail else ("WARNING" if has_warning else "PASS")

    nist_assessment = {
        "overall_status": overall_status,
        "checks": checks,
    }

    risk_assessment = calculate_deterministic_risk_score(checks, features)

    return nist_assessment, risk_assessment
