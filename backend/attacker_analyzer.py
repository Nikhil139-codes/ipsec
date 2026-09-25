"""
Attacker Simulation Module - Groq AI Integration
Generates controlled, authorized security validation tests from the latest security assessment report
and analyzes potential attacker next-steps and hardening recommendations.

Safety & Architectural Guarantees:
- Strictly defensive security prototype.
- Only predefined, non-destructive validation test commands are generated (pfs-test, replay-test, cipher-test, sa-test, metadata-test).
- Raw PCAP files are NEVER sent to Groq. Only extracted features, NIST findings, and risk assessments.
- Sensitive credentials or internal stack traces are never exposed to the client.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

BASE_DIR = Path(__file__).resolve().parent

def _load_env() -> None:
    for env_file in [
        BASE_DIR / ".env",
        BASE_DIR / ".env.local",
        BASE_DIR.parent / ".env.local",
        BASE_DIR.parent / ".env",
    ]:
        if env_file.exists():
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip()
                            v = v.strip().strip('"').strip("'")
                            if k not in os.environ and v:
                                os.environ[k] = v
            except Exception:
                pass

_load_env()

GROQ_CHAT_COMPLETIONS_URL = "https://api.groq.com/openai/v1/chat/completions"
FALLBACK_MODELS = [
    "groq/compound",
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-20b",
]

AUTHORIZED_COMMANDS = {
    "pfs-test": "Validate Perfect Forward Secrecy enforcement on CHILD_SAs",
    "replay-test": "Validate anti-replay window protection and sequence number progression",
    "cipher-test": "Validate cryptographic encryption cipher suite and integrity parameters",
    "sa-test": "Validate Security Association parameters, lifetime rekeying, and SPI state",
    "metadata-test": "Validate traffic metadata leakage, outer IP headers, and timing patterns",
}

SYSTEM_PROMPT_TEST_GENERATOR = """You are an authorized VPN security testing and validation assistant.
Your role is to analyze a detected IPsec security assessment report and plan CONTROLLED, NON-DESTRUCTIVE security validation tests for an authorized VPN laboratory environment.

CRITICAL SAFETY & SYSTEM CONSTRAINTS:
1. This is a DEFENSIVE security prototype.
2. The user's VPN lab only supports these PREDEFINED, SAFE test commands:
   - "pfs-test": Validates whether Perfect Forward Secrecy (PFS) is enforced in CHILD_SA proposals.
   - "replay-test": Validates anti-replay window checks and monotonic sequence numbers.
   - "cipher-test": Validates symmetric encryption algorithms (e.g. AES-CBC vs AES-GCM) and integrity transforms.
   - "sa-test": Validates Security Association parameters, lifetime bounds, and SPI negotiation.
   - "metadata-test": Validates observable traffic metadata (outer IPs, SPIs, packet size variance, timing bursts).
3. DO NOT generate ANY arbitrary, external, or destructive commands (no bash scripts, no nmap, no hydra, no exploit tools).
4. Every test command MUST be exactly one of: "pfs-test", "replay-test", "cipher-test", "sa-test", "metadata-test".
5. Base your tests directly on the detected weaknesses, warnings, or failures in the security assessment report.
6. If the report has no explicit failures, generate baseline validation tests verifying the configured controls.
7. Return ONLY a valid JSON object matching this schema:
{
  "tests": [
    {
      "id": "TEST-001",
      "title": "PFS Configuration Validation",
      "reason": "PFS-related weakness was identified in the report.",
      "command": "pfs-test",
      "expected_result": "PFS requirement is not enforced",
      "potential_impact": "Weaker key-establishment security",
      "next_step": "Analyze the VPN configuration for additional weaknesses"
    }
  ]
}
"""

SYSTEM_PROMPT_ATTACK_PATH = """You are a senior defensive cyber threat intelligence and IPsec hardening expert.
You analyze simulated security test findings from an authorized VPN test environment.

CRITICAL INSTRUCTIONS:
1. Frame your response strictly as a POTENTIAL attack progression or hypothetical threat path, NOT a guaranteed prediction.
2. Never claim that a real system was compromised; these are simulated prototype results.
3. Focus on defensive mitigation, architectural hardening, and NIST SP 800-77 Rev. 1 compliance.
4. Return ONLY a valid JSON object matching this schema:
{
  "validated_weakness": "Brief name of the validated weakness (e.g., Weak PFS Configuration, Replay Protection Weakness, Cipher Configuration Weakness)",
  "test_result": "Summary of the simulated validation test result (e.g., Weakness Confirmed, Potential Replay Acceptance, Weak/Legacy Configuration Confirmed)",
  "potential_attacker_action": "Potential next reconnaissance, negotiation, or exploitation step an attacker might attempt",
  "potential_impact": "Clear explanation of the architectural or security impact",
  "recommended_hardening": "Specific, actionable configuration and hardening advice per NIST guidance"
}
"""

def _extract_clean_json(text: str) -> Optional[Dict[str, Any]]:
    """Extracts JSON from text, accommodating optional markdown fencing."""
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass

    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass

    first = text.find("{")
    last = text.rfind("}")
    if first != -1 and last != -1 and last > first:
        try:
            return json.loads(text[first : last + 1])
        except Exception:
            pass
    return None


def build_fallback_tests(report_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Deterministic fallback test plan mapped directly to NIST findings and detected weaknesses."""
    nist_checks = report_data.get("nist_assessment", {}).get("checks", [])
    tests: List[Dict[str, Any]] = []
    test_idx = 1

    # Map categories to predefined commands
    category_map = {
        "Forward Secrecy (PFS) Configuration": ("pfs-test", "PFS Configuration Validation", "PFS-related weakness or configuration check identified in the report.", "PFS requirement is not enforced in CHILD_SA negotiation", "Weaker key-establishment security if long-term private keys are ever exposed", "Review strongSwan / IPsec child configuration to enforce DH group 14+"),
        "Replay Protection": ("replay-test", "Replay Protection Validation", "Anti-replay protection and monotonic ESP sequence tracking evaluation.", "Potential window exhaustion or sequence out-of-order vulnerability", "Replay attacks could allow replay of valid ciphertext packets", "Verify 64-entry or higher anti-replay sliding window on ESP interface"),
        "Cryptographic Strength": ("cipher-test", "Cipher Suite Configuration Validation", "Cryptographic transform parameters evaluated against NIST SP 800-57.", "Use of deprecated or non-AEAD cipher suites", "Risk of chosen-ciphertext or bit-flipping integrity attacks", "Upgrade to AES-256-GCM authenticated encryption"),
        "Cipher Suite Strength": ("cipher-test", "Cipher Suite Strength Validation", "Evaluation of encryption algorithms and message integrity hash functions.", "Sub-optimal cipher or hash transform", "Lower cryptographic assurance against modern compute capabilities", "Enforce AES-GCM or AES-CTR with SHA-256+ MAC"),
        "Metadata Exposure": ("metadata-test", "Traffic Metadata Exposure Validation", "Outer IP, SPI, and timing burst leakage observed in telemetry.", "Cleartext outer IP headers and packet timing expose communication patterns", "Passive adversary can perform traffic flow correlation and endpoint profiling", "Deploy constant-rate traffic padding or cover traffic (IPsec TFC)"),
        "Security Association Parameters": ("sa-test", "Security Association Validation", "Active SA counts, SPI parameters, and lifetime rekey boundaries.", "Unconstrained SA lifetime or renegotiation without re-authentication", "Stale key material susceptible to cryptanalysis", "Enforce CHILD_SA lifetime limits of <= 8 hours or 4GB byte volume"),
        "Configuration Compliance": ("cipher-test", "Protocol Compliance Validation", "Protocol architecture and encapsulation compliance evaluated under NIST SP 800-77.", "Legacy AH or non-recommended encapsulation active", "Inefficient encapsulation or lack of payload confidentiality", "Migrate to ESP tunnel mode encapsulation with UDP 4500 NAT-T"),
    }

    # 1. Prioritize warnings and failures
    weaknesses = [c for c in nist_checks if c.get("status") in ("WARNING", "FAIL")]
    # If no warnings/failures, include checks that are PASS for baseline validation
    target_checks = weaknesses if weaknesses else nist_checks

    seen_cmds = set()
    for c in target_checks:
        cat = c.get("category", "")
        if cat in category_map and category_map[cat][0] not in seen_cmds:
            cmd, title, default_reason, exp_res, impact, next_st = category_map[cat]
            seen_cmds.add(cmd)
            reason = c.get("reason") or default_reason
            if len(reason) > 140:
                reason = reason[:137] + "..."
            tests.append({
                "id": f"TEST-{test_idx:03d}",
                "title": title,
                "reason": reason,
                "command": cmd,
                "expected_result": exp_res,
                "potential_impact": impact,
                "next_step": next_st,
            })
            test_idx += 1

    # Guarantee at least PFS and cipher tests are available as baseline
    if "pfs-test" not in seen_cmds:
        tests.append({
            "id": f"TEST-{test_idx:03d}",
            "title": "PFS Configuration Validation",
            "reason": "Verify Perfect Forward Secrecy enforcement on active CHILD_SAs.",
            "command": "pfs-test",
            "expected_result": "PFS configuration validated against simulated VPN profile",
            "potential_impact": "Compromised keys could affect forward secrecy if PFS disabled",
            "next_step": "Validate IPsec configuration in strongSwan / charon daemon",
        })
        test_idx += 1

    if "replay-test" not in seen_cmds:
        tests.append({
            "id": f"TEST-{test_idx:03d}",
            "title": "Anti-Replay Window Validation",
            "reason": "Verify anti-replay window mechanics and sequence counter boundaries.",
            "command": "replay-test",
            "expected_result": "Simulate replayed sequence numbers to verify drop policy",
            "potential_impact": "Replay attacks could inject outdated encrypted payloads",
            "next_step": "Check anti-replay window size configuration (e.g. 64 or 128)",
        })

    return tests


def build_fallback_attack_path(
    command: str,
    weakness: str,
    simulated_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Deterministic, robust fallback attack path analysis adhering to defensive security guidelines."""
    cmd = (command or "").lower()
    status = simulated_result.get("status", "WEAKNESS CONFIRMED")

    if "pfs" in cmd:
        return {
            "validated_weakness": weakness or "Weak PFS Configuration",
            "test_result": "Weakness Confirmed",
            "potential_attacker_action": "Attempt Weaker Negotiation",
            "attacker_next_step": "A passive eavesdropper may attempt weaker negotiation without ephemeral key exchange and record historical encrypted ESP flows.",
            "potential_impact": "Absence of ephemeral Diffie-Hellman renegotiation means compromise of long-term credentials or private keys could permit retroactive decryption of previously recorded tunnel sessions (Harvest-Now-Decrypt-Later).",
            "recommended_hardening": "Enforce Perfect Forward Secrecy in strongSwan (esp=aes256gcm16-modp2048!) and ensure Diffie-Hellman Group 14 (MODP-2048) or Group 19 (ECDH-256) is mandated on all CHILD_SAs.",
        }
    elif "replay" in cmd:
        return {
            "validated_weakness": weakness or "Replay Protection Weakness",
            "test_result": "Potential Replay Acceptance",
            "potential_attacker_action": "Attempt Duplicate Sequence Frame Injection",
            "attacker_next_step": "An attacker with network interception capabilities may attempt sequence-reset spoofing, duplicate frame injection, or state desynchronization against the VPN gateway.",
            "potential_impact": "Inadequate sliding window bounds or sequence number reuse can permit unauthorized reinjection of valid historical ciphertext packets.",
            "recommended_hardening": "Enable standard IPsec anti-replay protection with an active sliding window of at least 64 packets (or 128 packets for high-throughput connections) and drop duplicate sequence numbers.",
        }
    elif "cipher" in cmd:
        return {
            "validated_weakness": weakness or "Cipher Configuration Weakness",
            "test_result": "Weak/Legacy Configuration Confirmed",
            "potential_attacker_action": "Attempt Bit-Flipping Integrity Probing",
            "attacker_next_step": "An adversary may launch active man-in-the-middle bit-flipping attacks against non-authenticated ESP packets or exploit cryptographic weaknesses in CBC padding.",
            "potential_impact": "Use of legacy ciphers (e.g., 3DES, single DES) or non-AEAD modes without message integrity validation increases vulnerability to padding-oracle, bit-flipping, or brute-force attacks.",
            "recommended_hardening": "Enforce authenticated encryption with associated data (AEAD) using AES-256-GCM or ChaCha20-Poly1305. Deprecate legacy DES, 3DES, and MD5 algorithms entirely.",
        }
    elif "sa" in cmd:
        return {
            "validated_weakness": weakness or "Security Association Lifetime Weakness",
            "test_result": "Extended SA Lifetime Confirmed",
            "potential_attacker_action": "Harvest High-Volume Ciphertext for Keystream Analysis",
            "attacker_next_step": "An attacker collecting high volumes of traffic may analyze nonce collisions, keystream patterns, or launch statistical cryptanalysis against the static key.",
            "potential_impact": "Excessively long Security Association lifetimes or missing rekeying boundaries expose a large volume of ciphertext under a single cryptographic key.",
            "recommended_hardening": "Configure strict CHILD_SA time limits (maximum 8 hours) and volume limits (maximum 4 GB) with automated ephemeral rekeying per NIST SP 800-77 Section 3.2.4.",
        }
    elif "metadata" in cmd:
        return {
            "validated_weakness": weakness or "Traffic Metadata Exposure",
            "test_result": "Observable Metadata Exposure Confirmed",
            "potential_attacker_action": "Conduct Statistical Flow Correlation and Traffic Fingerprinting",
            "attacker_next_step": "A passive eavesdropper may conduct statistical traffic fingerprinting to map communication topology, identify remote server endpoints, or infer specific application usage patterns.",
            "potential_impact": "Cleartext outer IP headers, SPIs, packet length variations, and timing bursts allow network observers to reconstruct user activities, application types, or communication relationships.",
            "recommended_hardening": "Deploy IPsec Traffic Flow Confidentiality (TFC) per RFC 4303 Section 2.7 or constant-rate padding to obscure packet length variations and burst timing.",
        }
    else:
        return {
            "validated_weakness": weakness or "VPN Configuration Weakness",
            "test_result": "Weakness Confirmed",
            "potential_attacker_action": "Attempt Weaker Negotiation",
            "attacker_next_step": "An attacker may conduct further reconnaissance of the gateway's IKE exchange types, proposal lists, and supported transform IDs to identify downgradable parameters.",
            "potential_impact": "Sub-optimal VPN parameters create opportunities for traffic analysis, protocol degradation, or unauthorized interception in hostile network segments.",
            "recommended_hardening": "Audit all IKEv2 and ESP configuration profiles against NIST SP 800-77 Rev. 1 guidelines, enforcing modern AEAD ciphers, PFS, and strict packet replay filtering.",
        }


async def generate_attacker_tests(
    report_data: Dict[str, Any],
    timeout_seconds: float = 20.0,
) -> Dict[str, Any]:
    """
    Sends sanitized report data to Groq to generate controlled, authorized security tests.
    Does NOT transmit raw PCAP data.
    Gracefully degrades if Groq is unavailable.
    """
    _load_env()
    api_key = os.environ.get("GROQ_API_KEY") or os.environ.get("XAI_API_KEY")
    configured_model = os.environ.get("GROQ_MODEL") or os.environ.get("XAI_MODEL") or "groq/compound"
    if "grok" in configured_model.lower():
        configured_model = "groq/compound"

    # Sanitize report data: ONLY extracted features summary, NIST findings, risk score, weaknesses
    features = report_data.get("observed_features") or report_data.get("features") or {}
    nist = report_data.get("nist_assessment") or {}
    risk = report_data.get("risk_assessment") or {}
    ai = report_data.get("ai_analysis") or {}

    checks = nist.get("checks", [])
    weaknesses = [
        {
            "category": c.get("category"),
            "status": c.get("status"),
            "severity": c.get("severity"),
            "reason": c.get("reason"),
            "observed_value": c.get("observed_value"),
            "policy": c.get("expected_or_policy"),
        }
        for c in checks
        if c.get("status") in ("WARNING", "FAIL")
    ]

    sanitized_report = {
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "detected_weaknesses": weaknesses,
        "all_nist_checks_summary": [
            {"category": c.get("category"), "status": c.get("status"), "severity": c.get("severity")}
            for c in checks
        ],
        "cryptographic_profile": {
            "ike_version": features.get("ike", {}).get("version"),
            "encryption": features.get("cryptography", {}).get("esp", {}).get("encryption"),
            "integrity": features.get("cryptography", {}).get("esp", {}).get("integrity"),
            "dh_group": features.get("ike", {}).get("key_exchange_methods"),
            "esp_ratio": features.get("espRatio"),
        },
        "recommendations": ai.get("recommendations", [])[:4],
        "authorized_commands_available": AUTHORIZED_COMMANDS,
    }

    if not api_key or not api_key.strip():
        return {
            "tests": build_fallback_tests(report_data),
            "status": "fallback",
            "message": "AI attack-test generation is temporarily unavailable.",
        }

    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }

    user_payload = {
        "task": "Generate controlled security validation tests for an authorized VPN laboratory based strictly on the provided report.",
        "report": sanitized_report,
    }

    models_to_try = [configured_model] + [m for m in FALLBACK_MODELS if m != configured_model]
    last_err = None

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        for model in models_to_try:
            try:
                body = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT_TEST_GENERATOR},
                        {"role": "user", "content": json.dumps(user_payload, indent=2)},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2,
                }
                resp = await client.post(GROQ_CHAT_COMPLETIONS_URL, json=body, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        raw = choices[0].get("message", {}).get("content", "")
                        parsed = _extract_clean_json(raw)
                        if parsed and "tests" in parsed and isinstance(parsed["tests"], list):
                            # Validate that commands are strictly within authorized set
                            valid_tests = []
                            for idx, t in enumerate(parsed["tests"]):
                                cmd = t.get("command", "").strip().lower()
                                if cmd not in AUTHORIZED_COMMANDS:
                                    # Fallback mapping
                                    cmd = "pfs-test" if "pfs" in t.get("title", "").lower() else "cipher-test"
                                valid_tests.append({
                                    "id": t.get("id") or f"TEST-{idx+1:03d}",
                                    "title": t.get("title") or "VPN Security Validation",
                                    "reason": t.get("reason") or "Weakness identified in report",
                                    "command": cmd,
                                    "expected_result": t.get("expected_result") or "Weakness confirmed in simulated profile",
                                    "potential_impact": t.get("potential_impact") or "Reduced security assurance",
                                    "next_step": t.get("next_step") or "Inspect VPN configuration",
                                })
                            if valid_tests:
                                return {
                                    "tests": valid_tests,
                                    "status": "success",
                                    "message": None,
                                }
                else:
                    last_err = f"HTTP {resp.status_code}"
            except Exception as e:
                last_err = str(e)
                continue

    return {
        "tests": build_fallback_tests(report_data),
        "status": "fallback",
        "message": "AI attack-test generation is temporarily unavailable.",
    }


async def analyze_attack_path(
    command: str,
    weakness: str,
    simulated_result: Dict[str, Any],
    report_summary: Optional[Dict[str, Any]] = None,
    timeout_seconds: float = 20.0,
) -> Dict[str, Any]:
    """
    Sends the validated weakness, command, and simulated result to Groq to generate
    potential attacker next steps and hardening recommendations.
    """
    _load_env()
    api_key = os.environ.get("GROQ_API_KEY") or os.environ.get("XAI_API_KEY")
    configured_model = os.environ.get("GROQ_MODEL") or os.environ.get("XAI_MODEL") or "groq/compound"
    if "grok" in configured_model.lower():
        configured_model = "groq/compound"

    if not api_key or not api_key.strip():
        return build_fallback_attack_path(command, weakness, simulated_result)

    user_payload = {
        "question": "Based on this validated weakness, what could an attacker potentially attempt next?",
        "test_command": command,
        "detected_weakness": weakness,
        "simulated_test_result": simulated_result,
        "report_context": report_summary or {},
        "guidance": "Frame as potential attack progression in an authorized lab, not a guaranteed exploit. Emphasize NIST SP 800-77 hardening.",
    }

    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }

    models_to_try = [configured_model] + [m for m in FALLBACK_MODELS if m != configured_model]

    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        for model in models_to_try:
            try:
                body = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT_ATTACK_PATH},
                        {"role": "user", "content": json.dumps(user_payload, indent=2)},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2,
                }
                resp = await client.post(GROQ_CHAT_COMPLETIONS_URL, json=body, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        raw = choices[0].get("message", {}).get("content", "")
                        parsed = _extract_clean_json(raw)
                        if parsed and ("potential_impact" in parsed or "attacker_next_step" in parsed or "potential_attacker_action" in parsed):
                            action = parsed.get("potential_attacker_action") or parsed.get("attacker_next_step") or "Analyze the VPN configuration for additional weaknesses"
                            return {
                                "validated_weakness": parsed.get("validated_weakness") or weakness,
                                "test_result": parsed.get("test_result") or simulated_result.get("status") or "Weakness Confirmed",
                                "potential_attacker_action": action,
                                "attacker_next_step": action,
                                "potential_impact": parsed.get("potential_impact") or "Weaker key-establishment security",
                                "recommended_hardening": parsed.get("recommended_hardening") or "Enforce NIST SP 800-77 compliant cryptographic parameters.",
                            }
            except Exception:
                continue

    return build_fallback_attack_path(command, weakness, simulated_result)
