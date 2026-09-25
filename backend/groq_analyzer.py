"""
Server-Side Groq AI Analysis Client
Integrates with the Groq API (https://api.groq.com/openai/v1/chat/completions)
for high-speed LPU inference, security interpretation, and probabilistic traffic classification.

Security & Architecture Guarantees:
- GROQ_API_KEY is kept strictly server-side and never exposed to the client.
- Raw PCAPs are NEVER transmitted to Groq; only extracted feature JSON and NIST findings are sent.
- If GROQ_API_KEY is missing or Groq API fails, the service gracefully degrades and returns a structured fallback
  while preserving NIST findings and deterministic risk scores.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx

BASE_DIR = Path(__file__).resolve().parent

# Auto-load environment variables from .env / .env.local if present
def _load_local_env() -> None:
    candidate_paths = [
        BASE_DIR / ".env",
        BASE_DIR / ".env.local",
        BASE_DIR.parent / ".env.local",
        BASE_DIR.parent / ".env",
    ]
    for env_file in candidate_paths:
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

_load_local_env()

GROQ_CHAT_COMPLETIONS_URL = "https://api.groq.com/openai/v1/chat/completions"

ALLOWED_TRAFFIC_CLASSES = [
    "Web Browsing",
    "Video Streaming",
    "Audio Streaming",
    "VoIP",
    "File Transfer",
    "DNS",
    "Messaging",
    "Gaming",
    "Bulk Data Transfer",
    "Unknown",
]

GROQ_SYSTEM_PROMPT = """You are a senior IPsec security analyst and encrypted network traffic classification expert.
You evaluate observable IPsec network telemetry, deterministic NIST-derived rule engine findings, and risk assessments.

CRITICAL RULES:
1. Strict Evidence Adherence: Never invent, assume, or hallucinate cryptographic parameters, keys, lifetimes, or tunnel modes that are marked NOT_OBSERVABLE or absent in the extracted evidence.
2. Probabilistic Classification: Network payload is encrypted; traffic classification must be probabilistic based on packet sizes, timing, inter-arrival times, burstiness, and protocol headers.
3. General Categories Only: Classify traffic into one of these standard categories:
   - Web Browsing
   - Video Streaming
   - Audio Streaming
   - VoIP
   - File Transfer
   - DNS
   - Messaging
   - Gaming
   - Bulk Data Transfer
   - Unknown
   Do NOT claim a specific application brand (such as YouTube, Netflix, Zoom) unless the evidence unequivocally identifies it.
4. Output Format: You must output ONLY a valid JSON object matching this exact schema:
{
  "traffic_class": "Video Streaming",
  "confidence": 0.91,
  "summary": "Brief 1-2 sentence executive summary of traffic behavior and security state.",
  "security_interpretation": "Detailed paragraph explaining the cryptographic strength, configuration posture, and metadata exposure implications.",
  "key_observations": [
    "Observation 1 regarding observed cipher suites, SPIs, or flow patterns",
    "Observation 2 regarding visible metadata, packet sizes, or timing"
  ],
  "recommendations": [
    "Actionable recommendation 1 regarding IPsec configuration or NIST compliance",
    "Actionable recommendation 2"
  ]
}
"""

FALLBACK_MODELS = [
    "groq/compound",
    "openai/gpt-oss-120b",
    "qwen/qwen3.8-27b",
    "openai/gpt-oss-20b",
]


def _build_fallback_analysis(
    reason: str = "AI analysis unavailable — NIST assessment completed.",
    features: Optional[Dict[str, Any]] = None,
    risk: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generates a structured, predictable fallback response when GROQ_API_KEY is unset or API fails."""
    traffic_guess = "Unknown"
    confidence = 0.50

    if features:
        avg_size = features.get("avgPacketSize") or 0
        esp_ratio = features.get("espRatio") or 0
        packet_rate = features.get("packetRate") or 0
        if esp_ratio > 80:
            if avg_size > 1000 and packet_rate > 30:
                traffic_guess = "Video Streaming"
                confidence = 0.82
            elif avg_size > 1000:
                traffic_guess = "Bulk Data Transfer"
                confidence = 0.78
            elif avg_size < 300 and packet_rate > 20:
                traffic_guess = "VoIP"
                confidence = 0.72
            else:
                traffic_guess = "Web Browsing"
                confidence = 0.70

    score = risk.get("score", "N/A") if risk else "N/A"
    level = risk.get("level", "N/A") if risk else "N/A"

    return {
        "available": False,
        "error": reason,
        "traffic_class": traffic_guess,
        "confidence": round(confidence, 2),
        "summary": f"{reason} Deterministic risk score: {score}/100 ({level}).",
        "security_interpretation": (
            "The NIST deterministic rule engine evaluated 8 core security categories from the captured PCAP trace. "
            "Server-side Groq AI narrative analysis was not executed. Configure GROQ_API_KEY in the server environment "
            "to enable automated threat modeling and deep traffic analysis."
        ),
        "key_observations": [
            f"Deterministic NIST-derived assessment completed with risk level: {level}.",
            "All cryptographic and protocol compliance checks strictly reflect wire observations.",
            "Payload data remains encrypted under ESP encapsulation.",
        ],
        "recommendations": [
            "Review the individual NIST category findings below for configuration compliance.",
            "Ensure Diffie-Hellman Group 14 or higher is enforced across all CHILD_SA renegotiations.",
            "Deploy packet padding or traffic flow confidentiality if metadata leakage is a concern.",
        ],
    }


def _extract_clean_json(text: str) -> Optional[Dict[str, Any]]:
    """Extracts and parses JSON from model response text even if wrapped in markdown fences."""
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

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        try:
            return json.loads(text[first_brace : last_brace + 1])
        except Exception:
            pass

    return None


async def analyze_with_groq(
    features: Dict[str, Any],
    nist_assessment: Dict[str, Any],
    risk_assessment: Dict[str, Any],
    timeout_seconds: float = 25.0,
) -> Dict[str, Any]:
    """Sends sanitized feature telemetry and NIST findings to Groq via Groq API."""
    _load_local_env()
    api_key = os.environ.get("GROQ_API_KEY") or os.environ.get("XAI_API_KEY")
    configured_model = os.environ.get("GROQ_MODEL") or os.environ.get("XAI_MODEL")

    # If the configured model was a grok model name (e.g. grok-4.6), replace with Groq model
    if not configured_model or "grok" in configured_model.lower():
        configured_model = "groq/compound"

    if not api_key or not api_key.strip():
        return _build_fallback_analysis(
            reason="AI analysis unavailable — NIST assessment completed.",
            features=features,
            risk=risk_assessment,
        )

    # Sanitize and summarize features to avoid token bloat
    sanitized_features = {
        "capture_name": features.get("capture_name") or features.get("capture", {}).get("filename"),
        "total_packets": features.get("totalPackets"),
        "avg_packet_size": features.get("avgPacketSize"),
        "packet_rate": features.get("packetRate"),
        "esp_ratio": features.get("espRatio"),
        "ike_ratio": features.get("ikeRatio"),
        "burstiness": features.get("burstiness"),
        "entropy": features.get("entropy"),
        "ipsec": {
            "detected": features.get("ipsec", {}).get("ipsec_detected"),
            "protocols": features.get("ipsec", {}).get("protocols_detected"),
            "nat_t": features.get("ipsec", {}).get("nat_t_detected"),
            "spi_values": features.get("esp", {}).get("spi_values", [])[:4],
            "sequence_range": [
                features.get("esp", {}).get("sequence_number_min"),
                features.get("esp", {}).get("sequence_number_max"),
            ],
            "sequence_count": features.get("esp", {}).get("sequence_number_count"),
        },
        "ike": {
            "version": features.get("ike", {}).get("version"),
            "exchanges": features.get("ike", {}).get("exchange_types"),
            "encryption": features.get("ike", {}).get("encryption_algorithms"),
            "integrity": features.get("ike", {}).get("integrity_algorithms"),
            "dh_groups": features.get("ike", {}).get("key_exchange_methods"),
        },
        "network_metadata": {
            "source_ips": (features.get("network", {}).get("unique_source_ips") or [])[:5],
            "destination_ips": (features.get("network", {}).get("unique_destination_ips") or [])[:5],
            "packet_sizes": features.get("network", {}).get("packet_size_statistics") or features.get("network", {}).get("packet_sizes"),
            "timing": features.get("network", {}).get("timing_statistics") or features.get("network", {}).get("iat_statistics"),
        },
    }

    user_payload = {
        "task": "Analyze observed IPsec network telemetry and validate NIST security compliance findings.",
        "observed_telemetry": sanitized_features,
        "nist_assessment": nist_assessment,
        "deterministic_risk_assessment": risk_assessment,
        "security_standards_context": "NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs) and NIST SP 800-57 Part 1 Rev. 5.",
    }

    headers = {
        "Authorization": f"Bearer {api_key.strip()}",
        "Content-Type": "application/json",
    }

    user_content = json.dumps(user_payload, indent=2)

    # Models to try (configured model first, then fallbacks)
    models_to_try = [configured_model] + [m for m in FALLBACK_MODELS if m != configured_model]

    last_err = None
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        for model_name in models_to_try:
            try:
                chat_payload = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": GROQ_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.2,
                }
                resp = await client.post(GROQ_CHAT_COMPLETIONS_URL, json=chat_payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    choices = data.get("choices", [])
                    if choices:
                        raw_text = choices[0].get("message", {}).get("content", "")
                        parsed = _extract_clean_json(raw_text)
                        if parsed:
                            return _normalize_ai_response(parsed)
                else:
                    last_err = f"Groq HTTP {resp.status_code}: {resp.text[:80]}"
            except Exception as err:
                last_err = str(err)
                continue

    return _build_fallback_analysis(
        reason=f"Groq API call failed ({last_err or 'unknown error'}). NIST assessment completed.",
        features=features,
        risk=risk_assessment,
    )


def _normalize_ai_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures all expected schema fields are well-formed and valid."""
    traffic_class = data.get("traffic_class") or "Unknown"
    if traffic_class not in ALLOWED_TRAFFIC_CLASSES:
        for allowed in ALLOWED_TRAFFIC_CLASSES:
            if allowed.lower() in traffic_class.lower():
                traffic_class = allowed
                break
        else:
            traffic_class = "Unknown"

    conf = data.get("confidence", 0.85)
    try:
        conf_float = float(conf)
        if conf_float > 1.0:
            conf_float = conf_float / 100.0
        conf_float = max(0.0, min(1.0, conf_float))
    except Exception:
        conf_float = 0.85

    return {
        "available": True,
        "traffic_class": traffic_class,
        "confidence": round(conf_float, 2),
        "summary": str(data.get("summary") or "Traffic behavior and security posture assessed against NIST guidance."),
        "security_interpretation": str(data.get("security_interpretation") or "Standard IPsec VPN encapsulation observed."),
        "key_observations": list(data.get("key_observations") or []),
        "recommendations": list(data.get("recommendations") or []),
    }


# Alias for backward compatibility
analyze_with_grok = analyze_with_groq
