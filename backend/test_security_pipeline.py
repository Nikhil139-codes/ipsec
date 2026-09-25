"""
Integration test for NIST Security Rule Engine, Deterministic Risk Scorer, and Grok AI pipeline.
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import asyncio
from extractor.tshark import extract_packets_with_tshark
from extractor.features import extract_features_from_packets
from security_engine import run_nist_security_engine
from grok_analyzer import analyze_with_grok, _build_fallback_analysis, _extract_clean_json
from main import app, analyze_security

def test_full_pipeline():
    pcap_path = BASE_DIR.parent / "test_ipsec.pcap"
    assert pcap_path.exists(), f"PCAP not found: {pcap_path}"

    print(f"1. Testing TShark extraction on: {pcap_path.name} ...")
    packets, _ = extract_packets_with_tshark(str(pcap_path))
    assert len(packets) > 0, "No packets extracted"
    print(f"   [OK] Extracted {len(packets)} packets")

    print("2. Testing Feature Extraction ...")
    features = extract_features_from_packets(packets, str(pcap_path), pcap_path.name)
    assert features.get("totalPackets") == len(packets)
    print(f"   [OK] Features extracted: ESP Ratio = {features.get('espRatio')}%, IKE = {features.get('ike', {}).get('version')}")

    print("3. Testing NIST Security Rule Engine (8 categories) ...")
    nist_assessment, risk_assessment = run_nist_security_engine(features)

    expected_categories = [
        "Cryptographic Strength",
        "Configuration Compliance",
        "Security Association Parameters",
        "Key Lifetime",
        "Replay Protection",
        "Forward Secrecy (PFS) Configuration",
        "Cipher Suite Strength",
        "Metadata Exposure",
    ]

    checks = nist_assessment.get("checks", [])
    assert len(checks) == 8, f"Expected 8 checks, got {len(checks)}"

    evaluated_cats = [c["category"] for c in checks]
    for cat in expected_categories:
        assert cat in evaluated_cats, f"Missing category: {cat}"
        check = next(c for c in checks if c["category"] == cat)
        assert check["status"] in ("PASS", "WARNING", "FAIL", "NOT_OBSERVABLE"), f"Invalid status: {check['status']}"
        assert check["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), f"Invalid severity: {check['severity']}"
        assert "expected_or_policy" in check
        assert "reason" in check
        if check["status"] == "NOT_OBSERVABLE":
            assert check["observed_value"] is None, f"Expected observed_value to be None for unobservable check {cat}"
        print(f"   [OK] Category: {cat:<36} -> {check['status']:<14} ({check['severity']})")

    print("4. Testing Deterministic Risk Scorer ...")
    score = risk_assessment.get("score")
    level = risk_assessment.get("level")
    method = risk_assessment.get("method")
    factors = risk_assessment.get("factors")

    assert 0 <= score <= 100, f"Score out of range: {score}"
    assert level in ("LOW", "MODERATE", "HIGH", "CRITICAL"), f"Invalid level: {level}"
    assert method == "project_policy_v1"
    assert isinstance(factors, list)
    print(f"   [OK] Risk Score = {score}/100, Level = {level}, Factors count = {len(factors)}")

    print("5. Testing Server-Side Grok AI Fallback / Offline Handling ...")
    fallback = _build_fallback_analysis("AI analysis unavailable — NIST assessment completed.", features, risk_assessment)
    assert fallback["available"] is False
    assert "traffic_class" in fallback
    assert "confidence" in fallback
    assert "summary" in fallback
    assert "security_interpretation" in fallback
    assert len(fallback["key_observations"]) > 0
    assert len(fallback["recommendations"]) > 0
    print(f"   [OK] Fallback response verified: {fallback['summary']}")

    print("6. Testing JSON Extractor Utility ...")
    sample_wrapped = '```json\n{"traffic_class": "Video Streaming", "confidence": 0.91, "summary": "Test", "security_interpretation": "OK", "key_observations": ["obs1"], "recommendations": ["rec1"]}\n```'
    parsed = _extract_clean_json(sample_wrapped)
    assert parsed is not None
    assert parsed["traffic_class"] == "Video Streaming"
    assert parsed["confidence"] == 0.91
    print("   [OK] JSON markdown fence parsing verified")

    print("7. Testing Endpoint analyze_security() directly ...")
    endpoint_res = asyncio.run(analyze_security(None))
    assert "session_id" in endpoint_res
    assert "observed_features" in endpoint_res
    assert "nist_assessment" in endpoint_res
    assert "risk_assessment" in endpoint_res
    assert "ai_analysis" in endpoint_res
    print("   [OK] analyze_security() endpoint returned all expected top-level keys")

    print("\nALL 7 PIPELINE VERIFICATION CHECKS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_full_pipeline()
