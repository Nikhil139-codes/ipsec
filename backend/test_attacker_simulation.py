"""
Unit & Integration Tests for Attacker Simulation Module
Tests:
- Attacker test generation (Groq & deterministic fallback)
- Predefined simulation command constraints
- Breaking point and attack path analysis
- Backend API endpoints (/api/attacker/*)
- Absence of destructive or unauthorized commands
"""

import sys
from pathlib import Path
from typing import Dict, Any

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pytest
from fastapi.testclient import TestClient
from main import app, session_store
from attacker_analyzer import (
    AUTHORIZED_COMMANDS,
    build_fallback_tests,
    build_fallback_attack_path,
    generate_attacker_tests,
    analyze_attack_path,
)

client = TestClient(app)

SAMPLE_REPORT: Dict[str, Any] = {
    "session_id": "test-session-001",
    "report_id": "test-session-001",
    "name": "office-vpn.pcap",
    "features": {
        "espRatio": 92.4,
        "ike": {
            "version": "IKEv2",
            "key_exchange_methods": ["MODP-2048 (Group 14)"],
        },
        "cryptography": {
            "esp": {
                "encryption": ["AES-256-GCM"],
                "integrity": ["AUTH_HMAC_SHA2_256_128"],
            }
        },
    },
    "nist_assessment": {
        "overall_status": "WARNING",
        "checks": [
            {
                "category": "Forward Secrecy (PFS) Configuration",
                "status": "WARNING",
                "severity": "HIGH",
                "reason": "CHILD_SA proposal negotiation missing ephemeral Diffie-Hellman transform.",
                "observed_value": "PFS Disabled",
                "expected_or_policy": "NIST SP 800-77: PFS enabled with DH Group >= 14.",
            },
            {
                "category": "Replay Protection",
                "status": "PASS",
                "severity": "LOW",
                "reason": "Monotonically increasing ESP sequence numbers observed.",
                "observed_value": "Monotonic [1..5871]",
                "expected_or_policy": "RFC 4303: Monotonically increasing sequence numbers with anti-replay window.",
            },
            {
                "category": "Metadata Exposure",
                "status": "WARNING",
                "severity": "MEDIUM",
                "reason": "Outer IP headers, SPIs, and packet size variations visible in cleartext.",
                "observed_value": "Outer IPs: 2; SPIs: 2; Rate: 47.2 pps",
                "expected_or_policy": "NIST SP 800-77: Traffic flow confidentiality recommended.",
            },
            {
                "category": "Cryptographic Strength",
                "status": "PASS",
                "severity": "LOW",
                "reason": "AES-256-GCM (256-bit AEAD) compliant with NIST SP 800-57.",
                "observed_value": "AES-256-GCM",
                "expected_or_policy": "NIST SP 800-77: AES-128/256 GCM.",
            },
        ],
    },
    "risk_assessment": {
        "score": 42,
        "level": "HIGH",
        "method": "project_policy_v1",
        "factors": [
            {
                "category": "Forward Secrecy (PFS) Configuration",
                "points": 25,
                "reason": "PFS disabled on CHILD_SA",
            },
            {
                "category": "Metadata Exposure",
                "points": 17,
                "reason": "Outer IPs and timing exposed",
            },
        ],
    },
    "ai_analysis": {
        "traffic_class": "Web Browsing",
        "confidence": 0.88,
        "summary": "PFS weakness identified in CHILD_SA configuration.",
        "recommendations": [
            "Enforce PFS with Diffie-Hellman Group 14 or higher.",
            "Deploy packet padding to limit traffic analysis.",
        ],
    },
}


def test_authorized_commands_set():
    """Verify only authorized, safe validation commands are supported."""
    allowed = {"pfs-test", "replay-test", "cipher-test", "sa-test", "metadata-test"}
    assert set(AUTHORIZED_COMMANDS.keys()) == allowed


def test_fallback_test_generation():
    """Verify tests are generated directly from report weaknesses."""
    tests = build_fallback_tests(SAMPLE_REPORT)
    assert len(tests) >= 2

    commands = [t["command"] for t in tests]
    # PFS was a warning, so pfs-test must be prioritized
    assert "pfs-test" in commands
    for t in tests:
        assert t["command"] in AUTHORIZED_COMMANDS
        assert t["id"].startswith("TEST-")
        assert "title" in t
        assert "reason" in t
        assert "expected_result" in t
        assert "potential_impact" in t
        assert "next_step" in t


def test_fallback_attack_path():
    """Verify attack path analysis generates potential next steps and hardening advice."""
    res = build_fallback_attack_path(
        command="pfs-test",
        weakness="PFS Configuration Weakness",
        simulated_result={"status": "WEAKNESS CONFIRMED"},
    )
    assert "potential_impact" in res
    assert "attacker_next_step" in res
    assert "recommended_hardening" in res
    assert "PFS" in res["validated_weakness"]
    assert "Diffie-Hellman" in res["recommended_hardening"] or "PFS" in res["recommended_hardening"]


def test_api_latest_report_404_when_empty():
    """When no report is in session_store, /api/attacker/latest-report should return 404."""
    # Temporarily clear session store for this test
    old_sessions = dict(session_store)
    session_store.clear()
    try:
        response = client.get("/api/attacker/latest-report")
        assert response.status_code == 404
        assert "No Security Assessment Report available" in response.json()["detail"]
    finally:
        session_store.update(old_sessions)


def test_api_latest_report_and_generate_tests():
    """When a report exists, /api/attacker/latest-report and /generate-tests should succeed."""
    session_store["test-session-001"] = dict(SAMPLE_REPORT)
    try:
        # 1. Test GET /api/attacker/latest-report
        resp = client.get("/api/attacker/latest-report")
        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == "test-session-001"
        assert data["risk_assessment"]["score"] == 42
        assert data["risk_assessment"]["level"] == "HIGH"

        # 2. Test POST /api/attacker/generate-tests
        gen_resp = client.post(
            "/api/attacker/generate-tests",
            json={"session_id": "test-session-001"},
        )
        assert gen_resp.status_code == 200
        gen_data = gen_resp.json()
        assert "tests" in gen_data
        assert len(gen_data["tests"]) > 0

        # Verify all generated commands are in authorized set
        for test in gen_data["tests"]:
            assert test["command"] in AUTHORIZED_COMMANDS

        # 3. Test POST /api/attacker/attack-path
        path_resp = client.post(
            "/api/attacker/attack-path",
            json={
                "command": "pfs-test",
                "weakness": "PFS Configuration Weakness",
                "simulated_result": {
                    "command": "pfs-test",
                    "status": "WEAKNESS CONFIRMED",
                    "breaking_point": "PFS requirement not enforced",
                },
            },
        )
        assert path_resp.status_code == 200
        path_data = path_resp.json()
        assert "potential_impact" in path_data
        assert "attacker_next_step" in path_data
        assert "recommended_hardening" in path_data

    finally:
        session_store.pop("test-session-001", None)
