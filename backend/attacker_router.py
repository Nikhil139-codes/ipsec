"""
Attacker Simulation Router
Provides endpoints for retrieving the latest security assessment report,
generating controlled security validation tests via Groq AI,
and analyzing potential attacker next steps and hardening guidance.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from attacker_analyzer import (
    AUTHORIZED_COMMANDS,
    analyze_attack_path,
    build_fallback_tests,
    generate_attacker_tests,
)

attacker_router = APIRouter(prefix="/api/attacker", tags=["Attacker Simulation"])


class GenerateTestsRequest(BaseModel):
    session_id: Optional[str] = None
    report_data: Optional[Dict[str, Any]] = None


class AttackPathRequest(BaseModel):
    session_id: Optional[str] = None
    test_id: Optional[str] = None
    command: str
    weakness: str
    simulated_result: Dict[str, Any]
    report_summary: Optional[Dict[str, Any]] = None


def _get_active_session_data(session_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Helper to retrieve session report from main.py's session_store."""
    from main import session_store, latest_session_id

    # 1. If explicit session_id requested
    if session_id and session_id in session_store:
        return session_store[session_id]

    # 2. Check latest_session_id
    if latest_session_id and latest_session_id in session_store:
        return session_store[latest_session_id]

    # 3. Check if any session exists in session_store
    if session_store:
        # Return most recently added session
        last_key = list(session_store.keys())[-1]
        return session_store[last_key]

    return None


@attacker_router.get("/latest-report")
async def get_latest_report() -> Dict[str, Any]:
    """
    Returns the most recently generated security assessment report.
    Returns 404 if no PCAP has been analyzed yet.
    """
    sess = _get_active_session_data()
    if not sess or not (sess.get("nist_assessment") or sess.get("features")):
        raise HTTPException(
            status_code=404,
            detail="No Security Assessment Report available. Please analyze a PCAP first.",
        )

    sid = sess.get("session_id") or sess.get("id") or "active-session"
    return {
        "session_id": sid,
        "report_id": sid,
        "name": sess.get("name", "capture.pcap"),
        "size": sess.get("size", "—"),
        "packets": sess.get("packets", 0),
        "duration": sess.get("duration", "00:00:00"),
        "capturedAt": sess.get("capturedAt", ""),
        "observed_features": sess.get("features"),
        "nist_assessment": sess.get("nist_assessment"),
        "risk_assessment": sess.get("risk_assessment"),
        "ai_analysis": sess.get("ai_analysis"),
    }


@attacker_router.post("/generate-tests")
async def generate_tests_endpoint(payload: Optional[GenerateTestsRequest] = None) -> Dict[str, Any]:
    """
    Analyzes the latest security report and uses Groq AI to generate
    controlled, authorized security validation tests.
    """
    report_data = payload.report_data if payload else None
    session_id = payload.session_id if payload else None

    # If client did not transmit report_data, resolve from backend session
    if not report_data:
        sess = _get_active_session_data(session_id)
        if not sess or not sess.get("nist_assessment"):
            raise HTTPException(
                status_code=404,
                detail="No Security Assessment Report available. Please analyze a PCAP first.",
            )
        report_data = {
            "session_id": sess.get("session_id"),
            "report_id": sess.get("session_id"),
            "observed_features": sess.get("features"),
            "nist_assessment": sess.get("nist_assessment"),
            "risk_assessment": sess.get("risk_assessment"),
            "ai_analysis": sess.get("ai_analysis"),
        }

    try:
        result = await generate_attacker_tests(report_data)
        return result
    except Exception as e:
        # Graceful degradation without exposing internal traces
        fallback = build_fallback_tests(report_data)
        return {
            "tests": fallback,
            "status": "fallback",
            "message": "AI attack-test generation is temporarily unavailable.",
        }


@attacker_router.post("/attack-path")
async def attack_path_endpoint(payload: AttackPathRequest) -> Dict[str, Any]:
    """
    Submits a validated weakness, executed simulation command, and simulated result
    to Groq AI to assess potential attacker next steps and recommended hardening.
    """
    try:
        result = await analyze_attack_path(
            command=payload.command,
            weakness=payload.weakness,
            simulated_result=payload.simulated_result,
            report_summary=payload.report_summary,
        )
        return result
    except Exception as e:
        # Structured fallback adhering to defensive guidelines
        from attacker_analyzer import build_fallback_attack_path
        return build_fallback_attack_path(
            command=payload.command,
            weakness=payload.weakness,
            simulated_result=payload.simulated_result,
        )
