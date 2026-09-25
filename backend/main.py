import os
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from extractor.features import extract_features_from_packets, format_bytes
from extractor.tshark import extract_packets_with_tshark, find_tshark_binary, get_tshark_version
from groq_analyzer import analyze_with_grok, analyze_with_groq
from security_engine import run_nist_security_engine


BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

from testbed_router import testbed_router

app = FastAPI(
    title="IPsec Traffic Security Analyzer API",
    description="Backend service for PCAP ingestion, TShark packet dissection, NIST-based rule evaluation, and AI threat analysis.",
    version="1.0.0",
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include IPsec Testbed Router
app.include_router(testbed_router)

# In-memory session registry (session_id -> metadata, cached packets, and extracted features)
session_store: Dict[str, Dict[str, Any]] = {}
latest_session_id: Optional[str] = None

from attacker_router import attacker_router
app.include_router(attacker_router)



class FeaturesRequest(BaseModel):
    session_id: Optional[str] = None


class SecurityAnalyzeRequest(BaseModel):
    session_id: Optional[str] = None


class RagChatRequest(BaseModel):
    report_id: Optional[str] = None
    session_id: Optional[str] = None
    question: str


@app.get("/health")
def health_check() -> Dict[str, Any]:
    binary = find_tshark_binary()
    version = get_tshark_version()
    return {
        "status": "operational",
        "tshark_available": binary is not None,
        "tshark_path": binary,
        "tshark_version": version,
        "active_sessions": len(session_store),
    }


@app.post("/pcap/upload")
async def upload_pcap(file: UploadFile = File(...)) -> Dict[str, Any]:
    global latest_session_id
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required.")

    filename = file.filename
    lower_name = filename.lower()
    if not (lower_name.endswith(".pcap") or lower_name.endswith(".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Unsupported file format. Please upload a valid .pcap or .pcapng file.",
        )

    session_id = str(uuid.uuid4())
    safe_name = f"{session_id}_{Path(filename).name}"
    file_path = UPLOADS_DIR / safe_name

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to store uploaded capture file: {e}")

    file_size = os.path.getsize(file_path)

    # Initial packet parsing via TShark to extract basic capture info
    packets: List[Dict[str, Any]] = []
    tshark_err = None
    try:
        packets, _ = extract_packets_with_tshark(str(file_path))
    except Exception as e:
        tshark_err = str(e)

    packet_count = len(packets)
    duration_str = "00:00:00"
    if packets:
        timestamps = [p["time_epoch"] for p in packets if p.get("time_epoch") is not None]
        if len(timestamps) >= 2:
            dur_sec = max(0.0, max(timestamps) - min(timestamps))
            hrs = int(dur_sec // 3600)
            mins = int((dur_sec % 3600) // 60)
            secs = int(dur_sec % 60)
            duration_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

    captured_at = datetime.now(timezone.utc).strftime("%b %d, %Y, %I:%M %p UTC")

    # Extract features immediately and dynamically for this exact uploaded PCAP
    features = extract_features_from_packets(
        packets=packets,
        file_path=str(file_path),
        original_filename=filename,
    )
    features["session_id"] = session_id
    features["capture_name"] = filename
    features["capture_size"] = format_bytes(file_size)

    # Run deterministic NIST security engine & risk score immediately
    nist_assessment, risk_assessment = run_nist_security_engine(features)

    session_data = {
        "session_id": session_id,
        "id": session_id,
        "name": filename,
        "file_path": str(file_path),
        "size": format_bytes(file_size),
        "size_bytes": file_size,
        "packets": packet_count,
        "duration": duration_str,
        "capturedAt": captured_at,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "cached_packets": packets if packets else None,
        "features": features,
        "nist_assessment": nist_assessment,
        "risk_assessment": risk_assessment,
        "tshark_error": tshark_err,
    }

    session_store[session_id] = session_data
    latest_session_id = session_id

    # Return structure matching frontend PCAPInfo + session_id + fresh extraction
    return {
        "session_id": session_id,
        "id": session_id,
        "name": filename,
        "size": format_bytes(file_size),
        "packets": packet_count,
        "duration": duration_str,
        "capturedAt": captured_at,
        "features": features,
        "nist_assessment": nist_assessment,
        "risk_assessment": risk_assessment,
    }


def ensure_active_session(session_id: Optional[str] = None) -> Optional[str]:
    global latest_session_id
    if session_id and str(session_id).strip():
        sid = str(session_id).strip()
        if sid in session_store:
            return sid
    if latest_session_id and latest_session_id in session_store:
        return latest_session_id

    # Fallback to existing PCAP in uploads directory
    uploaded_files = sorted(
        [p for p in UPLOADS_DIR.iterdir() if p.is_file() and p.suffix.lower() in ('.pcap', '.pcapng')],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    candidate_path = None
    original_name = None
    if uploaded_files:
        candidate_path = uploaded_files[0]
        original_name = candidate_path.name.split('_', 1)[-1] if '_' in candidate_path.name else candidate_path.name
    else:
        # Check workspace root for test_ipsec.pcap
        root_test = BASE_DIR.parent / "test_ipsec.pcap"
        if root_test.exists():
            candidate_path = root_test
            original_name = "test_ipsec.pcap"

    if candidate_path and candidate_path.exists():
        fallback_id = "default-session"
        try:
            packets, _ = extract_packets_with_tshark(str(candidate_path))
        except Exception:
            packets = []
        file_size = candidate_path.stat().st_size
        feat = extract_features_from_packets(packets, str(candidate_path), original_name)
        feat["session_id"] = fallback_id
        feat["capture_name"] = original_name
        feat["capture_size"] = format_bytes(file_size)
        nist, risk = run_nist_security_engine(feat)

        session_data = {
            "session_id": fallback_id,
            "id": fallback_id,
            "name": original_name,
            "file_path": str(candidate_path),
            "size": format_bytes(file_size),
            "size_bytes": file_size,
            "packets": len(packets),
            "duration": "00:00:00",
            "capturedAt": datetime.now(timezone.utc).strftime("%b %d, %Y, %I:%M %p UTC"),
            "cached_packets": packets,
            "features": feat,
            "nist_assessment": nist,
            "risk_assessment": risk,
        }
        session_store[fallback_id] = session_data
        latest_session_id = fallback_id
        return fallback_id

    return None


@app.post("/analysis/features")
async def extract_features(payload: Optional[FeaturesRequest] = None) -> Dict[str, Any]:
    global latest_session_id
    req_id = payload.session_id if payload else None
    target_id = ensure_active_session(req_id)
    if not target_id or target_id not in session_store:
        raise HTTPException(
            status_code=404,
            detail="No capture session found. Please upload a PCAP file first via /pcap/upload.",
        )

    session = session_store[target_id]
    file_path = session["file_path"]

    # Return cached features if already extracted for this session
    if session.get("features"):
        return session["features"]

    # Use cached parsed packets if available, otherwise run TShark
    packets = session.get("cached_packets")
    if packets is None:
        try:
            packets, _ = extract_packets_with_tshark(file_path)
            session["cached_packets"] = packets
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"TShark feature extraction failed: {str(e)}",
            )

    features = extract_features_from_packets(
        packets=packets,
        file_path=file_path,
        original_filename=session["name"],
    )

    # Attach session metadata to response
    features["session_id"] = target_id
    features["capture_name"] = session["name"]
    features["capture_size"] = session["size"]
    session["features"] = features
    return features


@app.get("/pcap/packets")
async def get_packets(
    session_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=1000),
) -> List[Dict[str, Any]]:
    global latest_session_id
    target_id = ensure_active_session(session_id)
    if not target_id or target_id not in session_store:
        raise HTTPException(status_code=404, detail="No active PCAP session found.")

    session = session_store[target_id]
    packets = session.get("cached_packets")
    if packets is None:
        try:
            packets, _ = extract_packets_with_tshark(session["file_path"])
            session["cached_packets"] = packets
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"TShark packet inspection failed: {e}")

    result: List[Dict[str, Any]] = []
    for p in packets[:limit]:
        proto = p.get("protocol") or str(p.get("ip_proto") or "IP")
        is_encrypted = proto == "ESP" or bool(p.get("esp_spi"))
        result.append({
            "no": p.get("frame_number", 0),
            "time": f"{p.get('time_epoch', 0.0):.6f}" if p.get("time_epoch") is not None else "0.000000",
            "source": p.get("src_ip") or "—",
            "destination": p.get("dst_ip") or "—",
            "protocol": proto,
            "length": p.get("frame_len", 0),
            "info": p.get("info") or ("Encrypted payload data" if is_encrypted else f"{proto} packet"),
            "encrypted": is_encrypted,
        })
    return result


@app.post("/api/security/analyze")
@app.post("/security/analyze")
async def analyze_security(payload: Optional[SecurityAnalyzeRequest] = None) -> Dict[str, Any]:
    global latest_session_id
    req_id = payload.session_id if payload else None
    target_id = ensure_active_session(req_id)
    if not target_id or target_id not in session_store:
        raise HTTPException(
            status_code=404,
            detail="No capture session found. Please upload a PCAP file first via /pcap/upload.",
        )

    session = session_store[target_id]
    file_path = session["file_path"]

    # Use cached features if available
    features = session.get("features")
    if not features:
        packets = session.get("cached_packets")
        if packets is None:
            try:
                packets, _ = extract_packets_with_tshark(file_path)
                session["cached_packets"] = packets
            except Exception as e:
                raise HTTPException(
                    status_code=500,
                    detail=f"TShark packet inspection failed: {str(e)}",
                )

        features = extract_features_from_packets(
            packets=packets,
            file_path=file_path,
            original_filename=session["name"],
        )
        features["session_id"] = target_id
        features["capture_name"] = session["name"]
        features["capture_size"] = session["size"]
        session["features"] = features

    # 1. NIST rule engine & Deterministic Risk Score
    nist_assessment, risk_assessment = run_nist_security_engine(features)
    session["nist_assessment"] = nist_assessment
    session["risk_assessment"] = risk_assessment

    # 2. Server-side AI Analysis (xAI Grok / Groq API with graceful fallback)
    ai_analysis = await analyze_with_grok(
        features=features,
        nist_assessment=nist_assessment,
        risk_assessment=risk_assessment,
    )

    result_payload = {
        "session_id": target_id,
        "report_id": target_id,
        "observed_features": features,
        "nist_assessment": nist_assessment,
        "risk_assessment": risk_assessment,
        "ai_analysis": ai_analysis,
        "name": session.get("name", "capture.pcap"),
        "size": session.get("size", "—"),
        "packets": session.get("packets", 0),
        "duration": session.get("duration", "00:00:00"),
    }

    # Automatically ingest freshly generated report into RAG vector store
    try:
        from rag_engine import rag_vector_store
        rag_vector_store.ingest_report(result_payload, report_id=target_id, session_id=target_id)
    except Exception as e:
        print(f"[RAG] Warning: Ingestion failed in analyze_security: {e}")

    return result_payload


@app.post("/api/rag/report-chat")
async def rag_report_chat(payload: RagChatRequest) -> Dict[str, Any]:
    """
    RAG Chat endpoint strictly answering questions using the active security assessment report.
    Automatically retrieves grounded semantic chunks and generates answers using Groq.
    """
    if not payload.question or not payload.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    from rag_engine import answer_report_question, rag_vector_store

    target_id = payload.report_id or payload.session_id or rag_vector_store.latest_report_id
    if not target_id:
        target_id = ensure_active_session()

    # If this session hasn't been ingested into RAG yet (e.g. from prior runs), auto-ingest now
    if target_id and target_id in session_store and target_id not in rag_vector_store.report_chunks:
        sess = session_store[target_id]
        if sess.get("features") or sess.get("nist_assessment"):
            try:
                rag_vector_store.ingest_report(sess, report_id=target_id, session_id=target_id)
            except Exception as e:
                print(f"[RAG] Auto-ingest fallback warning: {e}")

    result = await answer_report_question(
        question=payload.question.strip(),
        report_id=target_id,
        session_id=payload.session_id or target_id,
    )
    return result



@app.post("/analysis/predict")
async def run_traffic_prediction(payload: Optional[SecurityAnalyzeRequest] = None) -> Dict[str, Any]:
    global latest_session_id
    req_id = payload.session_id if payload else None
    target_id = ensure_active_session(req_id)
    if not target_id or target_id not in session_store:
        raise HTTPException(status_code=404, detail="No active PCAP session found.")

    session = session_store[target_id]
    features = session.get("features")
    if not features:
        packets = session.get("cached_packets")
        if packets is None:
            try:
                packets, _ = extract_packets_with_tshark(session["file_path"])
                session["cached_packets"] = packets
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"TShark inspection failed: {e}")

        features = extract_features_from_packets(packets, session["file_path"], session["name"])
        features["session_id"] = target_id
        features["capture_name"] = session["name"]
        features["capture_size"] = session["size"]
        session["features"] = features

    esp_ratio = features.get("espRatio", 0.0)
    has_ike = features.get("ike", {}).get("detected", False)
    cleartext_ratio = features.get("cleartextRatio", 0.0)

    is_vpn = esp_ratio >= 50.0 or has_ike
    if not is_vpn and cleartext_ratio >= 90.0:
        vpn_prob = 1.2
        reg_prob = 98.8
        label = "Regular Traffic"
        explanation = (
            f"Observable network telemetry shows {cleartext_ratio}% unencrypted plain-text traffic "
            f"with zero active IPsec encapsulation."
        )
    else:
        confidence = min(99.4, max(85.0, 70.0 + (esp_ratio * 0.28))) if is_vpn else 88.0
        vpn_prob = round(confidence, 1) if is_vpn else round(100.0 - confidence, 1)
        reg_prob = round(100.0 - vpn_prob, 1)
        label = "VPN Encrypted Traffic" if is_vpn else "Regular Traffic"
        explanation = (
            f"Observable indicators ({esp_ratio}% ESP encapsulation, "
            f"{'IKE handshake detected' if has_ike else 'UDP-encapsulated flow'}) "
            f"indicate active IPsec tunnel operation."
        )

    return {
        "label": label,
        "confidence": vpn_prob if is_vpn else reg_prob,
        "probabilities": [
            {"label": "VPN Encrypted Traffic", "value": vpn_prob},
            {"label": "Regular Traffic", "value": reg_prob},
        ],
        "explanation": explanation,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
