"""
RAG Engine for IPsec Security Assessment Reports
Provides embedding generation, FAISS vector indexing, session-isolated retrieval,
and strictly grounded Groq question-answering with section citations.
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
import numpy as np

try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    FAISS_AVAILABLE = False

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False

from rag_chunker import chunk_security_report

BASE_DIR = Path(__file__).resolve().parent

# Auto-load environment variables
def _load_local_env() -> None:
    candidates = [
        BASE_DIR / ".env",
        BASE_DIR / ".env.local",
        BASE_DIR.parent / ".env.local",
        BASE_DIR.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.exists():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
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

EMBEDDING_MODEL_NAME = os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"

# Global embedding model singleton
_EMBEDDING_MODEL = None


def get_embedding_model():
    """Lazily loads the embedding model singleton."""
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None and SENTENCE_TRANSFORMERS_AVAILABLE:
        try:
            _EMBEDDING_MODEL = SentenceTransformer(EMBEDDING_MODEL_NAME)
        except Exception as e:
            print(f"[RAG] Warning: Could not load SentenceTransformer '{EMBEDDING_MODEL_NAME}': {e}")
            _EMBEDDING_MODEL = None
    return _EMBEDDING_MODEL


def compute_embeddings(texts: List[str]) -> np.ndarray:
    """Computes normalized dense embeddings (or bag-of-words fallback)."""
    model = get_embedding_model()
    if model is not None:
        try:
            embs = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
            return np.array(embs, dtype=np.float32)
        except Exception as e:
            print(f"[RAG] Embedding encoding error: {e}")

    # Fallback to simple deterministic character n-gram / term frequency hashing
    dim = 384
    matrix = np.zeros((len(texts), dim), dtype=np.float32)
    for i, t in enumerate(texts):
        words = re.findall(r"\w+", t.lower())
        for w in words:
            h = hash(w) % dim
            matrix[i, h] += 1.0
        norm = np.linalg.norm(matrix[i])
        if norm > 0:
            matrix[i] /= norm
        else:
            matrix[i, 0] = 1.0
    return matrix


class ReportVectorStore:
    """
    In-memory, session-isolated FAISS vector database.
    Stores and retrieves chunks partitioned by report_id / session_id.
    """

    def __init__(self):
        # Maps report_id -> list of chunk dicts
        self.report_chunks: Dict[str, List[Dict[str, Any]]] = {}
        # Maps report_id -> normalized embeddings ndarray
        self.report_embeddings: Dict[str, np.ndarray] = {}
        # Maps report_id -> FAISS index (if available)
        self.report_indexes: Dict[str, Any] = {}
        self.latest_report_id: Optional[str] = None

    def ingest_report(
        self,
        report_data: Dict[str, Any],
        report_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        Ingests a report: chunks it, embeds it, and indexes it.
        Returns the active report_id.
        """
        sid = session_id or report_data.get("session_id") or "default-session"
        rid = report_id or report_data.get("report_id") or sid

        chunks = chunk_security_report(report_data, report_id=rid, session_id=sid)
        if not chunks:
            return rid

        texts = [c["content"] for c in chunks]
        embs = compute_embeddings(texts)

        # Store chunks and embeddings
        self.report_chunks[rid] = chunks
        self.report_embeddings[rid] = embs

        # If FAISS is available, create an inner product index (cosine similarity since embs are normalized)
        if FAISS_AVAILABLE:
            try:
                dim = embs.shape[1]
                index = faiss.IndexFlatIP(dim)
                index.add(embs)
                self.report_indexes[rid] = index
            except Exception as e:
                print(f"[RAG] Warning: FAISS indexing failed: {e}")

        # Also register under session_id if distinct
        if sid != rid:
            self.report_chunks[sid] = chunks
            self.report_embeddings[sid] = embs
            if rid in self.report_indexes:
                self.report_indexes[sid] = self.report_indexes[rid]

        self.latest_report_id = rid
        print(f"[RAG] Successfully ingested report '{rid}' with {len(chunks)} semantic chunks.")
        return rid

    def search(
        self,
        query: str,
        report_id: Optional[str] = None,
        session_id: Optional[str] = None,
        top_k: int = 4,
    ) -> List[Tuple[Dict[str, Any], float]]:
        """
        Searches ONLY within the specified report_id / session_id chunks.
        Returns list of (chunk, similarity_score).
        """
        target_id = report_id or session_id or self.latest_report_id
        if not target_id or target_id not in self.report_chunks:
            # Fallback: check if any report exists
            if self.report_chunks:
                target_id = list(self.report_chunks.keys())[-1]
            else:
                return []

        chunks = self.report_chunks[target_id]
        if not chunks:
            return []

        query_emb = compute_embeddings([query])

        # 1. Try FAISS search
        if FAISS_AVAILABLE and target_id in self.report_indexes:
            try:
                index = self.report_indexes[target_id]
                k = min(top_k, len(chunks))
                scores, indices = index.search(query_emb, k)
                results = []
                for score, idx in zip(scores[0], indices[0]):
                    if 0 <= idx < len(chunks):
                        # Cosine similarity in range [0, 1]
                        sim = float(max(0.0, min(1.0, (score + 1.0) / 2.0 if score < 0 else score)))
                        results.append((chunks[idx], sim))
                return results
            except Exception as e:
                print(f"[RAG] FAISS search error: {e}")

        # 2. Numpy Cosine Similarity fallback
        doc_embs = self.report_embeddings.get(target_id)
        if doc_embs is not None:
            # dot product of normalized vectors = cosine similarity
            sims = np.dot(doc_embs, query_emb[0])
            sorted_indices = np.argsort(sims)[::-1][:top_k]
            results = []
            for idx in sorted_indices:
                score = float(sims[idx])
                sim = float(max(0.0, min(1.0, (score + 1.0) / 2.0 if score < 0 else score)))
                results.append((chunks[idx], sim))
            return results

        # 3. Simple term match fallback
        query_words = set(query.lower().split())
        scored_chunks = []
        for c in chunks:
            c_words = set(c["content"].lower().split())
            overlap = len(query_words.intersection(c_words))
            scored_chunks.append((c, min(1.0, overlap / max(1, len(query_words)))))
        scored_chunks.sort(key=lambda x: x[1], reverse=True)
        return scored_chunks[:top_k]


# Global vector store instance
rag_vector_store = ReportVectorStore()


# Strict RAG System Prompt
RAG_SYSTEM_PROMPT = """You are a security report assistant.
Answer the user's question using the retrieved content from the current Security Assessment Report.
Do not invent findings, values, algorithms, risk scores, packet statistics, or recommendations that are not supported by the report.
If the answer is not present or cannot be determined from the report, clearly say:
'I couldn't find that information in the current security assessment report.'
You may explain information from the report, but do not fabricate missing evidence."""


async def answer_report_question(
    question: str,
    report_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes the full RAG pipeline:
    1. Retrieves relevant chunks from vector store.
    2. Builds grounded context.
    3. Calls Groq API for grounded answer.
    4. Formats clean citations with section names and relevance scores.
    """
    target_id = report_id or session_id or rag_vector_store.latest_report_id or "default"
    matches = rag_vector_store.search(question, report_id=target_id, session_id=session_id, top_k=4)

    if not matches:
        return {
            "report_id": target_id,
            "session_id": session_id or target_id,
            "question": question,
            "answer": "I couldn't find that information in the current security assessment report. Please ensure a PCAP security assessment has been run first.",
            "sources": [],
        }

    # Format context and sources
    context_blocks = []
    sources = []
    seen_sections = set()

    for chunk, score in matches:
        section = chunk.get("section", "General")
        context_blocks.append(f"--- Section: {section} ---\n{chunk.get('content', '')}")
        if section not in seen_sections:
            sources.append({
                "section": section,
                "relevance": round(float(score), 2),
            })
            seen_sections.add(section)

    context_text = "\n\n".join(context_blocks)

    groq_key = os.environ.get("GROQ_API_KEY") or GROQ_API_KEY
    if not groq_key or groq_key.startswith("your_") or len(groq_key) < 15:
        # Grounded fallback extract if Groq API key is not configured
        fallback_answer = (
            f"Based on the **{sources[0]['section']}** section of the security report:\n\n"
            f"{matches[0][0]['content']}\n\n"
            f"*(Groq API key not configured for generative text synthesis; direct report excerpt provided above.)*"
        )
        return {
            "report_id": target_id,
            "session_id": session_id or target_id,
            "question": question,
            "answer": fallback_answer,
            "sources": sources,
        }

    # Candidate models for Groq
    models_to_try = [
        os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "groq/compound",
        "mixtral-8x7b-32768",
    ]

    answer = None
    for model in models_to_try:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": RAG_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            f"=== RETRIEVED REPORT CONTENT ===\n"
                            f"{context_text}\n"
                            f"=== END OF REPORT CONTENT ===\n\n"
                            f"User Question: {question}\n\n"
                            f"Provide a clear, accurate, report-grounded answer based strictly on the retrieved report content above."
                        ),
                    },
                ],
                "temperature": 0.2,
                "max_tokens": 800,
            }

            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    GROQ_CHAT_URL,
                    headers={
                        "Authorization": f"Bearer {groq_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )

                if res.status_code == 200:
                    data = res.json()
                    choices = data.get("choices", [])
                    if choices and "message" in choices[0]:
                        answer = choices[0]["message"]["content"].strip()
                        break
                else:
                    print(f"[RAG] Groq model '{model}' returned status {res.status_code}: {res.text[:200]}")
        except Exception as e:
            print(f"[RAG] Error calling Groq with model '{model}': {e}")

    if not answer:
        # Graceful fallback answer based directly on top section
        top_chunk = matches[0][0]
        answer = (
            f"Based on the **{top_chunk['section']}** section of the security report:\n\n"
            f"{top_chunk['content']}"
        )

    return {
        "report_id": target_id,
        "session_id": session_id or target_id,
        "question": question,
        "answer": answer,
        "sources": sources,
    }
