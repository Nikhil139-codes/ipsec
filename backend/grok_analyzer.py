"""
Compatibility bridge redirecting to groq_analyzer.
"""
from groq_analyzer import (
    analyze_with_groq,
    analyze_with_grok,
    _build_fallback_analysis,
    _extract_clean_json,
    GROQ_SYSTEM_PROMPT,
    ALLOWED_TRAFFIC_CLASSES,
)

__all__ = [
    "analyze_with_groq",
    "analyze_with_grok",
    "_build_fallback_analysis",
    "_extract_clean_json",
    "GROQ_SYSTEM_PROMPT",
    "ALLOWED_TRAFFIC_CLASSES",
]
