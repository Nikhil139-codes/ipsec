"""
NIST-Based Security Policy and Scoring Configuration
Governs evaluation criteria derived from:
- NIST SP 800-77 Rev. 1: Guide to IPsec VPNs
- NIST SP 800-57 Part 1 Rev. 5: Recommendation for Key Management

IMPORTANT NOTICE:
This software applies security guidance derived from NIST publications.
It does not claim official NIST certification or formal accreditation.
"""

from typing import Dict, Tuple

POLICY_METHOD = "project_policy_v1"

# Risk score brackets
RISK_LEVEL_THRESHOLDS: Dict[str, Tuple[int, int]] = {
    "LOW": (0, 19),
    "MODERATE": (20, 39),
    "HIGH": (40, 69),
    "CRITICAL": (70, 100),
}

def get_risk_level(score: int) -> str:
    clamped = max(0, min(100, score))
    for level, (low, high) in RISK_LEVEL_THRESHOLDS.items():



        
        if low <= clamped <= high:
            return level
    return "CRITICAL" if clamped >= 70 else "LOW"


# NIST Guidance References and Threshold Constants
NIST_REFERENCES = {
    "crypto": "NIST SP 800-77 Rev. 1 Section 3.3 & NIST SP 800-57 Part 1 Rev. 5 Table 2 (Cryptographic Algorithms & Key Lengths)",
    "config": "NIST SP 800-77 Rev. 1 Section 3.2 (IKE Protocol Architecture) & Section 3.4 (IPsec Protocol Configurations)",
    "sa": "NIST SP 800-77 Rev. 1 Section 3.1 (Security Associations) & RFC 4301 / RFC 7296",
    "key_lifetime": "NIST SP 800-77 Rev. 1 Section 3.2.4 & SP 800-57 Part 1 Rev. 5 (Cryptoperiod Limits)",
    "replay": "NIST SP 800-77 Rev. 1 Section 3.1.3 & RFC 4303 Section 3.4.3 (Anti-Replay Protection)",
    "pfs": "NIST SP 800-77 Rev. 1 Section 3.2.3 (Perfect Forward Secrecy in CHILD_SA) & SP 800-56A",
    "cipher_suite": "NIST SP 800-77 Rev. 1 Section 3.3.1 (Approved IPsec Cipher Suites) & CNSA Suite",
    "metadata": "NIST SP 800-77 Rev. 1 Section 3.1.1 (Traffic Analysis & Metadata Protection in Encapsulated Packets)",
}

# Algorithms categorized per NIST SP 800-77 Rev. 1 and SP 800-57 Part 1 Rev. 5
APPROVED_ENCRYPTION_ALGORITHMS = {
    "AES-256-GCM": {"bits": 256, "aead": True, "strength": "HIGH"},
    "AES-128-GCM": {"bits": 128, "aead": True, "strength": "HIGH"},
    "AES-256-CBC": {"bits": 256, "aead": False, "strength": "HIGH"},
    "AES-192-CBC": {"bits": 192, "aead": False, "strength": "HIGH"},
    "AES-128-CBC": {"bits": 128, "aead": False, "strength": "MEDIUM"},
    "AES-256-CTR": {"bits": 256, "aead": False, "strength": "HIGH"},
    "AES-128-CTR": {"bits": 128, "aead": False, "strength": "MEDIUM"},
    "AES-CCM-8": {"bits": 128, "aead": True, "strength": "MEDIUM"},
    "AES-CCM-12": {"bits": 128, "aead": True, "strength": "MEDIUM"},
    "ChaCha20-Poly1305": {"bits": 256, "aead": True, "strength": "HIGH"},
}

DEPRECATED_ENCRYPTION_ALGORITHMS = {
    "3DES-CBC": {"reason": "3DES is disallowed/deprecated after 2023 per NIST SP 800-131A Rev. 2", "severity": "HIGH"},
    "DES": {"reason": "DES provides insufficient security strength (56 bits); prohibited by NIST", "severity": "CRITICAL"},
    "DES-IV64": {"reason": "Legacy DES is obsolete and vulnerable to brute-force attacks", "severity": "CRITICAL"},
    "RC4": {"reason": "RC4 is completely insecure and prohibited across all protocols", "severity": "CRITICAL"},
    "NULL": {"reason": "NULL encryption provides zero confidentiality protection", "severity": "CRITICAL"},
}

APPROVED_INTEGRITY_ALGORITHMS = {
    "AUTH_HMAC_SHA2_256_128": {"bits": 256, "strength": "HIGH"},
    "AUTH_HMAC_SHA2_384_192": {"bits": 384, "strength": "HIGH"},
    "AUTH_HMAC_SHA2_512_256": {"bits": 512, "strength": "HIGH"},
    "PRF_HMAC_SHA2_256": {"bits": 256, "strength": "HIGH"},
    "PRF_HMAC_SHA2_384": {"bits": 384, "strength": "HIGH"},
    "PRF_HMAC_SHA2_512": {"bits": 512, "strength": "HIGH"},
    "AUTH_AES_XCBC_96": {"bits": 128, "strength": "MEDIUM"},
}

DEPRECATED_INTEGRITY_ALGORITHMS = {
    "AUTH_HMAC_MD5_96": {"reason": "MD5 suffers from severe collision vulnerabilities; disallowed by NIST", "severity": "HIGH"},
    "AUTH_HMAC_SHA1_96": {"reason": "SHA-1 is deprecated by NIST per SP 800-131A due to collision risks", "severity": "MEDIUM"},
    "AUTH_DES_MAC": {"reason": "DES-MAC relies on obsolete 56-bit DES cryptography", "severity": "CRITICAL"},
}

APPROVED_DH_GROUPS = {
    "14": {"name": "MODP-2048 (Group 14)", "bits": 112, "nist_status": "ACCEPTABLE"},
    "15": {"name": "MODP-3072 (Group 15)", "bits": 128, "nist_status": "RECOMMENDED"},
    "16": {"name": "MODP-4096 (Group 16)", "bits": 128, "nist_status": "RECOMMENDED"},
    "19": {"name": "ECP-256 (Group 19)", "bits": 128, "nist_status": "RECOMMENDED"},
    "20": {"name": "ECP-384 (Group 20)", "bits": 192, "nist_status": "RECOMMENDED"},
    "21": {"name": "ECP-521 (Group 21)", "bits": 256, "nist_status": "RECOMMENDED"},
    "31": {"name": "Curve25519 (Group 31)", "bits": 128, "nist_status": "RECOMMENDED"},
}

DEPRECATED_DH_GROUPS = {
    "1": {"name": "MODP-768 (Group 1)", "reason": "768-bit MODP offers < 80-bit security; easily breakable", "severity": "CRITICAL"},
    "2": {"name": "MODP-1024 (Group 2)", "reason": "1024-bit MODP offers < 80-bit security; deprecated by NIST since 2013", "severity": "HIGH"},
    "5": {"name": "MODP-1536 (Group 5)", "reason": "1536-bit MODP offers < 112-bit security; deprecated by NIST", "severity": "HIGH"},
}
