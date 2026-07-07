"""JWT decode / inspect / verify helpers.

Day 1 scaffold: decoding + claim inspection are implemented so the tools are
useful immediately. Signature verification against a JWKS endpoint is stubbed
and gets fleshed out later in the week.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any

import jwt
from jwt import InvalidTokenError


def _b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, tolerating missing padding."""
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"segment is not valid base64url: {exc}") from exc


def decode_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT WITHOUT verifying its signature.

    Returns the header, payload, and a human-readable reading of the standard
    time-based claims (exp / iat / nbf). Never trust an unverified token for
    authz decisions — this is purely for debugging what a token *claims*.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"expected a 3-part JWT (header.payload.signature), got {len(parts)} part(s)"
        )

    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))

    return {
        "header": header,
        "payload": payload,
        "signature_present": bool(parts[2]),
        "claims_analysis": analyze_claims(payload),
    }


def analyze_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """Interpret the standard registered time claims relative to 'now'."""
    now = int(time.time())
    findings: list[str] = []

    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if now >= exp:
            findings.append(f"EXPIRED {now - int(exp)}s ago (exp={int(exp)})")
        else:
            findings.append(f"valid for another {int(exp) - now}s")

    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf:
        findings.append(f"not yet valid (nbf={int(nbf)}, {int(nbf) - now}s in the future)")

    iat = payload.get("iat")
    if isinstance(iat, (int, float)) and iat > now + 60:
        findings.append(f"issued in the future (iat={int(iat)}) — check clock skew")

    return {
        "now": now,
        "expired": bool(isinstance(exp, (int, float)) and now >= exp),
        "notes": findings,
    }


def verify_jwt(token: str, key: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    """Verify a JWT's signature against a provided key/secret.

    `key` is an HMAC secret (HS*) or a PEM public key (RS*/ES*). JWKS-URL
    resolution is a later-day enhancement.
    """
    algorithms = algorithms or ["RS256", "HS256", "ES256"]
    try:
        payload = jwt.decode(token, key, algorithms=algorithms)
        return {"valid": True, "payload": payload}
    except InvalidTokenError as exc:
        return {"valid": False, "error": str(exc)}


# TODO(week1): resolve signing key from an OIDC issuer's JWKS endpoint (httpx).
def verify_jwt_with_jwks(token: str, jwks_url: str) -> dict[str, Any]:  # pragma: no cover
    raise NotImplementedError("JWKS-based verification lands later this week")
