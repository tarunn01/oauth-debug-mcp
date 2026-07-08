"""OAuth 2.0 / PKCE helpers and authorization-flow analysis.

Day 1 scaffold: PKCE generation/verification and auth-URL parsing are
implemented. Deeper flow analysis (token endpoint round-trips, discovery
document fetches) is stubbed for later.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlparse
import httpx


def generate_pkce_pair(length: int = 64) -> dict[str, str]:
    """Generate a PKCE code_verifier / code_challenge pair (S256).

    RFC 7636: verifier is 43-128 chars of unreserved characters; the S256
    challenge is base64url(sha256(verifier)) with padding stripped.
    """
    if not 43 <= length <= 128:
        raise ValueError("PKCE code_verifier length must be between 43 and 128")

    verifier = secrets.token_urlsafe(length)[:length]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    return {
        "code_verifier": verifier,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> dict[str, Any]:
    """Check that a code_verifier matches a code_challenge."""
    method = method.upper()
    if method == "PLAIN":
        computed = code_verifier
    elif method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    else:
        raise ValueError(f"unsupported PKCE method: {method!r}")

    return {
        "matches": secrets.compare_digest(computed, code_challenge),
        "method": method,
        "computed_challenge": computed,
    }

def analyze_authorization_url(url: str) -> dict[str, Any]:
    """Parse an OAuth authorization request URL and flag common issues."""
    parsed = urlparse(url)
    params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(parsed.query).items()}

    findings: list[str] = []
    response_type = params.get("response_type")
    if response_type == "token":
        findings.append("uses the implicit flow (response_type=token) — deprecated; prefer code + PKCE")
    if "code_challenge" not in params and response_type == "code":
        findings.append("authorization-code flow without PKCE (no code_challenge)")
    if params.get("code_challenge_method") == "plain":
        findings.append("PKCE method is 'plain' — prefer S256")
    if "state" not in params:
        findings.append("no 'state' parameter — CSRF protection missing")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        findings.append("authorization endpoint is not HTTPS")

    return {
        "endpoint": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
        "params": params,
        "findings": findings,
    }


def fetch_discovery_document(issuer: str, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch and summarize an OIDC provider's discovery document.

    Given an issuer base URL (e.g. https://accounts.google.com), fetches
    ``{issuer}/.well-known/openid-configuration`` and pulls out the endpoints
    and capabilities that matter when debugging a flow. Network/HTTP errors are
    returned as data (``ok: False``) rather than raised, so the tool degrades
    gracefully.
    """
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        response = httpx.get(discovery_url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        doc = response.json()
    except httpx.HTTPError as exc:
        return {"ok": False, "discovery_url": discovery_url, "error": str(exc)}

    findings: list[str] = []
    if "code" not in (doc.get("response_types_supported") or []):
        findings.append("does not advertise the authorization-code response type")
    if "S256" not in (doc.get("code_challenge_methods_supported") or []):
        findings.append("does not advertise PKCE S256 support")

    return {
        "ok": True,
        "discovery_url": discovery_url,
        "issuer": doc.get("issuer"),
        "authorization_endpoint": doc.get("authorization_endpoint"),
        "token_endpoint": doc.get("token_endpoint"),
        "userinfo_endpoint": doc.get("userinfo_endpoint"),
        "jwks_uri": doc.get("jwks_uri"),
        "scopes_supported": doc.get("scopes_supported"),
        "response_types_supported": doc.get("response_types_supported"),
        "grant_types_supported": doc.get("grant_types_supported"),
        "code_challenge_methods_supported": doc.get("code_challenge_methods_supported"),
        "findings": findings,
    }
