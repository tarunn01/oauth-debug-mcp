

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

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


def build_authorization_url(
    authorization_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str = "openid email profile",
    state: str | None = None,
    code_challenge: str | None = None,
    code_challenge_method: str = "S256",
) -> dict[str, Any]:
    """Construct an OAuth 2.0 authorization-code request URL.

    This is the URL you send a user's browser to in order to start login. For
    public clients, pass a PKCE ``code_challenge``. A random ``state`` is
    generated if you don't supply one (CSRF protection).
    """
    state = state or secrets.token_urlsafe(16)
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method

    return {
        "authorization_url": authorization_endpoint + "?" + urlencode(params),
        "params": params,
        "state": state,
    }


def simulate_auth_code_flow(
    issuer: str,
    client_id: str = "YOUR_CLIENT_ID",
    redirect_uri: str = "http://localhost:8080/callback",
    scope: str = "openid email profile",
) -> dict[str, Any]:
    """Walk an Authorization Code + PKCE flow end to end for a given issuer.

    Steps 1-3 (discovery, PKCE, auth URL) are *executed* for real; steps 4-6
    (browser login, token exchange, ID-token verification) need a live user, so
    they are *described* with the exact requests that would be made. Returns an
    ordered list of steps you can follow or hand to a user.
    """
    steps: list[dict[str, Any]] = []

    # Step 1 — Discovery (executed)
    disc = fetch_discovery_document(issuer)
    if not disc.get("ok"):
        return {"ok": False, "failed_at": "discovery", "error": disc.get("error"), "steps": steps}
    steps.append({
        "step": 1,
        "name": "OIDC Discovery",
        "status": "executed",
        "detail": f"Fetched {disc['discovery_url']} to locate the provider's endpoints.",
        "data": {
            "authorization_endpoint": disc["authorization_endpoint"],
            "token_endpoint": disc["token_endpoint"],
            "jwks_uri": disc["jwks_uri"],
        },
    })

    # Step 2 — Generate PKCE (executed)
    pkce = generate_pkce_pair()
    steps.append({
        "step": 2,
        "name": "Generate PKCE pair",
        "status": "executed",
        "detail": "code_verifier stays secret on the client; the S256 code_challenge goes in the auth URL.",
        "data": pkce,
    })

    # Step 3 — Build authorization URL (executed)
    built = build_authorization_url(
        disc["authorization_endpoint"],
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        code_challenge=pkce["code_challenge"],
        code_challenge_method=pkce["code_challenge_method"],
    )
    steps.append({
        "step": 3,
        "name": "Build authorization URL",
        "status": "executed",
        "detail": "Send the user's browser here to log in and consent.",
        "data": {"authorization_url": built["authorization_url"], "state": built["state"]},
    })

    # Step 4 — User authenticates (manual)
    steps.append({
        "step": 4,
        "name": "User logs in & consents",
        "status": "manual",
        "detail": (
            f"Open the step-3 URL in a browser. After login the provider redirects to "
            f"{redirect_uri}?code=AUTH_CODE&state={built['state']}. Confirm the returned "
            "state matches before continuing (CSRF check)."
        ),
    })

    # Step 5 — Exchange code for tokens (described)
    steps.append({
        "step": 5,
        "name": "Exchange code for tokens",
        "status": "described",
        "detail": "POST the auth code + code_verifier to the token endpoint:",
        "data": {
            "method": "POST",
            "url": disc["token_endpoint"],
            "body": {
                "grant_type": "authorization_code",
                "code": "AUTH_CODE_FROM_STEP_4",
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": pkce["code_verifier"],
            },
        },
    })

    # Step 6 — Verify the ID token (described)
    steps.append({
        "step": 6,
        "name": "Verify the ID token",
        "status": "described",
        "detail": (
            "The token response includes an id_token (a JWT). Verify it with "
            "verify_jwt_online(id_token, jwks_uri) using the jwks_uri below."
        ),
        "data": {"jwks_uri": disc["jwks_uri"]},
    })

    return {
        "ok": True,
        "issuer": disc["issuer"],
        "summary": "Authorization Code + PKCE — steps 1-3 executed, 4-6 need a browser/user.",
        "steps": steps,
    }
