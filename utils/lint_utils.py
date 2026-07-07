"""Linting rules for OAuth / OIDC client configuration.

Day 1 scaffold: a small starter ruleset over a client-config dict. Rules are
data-driven so more can be appended without touching the runner.
"""

from __future__ import annotations

from typing import Any, Callable

# A rule takes the config dict and returns a warning string, or None if it passes.
Rule = Callable[[dict[str, Any]], str | None]


def _no_wildcard_redirect(cfg: dict[str, Any]) -> str | None:
    uris = cfg.get("redirect_uris", []) or []
    if any("*" in uri for uri in uris):
        return "redirect_uris contains a wildcard — open redirect risk"
    return None


def _redirects_https(cfg: dict[str, Any]) -> str | None:
    uris = cfg.get("redirect_uris", []) or []
    bad = [u for u in uris if u.startswith("http://") and "localhost" not in u and "127.0.0.1" not in u]
    if bad:
        return f"non-HTTPS redirect_uris: {bad}"
    return None


def _pkce_for_public_clients(cfg: dict[str, Any]) -> str | None:
    if cfg.get("token_endpoint_auth_method") == "none" and not cfg.get("pkce", False):
        return "public client (auth_method=none) should require PKCE"
    return None


def _scopes_present(cfg: dict[str, Any]) -> str | None:
    if not cfg.get("scopes"):
        return "no scopes declared — verify least-privilege intent"
    return None


def _short_lived_tokens(cfg: dict[str, Any]) -> str | None:
    ttl = cfg.get("access_token_ttl_seconds")
    if isinstance(ttl, (int, float)) and ttl > 3600:
        return f"access token TTL is {int(ttl)}s (>1h) — consider shorter-lived tokens"
    return None


RULES: list[Rule] = [
    _no_wildcard_redirect,
    _redirects_https,
    _pkce_for_public_clients,
    _scopes_present,
    _short_lived_tokens,
]


def lint_client_config(config: dict[str, Any]) -> dict[str, Any]:
    """Run all lint rules against an OAuth client config dict."""
    warnings = [msg for rule in RULES for msg in [rule(config)] if msg]
    return {
        "passed": not warnings,
        "warning_count": len(warnings),
        "warnings": warnings,
        "rules_checked": len(RULES),
    }
