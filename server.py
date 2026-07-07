"""oauth-debug-mcp — a Model Context Protocol server for debugging OAuth/OIDC.

Run directly for stdio transport:

    uv run python server.py

Or, once installed:

    oauth-debug-mcp
"""

from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from utils import jwt_utils, lint_utils, oauth_utils

mcp = FastMCP("oauth-debug-mcp")


# --- JWT tools ---------------------------------------------------------------

@mcp.tool()
def decode_jwt(token: str) -> dict[str, Any]:
    """Decode a JWT without verifying its signature.

    Returns the header, payload, and an analysis of the exp/iat/nbf claims.
    Use this to inspect what a token claims — do NOT treat it as verified.
    """
    return jwt_utils.decode_jwt(token)


@mcp.tool()
def verify_jwt(token: str, key: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    """Verify a JWT signature against an HMAC secret or PEM public key."""
    return jwt_utils.verify_jwt(token, key, algorithms)


# --- OAuth / PKCE tools ------------------------------------------------------

@mcp.tool()
def generate_pkce() -> dict[str, str]:
    """Generate a fresh PKCE code_verifier / code_challenge (S256) pair."""
    return oauth_utils.generate_pkce_pair()


@mcp.tool()
def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> dict[str, Any]:
    """Check whether a PKCE code_verifier matches a code_challenge."""
    return oauth_utils.verify_pkce(code_verifier, code_challenge, method)


@mcp.tool()
def analyze_authorization_url(url: str) -> dict[str, Any]:
    """Parse an OAuth authorization request URL and flag common problems."""
    return oauth_utils.analyze_authorization_url(url)


# --- Config linting tool -----------------------------------------------------

@mcp.tool()
def lint_client_config(config: dict[str, Any]) -> dict[str, Any]:
    """Lint an OAuth client configuration dict for common misconfigurations."""
    return lint_utils.lint_client_config(config)


def main() -> None:
    """Console-script entry point (see [project.scripts] in pyproject.toml)."""
    mcp.run()


if __name__ == "__main__":
    main()
