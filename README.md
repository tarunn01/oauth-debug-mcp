# oauth-debug-mcp

An [MCP](https://modelcontextprotocol.io) server that gives an AI assistant tools for
debugging OAuth 2.0 / OpenID Connect flows: decoding and verifying JWTs, generating and
checking PKCE pairs, analyzing authorization URLs, and linting client configuration.

> ⚠️ Debugging aid only. Unverified JWT decoding is for inspection — never use it for
> authorization decisions.

## Tools

| Tool | What it does |
|------|--------------|
| `decode_jwt` | Decode a JWT (no signature check) and analyze exp/iat/nbf claims |
| `verify_jwt` | Verify a JWT signature against an HMAC secret or PEM public key |
| `generate_pkce` | Generate a PKCE `code_verifier` / `code_challenge` (S256) pair |
| `verify_pkce` | Check a `code_verifier` against a `code_challenge` |
| `analyze_authorization_url` | Parse an auth request URL and flag common issues |
| `lint_client_config` | Lint an OAuth client config dict for misconfigurations |

## Setup

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate

pip install -e .
```

## Run

```bash
python server.py
```

The server speaks MCP over stdio, so it's launched by an MCP client (e.g. Claude Desktop).
Example client config:

```json
{
  "mcpServers": {
    "oauth-debug": {
      "command": "python",
      "args": ["path/to/oauth-debug-mcp/server.py"]
    }
  }
}
```

## Project layout

```
oauth-debug-mcp/
├── server.py            # FastMCP server exposing all tools
├── utils/
│   ├── jwt_utils.py     # JWT decode / verify logic
│   ├── oauth_utils.py   # PKCE + authorization-flow analysis
│   └── lint_utils.py    # Client-config linting rules
├── pyproject.toml
└── README.md
```

## Status

Week 1 scaffold. JWKS-based verification and OIDC discovery-document fetching are stubbed
and land later this week.

## License

MIT
