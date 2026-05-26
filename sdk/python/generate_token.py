"""
Dev utility - generates a signed JWT for local testing.

Two signing modes (matching the gateway's two verifier modes, C.1.a):

  HS256 (default, dev / single-tenant):
      python generate_token.py
      python generate_token.py --secret my-shared-secret

  RS256 (production / multi-tenant; pair with JWT_JWKS_URL/PATH on gateway):
      # 1) generate a keypair + JWKS once
      python generate_jwks.py --kid k1 --out-private key.pem --out-jwks jwks.json
      # 2) sign tokens with the private key, referencing the kid
      python generate_token.py --alg RS256 --private-key key.pem --kid k1

The dashboard (sdk/python/dashboard/server.py) signs tokens it issues to
demo agents the same way: HS256 in dev, RS256 with a kid in production.
"""
import argparse
import datetime
import sys

import jwt  # pip install pyjwt[crypto]


def generate(
    agent_id: str = "agent_dev_001",
    owner_user_id: str = "user_dev_001",
    tenant_id: str = "tenant_1",
    roles: list = None,
    scopes: list = None,
    secret: str = "dev-secret-change-in-production",
    expires_hours: int = 24,
    *,
    alg: str = "HS256",
    private_key_pem: bytes = None,
    kid: str = None,
) -> str:
    """Sign and return a Tankada agent JWT.

    HS256 (default): symmetric, `secret` is shared with the verifier.
    RS256: asymmetric, `private_key_pem` must hold a PEM-encoded RSA private key
    and `kid` must reference an entry in the verifier's JWKS.
    """
    now = datetime.datetime.utcnow()
    payload = {
        "agent_id": agent_id,
        "owner_user_id": owner_user_id,
        "tenant_id": tenant_id,
        "roles": roles or ["read_only"],
        "scopes": scopes or ["orders:read"],
        "iat": now,
        "exp": now + datetime.timedelta(hours=expires_hours),
        "iss": "tankada-dev",
    }
    if alg == "HS256":
        return jwt.encode(payload, secret, algorithm="HS256")
    if alg == "RS256":
        if not private_key_pem or not kid:
            raise ValueError("RS256 requires --private-key and --kid")
        return jwt.encode(payload, private_key_pem, algorithm="RS256",
                          headers={"kid": kid})
    raise ValueError(f"unsupported alg {alg!r}; use HS256 or RS256")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a Tankada dev JWT")
    parser.add_argument("--agent-id",  default="agent_dev_001")
    parser.add_argument("--tenant-id", default="tenant_1")
    parser.add_argument("--role",   nargs="+", default=["read_only"])
    parser.add_argument("--scope",  nargs="+", default=["orders:read"])
    parser.add_argument("--alg", choices=["HS256", "RS256"], default="HS256",
                        help="signing algorithm (default: HS256)")
    parser.add_argument("--secret", default="dev-secret-change-in-production",
                        help="HS256 shared secret (ignored for RS256)")
    parser.add_argument("--private-key", default=None,
                        help="RS256 path to PEM private key (required for RS256)")
    parser.add_argument("--kid", default=None,
                        help="RS256 key id (must match an entry in the verifier's JWKS)")
    parser.add_argument("--raw", action="store_true",
                        help="print ONLY the token (no decorative banner / curl example); "
                             "use this when piping into a shell variable, e.g. "
                             "`python generate_token.py --raw > token.txt` "
                             "+ `set /p TOKEN=<token.txt` on cmd.")
    args = parser.parse_args()

    private_key_pem = None
    if args.alg == "RS256":
        if not args.private_key or not args.kid:
            print("error: --alg RS256 requires --private-key and --kid", file=sys.stderr)
            sys.exit(2)
        with open(args.private_key, "rb") as fh:
            private_key_pem = fh.read()

    token = generate(
        agent_id=args.agent_id,
        tenant_id=args.tenant_id,
        roles=args.role,
        scopes=args.scope,
        secret=args.secret,
        alg=args.alg,
        private_key_pem=private_key_pem,
        kid=args.kid,
    )
    if args.raw:
        print(token)
        sys.exit(0)
    print("\n-- Tankada Dev Token --------------------------------------")
    print(token)
    print("-----------------------------------------------------------\n")
    print("Test with:")
    print(f'  curl -s -X POST http://localhost:8080/v1/query \\')
    print(f'    -H "Authorization: Bearer {token}" \\')
    print(f'    -H "Content-Type: application/json" \\')
    print(f'    -d \'{{"query":"SELECT id, product FROM orders WHERE tenant_id = \\"tenant_1\\""}}\' | python -m json.tool')
