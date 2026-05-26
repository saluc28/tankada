"""
Dev utility - generate a new RSA keypair and APPEND its public JWK to an
existing JWKS file. Used for two scenarios:

  1. Provisioning a new customer (C.1.b multi-tenant):
       python add_to_jwks.py --jwks jwks.json --kid acme-2026-q2 \\
           --tenant acme --out-private acme.pem
     The deployed jwks.json now serves both the previous customers' keys AND
     a new one bound to tenant=acme. Give acme.pem to the new customer; their
     tokens MUST set tenant_id=acme (or the gateway rejects them, even if the
     signature is valid).

  2. Rotating a key for an existing tenant (zero downtime):
       # add a new kid for tenant=acme alongside the old one
       python add_to_jwks.py --jwks jwks.json --kid acme-2026-q3 \\
           --tenant acme --out-private acme-q3.pem
       # tell the signer to start using acme-q3.pem; wait for old tokens to expire;
       # then remove the acme-2026-q2 entry from jwks.json by hand.

Replaces any existing entry with the same `kid` (so re-running with the same
--kid lets you re-key a tenant; warns on stderr so it's not silent).
"""
import argparse
import json
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("error: this script needs the `cryptography` package.\n"
          "       install with: pip install cryptography",
          file=sys.stderr)
    sys.exit(1)

from generate_jwks import make_jwk


def main():
    ap = argparse.ArgumentParser(description="Append a new RSA key to an existing JWKS (Tankada C.1.b)")
    ap.add_argument("--jwks", required=True, help="path to the JWKS file to extend (modified in place)")
    ap.add_argument("--kid", required=True, help="key id (must be unique within the JWKS)")
    ap.add_argument("--tenant", default="",
                    help="bind this kid to a tenant id (recommended for multi-tenant). "
                         "Empty for a tenant-agnostic key (legacy / dev).")
    ap.add_argument("--out-private", required=True, help="where to write the PEM private key")
    ap.add_argument("--key-size", type=int, default=2048)
    args = ap.parse_args()

    try:
        with open(args.jwks, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as e:
        print(f"cannot read {args.jwks}: {e}", file=sys.stderr); sys.exit(1)
    keys = doc.get("keys", [])
    if not isinstance(keys, list):
        print(f"malformed JWKS: 'keys' is not a list", file=sys.stderr); sys.exit(1)

    # If a kid with this id already exists, REPLACE it (silent re-key would be
    # surprising; warn loudly).
    replaced = False
    keys = [k for k in keys if not (isinstance(k, dict) and k.get("kid") == args.kid and (replaced := True))]
    if replaced:
        print(f"WARNING: replaced existing kid {args.kid!r} in {args.jwks} (re-keying)", file=sys.stderr)

    key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(args.out_private, "wb") as fh:
        fh.write(priv_pem)
    keys.append(make_jwk(key.public_key(), args.kid, args.tenant))

    doc["keys"] = keys
    with open(args.jwks, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")

    tenant_note = f"tenant={args.tenant!r}" if args.tenant else "UNBOUND (any tenant_id accepted; pass --tenant for multi-tenant safety)"
    print(f"appended kid={args.kid!r} ({tenant_note}) to {args.jwks}")
    print(f"wrote {args.out_private} (KEEP SECRET; the signer uses this)")
    print(f"JWKS now has {len(keys)} keys total.")


if __name__ == "__main__":
    main()
