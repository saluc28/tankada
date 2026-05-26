"""
Dev utility - generates an RSA keypair and the corresponding JWKS JSON for
Tankada RS256 mode (C.1.a). Pair with generate_token.py --alg RS256.

  python generate_jwks.py --kid k1 --out-private key.pem --out-jwks jwks.json

  # gateway side: mount jwks.json and set JWT_JWKS_PATH=/path/to/jwks.json
  # signer side: keep key.pem secret; sign tokens with:
  #   python generate_token.py --alg RS256 --private-key key.pem --kid k1

To rotate keys in production:
  1) generate a NEW keypair with a NEW --kid (e.g. k2).
  2) APPEND the new JWK to the deployed jwks.json (now both k1 and k2 are valid).
  3) switch your signer to use the new private key + new kid.
  4) wait for all in-flight tokens signed with the old kid to expire.
  5) REMOVE the old JWK from jwks.json. Done, zero downtime.
"""
import argparse
import base64
import json
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("error: this script needs the `cryptography` package.\n"
          "       install with: pip install cryptography  (or pip install pyjwt[crypto])",
          file=sys.stderr)
    sys.exit(1)


def _b64url_uint(n: int) -> str:
    """RFC 7518 §6.3.1.1: a big-endian unsigned integer, base64url-encoded
    without padding."""
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, byteorder="big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def make_jwk(public_key, kid: str) -> dict:
    """Build the JWK dict (RFC 7517) for an `rsa.RSAPublicKey`."""
    nums = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "alg": "RS256",
        "use": "sig",
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }


def main():
    ap = argparse.ArgumentParser(description="Generate an RSA keypair + JWKS for Tankada RS256 mode")
    ap.add_argument("--kid", required=True, help="key id (string the gateway picks the public key by)")
    ap.add_argument("--out-private", default="private.pem",
                    help="path to write the PEM private key (default: private.pem)")
    ap.add_argument("--out-jwks", default="jwks.json",
                    help="path to write the JWKS JSON (default: jwks.json)")
    ap.add_argument("--key-size", type=int, default=2048,
                    help="RSA modulus bits (default: 2048; production: >=3072 recommended)")
    args = ap.parse_args()

    key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    with open(args.out_private, "wb") as fh:
        fh.write(priv_pem)
    jwk = make_jwk(key.public_key(), args.kid)
    with open(args.out_jwks, "w", encoding="utf-8") as fh:
        json.dump({"keys": [jwk]}, fh, indent=2)
        fh.write("\n")

    print(f"wrote {args.out_private} (KEEP SECRET; the signer uses this)")
    print(f"wrote {args.out_jwks}  (deploy to the verifier; set JWT_JWKS_PATH=/path/to/{args.out_jwks})")
    print(f"kid = {args.kid}")
    print()
    print("Sign a token with:")
    print(f"  python generate_token.py --alg RS256 \\")
    print(f"      --private-key {args.out_private} --kid {args.kid}")


if __name__ == "__main__":
    main()
