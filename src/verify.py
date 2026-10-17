#!/usr/bin/env python3

import argparse
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def verify_bytes(public_key, data: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def main():
    ap = argparse.ArgumentParser(description="Vérification RSA-PSS + SHA-256")
    ap.add_argument("file", help="fichier signé")
    ap.add_argument("signature", help="fichier de signature (.sig)")
    ap.add_argument("public_key", help="clé publique de l'émetteur (ex : alice_pub.pem)")
    args = ap.parse_args()

    try:
        pub = serialization.load_pem_public_key(open(args.public_key, "rb").read())
        ok = verify_bytes(pub, open(args.file, "rb").read(), open(args.signature, "rb").read())
    except (OSError, ValueError) as e:
        print("KO")
        print(f"Erreur : {e}", file=sys.stderr)
        sys.exit(1)

    print("OK" if ok else "KO")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
