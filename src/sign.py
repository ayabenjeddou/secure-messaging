#!/usr/bin/env python3

import argparse
import getpass
import sys

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


def load_private_key(path):
    data = open(path, "rb").read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:  # clé chiffrée par mot de passe
        pwd = getpass.getpass("Mot de passe de la clé privée : ").encode()
        return serialization.load_pem_private_key(data, password=pwd)


def sign_bytes(private_key, data: bytes) -> bytes:
    # PSS : salt aléatoire de la taille du hash (32 octets pour SHA-256)
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def main():
    ap = argparse.ArgumentParser(description="Signature RSA-PSS + SHA-256")
    ap.add_argument("file", help="fichier à signer (ex : message.txt)")
    ap.add_argument("private_key", help="clé privée de l'émetteur (ex : alice_priv.pem)")
    ap.add_argument("-o", "--out", help="fichier de signature (défaut : <file>.sig)")
    args = ap.parse_args()

    out = args.out or args.file + ".sig"
    try:
        key = load_private_key(args.private_key)
        sig = sign_bytes(key, open(args.file, "rb").read())
    except (OSError, ValueError, UnsupportedAlgorithm) as e:
        sys.exit(f"Erreur : {e}")
    open(out, "wb").write(sig)
    print(f"[+] Signature écrite dans {out} ({len(sig)} octets)")


if __name__ == "__main__":
    main()
