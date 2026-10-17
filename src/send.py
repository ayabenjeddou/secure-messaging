#!/usr/bin/env python3

import argparse
import base64
import getpass
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "SM-1.0"
AAD = b"secure_messaging_v1"  # données authentifiées (non chiffrées) liées au chiffré


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def signed_blob(key_enc, nonce, tag, ciphertext) -> bytes:
    """Encodage canonique à signer : chaque champ préfixé par sa longueur (4 octets)."""
    out = AAD
    for field in (key_enc, nonce, tag, ciphertext):
        out += struct.pack(">I", len(field)) + field
    return out


def load_private_key(path):
    data = open(path, "rb").read()
    try:
        return serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pwd = getpass.getpass("Mot de passe de la clé privée : ").encode()
        return serialization.load_pem_private_key(data, password=pwd)


def main():
    ap = argparse.ArgumentParser(description="Chiffre + signe un message (Alice -> Bob)")
    ap.add_argument("message", help="fichier en clair (message.txt)")
    ap.add_argument("--sender", default="alice")
    ap.add_argument("--recipient", default="bob")
    ap.add_argument("--sender-key", required=True, help="clé privée de l'émetteur")
    ap.add_argument("--recipient-key", required=True, help="clé publique du destinataire")
    ap.add_argument("-o", "--out", default="message.pkg")
    args = ap.parse_args()

    try:
        plaintext = open(args.message, "rb").read()
        sender_priv = load_private_key(args.sender_key)
        recipient_pub = serialization.load_pem_public_key(open(args.recipient_key, "rb").read())
    except (OSError, ValueError) as e:
        sys.exit(f"Erreur : {e}")

    # 1) clé symétrique éphémère AES-256
    K = AESGCM.generate_key(bit_length=256)

    # 2) AES-GCM : nonce 12 octets unique par message (JAMAIS réutilisé avec la même clé)
    nonce = os.urandom(12)
    ct_and_tag = AESGCM(K).encrypt(nonce, plaintext, AAD)
    ciphertext, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    # 3) K chiffrée avec la clé publique de Bob (RSA-OAEP / SHA-256)
    key_enc = recipient_pub.encrypt(
        K,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    # 4) signature de la structure finale (chiffrer puis signer)
    signature = sender_priv.sign(
        signed_blob(key_enc, nonce, tag, ciphertext),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )

    # 5) paquet JSON + base64
    pkg = {
        "version": VERSION,
        "sender": args.sender,
        "recipient": args.recipient,
        "algorithms": {"key_wrap": "RSA-OAEP-SHA256", "cipher": "AES-256-GCM",
                       "signature": "RSA-PSS-SHA256"},
        "key_enc": b64(key_enc),
        "nonce": b64(nonce),
        "tag": b64(tag),
        "ciphertext": b64(ciphertext),
        "signature": b64(signature),
    }
    with open(args.out, "w") as f:
        json.dump(pkg, f, indent=2)
    print(f"[+] {args.out} créé ({args.sender} -> {args.recipient}, {len(plaintext)} octets en clair)")


if __name__ == "__main__":
    main()
