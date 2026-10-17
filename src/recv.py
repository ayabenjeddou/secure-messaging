#!/usr/bin/env python3

import argparse
import base64
import binascii
import getpass
import json
import struct
import sys

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"secure_messaging_v1"


def signed_blob(key_enc, nonce, tag, ciphertext) -> bytes:
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


def fail(msg):
    print(f"[-] {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    ap = argparse.ArgumentParser(description="Réception d'un message sécurisé")
    ap.add_argument("package", help="message.pkg")
    ap.add_argument("--recipient-key", required=True, help="clé privée du destinataire (bob_priv.pem)")
    ap.add_argument("--sender-key", required=True, help="clé publique de l'émetteur (alice_pub.pem)")
    ap.add_argument("-o", "--out", default="recovered.txt")
    args = ap.parse_args()

    try:
        pkg = json.load(open(args.package))
        key_enc = base64.b64decode(pkg["key_enc"], validate=True)
        nonce = base64.b64decode(pkg["nonce"], validate=True)
        tag = base64.b64decode(pkg["tag"], validate=True)
        ciphertext = base64.b64decode(pkg["ciphertext"], validate=True)
        signature = base64.b64decode(pkg["signature"], validate=True)
        recipient_priv = load_private_key(args.recipient_key)
        sender_pub = serialization.load_pem_public_key(open(args.sender_key, "rb").read())
    except (OSError, ValueError, KeyError, binascii.Error) as e:
        fail(f"Paquet ou clé invalide : {e}")

    if len(nonce) != 12 or len(tag) != 16:
        fail("Taille de nonce/tag incorrecte")

    # 1) vérification de la signature (authenticité + intégrité du paquet)
    try:
        sender_pub.verify(
            signature,
            signed_blob(key_enc, nonce, tag, ciphertext),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        fail("Signature INVALIDE (KO) : paquet rejeté")
    print("[+] Signature valide (OK)")

    # 2) déchiffrement de K avec la clé privée de Bob (RSA-OAEP)
    try:
        K = recipient_priv.decrypt(
            key_enc,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except ValueError:
        fail("Impossible de déchiffrer la clé K (mauvaise clé privée ?)")

    # 3) AES-GCM : vérifie le tag puis déchiffre
    try:
        plaintext = AESGCM(K).decrypt(nonce, ciphertext + tag, AAD)
    except InvalidTag:
        fail("Tag GCM invalide : message altéré")

    open(args.out, "wb").write(plaintext)
    print(f"[+] Message déchiffré écrit dans {args.out} ({len(plaintext)} octets)")


if __name__ == "__main__":
    main()
