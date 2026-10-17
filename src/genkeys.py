"""
attrib +R alice_priv.pem 
python3 genkeys.py alice
python3 genkeys.py bob
dir -l *.pem
openssl rsa -in alice_priv.pem -check -noout     # doit afficher : RSA key ok
openssl rsa -pubin -in alice_pub.pem -text -noout | findstr /C:"Public-Key"   # Public-Key: (2048 bit)
Test négatif : python3 genkeys.py test --bits 1024 doit afficher « taille minimale autorisée est 2048 bits »
"""

import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keypair(bits: int = 2048):
    # e = 65537 : exposant public standard recommandé
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def save_keypair(private_key, name: str, passphrase: bytes | None = None):
    if passphrase:
        enc = serialization.BestAvailableEncryption(passphrase)
    else:
        enc = serialization.NoEncryption()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    priv_path = f"{name}_priv.pem"
    pub_path = f"{name}_pub.pem"

    # La clé privée est créée directement avec les droits 600 (lecture/écriture propriétaire)
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_pem)
    os.chmod(priv_path, 0o600)  # garantit 600 même si le FS ignore le mode d'os.open

    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return priv_path, pub_path


def main():
    parser = argparse.ArgumentParser(description="Génère une paire de clés RSA (PEM).")
    parser.add_argument("name", help="nom de l'utilisateur (ex : alice, bob)")
    parser.add_argument("--bits", type=int, default=2048,
                        help="taille de la clé RSA (>= 2048, défaut 2048)")
    parser.add_argument("--passphrase", action="store_true",
                        help="chiffre la clé privée avec un mot de passe demandé au clavier")
    args = parser.parse_args()

    if args.bits < 2048:
        sys.exit("Erreur : la taille minimale autorisée est 2048 bits.")

    passphrase = None
    if args.passphrase:
        p1 = getpass.getpass("Mot de passe de la clé privée : ")
        p2 = getpass.getpass("Confirmation : ")
        if p1 != p2 or not p1:
            sys.exit("Erreur : mots de passe vides ou différents.")
        passphrase = p1.encode()

    key = generate_keypair(args.bits)
    priv_path, pub_path = save_keypair(key, args.name, passphrase)
    print(f"[+] Clé privée  : {priv_path}")
    print(f"[+] Clé publique : {pub_path}")
    print(f"[+] RSA-{args.bits} généré pour '{args.name}'")


if __name__ == "__main__":
    main()
