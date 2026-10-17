#!/usr/bin/env bash
# demo.sh - Reproduit l'échange Alice -> Bob + tests négatifs
set -u
cd "$(dirname "$0")"
WORK=demo_work
rm -rf "$WORK" && mkdir "$WORK" && cd "$WORK"
P=..

echo "=== 1. Génération des clés (Alice et Bob) ==="
python3 $P/genkeys.py alice
python3 $P/genkeys.py bob

echo; echo "=== 2. Message d'Alice ==="
echo "Rapport confidentiel : réunion jeudi à 10h, salle B2." > message.txt
cat message.txt

echo; echo "=== 3. Signature seule + vérification ==="
python3 $P/sign.py message.txt alice_priv.pem
python3 $P/verify.py message.txt message.txt.sig alice_pub.pem

echo; echo "=== 4. Envoi (AES-GCM + RSA-OAEP + RSA-PSS) ==="
python3 $P/send.py message.txt --sender alice --recipient bob \
    --sender-key alice_priv.pem --recipient-key bob_pub.pem -o message.pkg

echo; echo "=== 5. Réception par Bob ==="
python3 $P/recv.py message.pkg --recipient-key bob_priv.pem --sender-key alice_pub.pem -o recovered.txt
diff message.txt recovered.txt && echo "[+] recovered.txt identique à message.txt"

echo; echo "=== 6. Test négatif : paquet altéré (ciphertext modifié) ==="
python3 - << 'PY'
import json, base64
p = json.load(open("message.pkg"))
c = bytearray(base64.b64decode(p["ciphertext"])); c[0] ^= 1
p["ciphertext"] = base64.b64encode(bytes(c)).decode()
json.dump(p, open("tampered.pkg", "w"))
PY
python3 $P/recv.py tampered.pkg --recipient-key bob_priv.pem --sender-key alice_pub.pem -o tampered.txt \
    || echo "[+] Altération détectée, rien n'a été écrit"
[ -e tampered.txt ] && echo "ERREUR : fichier écrit" || true

echo; echo "=== 7. Test négatif : mauvais expéditeur (Mallory se fait passer pour Alice) ==="
python3 $P/genkeys.py mallory >/dev/null
python3 $P/send.py message.txt --sender alice --recipient bob \
    --sender-key mallory_priv.pem --recipient-key bob_pub.pem -o forged.pkg
python3 $P/recv.py forged.pkg --recipient-key bob_priv.pem --sender-key alice_pub.pem -o forged.txt \
    || echo "[+] Usurpation détectée"
