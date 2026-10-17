# secure_messaging — Messagerie sécurisée hybride (Aya benjeddou MPSSI2 ( Mastère Professionnel en Sécurité des Systèmes Informatiques )


Ce projet permet à Alice d’envoyer un message sécurisé à Bob en utilisant RSA 
et AES pour assurer la confidentialité, l’intégrité et l’authenticité des messages

# Installation:
pip install cryptography      # Python >= 3.10

# Fichiers du projet :
`genkeys.py` => Génère les clés RSA.
`sign.py` => Signe un fichier avec la clé privée.
`verify.py` => Vérifie la signature.
`send.py` => Chiffre et signe le message.
`recv.py` => Vérifie et déchiffre le message reçu.
`demo.sh` => Exécute une démonstration complète.

# Utilisation :
1. Générer les clés d’Alice et de Bob :
python3 genkeys.py alice
python3 genkeys.py bob
2. Créer un message :
echo "Bonjour Bob" > message.txt

#signature seule:
python3 sign.py message.txt alice_priv.pem
python3 verify.py message.txt message.txt.sig alice_pub.pem      # OK / KO

# Alice envoie
python3 send.py message.txt --sender alice --recipient bob \
    --sender-key alice_priv.pem --recipient-key bob_pub.pem -o message.pkg

# Bob reçoit
python3 recv.py message.pkg --recipient-key bob_priv.pem --sender-key alice_pub.pem -o recovered.txt

Ou simplement : `bash demo.sh`

#Format de `message.pkg`
```json
{
  "version": "SM-1.0",
  "sender": "alice",
  "recipient": "bob",
  "algorithms": {"key_wrap": "RSA-OAEP-SHA256", "cipher": "AES-256-GCM", "signature": "RSA-PSS-SHA256"},
  "key_enc":    "<base64 : K chiffrée RSA-OAEP avec la clé publique de Bob (256 octets)>",
  "nonce":      "<base64 : 12 octets aléatoires>",
  "tag":        "<base64 : tag GCM, 16 octets>",
  "ciphertext": "<base64 : message chiffré AES-256-GCM>",
  "signature":  "<base64 : RSA-PSS-SHA256 d'Alice, 256 octets>"
}
```
- **AAD GCM** : `secure_messaging_v1` (authentifiée, non chiffrée).
- **Données signées** (chiffrer puis signer) : `AAD || len(key_enc) || key_enc || len(nonce) || nonce || len(tag) || tag || len(ciphertext) || ciphertext`, chaque longueur sur 4 octets big-endian (évite toute ambiguïté de concaténation).
- **Ordre à la réception** : signature → déchiffrement de K → vérification du tag GCM. Rien n'est écrit si une étape échoue.

## Choix de sécurité
- Nonce GCM de 96 bits tiré avec `os.urandom` et clé K **unique par message** : pas de réutilisation (nonce, clé).
- RSA-OAEP et RSA-PSS (et non PKCS#1 v1.5) ; SHA-256 partout.
- Clé privée en PKCS#8, droits 600, mot de passe optionnel.

## Limites
Pas de PKI : les clés publiques sont échangées « hors bande » et supposées authentiques. Pas de protection contre le rejeu (pas d'horodatage/identifiant de message), pas de forward secrecy, pas de métadonnées protégées.

