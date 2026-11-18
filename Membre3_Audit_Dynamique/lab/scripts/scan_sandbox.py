"""Recherche de données sensibles dans une copie du bac à sable applicatif (DAST-STO-01 / STO-05).

Usage : python scan_sandbox.py <dossier_copie> <flux.mitm> <fichier_env_comptes> <canari>
Cherche : le canari (contenu de messages), le jeton de session émis à l'application, le mot de passe
du compte factice, l'identifiant. Les valeurs ne sont jamais affichées : seuls les fichiers et le
nombre d'occurrences le sont. Signale aussi les bases SQLite non chiffrées (en-tête « SQLite format 3 »).
"""
import sys
from pathlib import Path

from mitmproxy import io

root, flow, envfile, canary = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), sys.argv[4]

env = dict(l.split("=", 1) for l in envfile.read_text(encoding="utf-8").splitlines() if "=" in l and not l.startswith("#"))
token = ""
with open(flow, "rb") as fh:
    for f in io.FlowReader(fh).stream():
        if getattr(f, "response", None) and f.request.path.startswith("/api/v4/users/login"):
            token = f.response.headers.get("Token", token)

needles = {
    "canari (contenu de messages)": canary.encode(),
    "jeton de session": token.encode(),
    "mot de passe alice": env["ALICE_PASS"].encode(),
    "identifiant alice": env["ALICE_USER"].encode(),
}
needles = {k: v for k, v in needles.items() if v}
print(f"copie analysée : {root}")
print(f"jeton recherché : {'oui' if token else 'non trouvé dans le flux'} ({len(token)} car.)\n")

files = sorted(p for p in root.rglob("*") if p.is_file())
total = sum(p.stat().st_size for p in files)
print(f"{len(files)} fichiers, {total/1024:.0f} Kio\n")
print("— Bases SQLite en clair (en-tête lisible) :")
for p in files:
    with p.open("rb") as fh:
        if fh.read(16).startswith(b"SQLite format 3"):
            print(f"  {p.relative_to(root)}  ({p.stat().st_size/1024:.0f} Kio)")

print("\n— Occurrences par élément recherché :")
for label, needle in needles.items():
    hits = []
    for p in files:
        data = p.read_bytes()
        n = data.count(needle) + data.count(needle.decode().encode("utf-16-le"))
        if n:
            hits.append(f"{p.relative_to(root)} ×{n}")
    print(f"  {label:32} : {'AUCUNE' if not hits else ''}")
    for h in hits[:12]:
        print(f"      {h}")
