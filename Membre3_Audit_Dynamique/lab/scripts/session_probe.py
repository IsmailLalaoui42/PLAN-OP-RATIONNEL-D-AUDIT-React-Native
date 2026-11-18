"""Sonde de session (DAST-AUTH) — rejoue le jeton émis à l'application contre le serveur de labo.

Usage :
  python session_probe.py <flux.mitm> me          -> GET /api/v4/users/me avec le dernier jeton capturé
  python session_probe.py <flux.mitm> sessions    -> liste les sessions de l'utilisateur (jeton admin requis via MM_ADMIN_TOKEN)
Le jeton n'est jamais affiché : seuls son empreinte SHA-256 tronquée et sa longueur le sont.
"""
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

from mitmproxy import io

BASE = os.environ.get("MM_BASE", "http://127.0.0.1:8065")


def last_token(path: str) -> str:
    token = ""
    with open(path, "rb") as fh:
        for f in io.FlowReader(fh).stream():
            if getattr(f, "response", None) and f.request.path.startswith("/api/v4/users/login"):
                token = f.response.headers.get("Token", token)
    if not token:
        raise SystemExit("aucun jeton de connexion trouvé dans le flux")
    return token


def fp(tok: str) -> str:
    return f"sha256:{hashlib.sha256(tok.encode()).hexdigest()[:12]}… ({len(tok)} car.)"


def get(path: str, tok: str):
    req = urllib.request.Request(BASE + path, headers={"Authorization": f"Bearer {tok}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def main():
    flow, action = sys.argv[1], sys.argv[2]
    tok = last_token(flow)
    print(f"jeton rejoué : {fp(tok)}  serveur : {BASE}")
    if action == "me":
        code, body = get("/api/v4/users/me", tok)
        summary = {k: body.get(k) for k in ("username", "roles")} if code == 200 else body
        print(f"GET /api/v4/users/me -> HTTP {code}  {json.dumps(summary, ensure_ascii=False)}")
    elif action == "sessions":
        admin = os.environ["MM_ADMIN_TOKEN"]
        code, me = get("/api/v4/users/me", tok)
        uid = me["id"]
        code, sessions = get(f"/api/v4/users/{uid}/sessions", admin)
        print(f"GET /api/v4/users/<alice>/sessions (admin) -> HTTP {code}")
        for s in sessions:
            props = s.get("props", {})
            days = (s["expires_at"] - s["create_at"]) / 86_400_000
            print(f"  session créée {s['create_at']} expire {s['expires_at']} -> durée {days:.1f} jours ;"
                  f" mobile={props.get('os', '') or s.get('device_id', '')[:12] and 'oui'} ;"
                  f" dernière activité {s['last_activity_at']}")


if __name__ == "__main__":
    main()
