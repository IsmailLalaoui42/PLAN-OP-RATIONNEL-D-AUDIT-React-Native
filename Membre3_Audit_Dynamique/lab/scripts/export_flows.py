"""Exporte un fichier de flux mitmproxy en texte lisible, secrets masqués (preuves Membre 3).

Usage : python export_flows.py <flux.mitm> [filtre_chemin ...]
Les valeurs sensibles (mot de passe, jeton, cookie, en-tête Authorization) sont remplacées par
« <MASQUÉ : n caractères, transmis en clair> » : la preuve montre leur présence sans les divulguer.
"""
import json
import sys

from mitmproxy import io
from mitmproxy.exceptions import FlowReadException

SENSITIVE_KEYS = {"password", "token", "login_id", "device_id", "mfa_token", "csrf"}
SENSITIVE_HEADERS = {"authorization", "token", "cookie", "set-cookie", "x-csrf-token"}


def mask(value: str) -> str:
    return f"<MASQUÉ : {len(value)} caractères, transmis en clair>" if value else value


def mask_json(obj):
    if isinstance(obj, dict):
        return {k: (mask(str(v)) if k.lower() in SENSITIVE_KEYS else mask_json(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_json(v) for v in obj]
    return obj


def body(msg) -> str:
    if not msg or not msg.raw_content:
        return ""
    text = msg.get_text(strict=False) or ""
    try:
        return json.dumps(mask_json(json.loads(text)), ensure_ascii=False, indent=2)[:1200]
    except (ValueError, TypeError):
        return text[:300] + ("…" if len(text) > 300 else "")


def headers(h) -> str:
    return "\n".join(f"    {k}: {mask(v) if k.lower() in SENSITIVE_HEADERS else v}" for k, v in h.items())


def main():
    path, filters = sys.argv[1], sys.argv[2:]
    with open(path, "rb") as fh:
        try:
            for f in io.FlowReader(fh).stream():
                if not hasattr(f, "request"):
                    continue
                req = f.request
                if filters and not any(x in req.path for x in filters):
                    continue
                print(f"=== {req.method} {req.scheme}://{req.pretty_host}:{req.port}{req.path.split('?')[0]}")
                print(f"  horodatage requête : {req.timestamp_start:.3f} (epoch)  version : {req.http_version}")
                print("  en-têtes requête :\n" + headers(req.headers))
                if (b := body(req)):
                    print("  corps requête :\n    " + b.replace("\n", "\n    "))
                if f.response:
                    print(f"  réponse : {f.response.status_code}")
                    print("  en-têtes réponse :\n" + headers(f.response.headers))
                print()
        except FlowReadException as e:
            print(f"lecture interrompue : {e}")


if __name__ == "__main__":
    main()
