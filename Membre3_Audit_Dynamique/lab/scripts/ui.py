"""Pilotage minimal de l'interface Android via uiautomator (banc d'essai Membre 3).

python ui.py dump                 -> liste les éléments visibles (texte / id / bornes)
python ui.py tap "<texte|id>"     -> touche le premier élément dont le texte, la description ou l'id contient la chaîne
python ui.py type "<texte|id>" "<valeur>" -> touche le champ puis saisit la valeur
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ADB = r"D:\DAST-Lab\android-sdk\platform-tools\adb.exe"


def adb(*args: str) -> str:
    return subprocess.run([ADB, *args], capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


def nodes():
    adb("shell", "uiautomator", "dump", "/sdcard/ui.xml")
    xml = adb("exec-out", "cat", "/sdcard/ui.xml")
    xml = xml[xml.find("<?xml"):]
    for n in ET.fromstring(xml).iter("node"):
        b = [int(x) for x in re.findall(r"\d+", n.get("bounds", ""))]
        if len(b) == 4:
            yield n, b


def find(q: str):
    """« =TEXTE » : correspondance exacte (texte, description ou id) ; sinon sous-chaîne insensible à la casse."""
    exact = q.startswith("=")
    ql = q[1:] if exact else q.lower()
    for n, b in nodes():
        fields = [n.get("text", ""), n.get("content-desc", ""), n.get("resource-id", "")]
        if (exact and ql in fields) or (not exact and ql in " ".join(fields).lower()):
            return n, b
    raise SystemExit(f"introuvable : {q}")


def tap(q: str):
    n, b = find(q)
    x, y = (b[0] + b[2]) // 2, (b[1] + b[3]) // 2
    adb("shell", "input", "tap", str(x), str(y))
    print(f"tap {q!r} @ {x},{y}")


def main():
    cmd = sys.argv[1]
    if cmd == "dump":
        for n, b in nodes():
            t, d, r = n.get("text", ""), n.get("content-desc", ""), n.get("resource-id", "")
            if t or d or r:
                print(f"{b} text={t!r} desc={d!r} id={r!r} pwd={n.get('password')} cls={n.get('class')}")
    elif cmd == "tap":
        tap(sys.argv[2])
    elif cmd == "type":
        tap(sys.argv[2])
        value = sys.argv[3].replace(" ", "%s")
        adb("shell", "input", "text", value)
        print("saisie effectuée")


if __name__ == "__main__":
    main()
