# Fonctions de collecte de preuves horodatées (Membre 3) — à charger avec : source ev.sh
# Chaque preuve est écrite dans 04_Preuves/<ID>/ et inscrite dans 04_Preuves/MANIFEST.csv
# (horodatage UTC, identifiant de test, fichier, SHA-256, commande).

EV_ROOT="/d/IACS/3eme_Annee_IACS/COMPLIANCE/MINI PROJECT/Membre3_Audit_Dynamique/04_Preuves"
export ADB="/d/DAST-Lab/android-sdk/platform-tools/adb.exe"
export MSYS_NO_PATHCONV=1   # empêche Git Bash de réécrire les chemins Android (/data/...)
export PATH="/d/DAST-Lab/jdk/jdk-17.0.21+9/bin:/d/DAST-Lab/android-sdk/platform-tools:$PATH"
mkdir -p "$EV_ROOT"
[ -f "$EV_ROOT/MANIFEST.csv" ] || echo "horodatage_utc;test_id;fichier;sha256;commande" > "$EV_ROOT/MANIFEST.csv"

_ev_register() { # id fichier commande
  local h; h=$(sha256sum "$2" | cut -d' ' -f1)
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ);$1;${2#"$EV_ROOT/"};$h;$(echo "$3" | tr ';\n' ',  ')" >> "$EV_ROOT/MANIFEST.csv"
}

# ev_cmd <ID> <nom_fichier> <commande...> : exécute, affiche et archive la sortie
ev_cmd() {
  local id=$1 name=$2; shift 2
  local dir="$EV_ROOT/$id"; mkdir -p "$dir"
  local f="$dir/$name"
  { echo "# Test      : $id"
    echo "# Horodatage: $(date -u +%Y-%m-%dT%H:%M:%SZ) (UTC)"
    echo "# Commande  : $*"
    echo "# ----"
    eval "$@" 2>&1; } > "$f"
  cat "$f"
  _ev_register "$id" "$f" "$*"
}

# ev_shot <ID> <nom_fichier.png> : capture d'écran de l'émulateur
ev_shot() {
  local dir="$EV_ROOT/$1"; mkdir -p "$dir"
  "$ADB" exec-out screencap -p > "$dir/$2"
  _ev_register "$1" "$dir/$2" "adb exec-out screencap -p"
  echo "capture: $1/$2"
}

# ev_file <ID> <fichier_source> [nom] : archive une preuve produite ailleurs
ev_file() {
  local dir="$EV_ROOT/$1"; mkdir -p "$dir"
  local dest="$dir/${3:-$(basename "$2")}"
  cp "$2" "$dest"; _ev_register "$1" "$dest" "copie de $(basename "$2")"
  echo "archivé: $1/$(basename "$dest")"
}

# try_server <ID> <url> <capture.png> : saisit une URL serveur, tente la connexion, capture le résultat
UI_PY="D:/IACS/3eme_Annee_IACS/COMPLIANCE/MINI PROJECT/Membre3_Audit_Dynamique/lab/scripts/ui.py"
ui() { PYTHONIOENCODING=utf-8 /d/DAST-Lab/venv/Scripts/python.exe -I "$UI_PY" "$@"; }
try_server() {
  local id=$1 url=$2 shot=$3
  ui tap server_form.server_url.input >/dev/null
  "$ADB" shell input keycombination 113 29; "$ADB" shell input keyevent KEYCODE_DEL
  "$ADB" shell input text "$url"; "$ADB" shell input keyevent 111
  ui tap server_form.server_display_name.input >/dev/null; "$ADB" shell input keycombination 113 29; "$ADB" shell input keyevent KEYCODE_DEL; "$ADB" shell input text "Lab"; "$ADB" shell input keyevent 111
  local t0; t0=$(date -u +%H:%M:%S)
  sleep 1; ui tap server_form.connect.button >/dev/null; sleep 7
  ev_shot "$id" "$shot"
  echo "début tentative (UTC): $t0"
  ui dump | grep -E "server_url.input|error|Cannot|certificate|trust" | sed 's/^\[[0-9, ]*\] //'
}
