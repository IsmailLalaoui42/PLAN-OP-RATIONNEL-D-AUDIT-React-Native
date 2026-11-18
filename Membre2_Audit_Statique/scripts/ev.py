#!/usr/bin/env python3
"""Génère les preuves SAST horodatées (même format que Membre 3 : en-tête + sortie de commande).
Usage : python3 ev.py <racine_source> <dossier_preuves>"""
import subprocess, sys, os, datetime

SRC, OUT = sys.argv[1], sys.argv[2]
A = 'android/app/src/main'
J = A + '/java/com/mattermost/helpers'

EV = [
 ('SAST-NET-01', '01_network_security_config.txt', f'cat -n {A}/res/xml/network_security_config.xml'),
 ('SAST-NET-01', '02_manifeste_cleartext.txt', f'grep -nE "networkSecurityConfig|usesCleartextTraffic" {A}/AndroidManifest.xml'),
 ('SAST-NET-01', '03_epinglage_inactif.txt', 'echo "Mécanisme d\'épinglage présent dans le code (lit assets/certs/*.cer) :"; grep -nE "CertificatePinner|assets.list|certs/" libraries/@mattermost/rnshare/android/src/main/java/com/mattermost/rnshare/ShareWorker.kt; echo; echo "Contenu de assets/certs dans le build public :"; ls -A android/app/src/main/assets/certs'),
 ('SAST-NET-02', '01_ecran_serveur_repli_http.txt', 'awk \'NR>=310 && NR<=331 {printf "%d: %s\\n", NR, $0}\' app/screens/server/index.tsx'),
 ('SAST-NET-02', '02_edition_serveur_repli_http.txt', 'sed -n 122,127p app/screens/edit_server/edit_server.tsx'),
 ('SAST-NET-02', '03_lien_magique_repli_http.txt', 'sed -n 430,442p app/actions/remote/session.ts'),
 ('SAST-PLT-01', '01_handleDeepLink_sans_confirmation.txt', 'sed -n 52,66p app/utils/deep_link/index.ts'),
 ('SAST-PLT-01', '02_lancement_a_froid.txt', 'sed -n 129,142p app/init/launch.ts'),
 ('SAST-PLT-01', '03_magicLinkLogin_envoi_jetons_push.txt', 'sed -n 449,457p app/actions/remote/session.ts'),
 ('SAST-PLT-01', '04_schemas_manifeste.txt', f'grep -nE "android:scheme" {A}/AndroidManifest.xml'),
 ('SAST-STO-01', '01_jeton_keystore.txt', 'sed -n 123,134p app/init/credentials.ts'),
 ('SAST-STO-01', '02_absence_chiffrement_base.txt', 'echo "Recherche SQLCipher / clé de chiffrement de base :"; grep -rniE "sqlcipher|encryptionKey|passphrase" app android/app/src/main libraries --include=*.ts --include=*.kt --include=*.java --include=*.gradle | grep -v "\\.test\\." || echo "0 occurrence"; grep -n "watermelondb" package.json'),
 ('SAST-STO-02', '01_anti_capture_par_defaut.txt', 'grep -nE "PreventScreenCapture|enableBlurScreen\\(this" app/managers/security_manager/index.ts'),
 ('SAST-STO-03', '01_logger_js.txt', 'sed -n 1,45p app/utils/log.ts; echo; grep -n "SentryEnabled" assets/base/config.json'),
 ('SAST-STO-03', '02_journaux_natifs.txt', f'grep -nE "TurboLog\\.(i|e)" {J}/PushNotificationDataHelper.kt'),
 ('SAST-RES-01', '01_proguard_signature.txt', 'grep -nE "enableProguardInReleaseBuilds|minifyEnabled|storePassword .android.|signingConfig signingConfigs.debug" android/app/build.gradle'),
 ('SAST-PLT-02', '01_permissions.txt', f'grep -n "uses-permission" {A}/AndroidManifest.xml'),
 ('SAST-PLT-02', '02_localisation_conditionnelle.txt', 'sed -n 90,100p app/managers/session_attributes_manager/index.ts'),
 ('SAST-PLT-03', '01_composants_exportes.txt', f'grep -nE "<activity|<service|<receiver|<provider|exported|launchMode|taskAffinity" {A}/AndroidManifest.xml'),
 ('SAST-PLT-03', '02_pendingintent_mutable.txt', f'sed -n 155,166p {J}/CustomPushNotificationHelper.java'),
 ('SAST-CODE-01', '01_sql_parametre.txt', f'sed -n 185,190p {J}/database_extension/General.kt; echo "-- appelants (noms de table/colonne littéraux) :"; grep -rhoE "(queryIds|queryByColumn|countByColumn|findByColumns)\\(db, *[^,]+, *[^,)]+" android/app/src/main/java | sort -u'),
 ('SAST-CODE-01', '02_regex_echappee.txt', 'sed -n 402,412p app/utils/deep_link/index.ts'),
 ('SAST-DEP-02', '01_collision_nom_paquet.txt', 'head -4 libraries/@mattermost/hardware-keyboard/package.json; grep -n "hardware-keyboard" package.json'),
 ('SAST-SEC-01', '01_cle_firebase.txt', 'grep -n "current_key" android/app/google-services.json | sed -E "s/(AIza[0-9A-Za-z_-]{6})[0-9A-Za-z_-]+/\\1…(masqué)/"; grep -nE "ApiKey|Dsn" assets/base/config.json'),
]

for tid, fname, cmd in EV:
    d = os.path.join(OUT, tid); os.makedirs(d, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    res = subprocess.run(['bash', '-c', cmd], cwd=SRC, capture_output=True, text=True)
    with open(os.path.join(d, fname), 'w') as f:
        f.write(f'# Test      : {tid}\n# Horodatage: {ts} (UTC)\n# Source    : mattermost-mobile v2.46.0 @ 655df13\n# Commande  : {cmd}\n# ----\n')
        f.write(res.stdout + (res.stderr if res.returncode not in (0, 1) else ''))
    print(tid, fname, len(res.stdout.splitlines()), 'lignes')
