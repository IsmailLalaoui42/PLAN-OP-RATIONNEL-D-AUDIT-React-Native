#!/usr/bin/env python3
"""Écrit livrables/donnees_sast.json (même schéma que donnees_audit.json du Membre 3) + inventaire."""
import json, sys, os, collections

OUT = sys.argv[1]
SRC = sys.argv[2]
RAW = sys.argv[3]

def P(tid):
    d = os.path.join(OUT, '04_Preuves', tid)
    return [f'{tid}/{f}' for f in sorted(os.listdir(d))] if os.path.isdir(d) else []

C = []
def add(**k):
    k['preuves'] = P(k['id']); C.append(k)

add(id='SAST-NET-01', titre="Trafic en clair autorisé et AC utilisateur approuvées ; épinglage prévu mais inactif",
    categorie='Réseau / TLS', masvs='MASVS-NETWORK-1, MASVS-NETWORK-2', mastg='MASTG-TEST-0235 / 0286 / 0242', iso='A.13.2.1, A.14.1.3, A.10.1.1',
    fichiers='android/app/src/main/res/xml/network_security_config.xml:3,8 ; AndroidManifest.xml:55,57 ; rnshare/ShareWorker.kt:47',
    exigence="Interdire HTTP et ne faire confiance qu'aux AC système ; épingler le certificat pour une app sensible.",
    observation="base-config cleartextTrafficPermitted=\"true\" et <certificates src=\"user\"/> pour tout domaine ; usesCleartextTraffic=\"true\" dans le manifeste. Un épinglage existe (OkHttp CertificatePinner alimenté par assets/certs/*.cer) mais le dossier ne contient qu'un .gitignore dans le build public : aucun certificat épinglé.",
    cause_dast=['DAST-NET-03', 'DAST-NET-05'], gravite='Élevée', etat='Non conforme', resultat='non_conforme',
    recommandation="cleartextTrafficPermitted=false, retirer src=\"user\" (ou le limiter à <debug-overrides>), livrer les certificats du serveur dans assets/certs pour les déploiements sensibles.",
    outil='mobsfscan (android_manifest_base_config_cleartext, _trust_user_certs, android_ssl_pinning absent) ; Semgrep (nsc-allows-user-ca-certs) ; revue manuelle')

add(id='SAST-NET-02', titre="Repli silencieux HTTPS → HTTP à l'ajout d'un serveur",
    categorie='Réseau / TLS', masvs='MASVS-NETWORK-1', mastg='MASTG-TEST-0235', iso='A.13.2.1, A.14.2.5',
    fichiers='app/screens/server/index.tsx:320-325 ; app/screens/edit_server/edit_server.tsx:124-126 ; app/actions/remote/session.ts:431-439',
    exigence="Un échec HTTPS ne doit jamais entraîner une nouvelle tentative en clair sans action explicite de l'utilisateur.",
    observation="pingServer() appelle getServerUrlAfterRedirect() en HTTPS ; si la requête échoue pour n'importe quelle raison (erreur TLS, port 443 bloqué), l'URL est réécrite pingUrl.replace('https:', 'http:') et la connexion est retentée en HTTP sans avertissement. Même logique dans l'édition du serveur et la connexion par lien magique. Un attaquant réseau qui bloque le 443 pendant l'ajout du serveur obtient donc une session en clair.",
    cause_dast=['DAST-NET-03'], gravite='Élevée', etat='Non conforme', resultat='non_conforme',
    recommandation="Supprimer le repli automatique ; si HTTP doit rester possible, l'exiger explicitement (http:// saisi) avec un avertissement bloquant.",
    contre_test_propose="Saisir https://<hôte> avec le 443 coupé et un serveur HTTP actif sur le 80 : vérifier dans mitmproxy que l'app bascule en HTTP.",
    outil='Revue manuelle (aucune règle Semgrep ne couvre ce motif)')

add(id='SAST-PLT-01', titre="Lien magique : connexion automatique à un serveur arbitraire via deep link",
    categorie='Plateforme / Liens profonds', masvs='MASVS-PLATFORM-1, MASVS-AUTH-1', mastg='MASTG-TEST-0028', iso='A.14.2.5, A.9.4.2',
    fichiers='app/utils/deep_link/index.ts:59-65,374-381 ; app/init/launch.ts:135-141 ; app/actions/remote/session.ts:430-456 ; AndroidManifest.xml:89,95',
    exigence="Un lien externe ne doit pas ajouter un serveur ni ouvrir une session sans confirmation de l'utilisateur.",
    observation="Un lien mattermost://<serveur>/login/one_time_link?t=<jeton> vers un serveur inconnu déclenche directement magicLinkLogin() : création du client, connexion au compte désigné par le jeton et envoi des identifiants push (deviceId, voipDeviceId) à ce serveur, sans écran de confirmation, y compris au lancement à froid. Le schéma est déclaré BROWSABLE, donc déclenchable depuis une page web ou une autre app. Risque : l'utilisateur se retrouve connecté au serveur de l'attaquant et y publie du contenu sensible.",
    cause_dast=['DAST-PLT-02'], gravite='Moyenne', etat='Non conforme (à confirmer en dynamique)', resultat='non_conforme',
    recommandation="Afficher une confirmation (nom et URL du serveur) avant tout ajout de serveur ou connexion issue d'un lien ; n'envoyer les jetons push qu'après confirmation ; refuser HTTP.",
    contre_test_propose="adb shell am start -a android.intent.action.VIEW -d 'mattermost://<serveur_labo_2>/login/one_time_link?t=<jeton>' com.mattermost.rnbeta ; observer l'absence de confirmation.",
    outil='Revue manuelle (suite du constat DAST-PLT-02)')

add(id='SAST-STO-01', titre="Jeton dans le Keystore, mais base locale non chiffrée",
    categorie='Stockage', masvs='MASVS-STORAGE-1', mastg='MASTG-TEST-0001 / 0052', iso='A.10.1.1, A.8.2.3',
    fichiers='app/init/credentials.ts:130-133 ; package.json (@nozbe/watermelondb)',
    exigence="Les données sensibles au repos doivent être chiffrées ou stockées dans le Keystore.",
    observation="Le jeton est écrit par react-native-keychain (SECURITY_LEVEL.SECURE_SOFTWARE, pas SECURE_HARDWARE). Aucune trace de SQLCipher ni de clé de chiffrement : la base WatermelonDB (messages) est en clair. Le cookie MMAUTHTOKEN relevé en dynamique n'est pas écrit par le code de l'app : il est posé par le serveur et conservé par la pile HTTP/WebView.",
    cause_dast=['DAST-STO-01'], gravite='Moyenne', etat='Partiel', resultat='partiel',
    recommandation="Chiffrer la base (SQLCipher) avec une clé du Keystore ; passer en SECURE_HARDWARE quand disponible ; vider les cookies serveur après lecture du jeton.",
    outil='Revue manuelle')

add(id='SAST-STO-02', titre="Anti-capture, détection root et biométrie désactivées par défaut (pilotées par le serveur)",
    categorie='Stockage / Plateforme', masvs='MASVS-PLATFORM-3, MASVS-RESILIENCE-1', mastg='MASTG-TEST-0010', iso='A.11.2.9, A.8.2.3',
    fichiers='app/managers/security_manager/index.ts:232-234,490,898',
    exigence="Les écrans sensibles doivent être protégés contre la capture.",
    observation="isScreenCapturePrevented() renvoie false si MobilePreventScreenCapture n'est pas fourni par le serveur ; idem pour MobileJailbreakProtection et MobileEnableBiometrics. Ces paramètres relèvent de la licence Enterprise : sans elle, aucune protection n'est appliquée.",
    cause_dast=['DAST-STO-07', 'CT-STO-07'], gravite='Moyenne', etat='Non conforme', resultat='non_conforme',
    recommandation="Activer la protection par défaut côté app (sécurité par défaut) ou documenter l'exigence de licence dans la politique de déploiement.",
    outil='mobsfscan (android_prevent_screenshot, android_root_detection : absents) ; revue manuelle')

add(id='SAST-DEP-01', titre="Dépendances vulnérables (npm audit)",
    categorie='Dépendances', masvs='MASVS-CODE-3', mastg='MASTG-TEST-0042', iso='A.12.6.1, A.14.2.1',
    fichiers='package-lock.json',
    exigence="Aucune dépendance embarquée ne doit présenter de vulnérabilité connue exploitable.",
    observation="51 alertes (3 critiques, 25 élevées, 21 moyennes, 2 faibles). La plupart concernent l'outillage de build (expo CLI, metro, handlebars, shell-quote) et n'entrent pas dans l'APK. Embarqués à l'exécution : zod <4.6.6 (déni de service, via react-native-network-client) et query-string / decode-uri-component (déni de service sur URI malformée, via expo-router, donc atteignable par lien profond).",
    cause_dast=[], gravite='Moyenne', etat='Partiel', resultat='partiel',
    recommandation="Mettre à jour zod, query-string et expo-router ; ajouter npm audit --omit=dev en CI ; traiter l'outillage de build séparément.",
    outil='npm audit --package-lock-only (npm ' + 'registry, ' + '2026-11-18)')

add(id='SAST-DEP-02', titre="Faux positif « malware » : collision de nom avec un paquet npm malveillant",
    categorie='Dépendances', masvs='MASVS-CODE-3', mastg='—', iso='A.14.2.1, A.15.1.1',
    fichiers='libraries/@mattermost/hardware-keyboard/package.json:2',
    exigence="Les paquets internes ne doivent pas être résolubles depuis le registre public.",
    observation="npm audit signale « Malware in mattermost-hardware-keyboard » (GHSA-322h-w7g8-cg56, critique). Vérification : la bibliothèque est locale (file:./libraries/…, lien symbolique, aucune URL resolved) ; le paquet malveillant n'est pas installé. Mais le nom interne non préfixé est identique à un paquet malveillant publié : risque de confusion de dépendance si la référence file: est un jour remplacée par une version.",
    cause_dast=[], gravite='Faible', etat='Partiel', resultat='partiel',
    recommandation="Renommer le paquet local avec le préfixe @mattermost/ et réserver ce nom sur le registre.",
    outil='npm audit + vérification manuelle du package-lock.json')

add(id='SAST-RES-01', titre="Release sans R8/ProGuard ; repli sur la clé de débogage",
    categorie='Résilience / Build', masvs='MASVS-RESILIENCE-3, MASVS-CODE-1', mastg='MASTG-TEST-0039 / 0051', iso='A.14.2.6, A.14.2.8',
    fichiers='android/app/build.gradle:76,157,161-163',
    exigence="Le build de production doit être minifié et signé avec une clé de production.",
    observation="enableProguardInReleaseBuilds = false : le code natif n'est ni réduit ni obfusqué en release. Si MATTERMOST_RELEASE_STORE_FILE est absent, la release est signée avec debug.keystore (mot de passe « android »). Cohérent avec DAST-RES-01 (APK distribué non signé, à signer par le déployeur).",
    cause_dast=['DAST-RES-01'], gravite='Faible', etat='Partiel', resultat='partiel',
    recommandation="Activer R8 en release ; faire échouer le build release si la clé de production manque.",
    outil='Revue manuelle')

add(id='SAST-PLT-02', titre="Permissions : localisation précise demandée sous condition",
    categorie='Plateforme / Vie privée', masvs='MASVS-PLATFORM-1, MASVS-PRIVACY-1', mastg='MASTG-TEST-0024', iso='A.18.1.4, A.9.4.1',
    fichiers='AndroidManifest.xml:8-36 ; app/managers/session_attributes_manager/index.ts:95-97',
    exigence="Ne déclarer que les permissions nécessaires et les demander au moment de l'usage.",
    observation="ACCESS_FINE_LOCATION est déclarée pour lire le SSID Wi-Fi ; elle n'est demandée que si le serveur exige l'attribut de session « ssid ». Caméra, micro et Bluetooth servent aux appels et pièces jointes. Les permissions de stockage sont limitées à maxSdkVersion 32.",
    cause_dast=['DAST-PLT-03'], gravite='Information', etat='Conforme (remarque)', resultat='conforme',
    recommandation="Documenter pour l'utilisateur l'usage de la localisation liée au SSID.",
    outil='Revue manuelle')

add(id='SAST-PLT-03', titre="Composants exportés, task hijacking et PendingIntent : faux positifs écartés",
    categorie='Plateforme', masvs='MASVS-PLATFORM-1', mastg='MASTG-TEST-0029', iso='A.14.2.5',
    fichiers='AndroidManifest.xml:71-119 ; CustomPushNotificationHelper.java:162',
    exigence="Seuls les composants nécessaires sont exportés ; pas de détournement de tâche.",
    observation="Exportés : MainActivity (lanceur + schémas) et ShareActivity (SEND), attendus. Services et receivers : exported=false. mobsfscan signale un task hijacking (launchMode=singleTask) : écarté, car taskAffinity=\"\" et targetSdk 36. PendingIntent FLAG_MUTABLE : intent explicite (composant nommé), nécessaire à la réponse rapide (RemoteInput), donc acceptable.",
    cause_dast=['DAST-PLT-01'], gravite='Information', etat='Conforme', resultat='conforme',
    recommandation='—', outil='mobsfscan (android_task_hijacking1/2, android_pending_intent_not_immutable) ; Semgrep (exported_activity)')

add(id='SAST-STO-03', titre="Journaux : pas de jeton ni de mot de passe journalisé",
    categorie='Stockage / Journaux', masvs='MASVS-STORAGE-2', mastg='MASTG-TEST-0003', iso='A.12.4.1, A.18.1.4',
    fichiers='app/utils/log.ts ; PushNotificationDataHelper.kt:58,119 ; assets/base/config.json:15',
    exigence="Aucune donnée sensible dans les journaux.",
    observation="Les appels logDebug/logWarning autour des identifiants ne journalisent que des messages d'état ; le jeton push est tronqué (redactedDeviceId). Les journaux natifs contiennent l'URL du serveur, l'ID du canal et l'ackId (métadonnées). Sentry est désactivé par défaut (SentryEnabled=false).",
    cause_dast=['DAST-STO-02'], gravite='Information', etat='Conforme (remarque)', resultat='conforme',
    recommandation="Retirer les identifiants de canal des journaux natifs en release.",
    outil='mobsfscan (android_kotlin_logging, 141 occurrences triées) ; grep')

add(id='SAST-SEC-01', titre="Secrets codés en dur : aucun secret exploitable",
    categorie='Code / Secrets', masvs='MASVS-STORAGE-1, MASVS-CODE-1', mastg='MASTG-TEST-0014', iso='A.9.4.3, A.14.2.1',
    fichiers='android/app/google-services.json:24 ; assets/base/config.json',
    exigence="Aucune clé privée, mot de passe ou jeton dans le code source.",
    observation="detect-secrets : 103 alertes, toutes des faux positifs (libellés i18n contenant « password », noms d'en-têtes ou de constantes). Seule valeur réelle : la clé d'API Firebase du google-services.json, qui est un identifiant client public par conception (la sécurité repose sur les restrictions côté console). Clés Rudder et DSN Sentry vides. Les 3 « hardcoded secrets » de mobsfscan sont dans des fichiers de test ; « hardcoded_api_key » pointe la constante KEY_TEXT_REPLY = « CAN_REPLY » (faux positif).",
    cause_dast=[], gravite='Information', etat='Conforme', resultat='conforme',
    recommandation="Vérifier que la clé Firebase est restreinte à l'empreinte de l'app côté console.",
    outil='detect-secrets 1.x ; mobsfscan (js_hardcoded_secret, hardcoded_api_key)')

add(id='SAST-CODE-01', titre="Injection SQL et ReDoS : faux positifs écartés",
    categorie='Code', masvs='MASVS-CODE-4', mastg='MASTG-TEST-0019', iso='A.14.2.5',
    fichiers='database_extension/General.kt:164-200 ; app/utils/deep_link/index.ts:409',
    exigence="Les requêtes SQL et expressions régulières ne doivent pas intégrer d'entrée non maîtrisée.",
    observation="mobsfscan relève 20 rawQuery Kotlin : les valeurs sont toujours passées en paramètres « ? » et les noms de table et de colonne sont des littéraux dans tous les appelants. Semgrep relève 9 RegExp non littérales : l'entrée passe toujours par escapeRegex() ou recopie une RegExp existante. L'alerte « prototype-pollution-assignment » (post_list/index.ts:302) porte sur une clé userId fournie par le serveur : non exploitable en pratique.",
    cause_dast=[], gravite='Information', etat='Conforme', resultat='conforme',
    recommandation='—', outil='mobsfscan (android_kotlin_sql_raw_query) ; Semgrep (detect-non-literal-regexp)')

meta = {
  'projet': "Audit statique d'une application mobile React Native", 'module': 'Compliance et Gouvernance International',
  'encadrant': 'Pr. Abdelhadi Zineddine', 'membre': 'Membre 2 — Audit statique (Nada Elaali)',
  'cible': 'Mattermost Mobile 2.46.0 (build 835) — même version que l\'APK du Membre 3',
  'depot': 'https://github.com/mattermost/mattermost-mobile', 'tag': 'v2.46.0', 'commit': '655df13b131da6810f4f073622c925af1b87c3fb',
  'outils': ['Semgrep 1.186.0 (règles semgrep-rules javascript/typescript/java/kotlin, clonées depuis GitHub)', 'mobsfscan 1.2.0', 'npm audit (package-lock-only)', 'detect-secrets', 'revue manuelle (grep, lecture du code)'],
  'referentiels': ['OWASP MASVS 2.x', 'OWASP MASTG', 'ISO/IEC 27001:2013 (annexe A, grille pédagogique)'],
  'periode': '2026-11-18', 'perimetre': 'Code JS/TS (app/), natif Android (android/, libraries/@mattermost/*/android), configuration et dépendances ; iOS hors périmètre ; fichiers de test exclus.',
  'limites': "Le registre Semgrep (semgrep.dev) n'était pas joignable : règles communautaires du dépôt GitHub semgrep-rules utilisées. Les jeux p/react-native de MobSF ne couvrent pas tout le natif. Le build Android n'a pas été recompilé : l'analyse porte sur le source du tag correspondant à l'APK du Membre 3. SAST-NET-02 et SAST-PLT-01 sont déduits du code : contre-tests proposés au Membre 3.",
}
json.dump({'meta': meta, 'echelle_gravite': ['Critique', 'Élevée', 'Moyenne', 'Faible', 'Information'], 'constats': C},
          open(os.path.join(OUT, 'livrables', 'donnees_sast.json'), 'w'), ensure_ascii=False, indent=1)
print(len(C), 'constats', collections.Counter(c['resultat'] for c in C), collections.Counter(c['gravite'] for c in C))
for c in C:
    assert c['preuves'] or c['id'] in ('SAST-DEP-01',), c['id']
