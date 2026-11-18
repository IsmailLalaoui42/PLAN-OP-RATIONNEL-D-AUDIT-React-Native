# Membre 2 — Audit statique (Nada Elaali)

Cible : **Mattermost Mobile 2.46.0 (build 835)**, tag `v2.46.0`, commit `655df13b131da6810f4f073622c925af1b87c3fb`. C'est la même version que l'APK testé par le Membre 3.

| Dossier | Contenu |
|---|---|
| `inventaire/` | Inventaire du code (volumes, modules, fichiers sensibles revus) et `dependances.csv` (100 dépendances d'exécution, 55 de développement) |
| `04_Preuves/SAST-*/` | Extraits de code horodatés : chaque fichier indique la commande qui le régénère. `MANIFEST.csv` contient les empreintes SHA-256 (même format que le Membre 3) |
| `outils_bruts/` | Sorties brutes de Semgrep, mobsfscan, npm audit et detect-secrets (les empreintes de secrets sont retirées) |
| `livrables/donnees_sast.json` | 13 constats au même format que `donnees_audit.json` du Membre 3, avec un champ `cause_dast` qui renvoie au test dynamique lié |
| `scripts/` | `ev.py` (régénère les preuves), `constats.py` (régénère le JSON) |

## Reproduire

```bash
git clone --depth 1 --branch v2.46.0 https://github.com/mattermost/mattermost-mobile src
pip install semgrep mobsfscan detect-secrets
git clone --depth 1 https://github.com/semgrep/semgrep-rules rules   # semgrep.dev non joignable
semgrep --config rules/javascript --config rules/typescript --config rules/java --config rules/kotlin \
        --metrics=off --json --exclude '*.test.*' src/app src/android/app/src src/libraries > semgrep.json
mobsfscan --json -o mobsfscan.json src/app src/android src/libraries
(cd src && npm audit --package-lock-only --json) > npm_audit.json
python3 scripts/ev.py src 04_Preuves
```

## Synthèse

| ID | Constat | Gravité | Résultat | Lien DAST |
|---|---|---|---|---|
| SAST-NET-01 | Trafic en clair et AC utilisateur autorisés ; épinglage prévu mais inactif | Élevée | Non conforme | NET-03, NET-05 |
| SAST-NET-02 | Repli silencieux HTTPS → HTTP à l'ajout d'un serveur | Élevée | Non conforme | NET-03 (contre-test proposé) |
| SAST-PLT-01 | Lien magique : connexion automatique à un serveur arbitraire | Moyenne | Non conforme, à confirmer | PLT-02 |
| SAST-STO-01 | Jeton dans le Keystore, mais base locale non chiffrée | Moyenne | Partiel | STO-01 |
| SAST-STO-02 | Anti-capture, détection root et biométrie désactivées par défaut | Moyenne | Non conforme | STO-07 |
| SAST-DEP-01 | 51 vulnérabilités npm ; zod et query-string embarqués | Moyenne | Partiel | — |
| SAST-DEP-02 | Collision de nom avec un paquet npm malveillant (alerte écartée, risque résiduel) | Faible | Partiel | — |
| SAST-RES-01 | Release sans R8 ; repli sur la clé de débogage | Faible | Partiel | RES-01 |
| SAST-PLT-02 | Localisation précise demandée sous condition | Info | Conforme | PLT-03 |
| SAST-PLT-03 | Composants exportés, task hijacking, PendingIntent (faux positifs) | Info | Conforme | PLT-01 |
| SAST-STO-03 | Journaux sans jeton ni mot de passe | Info | Conforme | STO-02 |
| SAST-SEC-01 | Aucun secret exploitable (103 alertes, toutes des faux positifs) | Info | Conforme | — |
| SAST-CODE-01 | Injection SQL et ReDoS (faux positifs) | Info | Conforme | — |
