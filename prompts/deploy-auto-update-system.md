# Prompt — Déploiement automatisé MIrAI LibreOffice

> Ce prompt est conçu pour être exécuté de manière autonome par un coding assistant (Claude Code, Cursor, etc.)
> Il produit du code, des tests, un simulateur, et un rapport final.
> Temps estimé : session longue (2-4h).

---

## Contexte

Deux dépôts collaborent pour le déploiement automatisé de l'extension LibreOffice MIrAI :

### 1. `AssistantMiraiLibreOffice` (le plugin)
- Extension `.oxt` pour LibreOffice Writer et Calc
- **Déjà implémenté** :
  - `_schedule_update(directive)` + `_perform_update(directive)` dans `src/mirai/entrypoint.py` (~ligne 952-1045)
  - Télécharge le binaire, vérifie le checksum SHA256, installe via `ExtensionManager.addExtension()`
  - Notification utilisateur "Redémarrez LibreOffice pour finaliser"
  - Télémétrie `ExtensionUpdated` envoyée après succès
  - La directive `update` est extraite de la réponse bootstrap `EnrichedConfigResponse`
- **Manquant / incomplet** :
  - Pas de reporting du statut d'installation au serveur (succès/échec/version installée)
  - Pas de gestion des erreurs réseau (retry, reprise)
  - Pas d'UI de progression pour l'utilisateur
  - Pas d'envoi de la version courante dans le header de la requête config
  - Pas de gestion de l'urgence (`urgency: critical` → install immédiat vs `normal` → différé)
  - Pas de rollback automatique si l'extension crashe après update

### 2. `device-management` (le serveur)
- API FastAPI avec PostgreSQL
- **Déjà implémenté** :
  - Modèle `artifacts` (upload OXT, checksum, version, S3 path)
  - Modèle `campaigns` (artifact → cohort, status, urgency, deadline, rollback_artifact)
  - Modèle `cohorts` (groupes de devices par type/email/uuid)
  - `_build_update_directive()` dans `app/main.py` (~ligne 776) : construit la directive update/rollback
  - `_upsert_campaign_device_status()` : tracking par device
  - Admin UI (OIDC) avec CRUD artifacts/campaigns/cohorts/devices
  - Endpoint `/config/{device_type}/config.json` renvoie la directive dans `response.update`
  - Storage S3 ou local pour les binaires
- **Manquant / incomplet** :
  - Pas d'endpoint de reporting de statut post-update (`POST /update/status`)
  - Pas de rollout progressif (pourcentage/paliers)
  - Pas de métriques de santé post-déploiement
  - Pas de vue de progression de campagne en temps réel
  - Pas de déclenchement depuis CLI/API (tout passe par l'admin UI)

### Environnement de déploiement
- K8s overlay Scaleway : `device-management/deploy/k8s/overlays/scaleway/`
- Bootstrap : `https://bootstrap.fake-domain.name`
- Keycloak : `https://mysso.fake-domain.name/realms/openwebui` (client: `bootstrap-iassistant`)
- LLM Scaleway : `https://api.scaleway.ai/...`
- Config profiles : `dev`, `int`, `prod`

---

## Mission

Exécute les phases ci-dessous dans l'ordre. Chaque phase produit du code fonctionnel et testé.
À la fin, génère un rapport complet dans `docs/deploy-auto-update-report.md`.

---

## Phase 1 — Plugin : compléter le client de mise à jour

### 1.1 Reporting de statut au serveur

Dans `src/mirai/entrypoint.py`, après `_perform_update()`, envoyer un `POST /update/status` au device-management :

```json
{
  "campaign_id": 42,
  "client_uuid": "xxx",
  "status": "installed|failed|checksum_error|download_error",
  "version_before": "1.0.0",
  "version_after": "1.1.0",
  "error_detail": "",
  "timestamp": "2026-03-28T12:00:00Z"
}
```

- Endpoint = `bootstrap_url + "/update/status"`
- Inclure le token d'accès si disponible
- Retry 3 fois avec backoff exponentiel en cas d'échec réseau

### 1.2 Envoi de la version courante

Dans `_fetch_config()`, ajouter un header `X-Plugin-Version: <version>` à la requête bootstrap.
Le device-management pourra ainsi construire la directive update sans dépendre du champ dans le body.

### 1.3 Gestion de l'urgence

Dans `_schedule_update()` :
- `urgency: critical` → téléchargement et installation immédiats, dialogue modal "Mise à jour critique en cours..."
- `urgency: normal` → téléchargement en arrière-plan, notification non-bloquante "Une mise à jour est disponible. Elle sera appliquée au prochain redémarrage."
- `urgency: deferred` → téléchargement uniquement, installation au prochain démarrage de LibreOffice

### 1.4 Barre de progression

Créer un mini-dialogue UNO (pattern existant : voir `_show_resize_dialog`) avec :
- Barre de progression (ou label pourcentage)
- Label d'état ("Téléchargement...", "Vérification...", "Installation...")
- Bouton Annuler (pour urgency != critical)

**Contrainte** : le téléchargement doit se faire dans un thread avec queue (même pattern que `stream_request`) car le thread principal doit rester disponible pour `processEventsToIdle`.

### 1.5 Retry et reprise réseau

Envelopper le téléchargement dans un retry avec :
- 3 tentatives max
- Backoff : 2s, 5s, 15s
- Logging de chaque tentative
- Si les 3 échouent → statut `download_error` envoyé au serveur

---

## Phase 2 — Serveur : compléter l'API de déploiement

### 2.1 Endpoint POST /update/status

Dans `device-management/app/main.py`, ajouter :

```python
@app.post("/update/status")
async def report_update_status(request: Request):
    # Valider le token PKCE
    # Insérer dans campaign_device_status : status, version_before, version_after, error_detail
    # Si status == "installed" → mettre à jour le device record avec la nouvelle version
    # Si status == "failed" → incrémenter un compteur d'échecs
    # Retourner {"ok": True}
```

### 2.2 Rollout progressif par paliers

Ajouter un champ `rollout_config` au modèle `campaigns` :

```json
{
  "strategy": "percentage",
  "stages": [
    {"percent": 5, "duration_hours": 24, "label": "canary"},
    {"percent": 25, "duration_hours": 48, "label": "early_adopters"},
    {"percent": 100, "duration_hours": 0, "label": "general_availability"}
  ],
  "auto_advance": true,
  "rollback_on_failure_rate": 0.1
}
```

Modifier `_build_update_directive()` pour :
- Calculer le palier actif en fonction du timestamp et de la date de début
- N'envoyer la directive update qu'aux devices qui tombent dans le pourcentage actif (hash(uuid) % 100 < percent)
- Si `auto_advance` et le taux d'échec < seuil → avancer au palier suivant
- Si taux d'échec > `rollback_on_failure_rate` → passer en status `paused` et alerter

### 2.3 API de lancement de campagne

Ajouter des endpoints REST (en plus de l'admin UI) :

```
POST   /api/campaigns              — créer une campagne
PATCH  /api/campaigns/{id}/start   — démarrer le rollout
PATCH  /api/campaigns/{id}/pause   — mettre en pause
PATCH  /api/campaigns/{id}/resume  — reprendre
PATCH  /api/campaigns/{id}/abort   — annuler et rollback
GET    /api/campaigns/{id}/status  — progression détaillée
```

Authentification : token admin (`DM_QUEUE_ADMIN_TOKEN`) ou OIDC.

### 2.4 Vue de progression

Ajouter un endpoint `GET /api/campaigns/{id}/progress` retournant :

```json
{
  "campaign_id": 42,
  "status": "rolling_out",
  "current_stage": "early_adopters",
  "stages": [
    {"label": "canary", "percent": 5, "eligible": 12, "installed": 12, "failed": 0, "pending": 0, "completed_at": "..."},
    {"label": "early_adopters", "percent": 25, "eligible": 60, "installed": 45, "failed": 1, "pending": 14, "started_at": "..."},
    {"label": "general_availability", "percent": 100, "eligible": 240, "installed": 0, "failed": 0, "pending": 240}
  ],
  "failure_rate": 0.004,
  "rollback_threshold": 0.1
}
```

---

## Phase 3 — Simulateur de déploiement à l'échelle

### 3.1 Script de simulation

Créer `tests/simulation/deploy_simulator.py` :

```python
# Simule N devices qui contactent le bootstrap à intervalles aléatoires
# Chaque device :
#   1. GET /config/libreoffice/config.json → reçoit (ou non) une directive update
#   2. Si directive → simule le téléchargement (HEAD sur artifact_url)
#   3. POST /update/status avec succès (95%) ou échec (5%)
#
# Paramètres CLI :
#   --devices 500         nombre de devices simulés
#   --concurrency 50      requêtes parallèles
#   --bootstrap-url https://bootstrap.fake-domain.name
#   --campaign-id 1       campagne à simuler
#   --failure-rate 0.05   taux d'échec simulé
#   --interval 2          secondes entre chaque vague
#   --profile int         profil config
#
# Output :
#   - Progression en temps réel (barre ASCII)
#   - Rapport JSON final avec latences, taux de succès, timeline
```

### 3.2 Fixtures pour tests locaux

Créer `tests/simulation/fixtures.py` :
- Créer N devices via l'API enroll (ou directement en DB)
- Créer un artifact factice
- Créer une campagne avec rollout_config par paliers
- Nettoyer après le test

### 3.3 Test de bout en bout

Créer `tests/simulation/test_e2e_rollout.py` :
1. Upload un artifact (OXT factice)
2. Créer une campagne canary (5%) → early (25%) → GA (100%)
3. Lancer le simulateur avec 100 devices
4. Vérifier que le canary ne touche que ~5 devices
5. Avancer manuellement au palier suivant
6. Vérifier que ~25 devices supplémentaires reçoivent la directive
7. Simuler un échec à 15% → vérifier que la campagne passe en `paused`
8. Résumer les résultats

---

## Phase 4 — Ergonomie et intégration VSCode

### 4.1 Script CLI de déploiement

Créer `scripts/deploy-release.sh` :

```bash
#!/usr/bin/env bash
# Usage: scripts/deploy-release.sh [--version 1.2.0] [--profile int|prod] [--strategy canary|immediate]
#
# Étapes :
# 1. Build l'OXT (scripts/02-build-oxt.sh)
# 2. Calcule le checksum SHA256
# 3. Upload l'artifact via POST /api/artifacts
# 4. Crée une campagne avec la stratégie choisie
# 5. Démarre le rollout
# 6. Affiche l'URL de suivi
```

### 4.2 Tâches VSCode

Créer `.vscode/tasks.json` avec :
- `MIrAI: Build OXT` → `scripts/02-build-oxt.sh`
- `MIrAI: Deploy Canary` → `scripts/deploy-release.sh --strategy canary --profile int`
- `MIrAI: Deploy GA` → `scripts/deploy-release.sh --strategy immediate --profile prod`
- `MIrAI: Campaign Status` → `curl .../api/campaigns/latest/progress | jq`
- `MIrAI: Simulate 100 devices` → `python tests/simulation/deploy_simulator.py --devices 100`

### 4.3 Commandes Claude Code (CLAUDE.md)

Ajouter dans `CLAUDE.md` des instructions pour que le coding assistant puisse :
- `/deploy canary` → build + upload + campagne canary
- `/deploy status` → progression de la dernière campagne
- `/deploy abort` → annuler la campagne en cours
- `/deploy simulate N` → lancer le simulateur avec N devices

---

## Phase 5 — Corrections et robustesse

### 5.1 Audit du code existant

- Vérifier que `_perform_update` gère correctement le cas où `ExtensionManager.addExtension` échoue
- Vérifier que le fichier temporaire est nettoyé dans tous les cas (try/finally)
- Vérifier que le thread de téléchargement ne bloque pas la fermeture de LibreOffice
- S'assurer que les headers `X-Plugin-Version` et `X-Client-UUID` sont envoyés à chaque requête config

### 5.2 Tests unitaires

Ajouter dans `tests/unit/` :
- `test_update_directive.py` : parsing de la directive, gestion des versions, checksum
- `test_update_status_report.py` : format du payload, retry, authentification
- `test_rollout_percentage.py` : hash(uuid) % 100 produit une distribution uniforme

### 5.3 Gestion des edge cases

- Device sans UUID → ne reçoit jamais de directive update
- Campagne sans artifact → directive = None (déjà géré)
- Deux campagnes actives pour le même device_type → seule la plus récente s'applique
- Version courante == version cible → pas de directive (déjà géré)
- Downgrade non autorisé sauf si rollback_artifact est défini (déjà géré)

---

## Phase 6 — Rapport final

Générer `docs/deploy-auto-update-report.md` avec :

```markdown
# Rapport — Système de déploiement automatisé MIrAI

## Résumé exécutif
<!-- 3-5 phrases : quoi, pourquoi, résultat -->

## Architecture
<!-- Diagramme ASCII du flux : build → upload → campagne → rollout → device → status -->

## Composants modifiés

### Plugin (AssistantMiraiLibreOffice)
<!-- Liste des fichiers modifiés/créés avec description -->

### Serveur (device-management)
<!-- Liste des fichiers modifiés/créés avec description -->

## API de déploiement
<!-- Tableau des endpoints avec méthode, path, description, auth -->

## Stratégies de rollout
<!-- Description des stratégies : canary, pourcentage, immédiat -->

## Simulateur
<!-- Comment l'utiliser, paramètres, interprétation des résultats -->

## Tests
<!-- Couverture, résultats, cas limites testés -->

## Recommandations
<!-- Améliorations futures : notifications push, dashboard temps réel, A/B testing config -->

## Bilan
<!-- Heures de travail, lignes de code, complexité, dette technique introduite -->
```

---

## Contraintes techniques

- **Plugin** : Python 3.x embarqué dans LibreOffice, uniquement `urllib.request` (pas de `requests`), API UNO
- **Serveur** : FastAPI, PostgreSQL, S3 optionnel
- **Threading** : ne jamais appeler `processEventsToIdle` depuis un thread secondaire (crash LibreOffice)
- **Pas de dépendances externes** dans le plugin (pas de pip install possible dans LibreOffice Python)
- **Compatibilité** : LibreOffice 7.x+ sur macOS, Linux, Windows
- **Les deux repos sont côte à côte** : `../device-management/` depuis le repo plugin

## Fichiers de référence

| Fichier | Rôle |
|---------|------|
| `src/mirai/entrypoint.py:952-1045` | Client update existant (plugin) |
| `device-management/app/main.py:776-822` | Build directive (serveur) |
| `device-management/app/admin/services/campaigns.py` | CRUD campagnes |
| `device-management/app/admin/services/artifacts.py` | CRUD artifacts |
| `device-management/app/admin/services/cohorts.py` | CRUD cohorts |
| `device-management/app/admin/services/devices.py` | CRUD devices |
| `device-management/deploy/k8s/overlays/scaleway/` | Déploiement K8s |
| `config/profiles/config.default.integration.json` | Profil intégration (bootstrap Scaleway) |

## Ordre d'exécution recommandé

1. Phase 2 (serveur) → les endpoints doivent exister avant que le plugin les appelle
2. Phase 1 (plugin) → client de mise à jour complet
3. Phase 3 (simulateur) → validation à l'échelle
4. Phase 5 (tests + corrections) → robustesse
5. Phase 4 (ergonomie) → CLI + VSCode
6. Phase 6 (rapport) → bilan final
