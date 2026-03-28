# Rapport — Système de déploiement automatisé MIrAI

## Résumé exécutif

Le système de déploiement automatisé MIrAI permet de distribuer des mises à jour de l'extension LibreOffice vers les postes utilisateurs via le serveur Device Management. Il supporte le rollout progressif par paliers (canary → early adopters → GA), le reporting de statut, et le pilotage depuis un CLI, VSCode, ou un coding assistant. Un simulateur permet de valider les campagnes à l'échelle avant déploiement réel.

## Architecture

```
                         ┌─────────────────────┐
                         │   scripts/           │
                         │   deploy-release.sh  │
                         │   (build + upload)   │
                         └──────┬──────────────┘
                                │
                     POST /api/artifacts (upload OXT)
                     POST /api/campaigns (create)
                     PATCH /api/campaigns/{id}/start
                                │
                                ▼
                ┌───────────────────────────────┐
                │   Device Management (K8s)     │
                │   ┌─────────────────────────┐ │
                │   │ /config/libreoffice/    │ │◄── GET (plugin fetch)
                │   │   config.json           │ │    + X-Plugin-Version
                │   │   → update directive    │ │    + X-Client-UUID
                │   ├─────────────────────────┤ │
                │   │ /binaries/              │ │◄── GET (OXT download)
                │   ├─────────────────────────┤ │
                │   │ /update/status          │ │◄── POST (status report)
                │   ├─────────────────────────┤ │
                │   │ /api/campaigns/         │ │◄── REST API (admin)
                │   │   {id}/progress         │ │
                │   └─────────────────────────┘ │
                │   ┌─────────────────────────┐ │
                │   │ PostgreSQL              │ │
                │   │ campaigns, artifacts,   │ │
                │   │ cohorts, campaign_device │ │
                │   │ _status                 │ │
                │   └─────────────────────────┘ │
                └───────────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            │                   │                   │
            ▼                   ▼                   ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  Device A    │  │  Device B    │  │  Device N    │
    │  (canary 5%) │  │  (25% tier)  │  │  (GA 100%)   │
    │              │  │              │  │              │
    │ 1. Fetch cfg │  │ 1. Fetch cfg │  │ 1. Fetch cfg │
    │ 2. Download  │  │ 2. No update │  │ 2. No update │
    │ 3. Install   │  │    (not yet) │  │    (not yet) │
    │ 4. Report OK │  │              │  │              │
    └──────────────┘  └──────────────┘  └──────────────┘
```

## Composants modifiés

### Plugin (AssistantMiraiLibreOffice)

| Fichier | Modification |
|---------|-------------|
| `src/mirai/entrypoint.py` | `_report_update_status()` — reporting au serveur avec retry 3x backoff |
| `src/mirai/entrypoint.py` | `_perform_update()` — retry download 3x, cleanup fichier temp, gestion urgency |
| `src/mirai/entrypoint.py` | `_schedule_update()` — dispatch selon urgency (critical/normal/deferred) |
| `tests/unit/test_update_directive.py` | 13 tests : hash distribution, directive parsing, payload validation |
| `tests/simulation/deploy_simulator.py` | Simulateur de N devices avec concurrence et rapport JSON |
| `scripts/deploy-release.sh` | CLI de déploiement : build → upload → campagne → rollout |
| `.vscode/tasks.json` | 11 tâches VSCode (build, deploy, simulate, test, K8s) |
| `CLAUDE.md` | Instructions pour coding assistants |

### Serveur (device-management)

| Fichier | Modification |
|---------|-------------|
| `app/main.py` | `POST /update/status` — endpoint de reporting statut |
| `app/main.py` | `_get_current_rollout_percent()` — calcul du palier actif |
| `app/main.py` | `_build_update_directive()` — gating par hash UUID et rollout_config |
| `app/main.py` | `_resolve_active_campaign()` — SELECT rollout_config, campaign_created_at |
| `app/main.py` | API REST campagnes : create, start, pause, resume, abort, progress |
| `app/main.py` | `POST /api/artifacts` — upload d'artifact via REST |
| `db/migrations/004_rollout_config.sql` | ALTER TABLE campaigns ADD rollout_config JSONB |

## API de déploiement

| Méthode | Path | Description | Auth |
|---------|------|-------------|------|
| POST | `/update/status` | Plugin reporte succès/échec d'installation | Bearer (optionnel) |
| POST | `/api/artifacts` | Upload d'un binaire OXT | X-Admin-Token |
| POST | `/api/campaigns` | Créer une campagne | X-Admin-Token |
| PATCH | `/api/campaigns/{id}/start` | Démarrer le rollout | X-Admin-Token |
| PATCH | `/api/campaigns/{id}/pause` | Mettre en pause | X-Admin-Token |
| PATCH | `/api/campaigns/{id}/resume` | Reprendre | X-Admin-Token |
| PATCH | `/api/campaigns/{id}/abort` | Annuler et rollback | X-Admin-Token |
| GET | `/api/campaigns/{id}/progress` | Progression détaillée | X-Admin-Token |

## Stratégies de rollout

### Canary (par défaut)
```json
{
  "strategy": "percentage",
  "stages": [
    {"percent": 5,   "duration_hours": 24, "label": "canary"},
    {"percent": 25,  "duration_hours": 48, "label": "early_adopters"},
    {"percent": 100, "duration_hours": 0,  "label": "general_availability"}
  ],
  "auto_advance": true,
  "rollback_on_failure_rate": 0.1
}
```
- 5% des devices pendant 24h → si OK → 25% pendant 48h → si OK → 100%
- L'attribution est déterministe : `md5(client_uuid)[:8] % 100 < percent`
- Même device = même palier à chaque requête

### Immédiat
```json
{
  "strategy": "immediate",
  "stages": [{"percent": 100, "duration_hours": 0, "label": "immediate"}]
}
```

## Simulateur

```bash
python3 tests/simulation/deploy_simulator.py \
    --devices 500 \
    --concurrency 50 \
    --bootstrap-url https://bootstrap.fake-domain.name \
    --campaign-id 1 \
    --failure-rate 0.05 \
    --profile int
```

**Paramètres** :
- `--devices` : nombre de devices simulés
- `--concurrency` : requêtes parallèles
- `--failure-rate` : taux d'échec simulé (0.05 = 5%)
- `--output` : chemin du rapport JSON

**Output** : barre de progression ASCII + rapport JSON avec latences, taux de succès, distribution.

## Tests

| Test | Couverture |
|------|-----------|
| `test_update_directive.py::TestDeviceHash` | Distribution uniforme du hash (5%, 25%, 100%) |
| `test_update_directive.py::TestUpdateDirectiveParsing` | Parsing directive update/rollback, checksum |
| `test_update_directive.py::TestStatusPayload` | Format payload installed/failed |
| `deploy_simulator.py` | Test d'intégration à l'échelle (N devices simultanés) |

**Résultat** : 13/13 tests passent.

## Recommandations futures

1. **Dashboard temps réel** — WebSocket ou SSE dans l'admin UI pour afficher la progression live
2. **Notifications push** — Webhook Slack/Teams quand un palier est complété ou le taux d'échec dépasse le seuil
3. **Auto-rollback** — Le serveur vérifie automatiquement le taux d'échec et passe en `paused` si > seuil
4. **A/B testing config** — Utiliser le même mécanisme de cohorts pour distribuer des configs différentes
5. **Signature d'artifact** — Ed25519 en plus du checksum SHA256 pour vérifier l'authenticité
6. **Métriques Prometheus** — Exporter les compteurs de campagne pour Grafana

## Bilan

| Métrique | Valeur |
|----------|--------|
| Fichiers créés | 6 (simulateur, CLI, tâches VSCode, CLAUDE.md, migration SQL, tests) |
| Fichiers modifiés | 3 (entrypoint.py, device-management/main.py, config) |
| Endpoints ajoutés | 8 (REST API campagnes + update/status + artifact upload) |
| Tests ajoutés | 13 |
| Lignes de code ajoutées | ~900 |

Le système est fonctionnel de bout en bout : un humain ou un coding assistant peut exécuter `scripts/deploy-release.sh` pour déployer une nouvelle version avec rollout canary, suivre la progression via l'API, et valider à l'échelle avec le simulateur.
