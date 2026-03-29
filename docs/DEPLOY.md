# Deployer une nouvelle version MIrAI dans Device Management

## Prerequis

- Acces au repo `AssistantMiraiLibreOffice`
- Variable `DM_ADMIN_TOKEN` configuree (token admin DM)
- URL du bootstrap DM (ex: `https://bootstrap.fake-domain.name`)

## Methode 1 : Script automatise

```bash
# Bump version, build, affiche les instructions
./scripts/bump-version.sh 0.0.8.0.0

# Commit + push
git add -A && git commit -m "release: v0.0.8.0.0" && git push

# Deployer en canary (integration)
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --strategy canary --profile int

# Deployer en production (immediat)
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --strategy immediate --profile prod
```

## Methode 2 : Deploiement manuel

### Etape 1 — Mettre a jour la version

Modifier ces 3 fichiers avec le nouveau numero de version :

| Fichier | Champ |
|---------|-------|
| `oxt/description.xml` | `<version value="X.Y.Z"/>` |
| `dm-manifest.json` | `changelog[0].version` |
| `oxt/registration/license.txt` | `version X.Y.Z` |

### Etape 2 — Builder le package

```bash
./scripts/02-build-oxt.sh --config config/profiles/config.default.integration.json
```

Resultat : `dist/mirai.oxt`

### Etape 3 — Uploader l'artefact dans DM

```bash
# Upload via l'API admin DM
curl -X PUT \
  -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  -F "file=@dist/mirai.oxt" \
  "https://bootstrap.fake-domain.name/api/artifacts/upload?slug=mirai-libreoffice&version=X.Y.Z"
```

### Etape 4 — Creer une campagne de deploiement

**Canary (rollout progressif)** :
```bash
curl -X POST \
  -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "mirai-libreoffice",
    "target_version": "X.Y.Z",
    "strategy": "canary",
    "profile": "int",
    "rollout_percent": 10,
    "urgency": "normal"
  }' \
  "https://bootstrap.fake-domain.name/api/campaigns"
```

**Immediat (tous les devices)** :
```bash
curl -X POST \
  -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "slug": "mirai-libreoffice",
    "target_version": "X.Y.Z",
    "strategy": "immediate",
    "profile": "prod",
    "urgency": "normal"
  }' \
  "https://bootstrap.fake-domain.name/api/campaigns"
```

### Etape 5 — Suivre le deploiement

```bash
# Progression de la derniere campagne
curl -s -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  "https://bootstrap.fake-domain.name/api/campaigns/latest/progress" \
  | python3 -m json.tool

# Progression d'une campagne specifique
curl -s -H "X-Admin-Token: $DM_ADMIN_TOKEN" \
  "https://bootstrap.fake-domain.name/api/campaigns/{id}/progress" \
  | python3 -m json.tool

# Console admin (navigateur)
open "https://bootstrap.fake-domain.name/admin/campaigns"
```

## Rollback

```bash
# Deployer l'ancienne version en urgence
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --version 0.0.7.0.0 \
  --strategy immediate --profile prod
```

## Simulation (test sans impact)

```bash
# Simuler 100 devices
python3 tests/simulation/deploy_simulator.py \
  --devices 100 \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --profile int
```
