# Prompt — Nettoyage des clés de configuration MIrAI

> Audit des clés servies par le bootstrap vs lues par le plugin.
> Objectif : supprimer les clés inutiles, ajouter les manquantes, harmoniser.
> Ce prompt s'adresse aux deux repos : **AssistantMiraiLibreOffice** (plugin) et **device-management** (serveur).

---

## Repos concernés

| Repo | Chemin | Rôle |
|------|--------|------|
| **AssistantMiraiLibreOffice** | `/Users/etiquet/Documents/GitHub/AssistantMiraiLibreOffice` | Plugin LibreOffice (client) |
| **device-management** | `/Users/etiquet/Documents/GitHub/device-management` | Serveur bootstrap + API (serveur) |

---

## Synthèse de l'audit

### Clés servies par le bootstrap ET utilisées par le plugin ✅

| Clé bootstrap | Où elle est lue | Rôle |
|---------------|----------------|------|
| `llm_base_urls` | entrypoint.py | URL du backend LLM |
| `llm_default_models` | entrypoint.py | Modèle par défaut |
| `llm_api_tokens` | entrypoint.py | Token API LLM |
| `authHeaderName` | entrypoint.py | Nom du header d'auth (Authorization) |
| `authHeaderPrefix` | entrypoint.py | Préfixe du header (Bearer) |
| `keycloakIssuerUrl` | entrypoint.py | URL du serveur Keycloak |
| `keycloakRealm` | entrypoint.py | Realm Keycloak |
| `keycloakClientId` | entrypoint.py | Client ID OIDC |
| `keycloak_redirect_uri` | entrypoint.py | URI de callback PKCE |
| `keycloak_allowed_redirect_uri` | entrypoint.py | URI autorisée |
| `portal_url` | writer.py, calc.py | URL du portail MIrAI (fallback doc) |
| `doc_url` | writer.py, calc.py | URL de la documentation |
| `systemPrompt` | entrypoint.py | Prompt système global |
| `api_type` | entrypoint.py, calc.py, writer.py | Type d'API (chat/completions) |
| `is_openwebui` | entrypoint.py | Mode OpenWebUI |
| `openai_compatibility` | entrypoint.py | Compatibilité OpenAI |
| `extend_selection_max_tokens` | writer.py | Budget tokens pour "Générer la suite" |
| `extend_selection_system_prompt` | writer.py | Prompt système additionnel |
| `edit_selection_max_new_tokens` | writer.py, entrypoint.py | Budget tokens pour "Modifier" et "Ajuster" |
| `edit_selection_system_prompt` | writer.py | Prompt système additionnel |
| `summarize_selection_max_tokens` | writer.py | Budget tokens pour "Résumer" |
| `summarize_selection_system_prompt` | writer.py | Prompt système additionnel |
| `enabled` | entrypoint.py | Extension activée/désactivée |
| `bootstrap_url` | entrypoint.py | URL du serveur bootstrap |
| `config_path` | entrypoint.py | Chemin de la config sur le serveur |
| `device_name` | entrypoint.py | Nom du device pour l'enrôlement |
| `enrolled` | entrypoint.py | Statut d'enrôlement |
| `access_token` | entrypoint.py | Token PKCE stocké |
| `refresh_token` | entrypoint.py | Refresh token stocké |
| `telemetryEnabled` | entrypoint.py | Télémétrie activée |
| `telemetryEndpoint` | entrypoint.py | URL endpoint télémétrie |
| `telemetryKey` | entrypoint.py | Clé de télémétrie |
| `telemetryAuthorizationType` | entrypoint.py | Type d'auth télémétrie (Bearer/Basic) |
| `telemetrylogJson` | entrypoint.py | Format JSON pour les logs |
| `relayAssistantBaseUrl` | entrypoint.py | URL du relay-assistant |

### Clés servies par le bootstrap MAIS NON utilisées par le plugin ❌

| Clé | Pourquoi inutile | Action |
|-----|-----------------|--------|
| `model` | Valeur `"achanger-model"` — placeholder jamais lu. Le plugin utilise `llm_default_models` | **Supprimer** |
| `_comment_device_management` | Commentaire humain, ignoré par le code | **Supprimer** |
| `simplify_selection_max_tokens` | Servie mais le plugin lit `edit_selection_max_new_tokens` pour Reformuler — **bug** | **Connecter** au code plugin |
| `simplify_selection_system_prompt` | Servie mais jamais lue par le plugin | **Connecter** au code plugin |
| `telemetrySel` | Servie, non lue par le plugin | **Supprimer** |
| `telemetryHost` | Servie, valeur vide, non lue | **Supprimer** |
| `telemetryFormatProtobuf` | Servie, valeur `false`, OTLP JSON uniquement | **Supprimer** |
| `obfuscated_telemetry_key` | Servie, non lue par le plugin | **Supprimer** |
| `telemetryKeyExpiresAt` | Générée dynamiquement par le serveur, non lue | **Garder** (debug) |
| `telemetryKeyTtlSeconds` | Générée dynamiquement par le serveur, non lue | **Garder** (debug) |

### Clés lues par le plugin MAIS NON servies par le bootstrap ⚠️

| Clé | Où elle est lue | Défaut hardcodé | Action |
|-----|----------------|-----------------|--------|
| `analyze_range_max_tokens` | calc.py | 4000 | **Ajouter** au bootstrap |
| `llm_request_timeout_seconds` | entrypoint.py | 45 | **Ajouter** au bootstrap |
| `ca_bundle_path` | entrypoint.py | (vide) | Garder local (spécifique poste) |
| `proxy_enabled/url/username/password` | entrypoint.py | (vide) | Garder local (spécifique réseau) |
| `proxy_allow_insecure_ssl` | entrypoint.py | false | **Harmoniser** avec le bootstrap |
| `keycloak_auth_timeout_seconds` | entrypoint.py | (vide) | Garder local |
| `edit_chunk_max_chars` | entrypoint.py | (vide) | Optionnel |

### Clés avec noms incohérents 🔄

| Clé bootstrap | Alias dans le code | Note |
|---------------|-------------------|------|
| `keycloakClientId` | `keycloak_client_id`, `client_id`, `clientId` | 4 noms — rétrocompatibilité, ne pas changer |
| `keycloakIssuerUrl` | `keycloak_base_url` | 2 noms |
| `keycloakRealm` | `keycloak_realm` | 2 noms |

---

## Prompt d'exécution

Effectue les modifications suivantes dans les deux repos. Lis chaque fichier avant de le modifier.

### Phase 1 — Device Management : nettoyer les configs servies

#### 1.1 Fichiers de config `config/libreoffice/`

Modifier les 3 fichiers du device-management :
- `device-management/config/libreoffice/config.json` (prod)
- `device-management/config/libreoffice/config.dev.json` (dev)
- `device-management/config/libreoffice/config.int.json` (int)

Dans chacun :

**Supprimer ces clés** de l'objet `config` :
```
"model": "achanger-model",
"_comment_device_management": "Device Management (configuration centralisee)",
"telemetrySel": "...",
"telemetryHost": "",
"telemetryFormatProtobuf": false,
"obfuscated_telemetry_key": "..."
```

**Ajouter ces clés** dans l'objet `config` (après `simplify_selection_system_prompt`) :
```json
"analyze_range_max_tokens": 4000,
"llm_request_timeout_seconds": 45
```

**Mettre à jour `config_path`** dans chaque fichier :
```
"/config/libreoffice/config.json" → "/config/mirai-libreoffice/config.json"
```

#### 1.2 Configmap K8s

Modifier `device-management/deploy/k8s/base/manifests/10-configmap-device-management.yaml` :

Appliquer les mêmes suppressions et ajouts dans les sections :
- `libreoffice-config.json` (bloc prod, ~ligne 78)
- `libreoffice-config-int.json` (bloc int, ~ligne 125)

Mettre à jour les `config_path` : `"/config/libreoffice/config.json"` → `"/config/mirai-libreoffice/config.json"`

#### 1.3 Deployment volumes

Modifier `device-management/deploy/k8s/base/manifests/20-device-management-deployment.yaml` :

Renommer les paths de montage des volumes (~ligne 402-405) :
```yaml
# Avant :
- key: libreoffice-config.json
  path: libreoffice/config.json
- key: libreoffice-config-int.json
  path: libreoffice/config.int.json

# Après :
- key: libreoffice-config.json
  path: mirai-libreoffice/config.json
- key: libreoffice-config-int.json
  path: mirai-libreoffice/config.int.json
```

#### 1.4 Répertoire de config

Renommer le répertoire :
```bash
cd device-management
mv config/libreoffice config/mirai-libreoffice
```

### Phase 2 — Plugin : connecter les clés manquantes

#### 2.1 Reformuler (`_simplify_selection`) utilise le mauvais budget tokens

Dans `AssistantMiraiLibreOffice/src/mirai/menu_actions/writer.py`, fonction `_simplify_selection` :

Chercher la ligne qui lit `edit_selection_max_new_tokens` et remplacer par :
```python
max_tokens = len(original_text) + job.get_config("simplify_selection_max_tokens", 15000)
```

Chercher si un `system_prompt` additionnel est lu — si non, ajouter :
```python
configured_sp = str(job.get_config("simplify_selection_system_prompt", "") or "").strip()
if configured_sp:
    system_prompt = configured_sp + " " + system_prompt
```

#### 2.2 `keys_to_sync` dans `entrypoint.py`

Dans `AssistantMiraiLibreOffice/src/mirai/entrypoint.py`, mettre à jour `keys_to_sync` (~ligne 887) :

```python
keys_to_sync = [
    "llm_base_urls", "llm_api_tokens", "llm_default_models",
    "systemPrompt", "api_type", "is_openwebui", "openai_compatibility",
    "telemetryEndpoint", "telemetryKey",
    "telemetryAuthorizationType",
    "relayAssistantBaseUrl",
    "doc_url", "portal_url",
    # Ajouts :
    "keycloak_redirect_uri", "keycloak_allowed_redirect_uri",
    "analyze_range_max_tokens", "llm_request_timeout_seconds",
    "simplify_selection_max_tokens", "simplify_selection_system_prompt",
    "extend_selection_max_tokens", "extend_selection_system_prompt",
    "edit_selection_max_new_tokens", "edit_selection_system_prompt",
    "summarize_selection_max_tokens", "summarize_selection_system_prompt",
]
```

Supprimer `telemetrySel` et `model` s'ils sont présents.

### Phase 3 — Vérification

#### 3.1 Tests unitaires
```bash
cd AssistantMiraiLibreOffice
python3 -m pytest tests/unit/ -v
```

#### 3.2 Vérification du bootstrap

Après redéploiement du device-management, vérifier :
```bash
# Le nouveau path fonctionne
curl -s "https://bootstrap.fake-domain.name/config/mirai-libreoffice/config.json?profile=int" | python3 -c "
import sys, json
d = json.load(sys.stdin)['config']
# Clés supprimées ne doivent plus apparaître
for k in ['model', '_comment_device_management', 'telemetryHost', 'telemetryFormatProtobuf', 'obfuscated_telemetry_key']:
    assert k not in d, f'Clé {k} devrait être supprimée'
# Clés ajoutées doivent être présentes
assert d.get('analyze_range_max_tokens') == 4000, 'analyze_range_max_tokens manquant'
assert d.get('llm_request_timeout_seconds') == 45, 'llm_request_timeout_seconds manquant'
# config_path mis à jour
assert 'mirai-libreoffice' in d.get('config_path', ''), 'config_path non mis à jour'
print('✅ Toutes les vérifications passent')
"
```

#### 3.3 Test end-to-end plugin

```bash
cd AssistantMiraiLibreOffice
# Purger la config locale
rm -f ~/Library/Application\ Support/LibreOffice/4/user/config/config.json
# Rebuild et lancer
scripts/dev-launch.sh --config config/profiles/config.default.integration.json
# Vérifier dans ~/log.txt que :
# - Le bootstrap répond sans les clés supprimées
# - Les nouvelles clés sont persistées localement
# - simplify_selection_max_tokens est lu par _simplify_selection
```

#### 3.4 Redéployer device-management sur Scaleway

```bash
cd device-management
./scripts/k8s/deploy.sh scaleway
kubectl rollout restart deployment/device-management -n bootstrap
```
