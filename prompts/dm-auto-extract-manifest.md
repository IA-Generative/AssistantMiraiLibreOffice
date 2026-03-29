# Prompt — Extraction automatique des métadonnées plugin par le Device Management

> Objectif : le DM extrait automatiquement toutes les informations nécessaires
> d'un package plugin (.oxt / .xpi / .crx) à l'upload, sans saisie manuelle.

---

## Contexte

Chaque package plugin contient maintenant des fichiers de métadonnées standardisés :

| Fichier | Contenu | Format |
|---------|---------|--------|
| `dm-manifest.json` | Identité du plugin (nom, description, features, changelog, URLs) | JSON |
| `dm-config.json` | Template de configuration par profil (default/local/dev/int/prod) | JSON |
| `description.xml` | Métadonnées OXT standard (version, identifier, licence, icône) | XML |
| `assets/logo.png` | Icône du plugin | PNG |
| `docs/README.md` | Documentation technique | Markdown |
| `docs/notice-utilisateur.md` | Notice utilisateur | Markdown |
| `registration/license.txt` | Licence et mentions légales | Texte |

## Structure de `dm-manifest.json`

```json
{
  "slug": "mirai-libreoffice",
  "name": "MIrAI — IA'ssistant LibreOffice",
  "description": "...",
  "intent": "...",
  "device_type": "libreoffice",
  "category": "productivity",
  "publisher": "Programme MIrAI — Ministère de l'Intérieur",
  "visibility": "public",
  "homepage_url": "https://github.com/IA-Generative/AssistantMiraiLibreOffice",
  "support_email": "fabrique-numerique@interieur.gouv.fr",
  "icon_url": "assets/logo.png",
  "doc_url": "https://github.com/.../docs/notice-utilisateur.md",
  "license": "MPL-2.0",
  "key_features": ["Feature 1", "Feature 2", ...],
  "changelog": [
    {"version": "0.2.0", "date": "2026-03-28", "changes": ["...", "..."]},
    {"version": "0.1.0", "date": "2026-03-01", "changes": ["..."]}
  ]
}
```

---

## Repo cible

`/Users/etiquet/Documents/GitHub/device-management`

## Fichiers à modifier

### 1. `app/admin/router.py` — endpoint `POST /admin/api/catalog/suggest`

Le suggest extrait déjà des fichiers du ZIP. Étendre pour extraire :

**a) `dm-manifest.json`** — métadonnées complètes

```python
# Ajouter à interesting_files :
"dm-manifest.json", "dm_manifest.json",

# Dans la boucle d'extraction :
if basename in ("dm-manifest.json", "dm_manifest.json"):
    try:
        dm_manifest = json.loads(raw)
        has_manifest = True
    except json.JSONDecodeError:
        pass
```

Quand `dm-manifest.json` est trouvé, l'utiliser **directement comme suggestion**
au lieu d'appeler le LLM (qui est lent et faillible) :

```python
if has_manifest:
    suggestion = {
        "slug": dm_manifest.get("slug", ""),
        "name": dm_manifest.get("name", ""),
        "description": dm_manifest.get("description", ""),
        "intent": dm_manifest.get("intent", ""),
        "device_type": dm_manifest.get("device_type", "libreoffice"),
        "category": dm_manifest.get("category", "productivity"),
        "publisher": dm_manifest.get("publisher", ""),
        "visibility": dm_manifest.get("visibility", "public"),
        "homepage_url": dm_manifest.get("homepage_url", ""),
        "support_email": dm_manifest.get("support_email", ""),
        "icon_url": dm_manifest.get("icon_url", ""),
        "doc_url": dm_manifest.get("doc_url", ""),
        "license": dm_manifest.get("license", ""),
        "key_features": dm_manifest.get("key_features", []),
        "changelog": dm_manifest.get("changelog", []),
        "_has_readme": has_readme,
        "_has_manifest": True,
        "_has_config_template": has_config_template,
        "_source": "dm-manifest.json",
    }
    if config_template:
        suggestion["config_template"] = config_template
    return JSONResponse(suggestion)
# Sinon, fallback sur le LLM comme avant
```

**b) `description.xml`** — extraire la version OXT

```python
if basename == "description.xml":
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(raw)
        ns = {"d": "http://openoffice.org/extensions/description/2006"}
        ver_el = root.find(".//d:version", ns)
        if ver_el is not None:
            oxt_version = ver_el.get("value", "")
        ident_el = root.find(".//d:identifier", ns)
        if ident_el is not None:
            oxt_identifier = ident_el.get("value", "")
    except Exception:
        pass
```

**c) `assets/logo.png`** — extraire et stocker l'icône

```python
# Extraire l'icône binaire pour la stocker localement ou en S3
icon_data = None
icon_filename = None
# Dans la boucle :
if basename in ("logo.png", "icon128.png", "icon48.png") and name.startswith("assets/"):
    icon_data = zf.read(name)  # bytes, pas decode
    icon_filename = basename
```

Stocker l'icône dans le répertoire des binaires :
```python
if icon_data and icon_filename:
    icons_dir = os.path.join(binaries_dir, "icons")
    os.makedirs(icons_dir, exist_ok=True)
    icon_path = os.path.join(icons_dir, f"{slug}_{icon_filename}")
    with open(icon_path, "wb") as f:
        f.write(icon_data)
    # Mettre à jour l'URL de l'icône pour qu'elle pointe vers le serveur
    suggestion["icon_url"] = f"/binaries/icons/{slug}_{icon_filename}"
```

### 2. `app/admin/router.py` — endpoint `POST /deploy/create`

Même extraction que suggest, mais au moment du déploiement :

```python
# Après extraction du dm-config.json (déjà fait), extraire aussi dm-manifest.json
deploy_manifest = None
try:
    with zipfile.ZipFile(io.BytesIO(original_data)) as zf:
        for name in zf.namelist():
            basename = name.rsplit("/", 1)[-1].lower()
            if basename in ("dm-manifest.json", "dm_manifest.json"):
                deploy_manifest = json.loads(zf.read(name).decode("utf-8"))
                break
except Exception:
    pass

# Après création de la campagne, mettre à jour le plugin avec les nouvelles métadonnées
if deploy_manifest:
    try:
        update_fields = {}
        for field in ("name", "description", "intent", "key_features",
                      "changelog", "homepage_url", "support_email",
                      "icon_url", "doc_url", "publisher"):
            if deploy_manifest.get(field):
                update_fields[field] = deploy_manifest[field]
        if update_fields:
            catalog_svc.update_plugin(cur, plugin_id_for_device_type, **update_fields)
    except Exception as e:
        logger.warning("deploy: manifest update failed: %s", e)
```

### 3. `app/admin/services/catalog.py` — `update_plugin()`

Ajouter les champs manquants à la liste `allowed` :

```python
allowed = {"name", "description", "intent", "key_features", "changelog",
           "category", "icon_url", "homepage_url", "support_email",
           "publisher", "visibility", "status", "config_template",
           "doc_url", "license"}  # ← ajoutés
```

Note : `doc_url`, `license` et `changelog` nécessitent des colonnes en DB.
Si elles n'existent pas, créer une migration :

```sql
-- db/migrations/005_plugin_metadata.sql
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS doc_url TEXT;
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS license TEXT;
ALTER TABLE plugins ADD COLUMN IF NOT EXISTS changelog JSONB;
```

### 4. `app/admin/router.py` — Strip dm-manifest.json du binaire distribué

Mettre à jour `_strip_dm_config_from_zip` pour aussi retirer le manifest :

```python
def _strip_dm_metadata_from_zip(data: bytes) -> bytes:
    """Remove dm-config.json and dm-manifest.json from ZIP before distribution."""
    import zipfile
    src = zipfile.ZipFile(io.BytesIO(data))
    buf = io.BytesIO()
    strip_names = {"dm-config.json", "dm_config.json", "dm-manifest.json", "dm_manifest.json"}
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            if item.filename.lower() in strip_names:
                continue
            dst.writestr(item, src.read(item.filename))
    return buf.getvalue()
```

Renommer l'appel dans `deploy_create` :
`data = _strip_dm_config_from_zip(data)` → `data = _strip_dm_metadata_from_zip(data)`

---

## Flux complet après implémentation

```
Développeur : git push → build OXT → upload dans DM admin
                                          │
                                          ▼
                              DM extrait du ZIP :
                              ├─ dm-manifest.json → slug, name, description,
                              │                      features, changelog, URLs
                              ├─ dm-config.json   → config template (profils)
                              ├─ description.xml  → version OXT, identifier
                              ├─ assets/logo.png  → icône stockée localement
                              ├─ docs/README.md   → description longue
                              └─ license.txt      → licence
                                          │
                              DM auto-remplit :
                              ├─ plugins.name, description, intent
                              ├─ plugins.key_features, changelog
                              ├─ plugins.icon_url (servie par /binaries/icons/)
                              ├─ plugins.doc_url, homepage_url
                              ├─ plugins.config_template (dm-config.json)
                              ├─ artifacts.version (depuis description.xml)
                              └─ artifacts.changelog_url (depuis homepage_url)
                                          │
                              DM strip dm-manifest.json + dm-config.json
                              du binaire avant distribution
                                          │
                                          ▼
                              Utilisateurs reçoivent un .oxt propre
                              (sans placeholders ni métadonnées DM)
```

## Vérification

```bash
# 1. Upload le .oxt dans l'admin
# 2. Vérifier que le suggest retourne les données du manifest (pas du LLM)
curl -s -X POST "http://localhost:3001/admin/api/catalog/suggest" \
  -F "plugin_file=@dist/mirai.oxt" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d.get('_source') == 'dm-manifest.json', 'Should use manifest, not LLM'
assert d.get('slug') == 'mirai-libreoffice'
assert d.get('name') == 'MIrAI — IA\\'ssistant LibreOffice'
assert len(d.get('key_features', [])) >= 8
assert len(d.get('changelog', [])) >= 2
assert d.get('homepage_url', '').startswith('https://github.com')
assert d.get('_has_config_template') == True
print('OK: manifest extrait correctement')
"

# 3. Vérifier que le binaire distribué ne contient plus les métadonnées DM
unzip -l /path/to/stored/artifact.oxt | grep -E "dm-manifest|dm-config"
# → aucun résultat attendu
```
