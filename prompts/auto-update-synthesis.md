# Synthèse : Mise à jour automatique du plugin MIrAI LibreOffice

## Vue d'ensemble

Le plugin MIrAI LibreOffice se met à jour automatiquement via Device Management (DM).
Le processus est cross-platform (macOS, Windows, Linux).

## Architecture

```
Plugin LibreOffice                    Device Management (DM)
─────────────────                    ─────────────────────
1. GET /config/{slug}/config.json ──→ Compare X-Plugin-Version vs campagne active
                                  ←── Retourne "update" directive (ou null)

2. GET /catalog/{slug}/download   ──→ Sert le .oxt via redirect 302
                                  ←── Fichier .oxt

3. Vérifie checksum SHA-256
4. Copie .oxt dans config/pending_update/
5. Crée script d'installation (bash/bat)
6. Dialogue "Redémarrer maintenant ?" (Oui/Non)
7. Si Oui : lance le script → desktop.terminate()

Script d'installation (exécuté hors LO) :
  - Attend que soffice quitte (pgrep/tasklist)
  - unopkg remove fr.gouv.interieur.mirai
  - unopkg add --force --suppress-license mirai_update.oxt
  - Relance LibreOffice
  - Logge chaque étape dans ~/log.txt [UPDATE]
```

## Fichiers impliqués

### Plugin (AssistantMiraiLibreOffice)

| Fichier | Rôle |
|---------|------|
| `src/mirai/entrypoint.py` | `_perform_update()` — download, checksum, staging, dialogue |
| `src/mirai/entrypoint.py` | `_schedule_update()` — lance _perform_update en thread daemon |
| `src/mirai/entrypoint.py` | `_build_update_directive` gating dans `_fetch_config()` |
| `oxt/description.xml` | Version courante du plugin (lue par `_get_extension_version()`) |
| `~/log.txt` | Traces du plugin ET du script d'installation `[UPDATE]` |
| `~/Library/Application Support/LibreOffice/4/user/config/config.json` | Config locale (macOS) |
| `%APPDATA%\LibreOffice\4\user\config\config.json` | Config locale (Windows) |
| `~/.config/libreoffice/4/user/config/config.json` | Config locale (Linux) |

### Device Management (device-management)

| Fichier | Rôle |
|---------|------|
| `app/main.py` | `_build_update_directive()` — compare versions, retourne directive |
| `app/main.py` | `_resolve_active_campaign()` — trouve la campagne active pour un device_type |
| `app/main.py` | `_parse_version_tuple()` — parse version en tuple (supporte N segments) |
| `app/main.py` | `POST /api/plugins/{slug}/deploy` — endpoint unifié de déploiement |
| `app/main.py` | `GET /catalog/{slug}/download` — sert le dernier artefact |

## Détails par plateforme

### macOS

```bash
# Script : config/pending_update/mirai_update.sh
#!/bin/bash
LOG="~/log.txt"
echo "$(date) - [UPDATE] script started" >> "$LOG"
while pgrep -x soffice >/dev/null 2>&1; do sleep 1; done
echo "$(date) - [UPDATE] LO quit detected" >> "$LOG"
sleep 2
"/Applications/LibreOffice.app/Contents/MacOS/unopkg" remove fr.gouv.interieur.mirai
echo "$(date) - [UPDATE] old extension removed" >> "$LOG"
"/Applications/LibreOffice.app/Contents/MacOS/unopkg" add --force --suppress-license "mirai_update.oxt"
# ... check RC, log result ...
open -a LibreOffice    # TODO: ajouter --args --writer pour activer les menus
rm -f "mirai_update.oxt" "mirai_update.sh"
```

**Chemin unopkg** : `/Applications/LibreOffice.app/Contents/MacOS/unopkg`
**Relance** : `open -a LibreOffice`
**Bug connu** : sans `--args --writer`, LO s'ouvre sans document → menus inactifs. Quitter et relancer résout le problème. Fix prévu : `open -a LibreOffice --args --writer`.

### Windows

```batch
@echo off
REM Script : config\pending_update\mirai_update.bat
:wait_lo
tasklist /FI "IMAGENAME eq soffice.bin" 2>nul | find /I "soffice.bin" >nul
if not errorlevel 1 (
  timeout /t 2 /nobreak >nul
  goto wait_lo
)
"C:\Program Files\LibreOffice\program\unopkg.com" remove fr.gouv.interieur.mirai
"C:\Program Files\LibreOffice\program\unopkg.com" add --force --suppress-license "mirai_update.oxt"
start "" "C:\Program Files\LibreOffice\program\soffice.exe"
del "mirai_update.oxt"
del "mirai_update.bat"
```

**Chemin unopkg** : `C:\Program Files\LibreOffice\program\unopkg.com`
**Relance** : `start "" "soffice.exe"`
**Lancement script** : `cmd /c start /min "" mirai_update.bat`

### Linux

```bash
# Script : config/pending_update/mirai_update.sh
#!/bin/bash
while pgrep -x soffice >/dev/null 2>&1; do sleep 1; done
sleep 2
/usr/bin/unopkg remove fr.gouv.interieur.mirai
/usr/bin/unopkg add --force --suppress-license "mirai_update.oxt"
/usr/bin/soffice --writer &
rm -f "mirai_update.oxt" "mirai_update.sh"
```

**Chemin unopkg** : `/usr/bin/unopkg` ou `/usr/lib/libreoffice/program/unopkg`
**Relance** : `soffice --writer &`

## Protections

| Protection | Détail |
|-----------|--------|
| **Anti-boucle** | Compare `target_version == current_version` → skip si identique |
| **X-Plugin-Version** | Toujours envoyé (fallback "unknown"), le DM ignore "unknown" |
| **Checksum SHA-256** | Vérifié avant installation |
| **Dialogue Oui/Non** | Le script ne se lance que si l'utilisateur accepte |
| **Script avant dialogue** | Le script est **créé** mais **pas lancé** avant confirmation |
| **OXT stable** | Copié dans `config/pending_update/` (survit au quit de LO) |
| **Wait for quit** | `pgrep`/`tasklist` attend la fin du process soffice |
| **Logs [UPDATE]** | Chaque étape du script est loggée dans `~/log.txt` |

## Stratégies de déploiement (côté DM)

| Stratégie | Comportement |
|-----------|-------------|
| `canary` | 5% (24h) → 25% (48h) → 100%. Hash déterministe du `client_uuid`. Automatique. |
| `immediate` | 100% immédiatement |

## Bugs connus et résolus

| Bug | Cause | Fix |
|-----|-------|-----|
| Version tronquée à 3 segments | `_parse_version_tuple` faisait `[:3]` | Supprimé le `[:3]` |
| Menus inactifs après update (macOS) | `open -a LibreOffice` sans document | **TODO** : ajouter `--args --writer` |
| Boucle infinie update→restart | Même version reproposée | Comparaison côté client + DM ignore "unknown" |
| Script lancé avant dialogue | `Popen` avant `msgbox` | Script staged, lancé seulement après "Oui" |
| unopkg add FAILED rc=141 | SIGPIPE, LO pas encore quitté | Wait loop `pgrep`/`tasklist` |
| unopkg add FAILED rc=1 | LO encore en train de quitter | `sleep 2` après wait + `--force` |
| Cache registry corrompu | `rm -rf registry` pendant update | Ne plus toucher au registry |
| `--suppress-license` manquant | `printf "yes\n"` ne marchait pas | `--force --suppress-license` |

## Commandes utiles

```bash
# Créer une version + build
./scripts/bump-version.sh 0.0.1.0.5

# Déployer
./scripts/deploy-release.sh \
  --bootstrap-url https://bootstrap.fake-domain.name \
  --strategy immediate

# Vérifier ce que le DM propose
curl -s -H "X-Plugin-Version: 0.0.1.0.3" \
  "https://bootstrap.fake-domain.name/config/mirai-libreoffice/config.json?profile=int" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(json.dumps(d.get('update'), indent=2))"

# Vérifier le download
curl -sL "https://bootstrap.fake-domain.name/catalog/mirai-libreoffice/download" | shasum -a 256

# Installer manuellement (macOS)
/Applications/LibreOffice.app/Contents/MacOS/unopkg add --force --suppress-license dist/mirai.oxt

# Lire les logs de mise à jour
grep "\[UPDATE\]" ~/log.txt
```
