# 📋 INSTRUCTION AUTONOME — Qualifier `master`, puis exécuter ce plan

> À copier-coller tel quel dans un autre agent. Rédigée pour une exécution **sans supervision** (l'utilisateur dort) : aucune question à poser, aucune décision à faire remonter, aucun blocage toléré. Dépose-la dans `prompts/qualification-et-execution.md` au début de ton travail.

## Contexte (tu ne connais rien de ce projet — lis ceci)

`~/Documents/GitHub/AssistantMiraiLibreOffice` est une **extension LibreOffice** (OXT, Python/UNO) qui intègre un assistant IA dans Writer et Calc pour le ministère de l'Intérieur. Elle se connecte à un backend compatible OpenAI via un **device-management (DM)** — dépôt voisin `../device-management` — qui gère enrôlement, configuration, jetons LLM, télémétrie et mises à jour.

Le code se lit en trois couches : la **coquille** (`src/mirai/entrypoint.py`, ~9 900 lignes : enrôlement, SSO Keycloak, DM, mise à jour, télémétrie), le **moteur** (`src/mirai/core/` : registre d'outils façon MCP, orchestrateur agentique, client LLM) et l'**IHM** (`src/mirai/ui/` : palette flottante style DSFR). Une branche expérimentale `exp-jetable/demonstrateur-moteur-mcp` porte déjà le moteur et la palette.

## Mission — deux phases, dans cet ordre

**Phase A — Qualifier la baseline `master`.** Constat pur, **aucune correction** : régressions, dette (« ça marche presque »), et deux configurations de travail vérifiées (DM local Docker + Ollama, DM Scaleway).

**Phase B — Exécuter le plan et tout corriger.** Sur une branche dédiée et taguée : exécuter le plan de refonte, **corriger tous les soucis relevés en phase A**, livrer un rapport d'exécution et un protocole de test humain.

> **Le plan à exécuter est un fichier local : `~/.claude/plans/une-reflexion-absolument-cozy-duckling.md`.**
> Lis-le **intégralement avant la phase B**. Il contient l'arborescence cible, les étapes numérotées, les budgets de qualité chiffrés, une section « Rejeu / anti-régressions » (22 pièges déjà payés — respecte-les, ils t'éviteront des heures) et une section « Vérification ». **Copie-le dans `prompts/plan-demonstrateur-moteur-mcp.md`** pour qu'il soit versionné avec ton travail.

La frontière est stricte : en phase A tu constates, en phase B tu corriges.

## ⚠️ Pièges déjà payés — lis avant de lancer quoi que ce soit

1. **macOS tue les binaires auxiliaires de LibreOffice.** Symptôme trompeur : `unopkg` échoue en `NoConnectException "couldn't connect to pipe"`. Cause réelle : SIGKILL « Launch Constraint Violation » (voir `~/Library/Logs/DiagnosticReports/uno-*.ips`). **Contrôle préalable obligatoire** : `/Applications/LibreOffice.app/Contents/Resources/python --version` doit renvoyer 0, pas 137. Sinon re-signer ad hoc (`codesign --force -s -`) `Contents/MacOS/{uno,unopkg,gengal,regview,senddoc,unoinfo,uri-encode,xpdfimport,opencltest}` **et** `Contents/Frameworks/LibreOfficePython.framework/Versions/3.11/{LibreOfficePython,bin/python3.11,Resources/Python.app/Contents/MacOS/LibreOfficePython}`. À refaire après chaque mise à jour de LibreOffice.
2. **Ne lance jamais `scripts/dev-launch.sh` en tâche de fond** — `unopkg` s'y bloque indéfiniment. Avant-plan uniquement.
3. **Ne pose JAMAIS `enrolled=true` à la main** dans `~/Library/Application Support/LibreOffice/4/user/config/config.json` : c'est l'« état absorbant » (drapeau posé sans paire relais) → 401 « Missing credentials » sur 100 % des appels LLM, sans reprise possible. Seule sortie : un **vrai ré-enrôlement** (`POST /enroll` est idempotent côté DM).
4. **Port 28443** : si un simulateur de plugin tourne, il intercepte le callback SSO et affiche « Callback invalide (state inconnu) ». Vérifie `lsof -nP -iTCP:28443` avant tout test d'authentification. Signature : aucune ligne `PKCE callback received` dans `~/log.txt` alors que le navigateur a affiché une page.
5. **Campagne de mise à jour du DM** : une directive d'update ouvre une boîte modale à chaque lancement et **interrompt le login SSO**. Neutralise-la (aligner la version du build sur la cible de campagne, ou désactiver la campagne côté DM) avant les tests d'authentification.
6. **`pkill` avec un document ouvert** → boîte de récupération au lancement suivant, qui **bloque les macros** passées en `--args`. Purger les items `/org.openoffice.Office.Recovery` de `registrymodifications.xcu` le cas échéant.
7. **Chemins absolus toujours** pour build et installation (`"$REPO/dist/mirai.oxt"`) : un `cd` refusé laisse le shell ailleurs et fait rebuilder silencieusement le mauvais répertoire.
8. **`~/log.txt` est le journal applicatif** — ta principale source de vérité, le code y trace énormément.

---

# PHASE A — Qualification de `master`

## A1. Repartir de `master`

```bash
cd ~/Documents/GitHub/AssistantMiraiLibreOffice
git fetch origin
git switch -c qualif/master-baseline origin/master
git log --oneline -10        # note le HEAD exact dans le rapport
```

## A2. Construire, installer, lancer

```bash
python3 -m pytest tests/unit/ -q      # baseline AVANT tout : note le compte exact
./scripts/03-test-local.sh
./scripts/02-build-oxt.sh
/Applications/LibreOffice.app/Contents/MacOS/unopkg add --force --suppress-license "$PWD/dist/mirai.oxt"
open -a LibreOffice "$PWD/tests/fixtures/sample.odt"
```

Vérifie dans `~/log.txt` la présence de `=== mirai extension registered successfully ===`.

**Automatisation sans interaction** : le profil LibreOffice contient déjà des macros Basic dans `Standard.Module1` — `MiraiDiag` (charge un document, instancie le composant, déclenche une action, écrit le résultat dans `/private/tmp/mirai_diag.txt`) et `MiraiDevInstall2` (installation in-process). Invocation : `open -a LibreOffice --args "vnd.sun.star.script:Standard.Module1.MiraiDiag?language=Basic&location=application"`. Réutilise ce patron pour piloter les tests.

## A3. Tester : régressions ET dette

### Automatique
- Suite `tests/unit/` : compte, échecs, **et tests ignorés** (un skip est souvent une régression déguisée).
- `tests/integration/test_full_enrollment_flow.py` : meilleure description exécutable du contrat coquille.
- `python3 -m py_compile $(git ls-files '*.py')` — `03-test-local.sh` ne couvre qu'une partie des modules.
- Si `ruff` est disponible : `ruff check --select E,F,B,C901 src/` pour un inventaire. **Ne l'ajoute pas au dépôt en phase A**, contente-toi de rapporter.

### Fonctionnel — tous les chemins utilisateur
Chaque item de menu, chaque bouton de barre d'outils, chaque raccourci de `oxt/Accelerators.xcu`, chaque entrée du menu contextuel (clic droit), dans **Writer et Calc**, sur document **nouvellement créé** (`onNew`) **et** ouvert depuis le disque (`onLoad`), **avec et sans sélection**. Pour chacun : déclenché ? résultat visible ? erreur dans `~/log.txt` ? temps de réponse ? Compare avec `tests/TEST-MANUEL-utilisateur.md` et `tests/RAPPORT-richard-menucontext.md`.

### Les neuf sondes à dette — le cœur de la phase A
1. **Déclaré vs implémenté** — croise les actions de `Addons.xcu`, `Accelerators.xcu` et du menu contextuel avec ce que `handle_writer_action` / `handle_calc_action` traitent vraiment. Une action déclarée sans branche = un clic sans effet.
2. **Raccourcis annoncés vs déclarés** — les libellés annoncent ⌘E, ⌘J… ; vérifie que chacun existe dans `Accelerators.xcu`.
3. **Exceptions avalées** — `grep -rn "except.*:\s*$" -A1 src/ | grep -B1 pass`. Pour chacune : si ce chemin échoue en production, l'utilisateur le saura-t-il ? Liste celles où la panne serait **invisible**.
4. **Threads de fond touchant l'UI** — `threading.Thread` dont le corps accède à `.getModel()`, `.Label`, `.setString` ou `processEventsToIdle`. Classe de crash aléatoire.
5. **Config morte / manquante** — clés lues (`get_config("…")`) vs clés réellement servies par le DM (réponse `/config` dans `~/log.txt`) vs `dm-config.json`. Signale les **deux sens**.
6. **Télémétrie déclarée vs émise** — `_ACTION_NAMES` vs spans réellement observés en exerçant les fonctions.
7. **Code mort** — fonctions jamais référencées, fichiers non embarqués par le build, branches inatteignables.
8. **Doc vs code** — `README.md`, `docs/*.md`, `docs/notice-utilisateur.md` : toute affirmation contredite par le code.
9. **Dégradation** — coupe le réseau et teste : chaque fonction doit échouer **visiblement et proprement**. Tout gel de l'interface est un défaut **majeur**, pas un détail.

## A4. Les deux configurations

### DM local en Docker + Ollama
`../device-management/deploy/docker/` contient un `docker-compose.yml` (services `device-management`, `queue-worker`, `llm-proxy`, `relay-assistant`, `postgres-local`) et son `README.md`. Port hôte du DM : `8089` (`DM_PORT`) ; l'amont LLM du relais se règle par `RELAY_LLM_UPSTREAM`.
1. Démarrer la pile (`cp .env.example .env`, `cp .env.secrets.example .env.secrets`, `docker compose up --build`), vérifier que `/config` répond.
2. Installer Ollama (`ollama serve` + un modèle léger type `llama3.2`), pointer l'amont LLM du DM vers lui — depuis un conteneur : `http://host.docker.internal:11434/v1`. **Vérifie le nom exact de la variable dans le compose** avant de l'écrire dans la doc.
3. Basculer le plugin : profil `config/profiles/config.default.dev.json` (bootstrap `http://localhost:8089`, `?profile=dev`) via `./scripts/06-use-config-profile.sh`, puis rebuild + réinstallation.
4. Dérouler le parcours complet : enrôlement → configuration → **appel LLM réel sur Ollama** → télémétrie.

### DM Scaleway (l'existant)
Documente la configuration en place (profils `config.default.production.json` / `config.default.kubernetes.json`, `?profile=prod`) et la **procédure de bascule dans les deux sens**, avec ses précautions (purge de configuration et ré-enrôlement obligatoires après changement de tier, cf. `scripts/00-clean-install.sh`).

## Livrables de la phase A
1. `docs/QUALIFICATION-master-<AAAA-MM-JJ>.md` — HEAD testé, version de LibreOffice, puis un tableau : **sévérité** (bloquant / majeur / mineur) · **catégorie** (régression / dette / doc) · **preuve** (extrait de log, `fichier:ligne`, capture) · **correction proposée**. Termine par les trois urgences.
2. `docs/CONFIGURATIONS.md` — les deux tiers côte à côte : prérequis, commandes exactes, bascule, vérifications. **Aucun secret, aucun jeton, aucune URL interne réelle** — des placeholders.

---

# PHASE B — Exécuter le plan et corriger

## B1. Branche dédiée et tags

```bash
git switch -c exp-jetable/demonstrateur-v2 origin/master
git merge --no-ff exp-jetable/demonstrateur-moteur-mcp   # récupère moteur + palette déjà écrits
git tag -a exp-jetable-v2-baseline -m "Base : master + moteur MCP, avant exécution du plan"
```

Le nom de branche porte explicitement **`exp-jetable`** : c'est un démonstrateur jetable, tout développeur doit le voir au premier coup d'œil. Bandeau d'avertissement en tête de `README.md`, et toute PR reste en **draft** avec la mention « ⚠️ EXPÉRIMENTATION JETABLE — ne pas merger vers master ». Pose un tag annoté à chaque jalon (`exp-jetable-v2-<jalon>`) et un `exp-jetable-v2-final` à la fin.

Résous les conflits de fusion en gardant : la coquille de `master` (elle contient le menu contextuel de Richard et le correctif d'authentification `/llm/v1`), le moteur et l'IHM de la branche expérimentale.

## B2. Exécuter le plan

Suis les étapes numérotées du plan, **dans l'ordre imposé** : fusionner master → supprimer le cœur legacy → découper `entrypoint.py` en mixins → itération 2 (exécution non bloquante, IHM épurée, indicateur de sélection, jauge d'activité, onglets, suggestions, redimensionnement) → menu contextuel branché sur le moteur → qualité (ruff + les 8 factorisations nommées) → documentation.

Règles non négociables, tirées de la section « Rejeu / anti-régressions » du plan :
- **La suite de tests reste verte à chaque commit.** Un refactor qui oblige à modifier une assertion a débordé : reviens en arrière.
- **Aucun appel UNO depuis un thread de fond** sans passer par le dispatcher de thread principal.
- **Aucun blocage du thread principal** : tout ce qui touche au réseau vit dans le thread worker.
- **Layout mesuré** (`getPreferredSize`), jamais de pixels estimés.
- Commits atomiques et relisables, messages en français expliquant le **pourquoi**.

## B3. Corriger tous les soucis de la phase A

Reprends ton tableau de qualification et traite **chaque ligne** : corrigée (avec le commit), ou écartée avec une justification écrite. Aucune ligne ne reste sans réponse. Les blocants et majeurs sont corrigés ; les mineurs peuvent être documentés comme dette assumée s'ils sortent du périmètre, mais **explicitement**.

## B4. Vérification finale

Déroule la section « Vérification » du plan (18 points, dont : non-blocage pendant un run long, retour visible en moins d'une seconde, chips sur une seule ligne, indicateur de sélection, menu contextuel sur `onNew` et `onLoad`, redimensionnement, budgets de qualité). Puis la validation de bout en bout sur **les deux tiers** (Docker+Ollama et Scaleway).

## Livrables de la phase B

1. **`docs/RAPPORT-EXECUTION-<AAAA-MM-JJ>.md`** — ce qui a été fait, commit par commit ; le sort de chaque ligne de qualification ; les métriques avant/après (tests, fonctions > 40 lignes, `except` anonymes, taille d'`entrypoint.py`) ; ce qui **n'a pas** été fait et pourquoi ; les risques résiduels. Sois factuel : si un test échoue encore, dis-le avec sa sortie.
2. **`docs/TEST-HUMAIN-<AAAA-MM-JJ>.md`** — protocole de recette **pour un humain non technique**, en français simple : prérequis et installation, puis une suite de scénarios numérotés avec, pour chacun, l'**action exacte** (« ouvrez `sample.odt`, placez le curseur dans le second paragraphe, appuyez sur Ctrl+Alt+Espace, cliquez sur *Résumer* »), le **résultat attendu** décrit précisément, et une case à cocher conforme/non conforme. Couvre : ouverture de la palette, chaque chip Writer et Calc, le menu contextuel, le prompt libre, les onglets, le redimensionnement, l'annulation, le comportement sans réseau, le parcours d'enrôlement, et les réglages. Termine par une section « Que faire si ça ne marche pas » (où trouver `~/log.txt`, quoi y chercher, quoi rapporter).
3. Tags posés, branche poussée, **aucune PR ouverte vers `master`**.

---

## Interdits

- Modifier `master`, ou pousser quoi que ce soit vers `master`.
- Corriger du code **pendant la phase A** (si c'est indispensable pour débloquer un test, isole-le dans un commit séparé clairement étiqueté et signale-le dans le rapport).
- Committer un secret, un jeton, une URL interne réelle.
- Poser `enrolled=true` à la main (piège n°3).
- Déclarer « ça marche » sans preuve dans le journal ou à l'écran.
- Laisser la suite de tests rouge en fin de travail sans l'écrire noir sur blanc en tête du rapport d'exécution.
