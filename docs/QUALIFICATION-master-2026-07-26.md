# Qualification de la baseline `master` — 2026-07-26

> **Phase A du plan de refonte.** Document de **constat pur** : rien n'a été corrigé ici.
> Les corrections sont l'objet de la phase B (branche `exp-jetable/demonstrateur-v2`).

## Périmètre testé

| Élément | Valeur |
|---|---|
| Commit qualifié | `621c5c84b393c94438b199464c3fd3e63891b11b` (*Add traduction and correction for context menu*) |
| Branche de qualification | `qualif/master-baseline` (créée depuis `origin/master`) |
| LibreOffice | 25.8.4.2 (`290daaa01b999472f0c7a3890eb6a550fd74c6df`), macOS 26 (Darwin 25.5.0) |
| Version OXT construite | 0.0.1.0.22 |
| Python LibreOffice | 3.11.14 — **contrôle des launch constraints macOS : exit 0, pas de re-signature nécessaire** |
| Date de la campagne | 2026-07-26, 00:20 → 01:00 CEST |

## Métriques de la baseline

| Métrique | Valeur mesurée sur `master` |
|---|---|
| Tests unitaires | **224 passés, 0 échec, 0 ignoré** (13,2 s) |
| Tests d'intégration | **2 échecs sur 6** (voir R-01) |
| `python3 -m py_compile` sur tous les `.py` suivis | OK |
| Lignes de code `src/` | 12 872 dont **9 889 pour `entrypoint.py`** |
| Fonctions > 40 lignes | **73** (record : `settings_box`, **990 lignes**) |
| Complexité cyclomatique > 10 (`C901`) | **57 fonctions** |
| `except Exception` | **511**, dont **285 blocs `pass` silencieux** |
| Diagnostics `ruff` (E,F,B,C901, 100 col.) | **369** |
| Code mort confirmé | **266 lignes** sur 7 fonctions |
| Linter configuré dans le dépôt | **aucun** |

---

## Tableau des constats

Sévérité : **bloquant** = empêche un usage normal ou casse une fonction système · **majeur** = perte de fonction, crash latent, ou risque de sécurité · **mineur** = confort, cohérence, dette.

### Régressions et défauts fonctionnels

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **R-01** | majeur | régression | **2 tests d'intégration sur 6 sont rouges.** `test_02_pkce_flow_stores_tokens` et `test_06_full_sequence_in_order` échouent : le navigateur n'est jamais ouvert. Cause : `_authorization_code_flow` appelle `_show_enrollment_wizard()` au premier enrôlement ; le test ne patche que `_confirm_message`, le wizard retourne `(False, …)` hors LibreOffice et le flux sort avant `webbrowser.open`. Le test n'a **jamais** été mis à jour depuis l'introduction du wizard (`53d5687`, 2026-03-14, même jour que le test `a35b17d`). | `AssertionError: 'auth_url' not found in {}` — [test_full_enrollment_flow.py:257](tests/integration/test_full_enrollment_flow.py#L257) ; branche wizard en [entrypoint.py:3452-3455](src/mirai/entrypoint.py#L3452-L3455) ; repli silencieux en [entrypoint.py:2683-2685](src/mirai/entrypoint.py#L2683-L2685) | Patcher `_show_enrollment_wizard` dans le harnais de test pour qu'il renvoie `(True, None, None, None, None)`. Le contrat testé (PKCE → jetons) reste inchangé. |
| **R-02** | bloquant | régression | **`Ctrl/Cmd+Q` est détourné vers `ExtendSelection`.** Sur macOS `MOD1` = ⌘ : le raccourci système « Quitter l'application » déclenche un appel LLM. L'utilisateur qui veut fermer LibreOffice lance une génération de texte. | [Accelerators.xcu](oxt/Accelerators.xcu) nœud `Q_MOD1` → `?ExtendSelection&src=key` | Supprimer ce binding. Le plan prévoit de toute façon un raccourci unique `SPACE_MOD1_MOD2` (⌃⌥Espace). |
| **R-03** | majeur | régression | **Tous les autres raccourcis écrasent des commandes LibreOffice natives** : `Ctrl+E` (centrer), `Ctrl+R` (aligner à droite), `Ctrl+L` (aligner à gauche) en Writer ; `Ctrl+K` (insérer un hyperlien) en Calc. Un utilisateur qui centre un paragraphe déclenche « Modifier la sélection ». | [Accelerators.xcu](oxt/Accelerators.xcu) : `E_MOD1`, `R_MOD1`, `L_MOD1`, `K_MOD1`, `T_MOD1`, `G_MOD1` | Idem R-02 : binding unique documenté et non conflictuel. |
| **R-04** | majeur | régression | **Deux entrées de menu Calc sont mortes.** `Addons.xcu` déclare 📚 Documentation et 🌐 Accéder au site mirai pour `SpreadsheetDocument`, mais `handle_calc_action` ne traite **ni** `Documentation` **ni** `OpenmiraiWebsite` : le clic ne fait rien, sans message ni trace. | Déclaration : [Addons.xcu](oxt/Addons.xcu) (contexte `com.sun.star.sheet.SpreadsheetDocument`) · Branches réellement traitées : [calc.py:918-1029](src/mirai/menu_actions/calc.py#L918-L1029) (`settings`, `AboutDialog`, `EditSelection`, `TransformToColumn`, `GenerateFormula`, `ExtendSelection`, `AnalyzeRange` — pas les deux autres) | Router ces deux actions en amont du dispatch par module, avec les autres actions non documentaires. |
| **R-05** | majeur | régression | **Sans sélection résoluble, TOUTES les actions Writer sont avalées en silence** — y compris ⚙️ Paramètres, ℹ️ À propos et 📚 Documentation. `handle_writer_action` sort sur `return True` dès que `text_range is None`, avant tout dispatch. | [writer.py:591-592](src/mirai/menu_actions/writer.py#L591-L592) ; getter renvoyant `None` en [writer.py:429-431](src/mirai/menu_actions/writer.py#L429-L431) | Dispatcher les actions non textuelles **avant** la résolution de sélection. Le plan v2 cible en outre le paragraphe courant quand il n'y a pas de sélection (piège n°5). |
| **R-06** | majeur | régression | **Une action inconnue ne produit strictement rien** : ni message, ni log, ni télémétrie. Vérifié en LibreOffice réel en déclenchant `OpenAssistant` (action inexistante sur `master`) : le dispatch atteint Writer puis retourne sans trace. | `~/log.txt`, 2026-07-26 00:42:28 — `trigger called: action=OpenAssistant` … `Processing Writer document` … `[writer-selection] ranges=1 selected_chars=0 empty=True`, **puis plus rien** | Branche `else` explicite journalisant l'action non gérée, et retour visible à l'utilisateur. |
| **R-07** | bloquant | régression | **`handle_calc_action` enveloppe tout son corps dans `except Exception: pass`** : n'importe quelle panne d'une action Calc est invisible (pas de message, pas de log), et la fonction retourne quand même `True`. C'est la fabrique à « il ne se passe rien ». | [calc.py:1026-1029](src/mirai/menu_actions/calc.py#L1026-L1029) | Journaliser et afficher une erreur lisible ; réserver les `except` larges aux frontières UNO, tracés. |

### Threading — crashs latents

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **T-01** | bloquant | dette | **Un appel LLM complet part d'un thread de fond alors qu'il pompe `processEventsToIdle`.** `_bg_ai_suggestions` s'exécute dans un `threading.Thread` et appelle `stream_request`, dont la docstring assume explicitement le thread principal. C'est la violation n°1 du projet (crash LibreOffice, `std::terminate` dans `DispatchUserEvents`). | Thread : [entrypoint.py:7999](src/mirai/entrypoint.py#L7999) · appel : [entrypoint.py:7945](src/mirai/entrypoint.py#L7945) · contrat violé : [entrypoint.py:5269-5270](src/mirai/entrypoint.py#L5269-L5270) | Modèle worker + `MainThreadDispatcher` de l'itération 2 : plus aucun `processEventsToIdle` dans le cœur. |
| **T-02** | majeur | dette | **`_selection_refresh_loop` écrit dans des contrôles VCL depuis un thread, toutes les 3 s, sans SolarMutex** (`.Label`, `.TextColor`). Contre-exemple cité tel quel par le plan (piège n°15). | [entrypoint.py:7709](src/mirai/entrypoint.py#L7709) → `_refresh_selection_label` [entrypoint.py:7712-7720](src/mirai/entrypoint.py#L7712-L7720) | Remplacer par un `XSelectionChangeListener` (livré sur le thread principal) — piège n°16. |
| **T-03** | majeur | dette | **`_animate` écrit `.Label` depuis un thread toutes les 0,5 s** pour animer un libellé « Suggestions ». | [entrypoint.py:7450](src/mirai/entrypoint.py#L7450) et boucle [entrypoint.py:7440-7449](src/mirai/entrypoint.py#L7440-L7449) | Passer par le dispatcher de thread principal (`post()`). |
| **T-04** | majeur | dette | **`_bg_load_ai_suggestions` manipule la liste UNO (`removeItems`/`addItems`) depuis un thread.** | [entrypoint.py:7517](src/mirai/entrypoint.py#L7517) → `_load_suggestions` [entrypoint.py:7458-7508](src/mirai/entrypoint.py#L7458-L7508) | Idem T-03. |

### Authentification et configuration

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **A-01** | bloquant | régression | **`master` ignore le contrat d'authentification `/llm/v1` du DM.** Le serveur sert `llmToken`, `llmEndpoint`, `llmTokenExpiresAt`, `embdUrl` — `master` n'en lit **aucun** (0 occurrence dans `src/`). Il ne connaît que `llm_api_tokens`, sans reprise après 401 ni distinction proxy/direct. Le correctif existe, mais seulement sur la branche expérimentale. | `grep` sur `src/` : `llmToken`, `llmEndpoint`, `embdUrl` → **0** · réponse `/config` du DM local : ces quatre clés sont présentes (vérifié ce jour) | Porter la chaîne d'auth de la branche expérimentale (commit `f0ef248`, 22 tests). |
| **A-02** | bloquant | régression | **L'« état absorbant » est atteint et sans issue.** Le profil de test porte `enrolled: true` **sans** paire relais et avec `llm_api_tokens` vide → 401 « Missing credentials » sur 100 % des appels. Pire : le drapeau court-circuite le ré-enrôlement, donc **rien ne peut plus le corriger côté plugin**. | `config.json` : `enrolled: true`, ni `relay_client_id` ni `relay_client_key`, `llm_api_tokens: ""` · `~/log.txt` 00:42:29 — `[RELAY] no relay creds: id=no key=no` puis 00:42:31 — `[ENROLL] Auto-check: already enrolled, skipping wizard` | `enrolled` ne doit jamais suffire : conditionner le gate à la **présence effective d'une paire relais**, et proposer un ré-enrôlement (idempotent côté DM). |
| **A-03** | majeur | régression | **Le rapport de statut d'update échoue en 401, trois fois, en silence.** Conséquence directe d'A-02 ; aucun retour utilisateur. | `~/log.txt` 00:42:29 — `Update status report attempt 3/3 failed: HTTP Error 401: Unauthorized` | Corriger A-02 ; journaliser explicitement l'abandon après la dernière tentative. |
| **A-04** | mineur | dette | **Quatre variantes de nommage cohabitent pour les mêmes réglages Keycloak** : `keycloakClientId`/`keycloak_client_id`, `keycloakRealm`/`keycloak_realm`, `tokenEndpoint`/`token_endpoint`/`keycloakTokenEndpoint`/`keycloak_token_endpoint`. 70 clés de configuration sont lues au total. | Inventaire des clés lues dans `src/mirai/` | Documenter la clé canonique et ne garder les alias qu'en lecture, avec un commentaire. |

### Sécurité

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **S-01** | majeur | sécurité | **Des noms d'hôtes d'infrastructure interne (domaine privé du ministère) sont committés dans un dépôt GitHub**, dans un profil de configuration, un test unitaire et un guide développeur. Le gate anti-leak du build n'inspecte que `config.default.json` : il ne les voit pas. | `config/profiles/config.default.dgx.json:6` · `tests/unit/test_bootstrap_insecure_ssl.py:20-21` · `docs/PLUGIN_DEVELOPER_GUIDE.md:629` (hôtes volontairement non recopiés ici) | Remplacer par des placeholders ; étendre le gate anti-leak à `config/profiles/`, `docs/` et `tests/`. |
| **S-02** | majeur | dette | **La télémétrie sécurisée (Ed25519) ne fonctionne sur aucun poste** : `security_flow.py` (831 lignes) exige `cryptography`, absent du Python de LibreOffice — et la contrainte no-pip interdit de l'installer. Le repli legacy est silencieux côté utilisateur. | `~/log.txt` 00:42:28 — `Secure flow init failed: ed25519 backend unavailable (install 'cryptography' in LibreOffice Python)` puis `Secure telemetry unavailable; fallback to legacy sender` · vérification : `/Applications/LibreOffice.app/Contents/Resources/python -c "import cryptography"` → `ModuleNotFoundError` | Décider explicitement : soit embarquer une implémentation Ed25519 pure-python, soit acter le repli et **documenter ces 831 lignes comme inertes** plutôt que de laisser croire qu'elles protègent. |
| **S-03** | mineur | dette | Le serveur de callback PKCE se lie sur `0.0.0.0:28443`. Avec `SO_REUSEADDR`, un autre processus lié à `127.0.0.1:28443` intercepte le callback sans que le plugin échoue : le code d'autorisation part ailleurs et le flux expire au bout de 3 min. | Piège n°8 du plan (vécu le 2026-07-25) ; port vérifié libre pendant cette campagne (`lsof -nP -iTCP:28443`) | Se lier explicitement à `127.0.0.1` pour échouer bruyamment en `EADDRINUSE`. |

### Qualité et dette

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **Q-01** | majeur | dette | **285 blocs `except … : pass` silencieux** sur 511 `except Exception`. Chaque panne survenue dans l'un d'eux est invisible pour l'utilisateur **et** pour le support. | Comptage par fichier : `entrypoint.py` 450/261 · `calc.py` 30/16 · `writer.py` 15/2 · `security_flow.py` 5/3 · `calc_prompt_function.py` 11/3 | Helper `suppress_and_log(shell, label)` ; `except` large réservé aux frontières et toujours journalisé. |
| **Q-02** | majeur | dette | **73 fonctions dépassent 40 lignes**, dont `settings_box` (990 l.), `_show_edit_selection_dialog` (766 l.), `_show_formula_assistant_dialog` (460 l.). `entrypoint.py` fait 9 889 lignes. | Mesure AST sur `src/mirai/**/*.py` | Découpage en mixins (`shell/`) + budgets chiffrés du plan. |
| **Q-03** | mineur | dette | **266 lignes de code mort** : `credentials_box` (147 l.), `_choose_model_via_ai` (66 l.), `_proxy_mismatch` (24 l.), `_api_reachable` (19 l.), `clear_rebind_required` (4 l.), `_ensure_device_management_state_with_dialog` (3 l.), `_strip_think_blocks` (3 l.). | Analyse AST croisée `src/` + `tests/` (callbacks UNO exclus) | Suppression au commit de nettoyage. |
| **Q-04** | mineur | dette | **Aucun linter configuré** ; `scripts/03-test-local.sh` ne compile ni `src/mirai/core/**` ni `src/mirai/ui/**`. `ruff` remonte 369 diagnostics (233 lignes trop longues, 57 `C901`, 20 f-strings sans placeholder, 3 `except:` nus, 4 imports inutilisés). | `ruff check --select E,F,B,C901 --line-length 100 src/` | `pyproject.toml` + branchement dans `03-test-local.sh` avec dégradation gracieuse. |

### Documentation

| # | Sév. | Catégorie | Constat | Preuve | Correction proposée |
|---|---|---|---|---|---|
| **D-01** | majeur | doc | **La notice utilisateur documente un raccourci qui n'existe pas et une entrée de menu absente.** §3.1 annonce « ✨ Générer la suite (⌘Q) … ou menu MIrAI → Générer la suite » : `ExtendSelection` **n'est pas** dans `Addons.xcu` — la seule voie d'accès est le raccourci qui casse ⌘Q (R-02). | [notice-utilisateur.md:90-97](docs/notice-utilisateur.md#L90-L97) vs [Addons.xcu](oxt/Addons.xcu) | Aligner la notice sur la refonte (entrée unique + palette). |
| **D-02** | majeur | doc | **⌘J est annoncé partout mais n'est déclaré nulle part.** README et notice présentent « Ajuster la longueur — Ctrl+J » ; aucun nœud `J_MOD1` dans `Accelerators.xcu`. | [README.md:34](README.md#L34), [notice-utilisateur.md:139-146](docs/notice-utilisateur.md#L139-L146) vs [Accelerators.xcu](oxt/Accelerators.xcu) | Idem D-01. |
| **D-03** | mineur | doc | **Les mentions upstream subsistent alors que le code a été réécrit** (John Balis / localwriter). | [README.md:5](README.md#L5), [README.md:372](README.md#L372), [README.md:377](README.md#L377), [license.txt:18-21](oxt/registration/license.txt#L18-L21) | Retrait prévu par le plan §« Retrait upstream » ; vérifier au passage qu'aucun code dérivé ne subsiste. |
| **D-04** | mineur | doc | Le `README.md` de `deploy/docker` (dépôt voisin) annonce l'API « sur http://localhost:3001 (par défaut `DM_PORT=3001`) » alors que le compose et le `.env` utilisent **8089**. | `../device-management/deploy/docker/README.md` vs `docker-compose.yml` (`${DM_PORT:-8089}`) | Corriger la doc du dépôt voisin (hors périmètre de cette branche — signalé). |

### Ce qui fonctionne — vérifié

| Élément | Preuve |
|---|---|
| Chargement et enregistrement de l'extension | `~/log.txt` — `=== mirai extension registered successfully ===` |
| Télémétrie applicative (chemin legacy) | `Telemetry trace sent successfully: ExtensionLoaded, status: 200` |
| Cohérence de la télémétrie | 19 spans déclarés dans `_ACTION_NAMES`, **19 émis** : aucun span mort, aucun span non déclaré |
| Menu contextuel Writer (travail de Richard) | `[context-menu] interceptor registered via qi (trigger)` — 4 entrées, toutes implémentées dans `writer.py` |
| Failover des URLs bootstrap | `DM bootstrap URLs (failover order): [...]` — deux bases essayées dans l'ordre |
| Compilation de tous les modules Python | `py_compile` sur l'ensemble des fichiers suivis : OK |
| Tests unitaires | 224/224 |

---

## Les trois urgences

1. **`Cmd+Q` détourné (R-02).** C'est le seul défaut qui casse une fonction système de l'OS : l'utilisateur qui veut quitter LibreOffice déclenche un appel LLM. À traiter en premier, indépendamment de la refonte.
2. **L'authentification `/llm/v1` (A-01 + A-02).** `master` ne connaît pas le contrat du serveur, et l'état absorbant rend la panne définitive côté plugin. Tant que ce n'est pas corrigé, **aucune fonction IA ne peut aboutir** — et le diagnostic accuse l'interface.
3. **L'appel LLM depuis un thread de fond (T-01).** Crash aléatoire de LibreOffice, difficile à reproduire, impossible à diagnostiquer pour un utilisateur. La refonte le supprime par construction ; c'est la raison technique principale de la faire.

## Note de méthode

Deux défauts ont été trouvés en exerçant le plugin en LibreOffice réel (R-06, S-02) et n'étaient pas visibles à la lecture du code : ils ne se manifestent que par une **absence** dans le journal. C'est la contrepartie de Q-01 — 285 chemins d'erreur muets — et cela justifie l'exigence du plan : *tout run doit produire un retour lisible*.
