# Plan — Démonstrateur jetable : moteur MCP interne + prompt universel DSFR

## Context

Le plugin MIrAI LibreOffice expose aujourd'hui des actions IA figées via menus (Writer : extend/edit/resize/summarize/simplify ; Calc : transform/formula/analyze). On réécrit **le cœur** autour d'un nouveau paradigme :

- Un **moteur interne de type MCP** : registre d'outils typés construits sur les API UNO (cible LibreOffice **25.8.x** / MIMO), orchestrés par le LLM au lieu d'actions codées en dur.
- Une **fenêtre de prompt universelle** (palette flottante non modale) : point d'entrée unique, chips/raccourcis pour les fonctions fréquentes, heuristiques contextuelles simples.
- IHM au plus près du **DSFR** (tokens vérifiés contre `@gouvfr/dsfr@1.14.0`).

La **coquille reste intacte** : enrollment, Keycloak/SSO, device management, auto-update, télémétrie — *à l'exception de la chaîne d'auth `/llm/v1`, corrigée séparément et déjà livrée* (voir §Auth `/llm/v1`). Statut : **démonstrateur jetable assumé**, mais dette maîtrisée (maintenable par un humain + assistant de codage) et **tests d'iso-fonctionnalité** reproduisant les 8 fonctions existantes.

## Décisions actées

- **Branche** : `exp-jetable/demonstrateur-moteur-mcp` — le nom porte explicitement « expérimentation » + « jetable » (règle d'équipe). Bandeau « ⚠️ EXPÉRIMENTATION JETABLE — ne pas merger vers master » en tête du README de la branche ; PR éventuelle en draft uniquement, avec la même mention.
- **IHM** : fenêtre **modale/flottante** type palette de commandes (pas de sidebar). Sidebar = éventuelle phase ultérieure pour l'historique.
- **Menus actuels supprimés** : une seule entrée « MIrAI — Assistant » (menu + bouton toolbar + raccourci) ; les anciennes fonctions deviennent des chips.
- **Tool calling** : double abstraction — natif OpenAI si le relais le supporte, repli JSON structuré parsé côté plugin ; mode `auto` avec sonde + override config `llm_tool_mode` (distribuable par DM).
- **Retrait des références upstream/auteur** (tout a été réécrit) : voir §Retrait upstream.

## État des lieux (synthèse exploration)

- `entrypoint.py` = 9 617 l. (~6 100 coquille, ~3 200 cœur, ~300 partagées). `security_flow.py` (831 l.) = coquille pure. `menu_actions/writer.py` + `calc.py` = fonctions pures prenant `job` — matière première des tools.
- **La couture** que le cœur consomme : (a) `make_api_request`/`make_chat_request`/`stream_request`/`extract_content_from_response` ; (b) `get_config`/`set_config` ; (c) `_send_telemetry` (+ `_ACTION_NAMES` l.479, avec fallback attrs explicites) ; (d) `input_box`/`_show_message`/thinking widget.
- **Threading** : pattern imposé = thread réseau → `queue.Queue` → drain sur thread principal avec `processEventsToIdle` (jamais depuis un thread de fond). ⚠️ violation latente existante : `_bg_ai_suggestions` (entrypoint.py:7749) appelle `stream_request` hors main thread.
- `stream_request` ne remonte que `delta.content` → il ne peut pas porter les `delta.tool_calls` natifs → nouveau pump SSE dans le cœur.
- `make_chat_request` n'a **pas** les clamps max_tokens par modèle (seul `make_api_request` les a) → la façade les réapplique.
- Le build (`02-build-oxt.sh`) copie `src/` en bloc → `src/mirai/core/` embarqué automatiquement ; gate anti-leak inchangé (n'inspecte que `config.default.json`).
- Tests : coquille bien testée (~2 200 l., stubs `tests/stubs/uno_stubs.py` + `make_job()`) ; cœur quasi pas testé (seulement `test_calc_menu_actions.py`, `test_summarize_writer.py`).
- **UI/DSFR faisable** en `UnoControlDialog` programmatique. Chips = `FixedText` cliquables (PAS `Button` : thèmes gtk3/macOS écrasent les couleurs) ; hover via `_add_rollover()` existant (entrypoint.py:6897). Limites : pas d'arrondis/ombres/animations — acceptable, les boutons DSFR sont carrés. Pas de webview dans LO (confirmé).
- **Marianne** : licence État hors MIT du DSFR → jamais embarquée dans l'OXT ; sonde runtime `Marianne` → `Arial` → `Liberation Sans` (cache).
- **Raccourci** : 🚨 pas Ctrl+Shift+Espace (= espace insécable Writer / Tout sélectionner Calc). Slot libre vérifié : `SPACE_MOD1_MOD2` (Ctrl+Alt+Espace) + variante `install:module="macosx"` `SPACE_MOD3_MOD2` (Ctrl+Opt+Espace, car Cmd+Alt+Espace = Finder).
- ⚠️ **LO 25.8 EOL depuis le 12/06/2026** (supporté : 26.2.x) — à signaler au MIMO. Mitigation : aucune API > LO 7.x → même OXT sur 25.2/25.8/26.2. `description.xml` ne déclare aucune version minimale (inchangé).

## Approche recommandée

### Arborescence cible du plugin

Trois couches, une dépendance à sens unique : **`ui/` → `core/` → façade → `shell/`**. Aucune flèche en retour (règles vérifiées par tests). Tailles indicatives ; ✅ = déjà écrit, 🔜 = itération 2.

```
AssistantMiraiLibreOffice/
├── main.py                          # shim UNO (inchangé) → importe entrypoint
├── src/mirai/
│   ├── entrypoint.py                # 🔜 ~300 l. — assemblage MainJob(mixins), drapeaux de classe,
│   │                                #    execute/trigger, g_ImplementationHelper (aujourd'hui 9 915 l.)
│   ├── security_flow.py             # coquille pure, intouchée (831 l.) — Ed25519, vaults OS, télémétrie
│   ├── calc_prompt_function.py      # =PROMPT() autonome, intouché (dette assumée et documentée)
│   │
│   ├── shell/                       # 🔜 COQUILLE découpée en mixins (cf. §Découpage d'entrypoint.py)
│   │   ├── common.py                #    log_to_file, _UI, user-agent, redaction, _EXT_MGR_SINGLETON
│   │   ├── config.py                #    config fichier, bootstrap URLs, failover, _fetch_config, cache
│   │   ├── http.py                  #    _urlopen, proxy, contexte SSL
│   │   ├── auth.py                  #    Keycloak PKCE, jetons, llmToken, _recover_llm_auth
│   │   ├── enrollment.py            #    gate, assistant d'enrôlement, état device management
│   │   ├── update.py                #    auto-update (~800 l.)
│   │   ├── telemetry.py             #    _send_telemetry, LlmRelayError, secure flow
│   │   ├── llm_legacy.py            #    make_api_request/make_chat_request/stream_request (à supprimer)
│   │   ├── dialogs.py               #    input_box, message/confirm, widget « réflexion »
│   │   ├── settings_ui.py           #    settings_box, proxy, credentials, à-propos
│   │   └── context_menu.py          #    intercepteur clic droit + listener document (repris de Richard)
│   │
│   ├── core/                        # MOTEUR — n'importe JAMAIS la coquille (test d'archi)
│   │   ├── shell_facade.py     ✅   #    ShellServices + MainJobShell (duck-typing, + recover_llm_auth)
│   │   ├── tool_calls.py       ✅   #    ToolSpec / ToolCall / ToolResult + validateur JSON-schema
│   │   ├── registry.py         ✅   #    list_tools / call_tool (miroir MCP) + openai_tools + catalogue
│   │   ├── context.py          ✅   #    ToolContext : document, contrôleur, undo paresseux (1 Ctrl+Z/run)
│   │   ├── llm_client.py       ✅   #    step() natif|JSON, sonde auto, reprise 401, parseur tolérant
│   │   ├── sse_pump.py         ✅🔜 #    lecture SSE ; 🔜 perd son drain processEventsToIdle
│   │   ├── orchestrator.py     ✅   #    boucle agentique + RunObserver (journal d'actions)
│   │   ├── presets.py          ✅🔜 #    chips ; 🔜 factorisé en run_text_pipeline + Corriger/Traduire
│   │   ├── sinks.py            ✅   #    Palette / WriterInsert / WriterReplace / CalcCell
│   │   ├── prompts.py          ✅   #    prompts système FR + protocole d'outils JSON
│   │   ├── conversation.py     ✅   #    persistance MVP du fil (local, plafonné, effaçable)
│   │   ├── text_filters.py     ✅   #    think/markdown, stop phrases, motifs de question
│   │   ├── entry.py            ✅   #    open_palette() — unique point d'entrée depuis trigger()
│   │   ├── errors.py           🔜   #    messages d'erreur + error_message (fin de l'import circulaire)
│   │   ├── ui_thread.py        🔜   #    MainThreadDispatcher : post()/call() via AsyncCallback
│   │   ├── suggestions.py      🔜   #    recommandations contextuelles v1 (heuristiques pures)
│   │   └── tools/
│   │       ├── writer_tools.py ✅   #    5 tools Writer (sélection, carte, insert, replace, find/replace)
│   │       └── calc_tools.py   ✅   #    7 tools Calc (+ helpers portés : colonne résultat, formules)
│   │
│   ├── ui/                          # IHM — ne connaît que core/
│   │   ├── dsfr.py             ✅🔜 #    tokens DSFR, sonde police ; 🔜 add_clickable factorisé
│   │   └── palette.py          ✅🔜 #    🔜 épurée, redimensionnable, jauge d'activité, onglets
│   │
│   ├── menu_actions/           ❌   # SUPPRIMÉ au commit de nettoyage (writer.py, calc.py, shared.py)
│   ├── CAbundle/                    # chaîne CA bootstrap (inchangée)
│   ├── icons/                       # icônes toolbar/mascotte
│   └── idl/                         # XPromptFunction.idl (documentation)
│
├── oxt/
│   ├── Addons.xcu              🔜   # entrée unique + Paramètres/À propos/📚 Documentation
│   ├── Accelerators.xcu        ✅   # Ctrl+Alt+Espace (macOS : Ctrl+Opt+Espace)
│   ├── Jobs.xcu                🔜   # + onLoad/onNew (menu contextuel, repris de master)
│   ├── CalcAddIn.xcu, description.xml, META-INF/manifest.xml, registration/, assets/, icons/   # inchangés
│
├── config/                          # profils bootstrap + calc-functions.json (inchangés)
├── prompts/
│   ├── prompt-creation.md      🔜   # à compléter : chaîne d'auth /llm/v1 (§3.3, 3.5, 3.7, 4.1, 6.3, 9, 5)
│   └── fix-llm-token-auth.md, update-prompt-creation-llm-auth.md   # sources de vérité
│
├── docs/ARCHITECTURE.md        ✅🔜 # carte des couches ; 🔜 modèle worker/dispatcher + budgets qualité
├── pyproject.toml              🔜   # config ruff (dev uniquement, jamais embarquée)
└── tests/
    ├── stubs/                  ✅   # uno_stubs, fake_shell, fake_docs (+ 🔜 fake_dispatcher)
    ├── unit/                   ✅   # coquille (~2 200 l., intacte) + core/ (111 tests)
    │   └── core/               ✅🔜 # + test_ui_thread, test_suggestions, garde-fous d'architecture
    └── integration/, simulation/, fixtures/                        # inchangés
```

### Moteur de tools — 13 tools couvrent les 8 fonctions

Décision clé (petits modèles type llama-3.3) : **la prose générée ne transite jamais en argument JSON** — les tools lisent le contexte et font des mutations structurelles courtes ; le texte long est streamé comme message final vers un **sink** (préserve l'UX de streaming dans le document).

- Writer lecture : `writer_get_selection`, `writer_get_document_map` (réutilise `_chunk_doc_paragraphs`)
- Writer mutation : `writer_replace_selection`, `writer_insert_text`, `writer_find_replace` (paires FIND/REPLACE — reprend `_parse_find_replace`)
- Calc lecture : `calc_get_selection`, `calc_read_range`, `calc_get_sheet_overview` (reprend `_build_schema_context`)
- Calc mutation : `calc_write_cells`, `calc_write_result_column` (colonne « Résultat IA » non destructive), `calc_set_formula` (relit `Err:` → auto-correction LLM), `calc_fill_formula_down`
- UI : `ui_ask_user` (questions de clarification + confirmations preview→apply dans la palette)

Sinks : `PaletteSink`, `WriterInsertSink` (marqueurs legacy `---début-du-…---` conservés), `WriterReplaceSink`, `CalcCellSink`. `call_tool` n'échoue jamais en exception → `ToolResult(ok=False)` renvoyé au LLM.

### Presets / chips

- **Agentiques** (le LLM pilote les tools) : Modifier (sélection ou doc entier), Formule (injecte la base `config/calc-functions.json` + retrieval mots-clés conservé tel quel), Analyser, et le prompt libre.
- **Pipeline** (Python pilote, le LLM n'est qu'une fonction texte — iso-fonctionnalité et robustesse petits modèles) : Étendre, Résumer, Simplifier, Ajuster ±, Transformer (appels par ligne comme aujourd'hui).
- Visibilité des chips = heuristiques simples : type de doc, sélection présente, plage numérique. Pas de ML (v1 du « moteur de recommandation »).
- Télémétrie : les presets émettent les spans legacy (`SummarizeSelection`…) avec `{"via":"palette"}` → dashboards préservés ; nouveaux spans `assistant.open/run/tool/probe` passés en attrs explicites (`_ACTION_NAMES` intouché). Jamais de contenu de prompt.

### Persistance de conversation (minimum viable)

- `core/conversation.py` — `ConversationStore` : fichier `<UserConfig>/assistant_conversation.json`, écriture atomique (tmp + replace, même pattern que `FileJsonStore`), chemin fourni par la façade (`shell.user_config_dir()`). API : `load()`, `append(role, text, app)`, `clear()`.
- **Ce qui est persisté** : uniquement les tours user + réponse finale de l'assistant (jamais les tool calls/résultats — éphémères au sein d'un run). Cap : 20 derniers échanges et ~100 Ko, troncature FIFO. Tolérant à la corruption (JSON invalide → repart vide, jamais de crash).
- **Injection dans le contexte LLM** : l'orchestrateur préfixe les N derniers échanges (cap `conversation_context_max_chars`, défaut ~4 000) avant le prompt courant → permet le « continue », « raccourcis-le », etc.
- **UI** : la zone réponse de la palette devient un fil de conversation restauré à la réouverture (y compris après redémarrage de LO) ; bouton « Nouvelle conversation » (= `clear()`).
- **Vie privée** : stockage local dans le profil utilisateur uniquement (même statut que les documents eux-mêmes), jamais envoyé en télémétrie, effaçable en un clic ; mentionné dans la notice utilisateur.

### Client LLM double-mode

- `build_chat_request` (façade) : appelle `job.make_chat_request`, désérialise le body, merge `{"tools":…, "tool_choice":"auto"}` en natif, **réapplique les clamps max_tokens par modèle**, reconstruit la Request (aucune modif de la coquille). Test verrouillant l'équivalence.
- Natif : assemblage des `delta.tool_calls` fragmentés ; fin sur `finish_reason=="tool_calls"`.
- JSON fallback : catalogue de tools dans le prompt système + protocole `{"tool_calls":[…]}` ; parseur tolérant (fences, virgules traînantes, `<think>`, un seul call nu) ; buffering des deltas commençant par `{`/```` ``` ````/`<think>` avec **flush si le parse échoue** (jamais perdre la sortie).
- Sonde `auto` une fois par (endpoint, modèle), cachée en config ; erreurs HTTP remontées à `shell.report_llm_error` (télémétrie `LlmRelayError` + dédup conservées côté coquille).

### Palette universelle (DSFR)

- `UnoControlDialog` non modal : bandeau `0x000091` + filet accent 4 px ; rangée de chips (`FixedText`, bg `0xE3E3FD`, texte `0x000091`, hover `0xC1C1FB`, `Ctrl+1..9`) ; champ prompt multiline (focus ring émulé `0xDDDDDD`→`0x000091`) ; bouton primaire `0x000091`/hover `0x1212FF`, secondaire blanc bordé ; zone réponse streamée ; footer liens Réglages/À propos/Documentation (actions coquille existantes) + hint `0x666666`.
- Corrections tokens vs `_UI` existant : `text_body=0x3A3A3A` (0x161616 = titres), ajouter `0xEEEEEE`, `0xE3E3FD`/`0xC1C1FB` ; rouge actionnable `0xC9191E`.
- **Journal d'actions (optionnel, façon Claude cowork)** : zone repliable « Voir les actions » sous la zone de réponse, alimentée par le `RunObserver` de l'orchestrateur — chaque tool call proposé par le LLM s'affiche dès réception avec un libellé FR lisible (mapping nom de tool → « Lecture de la sélection », « Remplacement du texte », « Écriture de la formule en C4 »…) et un statut mis à jour en direct : ⏳ proposé → ⚙ en cours → ✓ fait / ✗ échec (+ durée). Replié par défaut, état du toggle mémorisé (`assistant_show_actions` en config). Implémentation légère : Edit read-only multiline mis à jour ligne à ligne pendant le drain main-thread (aucun coût quand replié). Le RunObserver émet : `on_tool_calls(proposés)`, `on_tool_result(résultat)`, `on_final(texte)` — testé dans `test_orchestrator_loop.py`.
- Clavier interne : Enter=envoyer, Shift+Enter=retour ligne, Esc=fermer, Tab=cycle chips.
- Ouverture : menu unique + bouton toolbar + `SPACE_MOD1_MOD2` (variante macOS `SPACE_MOD3_MOD2`).
- Réentrance : un seul run à la fois (flag busy, input désactivé pendant le pump).

> ⚠️ Les points UI ci-dessus (bandeau bleu, liens en pied, chips sur plusieurs lignes, bouton Envoyer) sont **remplacés par l'itération 2** — voir la section dédiée plus bas.

### Manifests

- `Addons.xcu` : sous-menu + toolbar remplacés par l'entrée unique `service:fr.gouv.interieur.mirai.do?OpenAssistant&src=…`.
- `Accelerators.xcu` : un seul binding par module (Writer + Calc).
- `Jobs.xcu`, `description.xml`, `manifest.xml`, `CalcAddIn.xcu` : **intouchés**.
- Branchement dans `trigger()` (entrypoint.py:9538), après le gate d'enrollment : `if action == "OpenAssistant": from .core.entry import open_palette; open_palette(self, model); return` (import lazy, zéro coût au chargement). Les actions résiduelles non-IA (`settings`, `AboutDialog`, `Documentation`, `OpenmiraiWebsite`) : mini-dispatch ~30 l. dans `trigger()`.

## Itération 2 (2026-07-25) — exécution non bloquante + UI épurée

### Constat après essai réel

- **« Il ne se passe rien quand on clique » est un problème de VISIBILITÉ, pas d'exécution.** Le log le prouve : clic → span `ResizeSelection` émis à 16:07:33 → appel LLM → 401 reçu 600 ms plus tard. L'action part bien ; le retour s'affiche dans une zone grise en 9 pt que rien ne signale, et l'utilisateur regarde son document.
- **L'application reste semi-bloquée pendant un run** : le réseau est déjà dans un thread, mais le thread principal s'immobilise ensuite dans une boucle de drain qui pompe `processEventsToIdle`. Ce pompage imbriqué est l'héritage du code historique — c'est lui qui rend LibreOffice « mou » et qui a causé le SIGABRT (`std::terminate` dans `DispatchUserEvents`).
- **L'IHM est trop grosse** : bandeau bleu épais, chips sur 2 lignes, historique en 9 pt, 5 liens en pied de fenêtre.

### A. Modèle d'exécution vraiment non bloquant (remplace le drain main-thread)

Principe : **le run entier part dans un thread worker ; le thread principal retourne immédiatement à la boucle d'événements de LibreOffice.** L'application reste 100 % utilisable pendant la génération (frappe, défilement, autre document).

- Nouveau `src/mirai/core/ui_thread.py` — `MainThreadDispatcher(uno_ctx)` :
  - `post(fn)` : exécute `fn` sur le thread principal, sans attendre (mises à jour d'UI).
  - `call(fn, timeout=30)` : depuis le worker, exécute `fn` sur le thread principal et **rend son résultat** (tout ce qui touche le document).
  - Bâti sur `com.sun.star.awt.AsyncCallback` + `XCallback` — pattern déjà éprouvé dans la coquille ([entrypoint.py:1969-1988](src/mirai/entrypoint.py#L1969-L1988)) et déjà utilisé par `_DeferredCall` de la palette.
- Tout ce qui touche UNO passe par le dispatcher : écritures document (sinks), exécution des tools (`registry.call_tool`), contexte undo, mises à jour de la palette.
- **`sse_pump` perd son drain** : il ne fait plus que lire le flux SSE dans le thread courant (désormais le worker). **Plus un seul `processEventsToIdle` dans le nouveau cœur** — la contrainte historique disparaît par construction, au lieu d'être contournée.
- **Anti-flood** : coalescence des deltas (flush au plus toutes les ~120 ms ou tous les ~80 caractères) pour ne pas saturer la file d'événements du thread principal.
- **Annulation** : `threading.Event` vérifié entre chunks et entre étapes ; pendant un run le bouton d'envoi devient « Arrêter ».
- **Garde-fous** : `call()` a un timeout (si le thread principal est retenu par un dialogue modal, on n'attend pas indéfiniment) ; `post()` devient inerte après fermeture de la palette ; un seul run à la fois (flag busy).
- **Tests** : `FakeDispatcher` synchrone (exécute immédiatement) → toute la suite existante reste valable sans réécriture ; nouveaux tests `test_ui_thread.py` (post/call, timeout, inertie après fermeture) et un garde-fou « aucun `processEventsToIdle` dans core/ » sur le modèle de `test_no_entrypoint_import.py`.

### B. Fenêtre flottante épurée, redimensionnable, à zone basse commutable

Structure cible (de haut en bas), tout le reste est supprimé :

```
┌──────────────────────────────────────────────────────┐  ← titre natif de la fenêtre
│ Continuer  Résumer  Simplifier  Raccourcir  Allonger │  chips — UNE seule ligne
│ Sélection : « Le préfet arrête que… »                │  indicateur de sélection (§C)
│ ┌───┬────────────────────────────────────────────┐   │
│ │ ⠹ │  champ de prompt (2 lignes)                 │   │  jauge d'activité à GAUCHE (§E)
│ │1240│                                            │   │
│ └───┴────────────────────────────────────────────┘   │
│ ┌──────────────────────────────────────────────────┐ │
│ │  zone basse commutable (historique/suggestions/  │ │  ← absorbe le redimensionnement
│ │  actions) — un seul rectangle, trois contenus    │ │
│ └──────────────────────────────────────────────────┘ │
│ Historique · Suggestions · Actions      Terminé      │  onglets en bas à gauche, statut à droite
└──────────────────────────────────────────────────────┘
```

- **Supprimé** : bandeau bleu épais (le titre natif suffit ; au plus un filet d'accent de 3 px), liens Réglages / À propos / Documentation, hint « Échap : fermer », bouton « Envoyer » (envoi à Entrée, rappelé dans la ligne de statut).
- **Chips sur UNE seule ligne, sans emoji** : `Continuer · Résumer · Simplifier · Raccourcir · Allonger · Modifier` (Writer), `Transformer · Formule · Analyser` (Calc). Police 7 pt, padding resserré. Contrainte dure : **jamais de retour à la ligne** — si ça déborde, raccourcir les libellés (`HelpText` porte le libellé complet), pas de seconde ligne.
- **Polices** : chips 7 pt, prompt 8 pt, zone basse 7 pt, statut 8 pt.
- `Addons.xcu` : ajouter **📚 Documentation** aux côtés de ⚙️ Paramètres et ℹ️ À propos (déjà rétablis) — ces trois fonctions vivent **uniquement dans le menu**.
- Le layout reste **mesuré** (`getPreferredSize`) : seules les constantes changent, aucune régression de troncature.

### C. Indicateur de sélection en direct (reprise de la logique historique)

Une ligne sous les chips, qui montre **ce sur quoi l'action va porter** — répond directement au « il ne se passe rien ».

- **Copier le bon patron, pas le mauvais.** Deux implémentations coexistent dans le legacy :
  - ✅ `FormulaSelectionListener` ([entrypoint.py:8256-8292](src/mirai/entrypoint.py#L8256-L8292)) — `XSelectionChangeListener` sur le contrôleur, **livré par LibreOffice sur le thread principal**, zéro polling. C'est le modèle à reprendre (y compris l'astuce de classe de base dynamique `*([_XSCListener] if _XSCListener else [])` qui garde le module importable hors LO).
  - ❌ `_selection_refresh_loop` ([entrypoint.py:7448-7461](src/mirai/entrypoint.py#L7448-L7461)) — thread de fond qui écrit `Label`/`TextColor` sur des contrôles VCL toutes les 3 s, sans SolarMutex ni marshalling. **À ne surtout pas porter** : c'est exactement la classe de bug qu'on vient d'éliminer.
- **Enregistrement / retrait** : `addSelectionChangeListener` après `createPeer` ; conserver le tuple `(listener, controller)` sur l'instance pour éviter le ramasse-miettes ; `removeSelectionChangeListener` **avant** `dispose()` dans `close()` — le legacy fait l'inverse ([entrypoint.py:8228-8245](src/mirai/entrypoint.py#L8228-L8245)), on corrige au passage. Garde `if self.busy: return` dans le callback.
- **Filet de sécurité** : sur Writer le listener est moins fiable qu'en Calc (déclenchement sur déplacement du curseur) → doubler d'une relecture au `windowActivated` de la palette, comme le fait déjà le legacy ([entrypoint.py:7363](src/mirai/entrypoint.py#L7363)) — coût nul, thread principal.
- **Formateurs (purs, testables hors LO)** :
  - Writer — reprendre la recette de `_selection_info` ([entrypoint.py:6822-6839](src/mirai/entrypoint.py#L6822-L6839)) : espaces compactés, ellipse médiane à 90 caractères sur frontière de mot. Adapter le libellé au ciblage paragraphe : `Sélection <extrait>` / sans sélection `Paragraphe courant : <extrait>` / document vide → invite courte.
  - Calc — réutiliser `_range_label` ([menu_actions/calc.py:52-59](src/mirai/menu_actions/calc.py#L52-L59)) qui rend exactement `5 cellules sélectionnées (A4:A8)`.
- **Ne pas reproduire** : le double appel à `_has_multiple_styles` ([entrypoint.py:6792](src/mirai/entrypoint.py#L6792), jusqu'à 2 000 allers-retours UNO, appelé deux fois par rafraîchissement). Calculer la condition une fois et la passer au setter — ou l'abandonner pour le démonstrateur.
- **Getter à repli** : reprendre le principe de `_get_current_selection` ([entrypoint.py:6419](src/mirai/entrypoint.py#L6419)) — re-résoudre le document à chaque appel, tout en `try/except`, et **ne jamais rendre `None`** (repli sur l'instantané d'ouverture). À greffer sur `_current_context()` de la palette plutôt que dupliquer les recherches de Desktop.

### D. Rendre le retour visible

- Ligne de statut lisible au-dessus de l'historique, colorée selon l'issue : erreur `#CE0500`, succès `#18753C`, en cours `#666666`.
- Pendant un run : « L'assistant travaille… » + bouton « Arrêter » ; à la fin : « Terminé » ou le message d'erreur explicite (401 → « Jeton expiré — Menu MIrAI ▸ Paramètres pour vous reconnecter »).

### E. Jauge d'activité LLM (à gauche du champ de prompt)

Colonne étroite (~34 px) collée à gauche du prompt, visible seulement pendant un run — elle répond au besoin de « voir que ça travaille » sur les opérations longues.

- **Caractère qui pulse** façon Claude : cycle braille `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (rendu fiable dans les contrôles UNO, largeur stable), rafraîchi toutes les ~120 ms — piloté par le worker qui `post()` la mise à jour sur le thread principal (même cadence que la coalescence des deltas, donc aucun coût supplémentaire).
- **Compteur de jetons** sous le spinner, en 7 pt : estimation locale en direct (≈ caractères reçus ÷ 4, sans dépendance externe — contrainte no-pip), **remplacée par la valeur exacte** si le relais renvoie un bloc `usage` en fin de flux. Aucune modification du corps de requête (pas de `stream_options`) : on lit `usage` s'il vient, on ne le réclame pas — on évite ainsi de casser les relais qui rejettent les champs inconnus.
- **Chronomètre** discret à côté du compteur pour les opérations longues (`1 240 tk · 12 s`).
- Au repos : la colonne affiche un point atone (pas de disparition, pour éviter tout saut de mise en page).

### F. Zone basse commutable : Historique / Suggestions / Actions

Un seul rectangle, trois contenus, **onglets en bas à gauche** — c'est le gain de place demandé.

- **Implémentation** : pas de `UnoControlTabPageContainer` (capricieux et peu stylable). Trois contrôles `Edit` en lecture seule superposés sur le **même rectangle**, on bascule par `setVisible()` ; les onglets sont des `FixedText` cliquables (primitive `add_chip` déjà écrite), l'onglet actif portant la couleur accent + un soulignement de 2 px (un mince `FixedText`). Robuste, testable, cohérent avec le reste du DSFR maison.
- **Historique** : le fil de conversation persisté (`ConversationStore`), en 7 pt.
- **Actions** : le journal d'outils déjà implémenté (`_JournalObserver` — ⏳ proposé → ✓/✗ + durée). Le toggle « ▸ Voir les actions » disparaît : c'est devenu un onglet.
- **Suggestions (nouveau)** : recommandations contextuelles cliquables — un clic remplit le prompt (et, pour les suggestions d'action, lance directement).
  - **v1 = heuristiques pures**, sans appel LLM ni apprentissage (conforme au garde-fou dette) : dérivées de l'application, de l'état de la sélection (vide / courte / longue / plage numérique) et du type de contenu. Exemples : sélection longue → « Résumer » ; plage de nombres en Calc → « Analyser » ; sans sélection → « Continuer le paragraphe » ; plus 3-4 amorces de prompt fréquentes (« Corrige l'orthographe », « Rends le ton plus formel »…).
  - Évolution possible, désormais **sans danger** grâce au modèle worker+dispatcher : des suggestions générées par le LLM, ce que faisait le legacy `_bg_ai_suggestions` ([entrypoint.py:7749](src/mirai/entrypoint.py#L7749)) — mais celui-ci appelait `stream_request` depuis un thread de fond, exactement la violation qu'on élimine. À ne reprendre qu'au travers du dispatcher.
- L'onglet actif est mémorisé en config (`assistant_active_tab`).

### G. Fenêtre redimensionnable

- Propriété `Sizeable` sur le modèle de dialogue — déjà utilisée par le dialogue d'édition historique, donc validée sur ce toolkit.
- `addWindowListener` → sur `windowResized`, relancer `_layout()` en prenant la **largeur/hauteur réelles du peer** au lieu de la largeur calculée. Répartition verticale : chips, sélection, prompt et onglets gardent leur hauteur ; **toute la hauteur supplémentaire va à la zone basse**. La largeur supplémentaire élargit prompt et zone basse.
- **Bornes** : largeur minimale = celle qui garde les chips sur une ligne (calculée au premier layout et mémorisée) ; hauteur minimale = tout sauf la zone basse + ~60 px.
- **Persistance** : position et taille enregistrées en config (`assistant_window_rect`) et restaurées à l'ouverture — le legacy mémorisait déjà x/y pour ses dialogues, on étend à la taille.

## Auth `/llm/v1` — prise en compte de `prompts/update-prompt-creation-llm-auth.md`

### Ce qui a changé sous nos pieds (vérifié dans l'arbre de travail)

Le correctif d'authentification du proxy LLM est **déjà livré** : `entrypoint.py` porte `_llm_proxy_mode` (l.3810), `_relay_credentials_valid` (l.3827), `_resolve_llm_token` (l.3843), `_check_relay_auth_notice` (l.3894), `_recover_llm_auth` (l.3958) ; la façade expose `recover_llm_auth()` ; `llm_client.step()` retente **une** fois après un 401 ; `tests/unit/test_llm_token_auth.py` = **22 tests verts**.

→ **Nuance à porter au plan** : « la coquille reste intacte » signifie désormais « intacte *hors* cette chaîne d'auth déjà corrigée ». Le moteur consomme la reprise via la façade, sans jamais connaître le détail des jetons.

### Le piège s'est refermé sur nos propres tests

L'« **état absorbant** » décrit par le prompt — `enrolled=True` **sans** paire relais — est exactement ce que j'ai fabriqué en forçant `enrolled=true` dans `config.json` pour franchir le gate d'enrôlement et tester l'IHM. Vérification à l'instant : `enrolled: True`, aucun `relay_client_id`, `llm_api_tokens` vide. **C'est la cause des 401 « Missing credentials » sur 100 % des appels**, y compris `/models` — pas un défaut de la palette.
→ Correctif : **un vrai ré-enrôlement** (`POST /enroll` est idempotent côté DM, il révoque puis ré-émet), jamais un nouveau drapeau posé à la main.

### Contraintes que l'itération 2 doit respecter

- **La reprise d'auth après 401 fait du réseau bloquant** → elle s'exécute dans le thread du pump (via `_build_request`), jamais sur le thread principal. Le modèle worker de l'itération 2 le garantit par construction — à énoncer explicitement dans `ARCHITECTURE.md`, même famille de piège que `processEventsToIdle`.
- **Ne jamais émettre `X-Relay-*` sur `/llm/v1`** : dès que `X-Relay-Client` est présent, le DM engage la branche relais et échoue en 401 **sans repli** vers le Bearer. Vecteur unique retenu : le `llmToken` seul (scopé `llm`, TTL 1 h) — la paire relais est le credential maître (30 j) et reste réservée à `/config`, la télémétrie et `/update/status`.
- **Une valeur vide est significative** : `llm_api_tokens`/`llmToken` vide signifie « aucun mint » et doit **effacer** la valeur locale, pas être ignorée.
- **Le drapeau `enrolled` ne prouve rien** : il atteste d'un HTTP 201 passé, pas d'une paire relais active — il ne doit jamais court-circuiter un ré-enrôlement.

### Tâche de documentation à exécuter (le prompt lui-même)

Mettre à jour `prompts/prompt-creation.md` (36 Ko, document de reconstruction from scratch) en **complétant en place**, sans restructurer ni renuméroter :

| Section | Ajout |
|---|---|
| §3.3 Enrôlement | Encadré : « enrôlé ⟺ paire relais **active** » + idempotence de `POST /enroll` comme porte de sortie |
| §3.5 Appels LLM | Distinguer **mode proxy DM** (défaut, `Bearer <llmToken>` HMAC 1 h) et **mode direct** (clé statique) ; chaîne complète `/enroll → paire relais → /config X-Relay-* → mint llmToken → appel LLM`, chaque maillon cassant produisant le **même** 401 |
| §3.7 Threading | Reprise d'auth dans le thread réseau du pump — jamais sur le thread principal |
| §4.1 Sécurité | Décision « `llmToken` seul » + critère (surface d'attaque minimale) + contrepartie assumée (`DM_LLM_TOKEN_SIGNING_KEY` = dépendance dure serveur) |
| §6.3 Config enrichie | `llmEndpoint`, `llmToken`, `llmTokenExpiresAt`, `embdUrl`, `embdToken`, `_auth_notice` ; `llm_api_tokens` = même valeur que `llmToken` ; vide = effacement |
| §9 Pièges | Les trois pièges reproductibles : état absorbant, repli Keycloak impossible, jeton périmé silencieux (TTL 1 h vs cache config 300 s) |
| §5 Tests | Renvoi aux scénarios de `tests/unit/test_llm_token_auth.py` |

**Règles de rédaction** : langue/ton/structure conservés (§ numérotés, mermaid, tableaux) ; aucune valeur réelle de jeton, clé ou URL interne ; en-têtes nommés `X-Relay-Client` / `X-Relay-Key` (alias `X-Client-Id` / `X-Client-Key`) — **jamais** `X-Relay-Client-Id`, forme fausse qui circule dans la doc DM ; **le code fait foi** en cas de divergence, et toute contradiction corrigée est signalée en fin de réponse plutôt qu'empilée comme exception.

## Reprise du travail de Richard (`rperaudin`) présent sur `origin/master`

4 commits absents de notre branche (`45331e2`, `3afe5b0`, `88819ce`, `621c5c8`), soit **+587 lignes** sur `entrypoint.py`, `menu_actions/writer.py`, `oxt/Jobs.xcu` et `tests/stubs/uno_stubs.py`. C'est du travail **validé en vrai** (« the menu context works on this version ») et complémentaire du nôtre : il attaque l'accès rapide là où nous refondons le moteur.

### Ce qu'il a intégré

- **Menu contextuel Writer** — `MirAIContextMenuInterceptor` (`XContextMenuInterceptor`) injecte un sous-menu MIrAI au clic droit, avec 4 entrées : *Résumer la sélection · Reformuler · **Corriger** · **Traduire***, chacune pointant sur `service:fr.gouv.interieur.mirai.do?<Action>&src=context`.
- **Enregistrement automatique par document** — `MirAIDocumentEventListener` (`XDocumentEventListener`) + `Jobs.xcu` étendu aux événements **`onLoad` et `onNew`** (nous n'avions que `onFirstVisibleTask`), plus l'ordonnancement `_schedule_context_menu_registration`.
- **Contournements pyuno** pour brancher l'intercepteur : `_resolve_context_menu_method_names`, `_get_context_menu_interception_iface`, `_invoke_via_core_reflection`, `_do_add_interceptor` — de la plomberie ingrate, déjà débuggée, à ne surtout pas réécrire.
- **Deux fonctions inédites chez nous** : `_correct_selection` (orthographe/grammaire/syntaxe, sans reformulation, `correct_selection_max_tokens` défaut 4 000) et `_translate_selection`, avec leurs prompts français prêts à l'emploi.
- **Stubs de test étendus** : `XContextMenuInterceptor`, `XDispatchProvider`, `XDispatch`, `ContextMenuInterceptorAction` — nécessaires pour tester tout ça hors LibreOffice.
- Nouvelle source de télémétrie `src=context`, déjà comprise par notre `trigger()`.
- Piste abandonnée en cours de route (à ne pas ressusciter) : `ProtocolHandler.xcu` + `WriterCommands.xcu`, retirés de l'arbre — les URLs `service:` suffisent.

### Comment on le reprend

Le menu contextuel devient le **chemin rapide** (une action sur la sélection, sans fenêtre), la palette reste le **chemin riche** (prompt libre, conversation, suggestions). C'est exactement la répartition que réclame l'exigence « épuré ».

1. **Fusionner `origin/master` dans la branche d'abord**, avant toute autre étape de l'itération 2 — repartir d'une base à jour évite de refactoriser deux fois.
2. **Reprendre l'infrastructure telle quelle** : les deux classes, les helpers de réflexion, `Jobs.xcu` (`onLoad`/`onNew`) et les stubs. Rien à réinventer.
3. **Repointer les entrées vers le nouveau moteur** : au lieu des actions legacy, des URLs `?AssistantPreset:<id>&src=context` traitées par `trigger()` → **exécution directe du preset** (le menu contextuel n'ouvre pas la palette), plus une entrée « Ouvrir l'assistant… » pour basculer vers la fenêtre.
4. **Adopter *Corriger* et *Traduire* comme deux presets pipeline**, en réutilisant les prompts de Richard. Après la factorisation `run_text_pipeline`, chacun tient en ~15 lignes déclaratives — bonne démonstration que la nouvelle architecture rend une fonction bon marché. Pour *Traduire*, la langue cible vient du champ de prompt (ou d'un sous-menu contextuel « Anglais / Espagnol / Allemand » si on veut rester à un clic).
5. **Conflits à anticiper** : `entrypoint.py` (nous y avons ajouté le routage `OpenAssistant`), `writer.py` (que nous supprimons au commit de nettoyage), `uno_stubs.py`, `Jobs.xcu`. → **Portage ciblé plutôt que `cherry-pick` aveugle** : garder l'infrastructure d'`entrypoint.py` + `Jobs.xcu` + stubs, et réimplémenter Corriger/Traduire côté presets au lieu de conserver les fonctions legacy de `writer.py`.
6. **Point de vigilance mesurable** : `onLoad`/`onNew` instancient `MainJob` à **chaque ouverture de document**, et son `__init__` déclenche télémétrie, vérification d'enrôlement et config. À vérifier au chronomètre sur l'ouverture d'un document — si c'est perceptible, différer l'enregistrement de l'intercepteur (il n'a pas besoin d'être synchrone) plutôt que de renoncer à la fonctionnalité.

## Retrait upstream / auteur (tout est réécrit)

- Supprimer les mentions John Balis / localwriter : [README.md:5](README.md#L5), [README.md:377](README.md#L377), [oxt/registration/license.txt:16-21](oxt/registration/license.txt#L16-L21).
- Supprimer le remote git `upstream` (`balisujohn/localwriter`) — corrige aussi le ciblage `gh` du mauvais repo — et mettre à jour `origin` vers `https://github.com/IA-Generative/AssistantMiraiLibreOffice.git` (l'URL actuelle `IA-Generative/localwriter.git` n'est qu'une redirection).
- Note factuelle : localwriter n'a **aucun fichier de licence** (vérifié via l'API GitHub). La mention MPL 2.0 (portions LibreOffice, gerrit 159938) : vérifier au moment du commit de cleanup qu'aucun code dérivé ne subsiste dans le cœur réécrit — si c'est le cas, retirer les deux paragraphes « Origine du projet » ; sinon conserver uniquement la ligne MPL.

## Étapes d'implémentation (commits revuables, tests verts à chaque étape)

0. Créer la branche `exp-jetable/demonstrateur-moteur-mcp` + bandeau README + retrait upstream/auteur + remotes.
1. `core: shell_facade + protocole + tests` (additif pur).
2. `core: text_filters + logique pure déplacée` (chunker, parseur FIND/REPLACE, helpers Calc) — anciens call sites importent depuis core, rien ne casse.
3. `core: moteur de tools` (schema/validateur/registry/context + writer_tools/calc_tools + tests).
4. `core: sse_pump + llm_client` (natif + JSON fallback + sonde + tests).
5. `core: orchestrator + presets + conversation store + tests golden iso-fonctionnels`.
6. `ui: dsfr.py + palette + entry.open_palette + routage OpenAssistant` — anciens menus encore présents (A/B manuel via dev-launch).
7. `manifests: Addons.xcu / Accelerators.xcu réduits à l'entrée unique`.
8. `cleanup: suppression du cœur legacy d'entrypoint.py + menu_actions/ + retrait des tests portés` — commit de **pure suppression**, chaque symbole vérifié non référencé (grep). `stream_request`/`make_api_request` conservés une release en fallback documenté.
9. `docs: ARCHITECTURE.md (~2 pages) + refresh CLAUDE.md + ADR` (schéma couches coquille/façade/moteur/UI, table des tools, mode natif vs JSON, règles threading « pump main-thread only », checklist ajout d'un tool, section « De démonstrateur à produit », ADR de la décision de réécriture).

### Itération 2 — étapes (commits revuables, suite verte à chaque étape)

9bis. `merge origin/master` — récupérer les 4 commits de Richard (menu contextuel) **avant** tout le reste, pour ne pas refactoriser deux fois. Suite complète verte après fusion.
10. `core: MainThreadDispatcher (ui_thread.py) + FakeDispatcher + tests` — additif pur, rien de branché.
11. `core: exécution du run dans un thread worker` — sinks, `registry.call_tool`, contexte undo et mises à jour UI passent par le dispatcher ; `sse_pump` perd son drain `processEventsToIdle` ; coalescence des deltas ; annulation. Garde-fou : test « aucun `processEventsToIdle` dans core/ ».
12. `ui: palette épurée` — bandeau supprimé, chips une ligne sans emoji, polices 7-8 pt, liens de pied retirés, statut coloré lisible, bouton Arrêter pendant un run.
13. `ui+core: indicateur de sélection en direct` — `XSelectionChangeListener` (patron Calc), formateurs purs testés, retrait du listener avant `dispose()`.
14. `ui: jauge d'activité` — spinner braille + compteur de jetons (estimation locale, `usage` exact si fourni) + chronomètre, à gauche du prompt.
15. `ui: zone basse à onglets` — Historique / Suggestions / Actions superposés + onglets cliquables ; le toggle « Voir les actions » disparaît.
16. `core+ui: moteur de suggestions v1` — heuristiques contextuelles pures (`core/suggestions.py`, testable hors LO), clic → prompt pré-rempli.
17. `ui: fenêtre redimensionnable` — `Sizeable`, `windowResized` → `_layout()` sur la taille réelle, bornes minimales, persistance `assistant_window_rect`.
18. `manifests: 📚 Documentation ajoutée au menu` (Paramètres et À propos déjà rétablis).
19. `qualité: ruff + factorisation` — `pyproject.toml` (ruff, complexité ≤ 10, 100 colonnes), `03-test-local.sh` étendu à `core/`+`ui/` avec dégradation gracieuse si ruff absent, puis les 8 factorisations nommées (dont `run_text_pipeline` et `core/errors.py`) — **la suite de tests doit rester verte à iso-comportement**, c'est le filet qui rend ce refactor sûr.
20. `docs: prompt-creation.md — chaîne d'auth /llm/v1` — exécuter `prompts/update-prompt-creation-llm-auth.md` (§3.3, §3.5, §3.7, §4.1, §6.3, §9, §5 complétés en place). Tâche **indépendante du reste** : peut être faite en premier, elle ne touche aucun code.
20bis. `ui+core: menu contextuel branché sur le moteur` — entrées repointées vers `?AssistantPreset:<id>&src=context` (exécution directe, sans ouvrir la palette) + entrée « Ouvrir l'assistant… » ; presets **Corriger** et **Traduire** ajoutés à partir des prompts de Richard.
20ter. `shell: découpage d'entrypoint.py en mixins` — **après** la fusion de master et **après** la suppression du cœur legacy. Un module par commit (`common`, `config`, `http`, `auth`, `enrollment`, `update`, `telemetry`, `llm_legacy`, `dialogs`, `settings_ui`, `context_menu`), suite complète verte à chaque étape ; drapeaux de classe et `_EXT_MGR_SINGLETON` traités comme indiqué ; test d'architecture « `shell/` n'importe pas `core/` ».
21. `docs: ARCHITECTURE.md — nouveau modèle d'exécution` (schéma worker/dispatcher, règle « aucun UNO hors thread principal sans dispatcher », reprise d'auth dans le thread réseau, anatomie de la palette, budgets de qualité).


## Tests (iso-fonctionnalité + moteur)

Nouveau `tests/unit/core/` (pytest, réutilise `install()`/`make_job()`), nouveaux stubs `tests/stubs/fake_llm.py` (scénarios scriptés incl. tool calls + `FakeSSE`) et `fake_writer_doc.py`/`fake_calc_sheet.py` (fakes à état réel, sur le modèle des harness existants) :

- Moteur : `test_tool_schema.py`, `test_registry.py`, `test_json_fallback_parser.py` (goldens vicieux), `test_llm_client_native.py` (fragments), `test_sse_pump.py`, `test_orchestrator_loop.py` (+ injection du contexte de conversation), `test_conversation_store.py` (roundtrip, caps, clear, JSON corrompu → repart vide), `test_shell_facade.py` (équivalence `build_chat_request` + clamps), `test_no_entrypoint_import.py` (règle d'archi : aucun fichier de `core/`/`ui/` ne contient « entrypoint »).
- Iso-fonctionnels : `test_presets_writer.py` / `test_presets_calc.py` — chaque fonction legacy rejouée via le moteur avec FakeLLM : marqueurs legacy, stop-phrases, retry sur question-pattern, FIND/REPLACE doc entier, ratios resize, colonne « Résultat IA », contexte formule + feedback `Err:` + fill-down, analyse fusionnée sous la sélection. Assertions portées depuis `test_summarize_writer.py` et `test_calc_menu_actions.py` (retirés au commit 8).
- Les ~2 200 l. de tests coquille restent verts sans modification du début à la fin.

## Vérification

1. `python3 -m pytest tests/unit/ -v` — tout vert à chaque commit (coquille + moteur + iso-fonctionnels).
2. `./scripts/02-build-oxt.sh` — build OK, gate anti-leak vert, `test_build_oxt_smoke.py` vert.
3. Test manuel : `./scripts/dev-launch.sh` (⚠️ à lancer en avant-plan / par l'utilisateur — jamais en background Claude Code, unopkg bloque) : ouvrir Writer → Ctrl+Alt+Espace → palette ; chip Résumer sur une sélection → streaming dans le doc avec marqueurs ; Ctrl+Z unique ; prompt libre agentique ; idem Calc (Transformer, Formule avec preview→apply). Vérifier enrollment/settings/about inchangés et traces télémétrie dans Tempo (`assistant.run` + spans legacy `via=palette`).
4. Test des deux modes LLM : `llm_tool_mode=json` forcé en config puis `native` — mêmes résultats fonctionnels.

### Vérification spécifique itération 2

5. **Non-blocage** : lancer un run long (prompt libre), puis **taper dans le document et faire défiler pendant la génération** — l'application doit rester parfaitement fluide, et le texte continuer d'arriver. Contrôle négatif : plus aucun `processEventsToIdle` dans `src/mirai/core/` (test automatisé).
6. **Retour visible** : sans login, cliquer une chip → message d'erreur explicite et coloré **en moins d'une seconde** (le log doit montrer le span + le 401). Avec login : statut « Terminé » et texte inséré dans le document.
7. **Une seule ligne de chips** : ouvrir la palette en Writer (6 chips) puis en Calc (3 chips) — aucun retour à la ligne, aucun libellé tronqué (capture d'écran à l'appui, Retina).
8. **Indicateur de sélection** : sélectionner du texte, déplacer le curseur, changer de paragraphe, basculer sur un autre document → l'indicateur suit ; en Calc, changer de plage → « N cellules sélectionnées (A4:A8) ». Fermer la palette pendant une sélection active : aucune exception dans le log (listener retiré avant `dispose`).
9. **Menu** : ⚙️ Paramètres, ℹ️ À propos et 📚 Documentation présents dans 🤖 MIrAI et fonctionnels ; absents de la fenêtre flottante.
10. **Annulation** : lancer un run, cliquer « Arrêter » → arrêt propre, statut mis à jour, aucun texte parasite inséré ensuite.
11. **Jauge d'activité** : sur un prompt long, le spinner pulse sans à-coups, le compteur de jetons progresse, le chronomètre avance ; à la fin, le compteur affiche la valeur exacte si le relais renvoie `usage` (sinon l'estimation). Au repos, aucun saut de mise en page.
12. **Onglets** : basculer Historique ↔ Suggestions ↔ Actions — le contenu change dans le même rectangle, l'onglet actif est visuellement distinct et mémorisé après réouverture. Pendant un run, l'onglet Actions se remplit en direct.
13. **Suggestions** : sans sélection, avec sélection courte, avec sélection longue, sur une plage numérique en Calc → les propositions changent ; un clic pré-remplit le prompt.
14. **Redimensionnement** : agrandir la fenêtre → seule la zone basse grandit, les chips restent sur une ligne ; rétrécir jusqu'aux bornes → aucun chevauchement ni troncature ; fermer/rouvrir → taille et position restaurées.
15. **Auth** : après un vrai ré-enrôlement, vérifier dans `config.json` la présence de `relay_client_id`/`relay_client_key` **et** d'un `llm_api_tokens` non vide, puis qu'un run aboutit ; couper le jeton (attendre l'expiration ou le vider) → la reprise automatique doit retenter **une** fois et réussir, sans gel de l'UI (`tests/unit/test_llm_token_auth.py` verrouille ces invariants, 22 tests).
16. **Menu contextuel** : clic droit sur une sélection dans Writer → sous-menu MIrAI avec Résumer / Reformuler / Corriger / Traduire + « Ouvrir l'assistant… » ; chaque entrée s'exécute **directement** sans ouvrir la fenêtre ; télémétrie `src=context`. Vérifier aussi sur un document **nouvellement créé** (`onNew`) et un document **ouvert depuis le disque** (`onLoad`), et chronométrer l'ouverture d'un document pour s'assurer que l'enregistrement de l'intercepteur ne la ralentit pas.
17. **Découpage de la coquille** : après chaque commit de découpage, `python3 -m pytest tests/unit/ -q` intégralement vert **sans modification des tests** (hors repointage des patches `entrypoint.time`), extension installable et fonctionnelle en vrai (enrôlement, réglages, mise à jour, menu contextuel), et `entrypoint.py` retombé sous ~300 lignes.
18. **Qualité** : `ruff check src/mirai/core src/mirai/ui` sans erreur (dont complexité ≤ 10) ; plus aucune fonction > 40 lignes dans `core/`+`ui/` (script de mesure AST déjà utilisé pour établir la ligne de base) ; nombre de `except Exception` en baisse nette et **chacun journalisé ou explicitement toléré** via `suppress_and_log` ; suite complète verte **avant et après** chaque factorisation (iso-comportement).

## Découpage d'`entrypoint.py` (9 915 lignes, 131 méthodes)

Oui, ça vaut le coup **même pour un jetable** : c'est le fichier que tout repreneur — humain ou agent — ouvre en premier, et personne ne « manipule » 10 000 lignes. Le tout est de le faire sans risquer la partie qui marche.

### Pourquoi c'est sûr : le découpage en *mixins*

`MainJob` est **une classe** de 131 méthodes qui s'appellent entre elles par `self.`. On ne déplace donc pas des fonctions libres (ce qui casserait tous les appels), on répartit les méthodes dans des **classes-mixins**, et `MainJob` en hérite :

```python
class MainJob(unohelper.Base, XJobExecutor, XJob,
              ConfigMixin, HttpMixin, AuthMixin, EnrollmentMixin,
              UpdateMixin, TelemetryMixin, LlmLegacyMixin,
              DialogsMixin, SettingsUiMixin, ContextMenuMixin):
```

- La résolution `self.foo()` est inchangée → **zéro modification d'appelant sur 131 méthodes**.
- **Fait vérifié** : tous les tests n'importent que `MainJob` depuis `src.mirai.entrypoint` → les ~2 200 lignes de tests coquille passent **sans être touchées**. C'est le filet qui rend l'opération mécanique.
- Un module par commit, suite complète verte après chacun.

### Cible

```
src/mirai/
├── entrypoint.py        # ~300 l. : globals, assemblage MainJob, drapeaux de classe, execute/trigger, g_ImplementationHelper
└── shell/
    ├── common.py        # log_to_file, _UI, user-agent, redaction, _EXTENSION_IDENTIFIER, _EXT_MGR_SINGLETON
    ├── config.py        # config fichier, bootstrap URLs, failover, _fetch_config, cache
    ├── http.py          # _urlopen, proxy, SSL
    ├── auth.py          # Keycloak PKCE, jetons, llmToken, _recover_llm_auth
    ├── enrollment.py    # gate, assistant d'enrôlement, _ensure_device_management_state
    ├── update.py        # auto-update complet (~800 l.)
    ├── telemetry.py     # _send_telemetry, LlmRelayError, secure flow
    ├── llm_legacy.py    # make_api_request / make_chat_request / stream_request (supprimés plus tard)
    ├── dialogs.py       # input_box, message/confirm, widget « réflexion »
    ├── settings_ui.py   # settings_box, proxy_settings_box, credentials_box, about
    └── context_menu.py  # intercepteur de Richard + listener de document
```

Aucun module au-dessus de ~800 lignes, la plupart sous 450 — ouvrables et modifiables sans défilement infini.

### Les cinq pièges, tous identifiés

1. **Les 6 drapeaux de classe restent déclarés sur `MainJob`** (`_enrollment_dismissed_cls`, `_enrollment_wizard_active_cls`, `_enrollment_wizard_lock_cls`, `_update_in_progress_cls`, `_update_launch_blocked_cls`, `_update_lock_cls`, l.369-377). Les déclarer dans un mixin créerait un *shadowing* silencieux à la première écriture `MainJob.x = …` ; par ailleurs `tests/unit/conftest.py` les réinitialise via `MainJob.*`.
2. **`_EXT_MGR_SINGLETON` est pré-lié à l'import, sur le thread principal** (l.16-19, contournement pyuno pour l'auto-update) → il doit rester dans un module chargé au démarrage : `shell/common.py`, importé en tête d'`entrypoint.py`.
3. **Les tests qui patchent `entrypoint.time`** cesseraient d'agir sur du code déplacé (qui importe son propre `time`) → les repointer vers le nouveau module. C'est **le seul type de test à modifier**, et il est repérable par grep.
4. **`shell/` ne doit jamais importer `core/`** — dépendance à sens unique, vérifiée par un test d'architecture, dans la lignée de celui qui existe déjà.
5. **Le build copie `src/` en bloc** → `shell/` embarqué automatiquement ; `main.py`, le manifeste et l'enregistrement UNO restent inchangés (`MainJob` continue de vivre dans `entrypoint.py`).

### Séquencement — c'est là que tout se joue

**Fusionner → supprimer → découper**, dans cet ordre :

1. **Fusionner `origin/master`** en premier : Richard a ajouté 385 lignes dans `entrypoint.py`, découper avant la fusion transformerait le merge en cauchemar.
2. **Supprimer le cœur legacy** (~3 200 lignes) : inutile de reloger soigneusement du code qu'on s'apprête à effacer.
3. **Découper le reste** (~6 400 lignes) : on travaille alors sur la plus petite surface possible.

## Qualité de code (exigence transverse — s'applique à toute l'itération 2)

État mesuré au 2026-07-25 sur `src/mirai/core` + `src/mirai/ui` : **15 fonctions > 40 lignes**, **68 `except Exception`**, **aucun linter configuré** dans le repo, et `scripts/03-test-local.sh` ne compile même pas `core/` ni `ui/`. Ces chiffres sont la ligne de base : l'itération 2 doit les faire baisser, pas grossir.

### Linter et format (outillage de développement, jamais embarqué)

- **`ruff`** en dépendance de **développement uniquement** — la contrainte no-pip porte sur le plugin livré, pas sur le poste de dev. Configuration dans `pyproject.toml` : `line-length = 100`, règles `E,W,F` (erreurs/pyflakes), `I` (tri des imports), `B` (bugbear — pièges classiques), `C901` (complexité cyclomatique **max 10**), `UP` (modernisation), `ARG` (arguments inutilisés).
- Branché dans `scripts/03-test-local.sh` avec **dégradation gracieuse** : si `ruff` est absent, le script prévient et continue (il ne doit jamais bloquer un build sur un poste sans outillage).
- **Corriger au passage** : `03-test-local.sh` ne liste pas `src/mirai/core/**` ni `src/mirai/ui/**` dans son `py_compile` — les ajouter.
- Aucun formateur automatique imposé (pas de `black`) pour ne pas noyer les diffs du démonstrateur ; `ruff format --check` reste possible plus tard.

### Budgets chiffrés (vérifiés par le linter, pas par la bonne volonté)

| Métrique | Budget | Aujourd'hui |
|---|---|---|
| Longueur de fonction | **≤ 40 lignes** | 15 dépassements |
| Complexité cyclomatique | **≤ 10** (`C901`) | non mesurée |
| Profondeur d'imbrication | ≤ 3 niveaux | — |
| Longueur de module | ≤ 400 lignes | `presets.py` et `palette.py` à surveiller |

### Factorisation — cibles nommées (les quasi-duplications réelles)

1. **`core/presets.py` — le gros morceau.** Les runners pipeline (`run_extend`, `run_summarize`, `run_simplify`, `_run_resize`, `run_transform`, `run_analyze`) répètent tous le même squelette : télémétrie → texte cible → prompt système + prompt utilisateur → client LLM → sink → `undo_begin` → `step` → gestion d'erreur → `sink.finish` → `undo_end`. → Extraire **un** `run_text_pipeline(ctx, shell, spec)` piloté par une petite structure déclarative (`TextPipelineSpec` : span, libellé undo, constructeurs de prompt, fabrique de sink, plafond de jetons). Chaque preset retombe alors à ~15 lignes **déclaratives**, et la logique d'erreur/undo n'existe qu'à un seul endroit.
2. **`ui/dsfr.py`** — `add_chip`, `add_link`, `add_primary_button` ont le même corps (créer le contrôle + brancher un `ClickHandler`). → Un `add_clickable(..., style)` + trois styles nommés (`CHIP`, `LINK`, `PRIMARY`).
3. **`ui/palette.py::_build` (125 l.)** → découper en `_build_chips`, `_build_prompt_row`, `_build_bottom_area`, `_build_tabs`, `_build_status_bar`. Idem `_layout` (83 l.) → une fonction de placement par bloc.
4. **`core/llm_client.py::_run_step` (100 l.)** → extraire deux petites classes à responsabilité unique : `_TextAccumulator` (accumulation + logique de rétention du mode JSON) et `_ToolCallAssembler` (recollage des fragments `delta.tool_calls`). Chacune testable isolément.
5. **`core/sse_pump.py::run_stream` (92 l.)** → séparer `_iter_sse_events(response)` (générateur pur, testable sans thread) de la boucle de dispatch.
6. **`core/tools/calc_tools.py`** — 14 `try/except` autour de `setPropertyValue` → un helper `set_property_safe(obj, name, value)`. Les fonctions `register()` (65 l. en Calc, 49 l. en Writer) deviennent une **liste de `ToolSpec`** parcourue en boucle.
7. **`core/orchestrator.py::run_agentic` (64 l.)** → extraire `_execute_tool_calls(step)`.
8. **Import circulaire contourné à la main** : `from .orchestrator import error_message` est fait *à l'intérieur* de six fonctions de `presets.py`. → Déplacer `error_message` et le dictionnaire de messages dans un `core/errors.py` neutre, et l'importer normalement en tête de module.

### Code défensif : discipliné, pas superstitieux

Le `try/except Exception: pass` est légitime aux frontières UNO (un contrôle disposé, une propriété non supportée), mais 68 occurrences anonymes masquent aussi les vraies erreurs.

- **Règle** : un `except` large est autorisé **uniquement** aux frontières (appel UNO, télémétrie, I/O disque) — jamais autour d'une logique métier.
- **Aucun `pass` silencieux** hors chemins de nettoyage/dispose documentés : tout catch large **journalise** (`shell.log`) avec un libellé identifiant l'opération.
- Rendre l'intention **greppable** : un helper unique `suppress_and_log(shell, label)` (gestionnaire de contexte, ~10 lignes) remplace la majorité des `try/except/pass` — on voit alors d'un coup d'œil ce qui est délibérément tolérant.
- Les exceptions attendues sont attrapées **par type** quand il est connu (`OSError`, `ValueError`, `KeyError`), pas en `Exception`.

### Dégradation gracieuse : chaque capacité externe a un repli documenté

Principe déjà appliqué par endroits, à généraliser et à énoncer : **rien de ce qui est optionnel ne doit pouvoir casser l'assistant.**

| Capacité | Repli |
|---|---|
| Police Marianne | Arial → Liberation Sans → défaut système |
| Tool calling natif | Protocole JSON parsé côté plugin |
| `usage` renvoyé par le relais | Estimation locale (caractères ÷ 4) |
| `AsyncCallback` indisponible | Exécution directe |
| Dispatcher en timeout | Arrêt propre du run + message |
| Conversation corrompue | Repart vide, jamais de crash |
| Config DM injoignable | Cache disque, puis valeurs par défaut |
| `ruff` absent sur le poste | Avertissement, le script continue |

### Nommage et lisibilité

- Identifiants **en anglais** (cohérent avec l'existant), messages utilisateur **en français** — ne pas mélanger dans un même nom.
- Fonctions = **verbe d'action** (`build_system_prompt`, `assemble_tool_calls`), données = nom (`selection_summary`). Bannir `_x`, `tmp`, `data2`, `handle_stuff`.
- Un nom doit dire **quoi**, la docstring **pourquoi/invariant** (une ligne suffit) — c'est la docstring qui porte les contraintes non devinables (« s'exécute exclusivement sur le thread principal »).
- Annotations de type sur les fonctions **publiques** de `core/` (avec `from __future__ import annotations`) : coût nul à l'exécution, gain direct pour un assistant de codage qui reprend le code.
- Pas de commentaire qui paraphrase le code ; un commentaire justifie une contrainte ou un contournement.

## Lisibilité & reprise (un humain + un agent de codage doivent s'y retrouver)

Objectif : si on décide de poursuivre au-delà du démonstrateur, le code doit pouvoir être lu, compris et étendu sans créer de dette — par un humain comme par un assistant de codage. Mesures concrètes :

- **Fichiers courts à responsabilité unique** (le contre-exemple étant les 9 617 l. d'entrypoint.py) : chaque module de `core/` < ~400 l., docstring d'en-tête énonçant le rôle et les **invariants** (ex. dans `sse_pump.py` : « le drain s'exécute exclusivement sur le thread principal »).
- **Règles d'architecture exécutables, pas seulement documentées** : `test_no_entrypoint_import.py` (core/ui n'importent jamais entrypoint) ; même principe extensible (ex. `tools/` n'importe pas `ui/`). Un agent de codage qui viole la structure casse un test immédiatement.
- **Un seul point d'extension documenté** : ajouter une fonctionnalité = ajouter un `ToolSpec` + éventuellement un preset — checklist pas-à-pas dans ARCHITECTURE.md (« comment ajouter un tool en 5 étapes, quel test écrire »).
- **Les tests golden comme documentation vivante** : chaque preset a un test qui raconte le comportement attendu (marqueurs, retry, undo) — c'est la spécification lisible par un repreneur.
- **CLAUDE.md tenu à jour dans le même commit** que tout changement de structure : carte des modules, contrat de la façade, règles threading, contraintes no-pip — c'est le fichier que lit un agent de codage en premier.
- **ADR** (format IA-Generative, via la skill `adr-new`) tracée sur la branche : décision de réécriture, statut « démonstrateur jetable », options écartées (sidebar, ScriptForge, webview) — pour qu'un futur dev comprenne le pourquoi sans archéologie.
- **Section « De démonstrateur à produit » dans ARCHITECTURE.md** : la liste ordonnée de ce qu'il faudrait durcir si on poursuit (supprimer `stream_request`/`make_api_request` legacy, unifier `=PROMPT()` sur la façade, i18n, multi-conversations + recherche dans l'historique, sidebar historique, UI de permissions par tool) — la dette résiduelle est **nommée et localisée**, jamais implicite.

## Garde-fous dette (explicitement NON construit)

i18n ; vrai serveur MCP (stdio/JSON-RPC) ; dépendance jsonschema (subset documenté) ; multi-conversations/recherche dans l'historique (une seule conversation MVP) ; reco au-delà des 3 heuristiques ; UI de permissions par tool ; frameworks async ; Impress/Draw ; exécution parallèle de tools ; gestion fine de fenêtre de contexte.

## Rejeu / anti-régressions (leçons de l'implémentation du 2026-07-25)

À respecter absolument si ce plan est rejoué ou repris — chaque point a coûté un cycle de debug réel :

1. **Environnement macOS d'abord** : macOS 26 tue les binaires auxiliaires de LibreOffice (`uno`, `unopkg`, python embarqué) — SIGKILL « Launch Constraint Violation ». Symptôme trompeur : `unopkg` échoue en `NoConnectException` pipe. Avant tout cycle build→install, vérifier `/Applications/LibreOffice.app/Contents/Resources/python --version` (doit sortir 0, pas 137) ; sinon re-signer ad hoc (`codesign --force -s -`) la liste de docs/ARCHITECTURE.md §Environnement. À refaire après chaque mise à jour de LO.
2. **Jamais de run LLM depuis un listener souris/clavier** : le pompage `processEventsToIdle` en dispatch imbriqué gèle l'UI pendant tout l'appel et peut aborter LO (`std::terminate` dans `SalUserEventList::DispatchUserEvents`). Toujours différer via `com.sun.star.awt.AsyncCallback` (pattern `_DeferredCall` de ui/palette.py).
3. **Rien de bloquant sur le thread principal AVANT le démarrage du pump** : `build_chat_request` déclenche côté coquille `_get_cached_models` → appel réseau. Exécuté sur le thread principal, il fige LibreOffice pendant tout le timeout (jusqu'à ~15 s si l'endpoint est injoignable) — l'utilisateur croit à un plantage. `sse_pump.run_stream` accepte une **fabrique** de requête, invoquée dans le thread réseau ; le thread principal ne fait que pomper. Garde-fou : `test_llm_client_does_not_build_request_on_calling_thread`. Règle générale : tout ce qui touche au réseau ou à la config lourde doit vivre dans le thread du pump.
4. **Jamais de layout UI en pixels estimés** : sur Retina les polices rendent ~1,5-2× → troncatures. Créer les contrôles, `createPeer`, puis TOUT positionner via `getPreferredSize()` + facteur d'échelle (pattern `_layout()` de ui/palette.py). Polices compactes : 7-10 pt.
5. **Actions directes sans sélection = paragraphe courant** : les chips Writer ciblent le paragraphe sous le curseur (`gotoStart/EndOfParagraph` + `controller.select`) quand rien n'est sélectionné (`_target_selection_text` de core/presets.py) — exigence utilisateur explicite.
6. **Conserver les menus ⚙️ Paramètres et ℹ️ À propos** dans le menu unique 🤖 MIrAI (exigence utilisateur — ne pas les reléguer uniquement au pied de palette).
7. **Neutraliser la campagne DM pendant les tests dev** : si le DM sert une directive d'update, le QUERYBOX modal revient à chaque lancement et INTERROMPT le login SSO en cours (vécu : dialog à 15:33 en plein flux Keycloak → timeout). Aligner la version du build sur la cible de campagne (`target == current` → directive sautée) ou désactiver la campagne côté DM.
8. **SSO/PKCE — 🚨 conflit de port 28443 avec le simulateur de plugin** : cause réelle du « Callback invalide (state inconnu) » vécu le 2026-07-25. `http.server` active `SO_REUSEADDR` : le simulateur (bind `127.0.0.1:28443`) et le plugin (bind `0.0.0.0:28443`) réussissent TOUS DEUX leur bind, le plugin loggue « Local callback server listening » et attend, mais le noyau route la connexion `localhost` vers la socket la plus spécifique → **le simulateur intercepte le code**, ne reconnaît pas le state et affiche l'erreur ; le plugin timeout à 3 min. **Signature de diagnostic infaillible** : aucune ligne `PKCE callback received` dans ~/log.txt alors que le navigateur a bien affiché une page. **Avant tout test SSO : arrêter le simulateur / vérifier `lsof -nP -iTCP:28443`.** Le message n'existe nulle part dans le code du plugin (son handler renvoie toujours « Authentification terminée ») — s'il s'affiche, ça ne vient JAMAIS du plugin. Durcissement possible (coquille, hors périmètre du démonstrateur) : binder explicitement `127.0.0.1` pour échouer bruyamment en EADDRINUSE au lieu de perdre le callback silencieusement.
   Secondairement : le listener vit 3 min et ne connaît que le state du DERNIER flux → fermer les anciens onglets SSO, une seule tentative.
9. **🚨 Ne JAMAIS poser `enrolled=true` à la main dans `config.json`.** C'est l'« état absorbant » documenté (`prompts/fix-llm-token-auth.md`) : le drapeau franchit le gate mais il n'y a **aucune paire relais**, donc 401 « Missing credentials » sur 100 % des appels `/llm/v1` — y compris `/models` — sans reprise possible. Vécu le 2026-07-25 : ce contournement de test a masqué le vrai problème pendant des heures et a fait accuser la palette. `00-clean-install.sh` purgeant creds relais + jetons, la seule sortie est un **vrai ré-enrôlement** (`POST /enroll` est idempotent côté DM : il révoque puis ré-émet).
10. **Chemins absolus pour build/install** : un `cd` refusé/bloqué laisse le cwd du shell ailleurs (vécu : rebuilds silencieux du mauvais répertoire pendant 40 min). Toujours `"$REPO/dist/mirai.oxt"` explicite.
11. **pkill avec document ouvert → dialog de récupération** au lancement suivant, qui bloque les macros `--args "vnd.sun.star.script:..."` : purger les items `/org.openoffice.Office.Recovery` de registrymodifications.xcu (recovery désactivée sur ce poste).
12. **Outillage de test LO sans UI** : macros profil `Standard.Module1.MiraiDevInstall2` (install in-process avec vrai XCommandEnvironment) et `MiraiDiag` (charge le doc, focus, instancie le composant, déclenche OpenAssistant, écrit le résultat dans /private/tmp) — les réutiliser au lieu de recréer.
13. **StarBasic** : déclarations `Global` en tête de module uniquement (sinon le module entier ne compile plus, silencieusement) ; `Array()` inline, pas de variable tableau vide.
14. **« Il ne se passe rien » = retour invisible, pas action manquante.** Avant de chercher un bug d'exécution, vérifier dans ~/log.txt la présence du span télémétrie de l'action (`ResizeSelection`, `SummarizeSelection`…) et de la réponse HTTP : si les deux sont là, l'action a bien tourné et c'est l'affichage qui est en cause. Corollaire de conception : **tout run doit produire un retour lisible** (ligne de statut colorée, taille suffisante), jamais seulement un texte discret dans une zone grise.
15. **Aucun UNO depuis un thread de fond sans passer par le dispatcher.** Le run vit dans un worker ; document, contrôles et undo ne se touchent que via `MainThreadDispatcher.call/post`. Le contre-exemple à ne jamais copier : `_selection_refresh_loop` ([entrypoint.py:7448](src/mirai/entrypoint.py#L7448)) écrit des `Label`/`TextColor` VCL depuis un thread, toutes les 3 s, sans SolarMutex.
16. **Sélection : push, jamais poll.** `XSelectionChangeListener` (livré sur le thread principal) + relecture au `windowActivated`. Retirer le listener **avant** `dispose()` (le legacy fait l'inverse et ne survit que grâce à un `try/except`).
17. **Chips sur une seule ligne — contrainte dure.** Si ça déborde : raccourcir les libellés (infobulle `HelpText` pour le texte complet) ou réduire le padding ; **jamais** de passage à deux lignes. Pas d'emoji dans les libellés de chips (largeur imprévisible selon la police).
18. **Réglages / À propos / Documentation vivent UNIQUEMENT dans le menu 🤖 MIrAI** — la fenêtre flottante ne garde que le strict minimum (chips, sélection, prompt + jauge, zone basse à onglets, statut).
19. **Une seule zone basse, trois contenus** : historique, suggestions et actions se partagent le MÊME rectangle via des onglets — ne jamais réempiler des zones distinctes « pour faire simple », c'est ce qui avait fait exploser la hauteur.
20. **Le redimensionnement ne doit jamais casser la ligne de chips** : la largeur minimale de la fenêtre est celle calculée au premier layout pour tenir les chips sur une ligne ; toute la hauteur gagnée va à la zone basse.
21. **Refactoriser sous filet de tests, jamais à l'aveugle** : chaque factorisation (surtout `run_text_pipeline`, qui touche les 6 presets iso-fonctionnels) se fait avec la suite verte avant ET après, sans toucher aux assertions. Si un test doit changer, c'est que le comportement a bougé — donc que la factorisation a débordé.
22. **Compteur de jetons sans dépendance ni modification de requête** : estimation locale (caractères ÷ 4), remplacée par `usage` **si** le relais l'envoie spontanément. Ne pas ajouter `stream_options` au corps — certains relais rejettent les champs inconnus (leçon du mode tools natif).

23. **🚨 `processEventsToIdle` hors du thread principal = ABORT, pas ralentissement — et l'application reste figée.** Vécu le 2026-07-26 pendant un enrôlement SSO réel contre le DM Scaleway : l'enrôlement réussit (paire relais + `llmToken` mintés, tracés), puis LibreOffice ne répond plus à un seul clic.
    **Enchaînement exact**, lu dans `sample <pid>` : un thread Python appelle `processEventsToIdle()` → `SalUserEventList::DispatchUserEvents` → `std::terminate()` → `abort` → le gestionnaire de signal de LO tente d'ouvrir la **boîte de récupération d'urgence** (`RecoveryUI` → `doEmergencySavePrepare`) → laquelle réclame le **SolarMutex**… que le thread en train de mourir détient encore. Interblocage définitif : le thread principal reste dans `SalYieldMutex::doAcquire`.
    **Signature de diagnostic** : l'application est vivante (`STAT=S`, ~1 % CPU), le journal s'arrête net au milieu d'une opération, et `sample <pid>` montre le thread principal bloqué dans `SalYieldMutex::doAcquire` sous un `_handleMouseDownEvent`. Chercher ensuite le thread `pythread_wrapper` : sa pile porte le `processEventsToIdle` fautif.
    **Chemin fautif dans ce projet** : `stream_request` pompe les événements ET ouvre le widget « MIrAI réfléchit » ; appelé depuis un thread de fond (c'est ce que fait `_bg_ai_suggestions`), tout ce bloc s'exécute au mauvais endroit. C'est le défaut T-01 de la qualification, classé « latent » : il ne l'est pas.
    **Parade posée** : un helper unique `pump_events(toolkit)` (`entrypoint.py`) qui vérifie `threading.current_thread() is threading.main_thread()` avant de pomper — no-op tracé sinon. 18 sites convertis, aucun appel direct ne subsiste. Verrouillé par `tests/unit/test_pump_events_safety.py`, dont un garde-fou AST qui interdit tout appel direct hors du helper.
    **Leçon de méthode** : un défaut qualifié « crash latent » parce qu'il vit dans du code qu'on prévoit de supprimer reste **atteignable tant qu'il n'est pas supprimé**. Poser une garde bon marché coûte moins cher qu'un diagnostic à chaud — d'autant que le symptôme (« le plugin est bloqué ») ne désigne jamais le coupable.

24. **Trois défauts d'IHM qui ne se voient qu'en usage réel** (2026-07-26, session de recette sur le tier Scaleway) :
    - **La croix de la fenêtre ne ferme rien.** Un `UnoControlDialog` non modal émet `windowClosing` et *attend qu'on agisse* : sans `XTopWindowListener`, le bouton de fermeture est inerte. Corollaire : brancher le `XKeyListener` d'Échap sur le seul champ de prompt ne suffit pas — dès que le focus est ailleurs (une chip, la zone de réponse), la fenêtre devient impossible à fermer au clavier aussi. Brancher Échap sur TOUS les contrôles focalisables.
    - **Le service `AsyncCallback` doit être CONSERVÉ, pas recréé à chaque appel.** Créé en variable locale, il perd sa dernière référence au retour de `post()` et peut disparaître avant d'avoir délivré l'événement. Symptôme trompeur : une mise à jour d'affichage sur deux se perd — ici le bouton restait sur « Arrêter » après la fin du run, alors que `busy` valait bien `False`. Garder une instance unique dans le dispatcher.
    - **Ne jamais mélanger écriture directe et écriture postée sur le même contrôle.** Mettre le libellé à « Arrêter » en direct (thread principal) puis le remettre via `post()` fait diverger l'affichage de l'état réel dès que le post se perd. Un seul chemin : tout poster, y compris depuis le thread principal.
    - **Polices : viser 6-8 pt, pas 9-10.** Sur Retina les tailles rendent bien plus grand qu'attendu ; 10 pt paraît le double du raisonnable. Le layout mesuré corrige les POSITIONS, pas la taille perçue du texte.

25. **🚨 Un moteur de tools n'agit que s'il a l'outil pour agir — et le prompt qui l'y oblige.** Vécu le 2026-07-26 : « peux-tu restructurer le document en 2 paragraphes ? » sans sélection ne produisait RIEN. La télémétrie disait pourtant `preset=free`, `iterations=1`, `ok=true` : le modèle avait répondu du **texte** décrivant la restructuration, sans toucher au document.
    **Deux causes, toutes deux nécessaires à corriger :**
    - **Il manquait l'outil.** `writer_get_document_map` numérote les paragraphes `[P1] [P2]…`, mais AUCUN outil ne savait les réécrire : `writer_replace_selection` exige une sélection, `writer_find_replace` exige des correspondances exactes (fragile sur du texte long). Le modèle n'avait donc littéralement aucun moyen d'appliquer la demande. D'où `writer_replace_paragraphs(start, end, text)` — le pendant écriture de la carte, dont les `\n` créent de vrais paragraphes.
    - **Le prompt système n'exigeait pas d'agir.** Ajouter une consigne explicite « AGIS, NE DÉCRIS PAS : applique la modification avec les outils d'écriture, ne renvoie pas le texte modifié en laissant le document inchangé ; sans sélection, la demande porte sur le document entier ».
    **Règle générale, à appliquer à chaque nouvelle capacité** : pour toute famille d'action envisagée, vérifier qu'il existe (a) un outil de LECTURE pour se repérer, (b) un outil d'ÉCRITURE de même granularité, et (c) une consigne qui impose l'usage du second. Un outil de lecture sans son pendant écriture produit un assistant qui commente au lieu d'agir — et le symptôme observé est, encore une fois, « il ne se passe rien ».
    **Diagnostic** : `iterations=1` + `ok=true` + document inchangé ⇒ le modèle n'a appelé aucun outil. Regarder d'abord le catalogue d'outils, pas le moteur.
    **Corollaire d'IHM** : la réponse texte partait dans l'onglet Historique ; si l'utilisateur regardait un autre onglet, il ne voyait rien non plus. Un run bascule désormais automatiquement sur l'onglet qui reçoit la sortie.

26. **🚨 Écrire dans le document ne se fait JAMAIS sur une plage multi-paragraphes.** `cursor.setString()` sur une étendue qui couvre plusieurs paragraphes applique le style du **premier** à tout le bloc : un document dont [P1] est un titre s'est retrouvé intégralement en gros bleu gras. Il faut écrire **paragraphe par paragraphe** (`para.setString()`), ce que faisait déjà le code historique via `findFirst` + `setString` ciblé (`_run_whole_doc_edit`). Corollaires :
    - **Exposer les styles au modèle** : la carte du document annote désormais `[P1] <Heading 1>`. Sans cette information, le modèle fusionne un titre avec le corps sans savoir qu'il détruit la mise en forme — et aucune règle de code ne peut deviner son intention à sa place.
    - **Annoncer la fin du document** : la carte se termine par `[FIN DU DOCUMENT — N paragraphes]`. Sans ce repère, une demande portant sur « tout le document » ne traitait que les premiers paragraphes, le modèle ignorant combien il y en avait.
    - **Le surplus/déficit de paragraphes** se traite explicitement : supprimer ceux en trop (`removeTextContent`), ajouter les manquants en héritant du style du **dernier** paragraphe remplacé (pas du premier — sinon le corps ajouté prend le style du titre).

27. **Un fil de conversation se lit en main courante — le plus récent EN HAUT.** Concaténer en fin de zone oblige à faire défiler pour voir ce qui vient d'arriver, dans un cadre déjà court. Conséquence d'implémentation : on ne peut plus « ajouter du texte à la fin du contrôle » ; il faut tenir l'échange en cours dans une variable et **recomposer** l'affichage à chaque flux (échange courant, puis les échanges passés du plus récent au plus ancien). Inverser les GROUPES, jamais les lignes à l'intérieur d'un échange : une réponse au-dessus de sa question est illisible. Interligne : un seul `\n` entre les lignes, un séparateur discret entre les échanges — le double saut de ligne gaspille la moitié de la hauteur utile. ⚠ Cette recomposition a un COÛT : voir piège n°39, elle ne doit jamais relire une source persistée.

28. **`Sizeable` ne suffit pas, et un layout qui ignore la largeur imposée échoue en silence.** Le redimensionnement n'agrandissait pas les champs parce que `_layout()` n'acceptait aucun paramètre : l'appel `_layout(width=…)` levait un `TypeError` avalé par le `try/except` du listener. Règle : la fonction de layout doit accepter une largeur **imposée** (celle du peer) et retomber sur la largeur naturelle sinon ; sans quoi la poignée de redimensionnement agrandit le cadre et rien d'autre. Prévoir aussi la garde anti-réentrance — `_layout()` appelle `setPosSize()`, qui re-déclenche `windowResized`.

29. **🚨 L'IHM n'était couverte par AUCUN test — et 465 tests verts ont laissé passer une palette qui ne s'ouvrait plus.** Une ligne (`self._width` lu avant d'être initialisé) a suffi : `AttributeError` dans `_layout()`, capté par le `try/except` d'`open_palette`, donc **aucun message à l'écran** — juste une fenêtre qui n'apparaît pas. Toute la suite portait sur le moteur ; rien ne CONSTRUISAIT la palette.
    **Parade** : `tests/unit/core/test_palette_build.py` monte la palette entière sur des contrôles factices. Il ne juge pas le rendu (impossible hors LibreOffice) mais attrape la famille de pannes qui empêche l'ouverture : attribut manquant, méthode inexistante, mauvaise signature, listener non branché. Trois exigences pour que ce harnais serve :
    - **des modèles de contrôle à état réel** (`Text`/`Label` = vraies chaînes) : un MagicMock rend `.Text` incomparable et les assertions sur le contenu affiché deviennent vides de sens ;
    - **le contrôle et son modèle doivent être le MÊME objet** des deux côtés (`getControl(name).model is model`), sinon une écriture via `_models[…]` ne se voit pas via `getControl()` ;
    - **injecter `DirectDispatcher`** : avec le vrai dispatcher, le service AsyncCallback est un MagicMock qui accepte les tâches sans jamais les exécuter — on testerait un affichage qui n'est jamais mis à jour.
    Compléter aussi `uno_stubs` au fur et à mesure : une interface absente (ici `XKeyListener`) donne un MagicMock comme classe de base et un « metaclass conflict » à l'import, très loin de la cause réelle.
    **Leçon générale** : un `try/except` autour de l'ouverture d'une fenêtre transforme toute erreur de construction en « il ne se passe rien ». Si une couche est protégée par un catch large, elle DOIT être couverte par un test de construction — sinon la protection sert à cacher les régressions.

30. **🚨 La PORTÉE d'une demande doit être annoncée au modèle, pas déduite par lui.** « Réécris l'article en 2 paragraphes » sans sélection ne faisait rien. Trois tentatives ont été nécessaires, et l'ordre d'efficacité est instructif :
    - une consigne dans le **prompt système** (« AGIS, NE DÉCRIS PAS ») → insuffisante seule : le modèle est passé de `iterations=1` à `iterations=2`, il LISAIT le document puis répondait quand même du texte ;
    - un **rappel dans le résultat de l'outil de lecture** (« ÉTAPE SUIVANTE OBLIGATOIRE : appelle maintenant l'outil d'écriture ») → bien plus fort, car il arrive juste avant que le modèle ne décide de son prochain coup, au lieu de se diluer dans un préambule ;
    - une **ligne de PORTÉE en tête de la demande utilisateur**, calculée depuis le document (« aucune sélection — la demande porte sur le DOCUMENT ENTIER, de [P1] au dernier paragraphe »).
    **Règle** : ce qui est évident pour l'utilisateur (« il n'y a pas de sélection, donc c'est tout le document ») n'est visible nulle part pour le modèle. Toute information de contexte que l'IHM connaît — portée, taille, type de contenu — doit être **injectée explicitement**, au plus près de la décision. Et pour vérifier : `iterations` dans la télémétrie dit combien d'allers-retours ont eu lieu ; `1` = aucun outil, `2` = lecture sans écriture.

31. **Une interface immobile est indiscernable d'une interface plantée.** Pendant un run long, trois retours minimum : (a) le champ de saisie et les chips **grisés** — un champ resté actif invite à retaper une demande que le drapeau `busy` refusera en silence ; (b) une **jauge qui bouge** — rotor braille `⠋⠙⠹…` (largeur stable dans les contrôles UNO, donc aucun tremblement de mise en page) rafraîchi ~200 ms ; (c) **de quoi le modèle s'occupe** — « Réflexion » quand arrivent des `reasoning_content`, « Rédaction » sur du `content`, « Action sur le document » pendant un tool call. Le compteur de jetons est une estimation locale (caractères ÷ 4, contrainte no-pip) **marquée d'un `~`** tant qu'elle n'est pas confirmée : si le relais envoie spontanément un bloc `usage`, la valeur exacte remplace l'estimation et le `~` disparaît. Ne JAMAIS réclamer `usage` en ajoutant `stream_options` au corps — certains relais rejettent les champs inconnus.

32. **🚨 Ne pas confier à un modèle moyen une action qui DOIT aboutir.** Après trois renforts (consigne système, rappel dans le résultat de l'outil, ligne de portée en tête de la demande), `llama-3.3-70b-instruct` continuait d'échouer sur « réécris l'article en deux paragraphes » : il appelait l'outil de LECTURE, recevait la carte du document, puis répondait du texte — `iterations=2`, `ok=true`, document intact. **Les modèles de cette taille n'enchaînent pas deux tool calls de façon fiable.** Aucune formulation de prompt ne corrige cela ; à un moment il faut cesser d'espérer.
    **Parade — le patron « pipeline » du plan** : Python lit le document, le LLM n'est qu'une **fonction texte** (« renvoie le document réécrit, un paragraphe par ligne »), Python applique le résultat. Zéro tool call requis, donc plus rien à négocier avec le modèle. C'est déterministe, et c'est déjà la recette des presets Résumer/Simplifier/Raccourcir.
    **Quand basculer sur ce chemin** : détection d'intention par mots-clés (`core/doc_rewrite.py`) + absence de sélection + application Writer. Le coût d'un faux positif est faible (le modèle réécrit à l'identique), celui d'un faux négatif est une action sans effet — donc on ratisse large, en excluant seulement les questions (« que dit ce document ? » appelle une réponse, pas une modification).
    **Règle générale** : le mode agentique convient à l'exploration et aux demandes ouvertes ; dès qu'une action DOIT aboutir, la piloter depuis Python. Le tool calling est une commodité, jamais une garantie.

33. **Montrer le raisonnement sans encombrer.** Quand un modèle « réfléchit » (`reasoning_content`), l'utilisateur veut pouvoir regarder — mais une fenêtre déjà dense n'a pas la place d'un second flux. L'infobulle native (`HelpText` sur la ligne de statut) est la bonne réponse : rien à cliquer, rien à disposer, rien à découvrir… à condition d'**afficher un indice** (un « ⓘ » ajouté au statut) — sans lui, personne ne pense à survoler un texte de statut. Garder la **FIN** du raisonnement, pas son début : c'est l'état courant de la pensée qui intéresse, et une infobulle de plusieurs milliers de caractères est illisible (plafond ~900).

34. **🚨 Réécrire une plage qui commence par un titre y déverse du corps de texte — qui hérite du style Titre.** Corriger l'écriture paragraphe par paragraphe (piège n°26) ne suffit pas : chaque paragraphe garde bien SON style, mais si le premier de la plage était un titre, le premier bloc de corps s'affiche en gros et gras. **Il faut EXCLURE les titres de la plage réécrite**, pas seulement préserver leur style. `doc_rewrite.body_range()` calcule la plage de corps (du premier au dernier paragraphe non-titre) ; les titres sont passés au modèle comme CONTEXTE, avec la consigne de ne pas les reprendre. C'est d'ailleurs ce qu'attend l'utilisateur : « restructure l'article » ne veut pas dire « réécris le titre ». Détection par préfixe de style, en minuscules et multilingue (`heading`, `titre`, `title`, `überschrift`…) — le nom dépend de la langue de l'interface.

35. **🚨 Toute écriture de configuration doit être ATOMIQUE.** `set_config` écrivait en place. Un lecteur concurrent — un autre thread du plugin, une seconde instance de LibreOffice — pouvait tomber sur un JSON tronqué, échouer au parse, et **repartir sur les valeurs par défaut** : les credentials disparaissent, le poste se retrouve marqué enrôlé sans paire relais. C'est une entrée dans l'état absorbant que personne n'a demandée. Patron : écrire dans `<fichier>.tmp`, `flush` + `fsync`, puis `os.replace` (atomique sur POSIX comme sur Windows), et nettoyer le temporaire en cas d'échec. Le symptôme en test était bien plus discret qu'en production — un échec qui se déplaçait d'un test à l'autre selon la charge de la machine : **une suite instable est souvent le premier signe d'une vraie course, pas d'un test mal écrit.**

36. **Tous les modèles n'émettent pas de `reasoning_content`.** Une jauge qui n'affiche que le raisonnement reste vide sur la plupart des modèles — et l'indice de survol ne s'affiche jamais, ce qui donne l'impression que la fonction est cassée. L'infobulle doit retomber sur **le texte en cours de rédaction**, en annonçant ce qu'elle montre (« Réflexion du modèle : » / « Texte en cours : »). Vérifier ce que le modèle cible émet réellement AVANT de bâtir un affichage dessus.

37. **Un onglet vide n'est pas forcément un bug d'affichage — vérifier d'abord qui l'alimente.** L'onglet « Actions » restait désespérément vide : le journal n'était alimenté que par le `RunObserver` du mode agentique. Un preset pipeline ou une réécriture déterministe n'y écrivaient rien, alors que c'est précisément là que l'utilisateur cherche ce qui vient de se passer. **Tout chemin d'exécution doit alimenter le journal**, pas seulement celui qui l'a inspiré. Corollaire de diagnostic : instrumenter le rendu (« fil rendu : N entrées, M caractères ») avant de conclure à un problème d'affichage — ici la trace a prouvé que l'historique, lui, était bien écrit.

38. **Ne pas trancher un désaccord d'usage à la place des utilisateurs.** Remplacer la sélection ou ajouter le résultat à la suite entre marqueurs : les deux camps ont raison, selon qu'on veut aller vite ou comparer avant de décider. Plutôt qu'un arbitrage arbitraire, une case à cocher « Ajouter à la suite » à côté du bouton d'envoi, dont le choix est **mémorisé** en configuration (`assistant_append_mode`) — un réglage à refaire à chaque ouverture est un réglage qu'on n'utilise pas. Les marqueurs reprennent la forme historique (`---début-du-texte-modifié---`), déjà familière.

39. **🚨 Recomposer tout l'affichage à chaque fragment du flux gèle l'interface.** Le passage du fil en main courante (piège n°27) a introduit une régression coûteuse : `_render_conversation()` était rappelé à CHAQUE delta — environ 8 fois par seconde — et, à chaque fois, **relisait le fichier de conversation sur disque** puis postait la chaîne entière au thread principal. Une entrée-sortie disque et une grande allocation par fragment : la file d'événements du thread principal sature, et l'utilisateur voit une progression… qui s'arrête net.
    **Règles** :
    - **Ne jamais relire une source persistée dans une boucle de rendu.** Mettre l'historique en cache, l'invalider seulement quand il change réellement (nouveau run, effacement).
    - **Un rendu incrémental doit rester incrémental** : la coalescence des deltas (~120 ms) ne sert à rien si chaque flush recompose tout. Le coût par flush doit être proportionnel au fragment, pas à l'historique.

40. **🚨 Distinguer « thread principal bloqué » de « mises à jour non délivrées » — deux gels, deux causes.** `sample <pid>` tranche en dix secondes :
    - le thread principal est dans `SalYieldMutex::doAcquire` ⇒ **interblocage**, quelqu'un détient le SolarMutex (voir piège n°23) ;
    - le thread principal est dans `Application::Yield` / `DoYield` et **aucun thread Python n'apparaît** ⇒ le run est TERMINÉ, mais les mises à jour de fin — postées via `AsyncCallback` — n'ont pas été délivrées. L'interface reste figée dans l'état « en cours » : champ grisé, bouton « Arrêter », alors que plus rien ne tourne.
    **Parade pour le second cas** : un filet `heal_if_stuck()` branché sur `windowActivated` — si l'état est « occupé » sans worker vivant, on restaure. Coût nul, et un blocage définitif devient une gêne d'une seconde. **Toute machine à états pilotée par des messages asynchrones a besoin d'un tel filet** : la perte d'un message ne doit jamais laisser l'interface dans un état dont elle ne peut plus sortir. ⚠ Le filet ne remplace pas la correction de fond — voir piège n°41, la vraie cause est que les messages ne sont pas délivrés du tout.

41. **🚨 `AsyncCallback` posté depuis un thread de fond ne RÉVEILLE PAS la boucle d'événements de LibreOffice.** C'est la cause racine des « gels » observés, et elle a résisté à trois correctifs successifs (service conservé, instantané préchargé, filet auto-réparant) parce qu'aucun ne s'attaquait au vrai mécanisme. La tâche est bien mise en file, mais elle n'est délivrée qu'au prochain **événement système** — un mouvement de souris, une touche. Au repos, l'interface reste figée dans l'état « en cours » alors que le journal dit `run: terminé, interface restaurée` : le code a bien tourné, l'affichage n'a pas suivi.
    **Diagnostic** : ajouter une trace en fin de run. Si elle apparaît alors que l'interface reste figée, ce n'est ni un blocage ni une exception — ce sont les messages qui ne passent pas.
    **Il n'existe pas de timer UNO** : `com.sun.star.awt.Timer` renvoie `null` (vérifié sur LO 25.8) ; seul `AsyncCallback` est disponible.
    **Parade — la pompe auto-entretenue** : une file thread-safe alimentée par les workers, et un drain qui s'exécute sur le thread principal puis **se réarme lui-même** via `addCallback`. Le réarmement partant du thread principal, il est délivré de façon fiable — contrairement à un armement venu d'un worker. Trois règles :
    - la pompe est **armée depuis le thread principal** (dans le gestionnaire qui lance le run), jamais depuis le worker ;
    - elle ne tourne que **pendant un run** (`stop_pump()` en fin de run) — mesuré à 0,1 % de CPU au repos ;
    - `post()` et `call()` court-circuitent la file quand on est déjà sur le thread principal : pas de détour, pas d'interblocage.

42. **🚨 Une pompe qui se réarme sans condition monopolise la boucle d'événements.** Corollaire immédiat du piège n°41 : la première version de la pompe se réarmait à chaque tour, y compris à vide. LibreOffice passait son temps à traiter des tours de pompe et ne répondait plus ni à la souris ni au clavier — un gel **pire** que celui qu'on corrigeait, et immédiat. **La pompe doit s'éteindre dès que la file est vide** ; c'est `post()` qui la relance à la tâche suivante. Pendant un run, le trafic régulier (fragments, jauge) la maintient vivante ; au repos elle ne tourne pas du tout — 0,0 % de CPU mesuré. Règle générale : toute boucle installée sur le thread d'interface doit avoir une **condition d'arrêt liée au travail restant**, jamais au seul état « un run est en cours ».

43. **🚨 Écrire `model.Text` ne repeint pas un contrôle qui a déjà un peer.** Symptôme déroutant : la zone de texte apparaît **vide à l'écran** alors que tout est correct par ailleurs — le contrôle est visible, dans le champ, et une **relecture du modèle rend bien les 1888 caractères** qu'on vient d'y écrire. La donnée est là, l'affichage non.
    **Méthode qui a permis de trancher** — instrumenter en trois temps, du plus général au plus précis, sans jamais deviner :
    1. *les données existent-elles ?* → `fil rendu : 40 entrées, 1837 caractères` ;
    2. *le contrôle est-il visible et dans le champ ?* → `layout: fenêtre 802x566, zone basse y=325 h=235, visibles=['response']` ;
    3. *le contrôle contient-il vraiment le texte ?* → **relecture après écriture** : `posé=1888, relu=1888`.
    Les trois réponses étant positives, il ne restait que le rendu.
    **Parade** : écrire dans le modèle ET appeler `setText()` sur le CONTRÔLE. Le modèle porte l'état, le contrôle l'affiche. Un helper unique (`_set_text`) pour toutes les zones de texte, plutôt que des `model.Text = …` disséminés.

## Risques principaux

- JSON fallback avec llama-3.3 : parseur tolérant + coercition d'arguments + presets pipeline pour le volume + flush-si-parse-échoue.
- Support tools du relais inconnu : sonde + override DM `llm_tool_mode`.
- Undo long sur run agentique : repli documenté = un contexte undo par tool mutant.
- LO 25.8 EOL : à remonter au MIMO ; aucune API récente utilisée.
- Découpage d'`entrypoint.py` : mécanique mais volumineux — d'où l'ordre fusionner → supprimer → découper, et la suite verte à chaque commit.

---

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
