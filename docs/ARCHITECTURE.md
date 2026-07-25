# Architecture — Démonstrateur « moteur MCP interne + palette universelle »

> ⚠️ Branche `exp-jetable/demonstrateur-moteur-mcp` — **expérimentation jetable**,
> ne pas merger vers master. Ce document est la carte pour qu'un humain **et**
> un assistant de codage puissent reprendre le code sans archéologie.

## Vue en couches

```
┌────────────────────────────────────────────────────────────┐
│ COQUILLE (inchangée) — src/mirai/entrypoint.py (MainJob)   │
│ enrollment · Keycloak/SSO · device management · auto-update│
│ télémétrie · proxy/_urlopen · SSL · config bootstrap       │
└────────────┬───────────────────────────────────────────────┘
             │ trigger("OpenAssistant") → import paresseux
┌────────────▼───────────────┐   ┌───────────────────────────┐
│ core/entry.py (le pont)    │──▶│ ui/palette.py (DSFR)      │
│ MainJobShell(job)          │   │ chips · prompt · fil de   │
└────────────┬───────────────┘   │ conversation · journal    │
             │ ShellServices     │ d'actions (repliable)     │
┌────────────▼───────────────────┴───────────────────────────┐
│ MOTEUR (core/) — jamais d'import de la coquille (testé)    │
│ registry (tools MCP-like) · orchestrator (boucle agentique)│
│ llm_client (natif/JSON) · sse_pump · sinks · presets       │
│ conversation (persistance MVP) · tools/writer · tools/calc │
└────────────────────────────────────────────────────────────┘
```

## Règles non négociables

1. **Threading — modèle worker + dispatcher** (itération 2, remplace le drain).
   Le run **entier** vit dans un thread worker ; le thread principal retourne
   immédiatement à la boucle d'événements de LibreOffice, qui reste utilisable
   pendant toute la génération. Tout ce qui touche UNO — document, contrôles,
   undo, exécution des tools — repasse par `MainThreadDispatcher`
   (`core/ui_thread.py`) :
   - `post(fn)` pour l'affichage (sans attendre) ;
   - `call(fn, timeout)` pour lire ou modifier le document (rend le résultat).

   **Plus aucun `processEventsToIdle` dans `core/` ni `ui/`** — vérifié par
   `test_core_and_ui_never_pump_events` (analyse AST, pas du texte). La classe
   de gel (et l'abort `std::terminate` dans `DispatchUserEvents`) devient
   impossible par construction, au lieu d'être évitée par vigilance.

   Corollaires :
   - **La reprise d'authentification après 401 fait du réseau bloquant** : elle
     vit dans le thread du pump (via la fabrique de requête de `run_stream`),
     jamais sur le thread principal. Même famille de piège que le drain.
   - **La sélection se lit en PUSH** (`XSelectionChangeListener`, livré par
     LibreOffice sur le thread principal), jamais par un thread qui interroge
     en boucle. Le listener est retiré **avant** `dispose()`.
   - **Anti-flood** : les deltas sont coalescés (~120 ms ou ~80 caractères)
     avant d'être postés, sinon la file du thread principal sature et
     l'application redevient molle.
2. **Zéro import de la coquille** dans `core/` et `ui/` — la façade
   `shell_facade.MainJobShell` duck-type l'objet MainJob. Règle exécutable :
   `tests/unit/core/test_no_entrypoint_import.py`.
3. **Pas de pip** : stdlib uniquement (validateur JSON-schema = sous-ensemble
   maison documenté dans `core/tool_calls.py`).
4. **Jamais de contenu documentaire en télémétrie** — uniquement compteurs,
   statuts, durées, noms de tools.
5. **Marianne jamais embarquée** (licence État) — sonde runtime dans
   `ui/dsfr.py` (Marianne → Arial → Liberation Sans).

## Les tools (miroir MCP interne)

| Tool | App | Mutant | Rôle |
|---|---|---|---|
| writer_get_selection | W | | texte sélectionné |
| writer_get_document_map | W | | doc en paragraphes numérotés [Pn] |
| writer_replace_selection | W | ✔ | remplace la sélection (court) |
| writer_insert_text | W | ✔ | insère après sélection / fin de doc |
| writer_find_replace | W | ✔ | paires find/replace exactes |
| calc_get_selection | C | | plage, dimensions, en-têtes, aperçu |
| calc_read_range | C | | plage → tableau texte |
| calc_get_sheet_overview | C | | structure de la feuille |
| calc_write_cells | C | ✔ | écrit des cellules |
| calc_write_result_column | C | ✔ | colonne « Résultat IA » non destructive |
| calc_set_formula | C | ✔ | formule + relecture d'erreur (Err:…) |
| calc_fill_formula_down | C | ✔ | recopie avec décalage de lignes |

Un run d'orchestrateur = **un seul contexte undo** (ouvert par le premier tool
mutant, fermé en finally) → l'action complète s'annule d'un Ctrl+Z.

Principe clé (petits modèles) : **la prose longue ne transite jamais en
argument JSON** — elle est streamée en réponse finale vers un *sink*
(`sinks.py` : PaletteSink, WriterInsertSink, WriterReplaceSink, CalcCellSink).

## Presets (les chips de la palette) — `core/presets.py`

- **pipeline** (Python pilote, iso-fonctionnalité stricte avec l'historique,
  marqueurs `---début-du-…---` conservés) : Continuer, Résumer, Simplifier,
  Raccourcir/Allonger, Transformer (Calc), Analyser (Calc).
- **agentique** (le LLM pilote les tools) : Modifier (Writer), Formule (Calc —
  contexte de feuille + retrieval `config/calc-functions.json`), prompt libre.
- Télémétrie : spans historiques conservés (`SummarizeSelection`, …) avec
  `{"via": "palette"}` + nouveaux spans `assistant.open/run/tool`.

## Client LLM double-mode — `core/llm_client.py`

- `llm_tool_mode` : `auto` (défaut) | `native` | `json` — distribuable par DM.
- `auto` : tools OpenAI natifs d'abord ; HTTP 400/404/422 sur une requête
  portant des tools → bascule définitive en JSON (cachée dans
  `llm_tool_mode_detected`).
- Mode JSON : catalogue + protocole dans le prompt système ; parseur tolérant
  (fences, `<think>`, virgules traînantes, quotes typographiques) ; deltas
  retenus tant que la réponse ressemble à un tool call, **flush intégral si le
  parse échoue** — la sortie du modèle n'est jamais perdue.
- Clamps max_tokens par modèle réappliqués par la façade
  (`shell_facade.MODEL_TOKEN_LIMITS`) car `make_chat_request` ne les a pas.

## Persistance de conversation (MVP) — `core/conversation.py`

`<UserConfig>/assistant_conversation.json` — 20 échanges / 100 Ko max,
écriture atomique, tolérant à la corruption, local uniquement, bouton
« Nouvelle conversation ». Les tours user + réponses finales seulement
(jamais les tool calls). Injection des derniers échanges dans le contexte
(cap ~4 000 caractères).

## Ajouter un tool en 5 étapes

1. Handler `def mon_tool(ctx, args) -> ToolResult` dans `core/tools/…`.
2. `registry.register(ToolSpec(name="app_mon_tool", description=…, parameters=
   {schema}, handler=…, apps=(…), mutates=bool))` dans `register()`.
3. Libellé FR dans `ui/palette.py:TOOL_LABELS` (journal d'actions).
4. Test dans `tests/unit/core/test_tools_uno.py` (fakes `tests/stubs/fake_docs.py`).
5. Si le tool sert un preset : câbler dans `core/presets.py` + test golden.

## Tests

`python3 -m pytest tests/unit/ -v` — 337 tests (coquille inchangée + moteur).
Golden iso-fonctionnels : `test_presets_writer.py` / `test_presets_calc.py`
rejouent chaque fonction historique via le moteur (FakeShell + SSE scripté +
faux documents à état réel).

## De démonstrateur à produit (dette nommée, si on poursuit)

1. Supprimer le cœur legacy d'entrypoint.py + `menu_actions/` (commit de pure
   suppression — prévu, non fait tant que la validation utilisateur n'est pas
   passée) puis, une release plus tard, `stream_request`/`make_api_request`.
2. Unifier `=PROMPT()` (`calc_prompt_function.py`) sur la façade (≈150 lignes
   dupliquées de la coquille, sans Keycloak ni relais).
3. `ui_ask_user` (questions de clarification interactives dans la palette).
4. i18n ; multi-conversations + recherche ; sidebar historique ;
   permissions par tool ; rafraîchir les chips quand l'app change sous une
   palette ouverte.

## Environnement de dev macOS — piège connu

macOS 26 (Darwin 25.5) tue les binaires auxiliaires de LibreOffice.app
(`uno`, `unopkg`, python embarqué) : SIGKILL « Launch Constraint Violation »
→ `unopkg add` et l'install in-process échouent. Réparation (2026-07-25) :
re-signature ad hoc (`codesign --force -s - <binaire>`) de
`Contents/MacOS/{uno,unopkg,gengal,regview,senddoc,unoinfo,uri-encode,xpdfimport,opencltest}`
et du framework Python embarqué. **À refaire après chaque mise à jour de
LibreOffice.app.**
