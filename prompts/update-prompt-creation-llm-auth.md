# Prompt — Répercuter la décision d'auth `/llm/v1` dans le document de création

## Objet

Mettre à jour `prompts/prompt-creation.md` (« Prompt de Création — Assistant Mirai
LibreOffice », document de référence pour recréer l'application from scratch) afin
qu'il capture la chaîne d'authentification du proxy LLM du device-management et la
décision d'architecture du 2026-07-25.

**Pourquoi c'est nécessaire :** le document décrit un monde antérieur au proxy DM.
Son §3.5 « Appels LLM » et son §6.3 « Format config enrichie » traitent
`llm_api_tokens` comme une **clé d'API statique** distribuée par la config. C'est
faux depuis `FORCE_LLM_ENDPOINT_OVERRIDE` : c'est un **jeton court, minté par
poste, à durée de vie 1 h**. Une reconstruction fidèle au document actuel
reproduirait exactement la panne du 2026-07-25.

## Sources de vérité — à lire avant d'écrire

- `prompts/fix-llm-token-auth.md` — diagnostic complet, décision d'architecture,
  et tâches DM.
- `src/mirai/entrypoint.py` — `_relay_credentials_valid`, `_resolve_llm_token`,
  `_effective_api_token`, `_check_relay_auth_notice`, `_recover_llm_auth`,
  `_llm_proxy_mode`, et le commentaire du point d'injection dans `_urlopen`.
- `src/mirai/core/llm_client.py` — reprise sur 401 dans `step()`.
- `tests/unit/test_llm_token_auth.py` — les invariants sous forme exécutable.
- Côté DM : `app/llm/auth.py`, `app/llm/tokens.py`,
  `app/main.py:_apply_llm_proxy_overrides`.

Ne rien inventer : chaque affirmation du document doit être vérifiable dans une de
ces sources. En cas de divergence entre le code des deux dépôts, **le code fait
foi**, pas la doc existante.

## Ce qu'il faut écrire, section par section

### §3.3 — Séquence d'enrôlement

Ajouter l'invariant, en encadré :

> Un poste est enrôlé si et seulement s'il détient une paire relais **active**.
> Le drapeau `enrolled` ne prouve que la réception d'un HTTP 201 — il ne doit
> jamais servir de condition de court-circuit à un ré-enrôlement.

Et le contrat qui rend la reprise possible : `POST /enroll` est idempotent côté DM
(`_mint_or_rotate_relay_credentials` révoque puis ré-émet à chaque appel). C'est
la porte de sortie de toute impasse d'auth.

### §3.5 — Appels LLM

Réécrire la partie authentification. Deux modes à distinguer explicitement :

- **Mode proxy DM** (`FORCE_LLM_ENDPOINT_OVERRIDE=true`, le défaut) : endpoint
  `<bootstrap>/llm/v1`, auth par `Authorization: Bearer <llmToken>` uniquement.
  Le `llmToken` est un HMAC `payload_b64.sig_b64` minté par `/config`, valable
  1 h, porteur de `scope:"llm"`. Un access_token Keycloak (JWT à 3 segments) n'en
  est pas un et sera rejeté.
- **Mode direct** (LLM local / hors DM) : clé d'API statique, comportement
  historique conservé.

Documenter la chaîne complète et le fait que chaque maillon casse en produisant le
**même** 401 : `/enroll` → paire relais → `/config` avec `X-Relay-*` → mint du
`llmToken` → appel LLM.

### §3.7 — Threading & Locks

Ajouter la contrainte, qui n'est pas négociable : la récupération d'auth après un
401 fait du réseau bloquant et s'exécute **dans le thread réseau du pump SSE**, via
`_build_request`. Sur le thread principal UNO, LibreOffice paraîtrait gelé. Même
famille de piège que l'interdit `processEventsToIdle` depuis un thread de fond.

### §4.1 — Sécurité

Ajouter la décision d'architecture et son critère :

> **Vecteur d'auth de `/llm/v1` : le `llmToken` seul.** Il faut choisir — dès que
> `X-Relay-Client` est présent, le DM engage la branche relais et échoue en 401
> **sans repli** vers le Bearer. Critère : minimiser la surface d'attaque. Le
> `llmToken` est scopé et vit 1 h ; la paire relais est le credential maître
> (config + télémétrie + LLM) et vit 30 jours. Ne jamais émettre `X-Relay-*` sur
> `/llm/v1`.

Ajouter la contrepartie assumée : `DM_LLM_TOKEN_SIGNING_KEY` devient une
dépendance dure côté serveur, sans porte de sortie côté client si elle manque.

### §6.3 — Format config enrichie

Compléter avec les champs du mode proxy : `llmEndpoint`, `llmToken`,
`llmTokenExpiresAt`, `embdUrl`, `embdToken`, et le signal `_auth_notice`.
Préciser deux règles que le document actuel ne permet pas de deviner :

- `llm_api_tokens` porte la **même** valeur que `llmToken` (compatibilité) ;
- une valeur **vide est significative** — elle signifie « aucun mint », et doit
  **effacer** la valeur locale au lieu d'être ignorée.

### §9 — Points d'attention & Pièges connus

Ajouter trois entrées, chacune formulée comme un piège reproductible :

1. **L'état absorbant** — `enrolled=True` sans creds relais. Symptôme : 401
   `invalid_api_key` « Missing credentials » sur 100 % des appels `/llm/v1`, y
   compris `/models`, sans aucune reprise possible. C'est la panne du 2026-07-25.
2. **Le repli impossible** — retomber sur l'access_token Keycloak quand il n'y a
   pas de `llmToken` ne peut pas marcher et masque la vraie cause derrière un 401
   qui accuse le token plutôt que l'enrôlement.
3. **Le jeton périmé silencieux** — servir `llm_api_tokens` sans vérifier
   `llmTokenExpiresAt` (TTL 1 h contre un cache de config de 300 s).

### §5 — Stratégie de test

Ajouter les scénarios de non-régression, en renvoyant à
`tests/unit/test_llm_token_auth.py` : ré-enrôlement depuis l'état absorbant,
token expiré ignoré, token vidé par le DM, refus du repli Keycloak en mode proxy,
réaction à `_auth_notice`, et reprise sur 401 exécutée hors thread principal.

## Contraintes de rédaction

- Conserver la langue, le ton et la structure du document (§ numérotés,
  diagrammes mermaid, tableaux). Ne pas le restructurer.
- Ne pas renuméroter les sections existantes : compléter en place.
- Aucun secret, aucune valeur réelle de token, de clé ou d'URL interne dans les
  exemples.
- Les noms d'en-têtes relais sont `X-Relay-Client` / `X-Relay-Key` (alias
  `X-Client-Id` / `X-Client-Key`). **Pas** `X-Relay-Client-Id` — cette forme
  circule dans la doc DM et est fausse.
- Si une affirmation du document existant contredit le code, la corriger et le
  signaler en fin de réponse plutôt que d'empiler une exception.
