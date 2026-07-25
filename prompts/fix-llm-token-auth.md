# Prompt — Auth du proxy LLM `/llm/v1` : ce qui reste à faire côté device-management

## Contexte

Le plugin LibreOffice MIrAI appelle le LLM via le proxy du device-management
(`https://<bootstrap>/llm/v1`, activé par `FORCE_LLM_ENDPOINT_OVERRIDE=true`).
Une panne bloquante a été diagnostiquée et **corrigée côté plugin** (branche
`exp-jetable/demonstrateur-moteur-mcp`). Ce prompt couvre les vérifications et
compléments **côté device-management** — le plugin est hors périmètre.

## La panne (résumé factuel, pour comprendre l'enjeu)

Un poste se retrouvait marqué `enrolled=True` **sans aucun credential relay** sur
disque (`relay_client_id` / `relay_client_key` absents). Conséquence en chaîne :

1. `GET /config` partait sans `X-Relay-Client` / `X-Relay-Key`.
2. `_apply_llm_proxy_overrides` ne mint le `llmToken` que si `relay_ok` — la
   réponse contenait donc `llm_api_tokens:""`, `llmToken:""`, `telemetryKey:""`
   et `_auth_notice:"Authentification requise…"`.
3. Sans `llmToken`, le plugin n'envoyait aucun credential exploitable.
4. `LlmAuthenticator.resolve` renvoyait **401 `invalid_api_key`** — « Missing
   credentials » — sur 100 % des appels `/llm/v1`, y compris `/models`.

Le plugin restait bloqué indéfiniment : son court-circuit d'enrôlement portait
sur le drapeau `enrolled` et non sur la présence des credentials relay. C'est ce
point qui a été corrigé côté plugin, avec en plus : lecture de
`llmTokenExpiresAt`, effacement d'un token révoqué, réaction au signal
`_auth_notice`, et reprise automatique sur 401 (refresh `/config` → ré-enrôlement
→ une re-tentative).

## Ce qui a déjà été vérifié dans device-management — ne pas y toucher

Ces points ont été lus dans le code et sont **corrects** ; le correctif plugin
s'appuie dessus. Les modifier casserait la reprise automatique.

- `_mint_or_rotate_relay_credentials` (`app/main.py`) révoque puis ré-émet
  inconditionnellement une paire relay à chaque `POST /enroll`. **Le
  ré-enrôlement d'un poste déjà connu rend donc bien de nouveaux credentials** —
  c'est l'hypothèse dont dépend la sortie d'impasse côté plugin.
- `_relay_allowed_targets` ajoute toujours `"llm"` aux targets accordés.
- `LlmAuthenticator.resolve` (`app/llm/auth.py`) accepte les deux vecteurs
  (en-têtes `X-Relay-*` puis `Bearer <llmToken>`) et re-vérifie la révocation en
  base.
- La réponse `/enroll` expose les creds sous les deux formes attendues
  (`relay.client_id/client_key` et `relayClientId`/`relayClientKey`).

## Tâches

### T1 — Vérifier la configuration des environnements (BLOQUANT)

> Cette tâche est un **prérequis de déploiement**, pas une vérification
> d'hygiène. Décision d'architecture du 2026-07-25 : le plugin authentifie ses
> appels `/llm/v1` avec le **llmToken seul**, sans repli sur les en-têtes
> `X-Relay-*` (voir « Décision » plus bas). Il n'existe donc aucune porte de
> sortie si le mint échoue.

Deux variables font échouer le mint **silencieusement**, sans erreur ni log
explicite, en produisant exactement le même symptôme que la panne d'origine :

- `DM_LLM_TOKEN_SIGNING_KEY` vide → `mint_llm_token` retourne `("", None)` et
  `llmToken` reste `""` **même avec des credentials relay parfaitement valides**.
- `RELAY_ENABLED=false` → `_relay_auth_from_request` refuse tout, donc
  `relay_ok=False`, donc aucun mint — quels que soient les credentials du poste.

Contrôler ces deux valeurs sur `dev`, `int` et `prod`, et documenter le résultat.
Si l'une manque sur un environnement où `FORCE_LLM_ENDPOINT_OVERRIDE=true`, c'est
une cause racine à part entière, indépendante du bug plugin.

### T2 — Rendre l'échec de mint diagnosticable

Aujourd'hui un mint impossible est indiscernable, côté client comme côté serveur,
d'un poste non enrôlé. Ajouter dans `_apply_llm_proxy_overrides` un log serveur
distinguant les trois cas :

- `relay_ok=False` → poste non authentifié (cas nominal avant enrôlement) ;
- `relay_ok=True` mais `mint_llm_token` rend `""` → **clé de signature absente**,
  erreur de configuration serveur, à logger en `warning` ;
- mint réussi → rien (ou `debug`).

Ne pas faire fuiter le token ni la clé dans les logs.

### T3 — Exposer les postes « enrôlés à moitié »

Un poste dont le dernier credential relay est révoqué ou expiré, et qui n'a pas
ré-enrôlé, est invisible dans l'admin alors qu'il est totalement hors service.
Ajouter à l'UI admin (onglet devices) une colonne ou un filtre dérivé de
`relay_clients` : dernier credential actif, date d'expiration, et un marqueur
« sans credential actif ». Objectif : détecter la population affectée sans avoir
à interroger la base à la main.

### T4 — Test d'intégration de bout en bout

Scénario à couvrir, qui reproduit exactement la panne :

1. Enrôler un poste, récupérer sa paire relay.
2. Révoquer son credential en base (`revoked_at = now()`), sans rien changer
   d'autre.
3. `GET /config` avec l'ancienne paire → doit rendre `llmToken:""` et poser
   `_auth_notice`.
4. `POST /chat/completions` sur `/llm/v1` avec cet état → **401
   `invalid_api_key`**.
5. Re-`POST /enroll` avec le même `plugin_uuid` → doit rendre une **nouvelle**
   paire relay (non révoquée).
6. `GET /config` avec la nouvelle paire → `llmToken` non vide, avec
   `llmTokenExpiresAt` cohérent avec `DM_LLM_TOKEN_TTL_SECONDS`.
7. `POST /chat/completions` avec ce token → **200**.

L'étape 5 est la garantie contractuelle dont dépend la reprise automatique du
plugin : si elle régresse, tous les postes affectés redeviennent bloqués sans
aucun moyen de s'en sortir.

### T5bis — Créer le document d'interface Plugin ↔ DM pour `/llm/v1`

Il n'existe aujourd'hui **aucun contrat d'interface écrit** pour l'authentification
du trafic LLM. La panne a coûté une demi-journée de rétro-ingénierie croisée entre
les deux dépôts, uniquement parce que la règle « le proxy n'accepte que le
llmToken ou les en-têtes relais, et jamais un JWT Keycloak » n'était écrite nulle
part.

Preuve que le besoin est réel et non théorique : `docs/plugin-developer/
plugin-dm-protocol-update-features.md` documente les en-têtes relais sous les noms
**`X-Relay-Client-Id` / `X-Relay-Client-Key`** (§ tableau des en-têtes, et snippet
Python copiable ~l. 844). Le code lit `x-relay-client` / `x-relay-key` (alias
`x-client-id` / `x-client-key`) — cf. `app/main.py:1829-1830` et
`app/llm/auth.py:98`. **Quiconque implémente d'après cette doc récolte des 401.**
Corriger au passage.

Créer `docs/plugin-developer/plugin-dm-protocol-llm.md`, calqué sur la forme du
document protocole existant (diagramme mermaid + tableaux d'en-têtes + exemples
`curl`). Contenu attendu :

1. **Les deux vecteurs d'auth acceptés**, avec l'ordre de résolution du serveur et
   le fait qu'il n'y a **aucun repli** de la branche relais vers le Bearer.
2. **Le vecteur nominal : le llmToken seul** (décision ci-dessous), et l'interdit
   correspondant côté client : ne pas émettre `X-Relay-*` sur `/llm/v1`.
3. **Cycle de vie du llmToken** : minté par `/config` uniquement si la paire
   relais est validée ; par requête, jamais mis en cache ; TTL
   `DM_LLM_TOKEN_TTL_SECONDS` (1 h par défaut) ; champs `llmToken` /
   `llmTokenExpiresAt` / `llm_api_tokens` de la réponse `/config` et leur
   relation. Préciser que `llm_api_tokens` porte la même valeur pour
   compatibilité, et qu'une valeur **vide est significative** (= aucun mint).
4. **Format du token** : `payload_b64.sig_b64`, HMAC-SHA256, claims
   `{jti, iat, exp, client_uuid, email, scope:"llm"}`. Dire explicitement qu'un
   JWT à 3 segments (access_token Keycloak) **n'est pas** un llmToken.
5. **Tableau des codes d'erreur** : chaque `LlmProxyError` (401 `invalid_api_key`
   dans ses variantes « missing credentials » / signature / expiration /
   révocation, 503 clé absente, 413, 429) → cause probable → action attendue du
   client.
6. **Le signal `_auth_notice`** : quand le DM le pose, ce qu'il signifie, et ce
   que le client doit en faire (ré-enrôler).
7. **Contrat d'idempotence de `/enroll`** : chaque appel révoque et ré-émet la
   paire relais. C'est la porte de sortie de toute impasse d'auth — à documenter
   comme une garantie opposable, pas comme un détail d'implémentation.
8. **Endpoints couverts** : `/models`, `/chat/completions`, `/embeddings` (même
   auth, même quota ; `embdUrl`/`embdToken` dérivés de `llmEndpoint`/`llmToken`).

Rattacher le document depuis `docs/plugin-developer/README.md` et depuis
`docs/architecture/adr-0002-proxy-llm-relais.md` (le contrat d'interface est la
mise en œuvre de cette ADR).

### T5 — Cohérence des TTL

`DM_LLM_TOKEN_TTL_SECONDS` vaut 3600 s par défaut, alors que le plugin
rafraîchit sa config toutes les 300 s. Le rapport est confortable, mais un TTL
abaissé sous ~600 s côté DM rendrait les 401 fréquents. Documenter cette borne
basse dans le README (section proxy LLM), à côté de la variable.

## Contraintes

- Périmètre strictement `device-management` ; ne pas modifier le plugin.
- Ne jamais faire sortir la clé backend `LLM_API_TOKEN` vers un client : en mode
  proxy, seul le `llmToken` signé par poste doit transiter.
- Aucun secret (token, clé, hash) dans les logs ou les réponses d'erreur.
- Les accès psycopg2 restent hors event-loop (`anyio.to_thread` /
  `run_in_threadpool`), conformément au code existant.

## Décision d'architecture — vecteur d'auth de `/llm/v1`

Retenue le 2026-07-25, à ne pas ré-ouvrir sans arbitrage explicite.

**Le llmToken est le seul vecteur d'authentification du trafic LLM.** Le plugin
n'envoie jamais `X-Relay-*` sur `/llm/v1`.

Il faut choisir, car l'ordre de résolution est fixé côté serveur et non
négociable par le client : dès que `X-Relay-Client` est présent,
`LlmAuthenticator.resolve` engage la branche relais et échoue en 401 **sans
repli** vers le Bearer. Envoyer les deux vecteurs ne donne pas « essaie l'un puis
l'autre » — les en-têtes relais gagnent toujours et masquent un llmToken valide.

Critère d'arbitrage : **minimiser la surface d'attaque**. Le llmToken est scopé
(`scope:"llm"`) et vit 1 h — durée adéquate pour du LLM. La paire relay est le
credential maître (config + télémétrie + LLM) et vit 30 jours
(`DM_RELAY_KEY_TTL_SECONDS=2592000`) : la rejouer sur chaque appel LLM, à travers
les WAF et proxies intermédiaires, étalerait un secret long-vivant sur la surface
la plus exposée. C'est précisément ce que le design du llmToken visait à éviter
(docstring de `app/llm/tokens.py`).

Conséquences pour device-management :

- `DM_LLM_TOKEN_SIGNING_KEY` est une **dépendance dure** de tout environnement où
  `FORCE_LLM_ENDPOINT_OVERRIDE=true` → d'où le statut bloquant de T1.
- Toute évolution de `LlmAuthenticator` doit préserver la branche Bearer comme
  chemin nominal ; la branche relais ne sert plus que le trafic non-LLM.
- Un abaissement de `DM_LLM_TOKEN_TTL_SECONDS` n'a plus aucun filet → cf. T5.

## Invariant à inscrire dans la doc d'architecture

> Un poste est « enrôlé » si et seulement s'il détient une paire relay active.
> Le drapeau `enrolled` ne prouve que la réception d'un HTTP 201 — il ne doit
> jamais servir de condition de court-circuit à un ré-enrôlement.
