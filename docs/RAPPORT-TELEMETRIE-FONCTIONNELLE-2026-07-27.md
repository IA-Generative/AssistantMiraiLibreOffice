# Télémétrie fonctionnelle — rapport d'exécution et de recette

**Date** : 2026-07-27
**Branches** : `feat/telemetrie-fonctionnelle` (plugin) · `feat/telemetry-typed-attributes` (device-management)
**Base** : `exp-jetable/demonstrateur-v2` · `fix/campaign-plugin-filter`

---

## 1. Pourquoi

`core/telemetry_steps.py` avait posé le socle — span unique `AssistantStep`, vocabulaire
fermé, filtre `safe_attributes` garantissant par construction qu'aucune phrase du document
ne quitte le poste. Il n'était branché que sur neuf étapes de la palette.

Le parcours du code a révélé que l'essentiel du fonctionnement restait invisible :

- **`AssistantRun` n'existait que pour le mode agentique.** Les trois autres chemins
  d'exécution — preset pipeline, réécriture de sélection, réécriture de document — ne
  laissaient aucune trace : ni durée, ni issue, ni cause. Or ce sont eux qui traitent la
  majorité des demandes sur un poste dont le modèle n'enchaîne pas les outils.
- **Aucune cause de fin.** Une annulation, un plafond d'itérations et un HTTP 429 se
  ressemblaient tous : `ok=false`.
- **Les mécanismes de rattrapage étaient à sens unique.** La bascule définitive
  natif→JSON, la reprise après 401 et la reprise après « budget mangé par le
  raisonnement » n'étaient tracées qu'en échec. Impossible de dire si elles servent.
- **Les refus et les gestes d'interface n'existaient pas.** Un preset cliqué à vide tous
  les jours ne produisait qu'un statut rouge que personne ne remonte.
- **Trois pannes muettes** : filet anti-blocage de la palette, attente bloquante de
  configuration (jusqu'à 15 s), action de menu non implémentée.

---

## 2. Ce qui a été livré

### Plugin — 4 commits

| Commit | Contenu |
|---|---|
| `4a6d264` | Socle : 7 constantes au vocabulaire fermé + `emit_run` (span de run sous le même filtre anti-contenu) |
| `efe2aed` | **Lot A — fiabilité** : span `AssistantRun` unifié sur les 4 chemins, cause de fin, motif d'échec des outils, coercitions d'arguments, bascules et reprises LLM |
| `b60d9b9` | **Lot B — usage** : refus de lancement, session de palette agrégée, `AssistantOpen` enrichi, refocus |
| `9877cf5` | **Lot C — santé** : filet anti-blocage, attente de configuration, action non gérée |
| `7876848` | Test de contrat moteur → fil → serveur |

### Device Management — 2 commits

| Commit | Contenu |
|---|---|
| `a0b89c4` | Lecture des attributs OTLP **typés** à la persistance SQL |
| `0fc2767` | La mise en lettre morte ne tue plus le worker de la file |

### Le point d'émission unique du span de run

L'orchestrateur n'émet plus `AssistantRun` : son `RunResult` portait déjà tout ce que le
span disait. L'émission passe dans le `finally` de `_run_in_worker`
([palette.py](../src/mirai/ui/palette.py)), seul endroit que les quatre branches
traversent — exceptions et fermeture de palette comprises. Deux émetteurs auraient fait
diverger deux formats du même span.

Attributs : `run.kind` (`agentic` | `pipeline` | `selection_rewrite` | `document_rewrite`),
`assistant.preset`, `assistant.ok`, `assistant.cancelled`, `assistant.reason`,
`assistant.mode`, `assistant.iterations`, `assistant.duration_ms`, `append.mode`.

Causes de fin possibles : `cancelled`, `max_iterations`, `http_401`/`http_429`/…,
`network_error`, `empty_document`, `headings_only`, `reasoning_starved`, `empty_reply`,
`palette_closed`, `exception`.

### Volumétrie maîtrisée

Une trace coûte une requête HTTP et un thread, sans mise en lot. Les gestes d'interface
(onglets, panneau de raisonnement, nouvelle conversation, bascules « Ajouter à la suite »,
consultations des Suggestions) sont donc **comptés en mémoire et émis en un seul span à la
fermeture**. Seuls les clics de l'utilisateur comptent, jamais les bascules
programmatiques. Deux refus consécutifs de même cause ne comptent qu'une fois (Entrée
martelée). Une action non gérée n'est signalée qu'une fois par nom et par session.

---

## 3. Deux défauts trouvés en recette

### 3.1 Les compteurs arrivaient vides en base *(corrigé)*

`_persist_telemetry_spans` ne lisait que `stringValue`. Depuis que le plugin encode ses
attributs avec les types OTLP, **tout entier ou booléen arrivait en chaîne vide** dans
`device_telemetry_events` — donc dans la vue « activité appareil » de l'admin. Tempo, lui,
recevait le corps verbatim et ne perdait rien : le défaut ne se voyait que côté SQL.

Chaque compteur ajouté par ce lot aurait été silencieusement perdu. Corrigé par un lecteur
typé (`stringValue` → `intValue` → `boolValue` → `doubleValue`), rétrocompatible.

### 3.2 Une tâche en échec tuait le worker de la file *(corrigé)*

`queue_job_dead_letters.job_id` ne portait aucune contrainte unique, alors que
`move_to_dead_letter` fait `ON CONFLICT (job_id)`. Postgres refuse la requête
(`InvalidColumnReference`), l'exception remonte la boucle du worker et **la tue** : la file
entière — télémétrie **et enrôlements** — cesse d'être traitée jusqu'au redémarrage du
conteneur.

Le déclencheur est banal : il suffit qu'une tâche épuise ses huit tentatives. Un amont OTLP
injoignable le provoque — c'est ainsi qu'il a été découvert. Une coupure de l'observabilité
emportait donc le traitement des enrôlements avec elle.

Corrigé par un index unique dans le schéma canonique, appliqué de façon idempotente au
démarrage. Débloque au passage `test_queue_load_smoke`, rouge jusqu'ici.

---

## 4. Recette

### 4.1 Tests automatisés

| Suite | Résultat |
|---|---|
| Plugin — `./scripts/03-test-local.sh` (unitaires + intégration + lint + build) | **657 tests verts**, lint propre, OXT produit |
| Device Management — `tests/test_telemetry.py`, `test_queue_validation.py`, `test_queue_load.py` | **12 verts** |
| Device Management — suite complète | **aucune régression** : 22 échecs avant / 21 après, tous préexistants sur HEAD propre (admin UI, enrôlement) — dont un **corrigé** par le lot |

Environ 90 tests ajoutés, écrits **avant** le code et vérifiés rouges (37 échecs initiaux
côté plugin, 2 côté DM) avant toute implémentation.

Le test de contrat [`test_telemetry_wire_contract.py`](../tests/integration/test_telemetry_wire_contract.py)
parcourt le trajet complet sans réseau — attributs émis → encodage OTLP de la coquille →
relecture par la logique du serveur — et couvre **chaque étape du vocabulaire fermé**. Il
échoue si l'un des trois maillons cesse de préserver les types. C'est le test qui manquait :
les tests unitaires s'arrêtaient à l'appel de `shell.telemetry`, précisément là où le défaut
3.1 se logeait.

### 4.2 Recette locale bout en bout (DM Docker + Tempo)

Huit spans représentatifs — un par nouveauté — fabriqués par le **vrai encodeur du plugin**
(`otel_attributes`, `generate_trace_id`), postés sur le vrai endpoint du DM local, puis
relus en base :

```
POST /telemetry/v1/traces × 8      → 202 Accepted
file telemetry.forward             → 8 done, 0 pending
device_telemetry_events            → 8 lignes
Tempo (service mirai-libreoffice)  → 8 traces
✓ tous les spans persistés avec leurs types intacts
```

Chaque attribut émis non textuel revient non textuel, à la même valeur — vérifié
individuellement par appariement sur un marqueur d'identité, l'ordre de traitement de la
file n'étant pas garanti. Exemples relus en base :

```json
AssistantRun          {"assistant.ok": false, "assistant.cancelled": false,
                       "assistant.duration_ms": 8421, "append.mode": true}
AssistantToolCall     {"tool.ok": false, "tool.duration_ms": 42, "tool.args_coerced": 2}
AssistantStep/closed  {"runs.count": 4, "tabs.switches": 7, "session.duration_ms": 754321}
AssistantOpen         {"selection.active": true, "caps.measured": false}
```

**Configuration locale ajustée** (fichiers non versionnés, `deploy/docker/.env.secrets`) :
`DM_TELEMETRY_TOKEN_SIGNING_KEY` était vide et écrasait la valeur de `.env` — le mint de
jeton répondait 503 ; `DM_TELEMETRY_UPSTREAM_ENDPOINT` pointait un collecteur inexistant.
Sauvegarde dans `.env.secrets.bak-e2e`. La pile d'observabilité locale (Tempo + Grafana) a
été démarrée : `docker compose -p mirai-obs -f deploy/docker/local-rcfg/docker-compose.observability.yml up -d`.

### 4.3 Intégration Scaleway — **vérifiée verte**

> **Résultat final (2026-07-28)** : les cinq déploiements sont sur
> `0.9.15-telemetry1` et la recette passe — `✓ tous les spans persistés avec leurs
> types intacts`. Le détail ci-dessous retrace le chemin, car la première bascule
> avait échoué pour une raison qui resservira.

```
POST /telemetry/v1/traces × 8   → 200 (telemetry-relay persiste en synchrone)
device_telemetry_events         → 8 lignes, types intacts
file / lettres mortes           → 0 en attente, 0 lettre morte
index unique lettre morte       → idx_queue_job_dead_letters_job_id présent
```

Relu en base d'intégration :

```json
AssistantRun          {"assistant.ok": false, "assistant.cancelled": false,
                       "assistant.duration_ms": 8421, "append.mode": true}
AssistantToolCall     {"tool.ok": false, "tool.duration_ms": 42, "tool.args_coerced": 2}
AssistantStep/closed  {"runs.count": 4, "tabs.switches": 7, "session.duration_ms": 754321}
AssistantOpen         {"selection.active": true, "caps.measured": false}
```

À comparer à l'état d'avant bascule de `telemetry-relay`, où **tous** ces attributs
valaient `""`.

#### Le chemin — bascule d'abord incomplète

Image construite et poussée : `docker.io/etiquet/device-management:0.9.15-telemetry1`
(linux/amd64, digest `sha256:89d6997a…`). Le tag `latest` n'a délibérément **pas** été
écrasé. Périmètre vérifié : l'intégration exécutait déjà le contenu de
`fix/campaign-plugin-filter`, la bascule se limite donc aux deux commits de télémétrie.

`deploy/device-management` a été basculé le 2026-07-28 — **et le retest a échoué** : les
huit spans arrivent bien en base, mais **tous les attributs typés y sont vides**, exactement
le comportement d'avant correctif.

#### La topologie d'intégration n'est pas celle du Docker local

C'est la leçon de cette recette. En local, un seul conteneur fait tout. En intégration,
**cinq déploiements partagent la même image**, et l'ingress répartit les chemins :

| Chemin | Service | Rôle |
|---|---|---|
| `/telemetry/v1` | **`telemetry-relay`** | ingère les traces **et les persiste en synchrone** (réponse 200, pas 202 : la file n'est pas utilisée pour la télémétrie en intégration) |
| `/` | `device-management` | API |
| `/admin` | `device-management-admin` | vue « activité appareil » |
| `/llm` | `llm-proxy` | proxy LLM |
| — | **`queue-worker`** (×2) | boucle de traitement de la file — c'est **elle** que le défaut de lettre morte tue |

Basculer `deploy/device-management` ne touche donc **ni** le service qui persiste la
télémétrie, **ni** celui qui exécute la boucle de file. Les deux correctifs de cette
livraison visent précisément ces deux déploiements-là.

#### Commandes restantes

```bash
IMAGE=docker.io/etiquet/device-management:0.9.15-telemetry1

# indispensable : c'est lui qui persiste la télémétrie
kubectl -n bootstrap set image deploy/telemetry-relay telemetry-relay=$IMAGE
# indispensable : c'est sa boucle que la lettre morte tuait
kubectl -n bootstrap set image deploy/queue-worker queue-worker=$IMAGE
# cohérence de version (aucun changement de comportement attendu)
kubectl -n bootstrap set image deploy/device-management-admin device-management-admin=$IMAGE
kubectl -n bootstrap set image deploy/llm-proxy llm-proxy=$IMAGE

for d in telemetry-relay queue-worker device-management-admin llm-proxy; do
  kubectl -n bootstrap rollout status deploy/$d --timeout=180s
done

# retour arrière : kubectl -n bootstrap rollout undo deploy/<nom>   (→ 0.9.15-ui1)
```

> Le nom du conteneur est repris du nom du déploiement ; vérifier au besoin avec
> `kubectl -n bootstrap get deploy <nom> -o jsonpath='{.spec.template.spec.containers[*].name}'`.

#### Retest

```bash
DM_URL=https://bootstrap.fake-domain.name DM_PROFILE=int DM_NAMESPACE=bootstrap \
  python3 <scratchpad>/e2e_telemetry.py
```

Attendu : `✓ tous les spans persistés avec leurs types intacts`. Contrôle direct :

```sql
SELECT span_name, attributes FROM device_telemetry_events
 ORDER BY id DESC LIMIT 8;
```

Les valeurs numériques et booléennes doivent apparaître **sans guillemets**. État constaté
avant la bascule de `telemetry-relay` — le défaut que corrige cette livraison :

```json
{"e2e.case": "", "caps.agentic": "", "caps.measured": "", "selection.active": "",
 "assistant.app": "writer", "plugin.action": "assistant.open"}
```

L'index unique de lettre morte, lui, était **déjà appliqué** en base dès la première
bascule : le schéma est réappliqué au démarrage, et seul le pod porteur du DSN
administrateur y parvient. Il ne protège toutefois `queue-worker` qu'une fois ce
déploiement basculé, puisque c'est son code qui exécute la boucle — ce qui est
désormais le cas.

#### Une erreur de démarrage, préexistante et sans lien

`telemetry-relay` journalise au démarrage `Failed to apply DB schema` →
`must be owner of table feature_flags`. Le partage des privilèges veut que seul le pod
porteur du DSN administrateur (`postgres`, propriétaire des tables) applique le schéma ;
les autres échouent au premier ordre exigeant la propriété. C'est structurel et antérieur
à cette livraison : l'ordre en cause est à la ligne 361 de `db/schema.sql`, non modifié
ici, alors que l'index ajouté est à la ligne 102 — il est donc atteint *avant*, et il est
bien créé. Sans effet sur le service, mais mériterait d'être traité pour ne pas polluer
les journaux.

---

## 5. Points ouverts

1. **Intégration : fait et vérifié vert** (§ 4.3). Reste, au démarrage de `telemetry-relay`,
   un `Failed to apply DB schema` (`must be owner of table feature_flags`) préexistant et
   sans effet sur le service — à traiter pour ne pas polluer les journaux.
2. **Filtre d'identité inchangé** — tant que l'identité télémétrie n'est pas « user », seuls
   les événements techniques sortent. Les spans `Assistant*` restent donc invisibles sur un
   poste non lié à un utilisateur : décision conservée telle quelle. Les deux nouveaux spans
   de coquille (`ConfigWaitAtTrigger`, `ActionUnhandled`) ont été ajoutés à la liste
   technique — ils décrivent le poste, pas la personne, et sont justement ceux dont on a
   besoin quand rien ne fonctionne encore.
3. **Recette en LibreOffice réel non faite** — elle demande une session interactive. Les
   chemins sont couverts par les tests, mais un passage manuel (un run par branche, une
   annulation, un refus, fermeture de palette) confirmerait les valeurs affichées dans
   `~/log.txt` avec `telemetrylogJson=true`.
4. **`writer_replace_paragraphs` ne déclare pas `mutates=True`** alors qu'il écrit — il
   n'ouvre donc pas le contexte d'annulation par le registre, et manque à la table des
   libellés du journal. Constaté au passage, **non corrigé** : hors périmètre.
5. **Les suggestions ne sont pas cliquables** — `core/suggestions.py` déclare pourtant
   `preset_id` et `runs_immediately`. Le compteur de consultations est en place ; le clic
   reste à implémenter.
