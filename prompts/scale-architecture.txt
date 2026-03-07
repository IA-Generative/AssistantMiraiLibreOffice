Tu es un ingénieur senior backend/SRE. Tu dois implémenter et déployer une nouvelle architecture “Postgres Queue” dans ce repository.

Repo cible:
- /Users/etiquet/Documents/GitHub/device-management

Contexte:
- Stack actuelle self-hosted: FastAPI + Postgres + relay-assistant (+ déploiements docker-compose et k8s déjà présents).
- Objectif: ajouter une file de traitement robuste basée sur Postgres (pas NATS/Kafka/Rabbit/Redis), avec reprise sur incident réseau, retries, idempotence et observabilité.
- Contraintes: rester compatible avec l’existant, limiter les changements destructifs, maintenir les endpoints existants.

Pré-requis Git (obligatoire avant toute modification):
- Créer un commit temporaire de sauvegarde de l’état courant pour rollback rapide.
- Commandes attendues:
  1) `git add -A`
  2) `git commit -m "chore: snapshot before postgres-queue architecture changes"`
- Afficher le SHA du commit créé.
- Si aucun changement local à commit, créer un tag temporaire sur HEAD:
  - `git tag pre-postgres-queue-snapshot-<timestamp>`
- Documenter la commande de rollback:
  - vers le commit snapshot: `git reset --hard <SHA>`
  - ou vers le tag: `git reset --hard pre-postgres-queue-snapshot-<timestamp>`

Exigences d’architecture distribuée (obligatoires):
- Le système doit être horizontalement scalable (API + workers) sans SPOF.
- Le déploiement cible doit fonctionner en grappe redondée sur plusieurs Availability Zones (multi-AZ).
- Concevoir pour tolérance aux pannes AZ: perte d’un nœud/AZ sans interruption majeure.
- Prévoir un mécanisme de synchronisation des données rapide entre clusters (multi-cluster), avec objectifs explicites:
  - RPO cible (ex: <= 30s)
  - RTO cible (ex: <= 5 min)
- Documenter et implémenter la stratégie recommandée de réplication/synchronisation:
  - base principale + réplicas,
  - réplication logique/streaming selon besoin,
  - résolution de conflits (si actif-actif envisagé),
  - ordre des événements, idempotence, anti-rejeu.
- Définir un plan de bascule/failover inter-cluster:
  - détection,
  - promotion,
  - reroutage trafic,
  - reprise.
- Ajouter des tests de résilience distribuée:
  - coupure AZ simulée,
  - perte de nœud worker/API,
  - latence réseau inter-cluster,
  - vérification de cohérence après reprise.
- Fournir des métriques/SLO de réplication:
  - lag de réplication,
  - âge max d’un événement non propagé,
  - taux d’échec de synchro,
  - temps moyen de convergence inter-cluster.

Leçons apprises (obligatoires à appliquer):
- Sécurité fail-closed pour les endpoints ops:
  - les endpoints `/ops/queue/*` ne doivent jamais être ouverts par défaut.
  - si le token admin (`DM_QUEUE_ADMIN_TOKEN`) est absent, répondre explicitement en erreur (pas de bypass implicite).
- Health checks sans faux négatifs:
  - `healthz` doit tester uniquement les dépendances réellement requises par la config active.
  - ex: ne pas échouer sur S3 si S3 n’est pas activé/nécessaire.
- Observabilité standardisée:
  - exposer `/metrics` (format Prometheus) avec au minimum:
    - disponibilité scrape,
    - état queue (`pending`, `processing`, `dead`, `oldest_pending_age_seconds`, `stale_processing`),
    - indicateur de mode runtime (api/worker/all).
  - livrer un pack Grafana minimum (obligatoire):
    - 1 dashboard "API/Ingress",
    - 1 dashboard "Queue/Workers",
    - 1 dashboard "Capacity/HPA",
    - panels + requêtes PromQL documentés.
  - inclure explicitement les métriques/panels suivants:
    - `dm_metrics_scrape_success`, `dm_queue_available`,
    - `dm_queue_pending_jobs`, `dm_queue_processing_jobs`, `dm_queue_dead_jobs`,
    - `dm_queue_oldest_pending_age_seconds`, `dm_queue_stale_processing_jobs`,
    - taux d’erreurs ingress `/enroll` (5xx) et latence p95,
    - replicas HPA courants/désirés pour `device-management` et `queue-worker`.
- Autoscaling Kubernetes:
  - créer des HPA pour API et workers (min/max + politique scale up/down).
  - vérifier après déploiement que HPA est actif et que les métriques ne sont pas `unknown`.
- Worker réellement horizontalisable:
  - éviter les volumes RWO partagés entre replicas workers (risque `Multi-Attach`).
  - si persistance nécessaire: utiliser RWX/object storage; sinon rendre worker stateless.
  - si contrainte forte RWO temporaire: documenter limitation et stratégie de rollout dédiée.
- Validation charge live renforcée:
  - inclure un tir de 5000 enrollments (concurrency 100) avec:
    - `success_201`, `error_rate`, `status_breakdown`, `p50/p95/p99/max`, `throughput`.
  - faire un contrôle backlog queue juste après test puis à +30s pour mesurer la résorption.
- Analyse des erreurs 5xx:
  - corréler erreurs client (`502/504`) avec logs ingress + événements pods (restarts/probes).
  - fournir cause racine probable et correctif appliqué.
- Validation Docker:
  - tester le mode scale local (`docker compose up -d --scale queue-worker=<n>`).
  - vérifier `/healthz`, `/metrics`, et signaler explicitement les limites d’environnement (ex: disque plein).

Travail attendu (obligatoire):
1) Implémenter la queue Postgres
- Ajouter schéma SQL (idempotent) pour:
  - jobs (id, topic, payload JSONB, status, attempts, max_attempts, next_attempt_at, locked_at, lock_owner, dedupe_key, created_at, updated_at, last_error)
  - job_dead_letters (historique des échecs définitifs)
- Utiliser une stratégie de consommation sûre:
  - SELECT ... FOR UPDATE SKIP LOCKED
  - verrouillage avec TTL de lock
  - retries avec backoff exponentiel + jitter
  - passage en dead-letter après max_attempts
- Ajouter idempotence via dedupe_key unique par topic.
- Garantir transactions cohérentes (claim + update statut).

2) Intégrer worker(s) applicatifs
- Créer un worker exécutable dans le même codebase (même image, mode process séparé).
- Prévoir le mode “API only” et “worker only” via variables d’environnement.
- Ajouter gestion propre des signaux (shutdown gracieux).

3) Exposer des métriques/health utiles
- Endpoint(s) de santé queue (profondeur, oldest age, dead letters).
- Logs structurés (topic, job_id, attempts, latence).
- Ajouter alertes minimales documentées (seuil backlog, taux d’échec).
- Ajouter un jeu de dashboards Grafana prêt à l’emploi:
  - JSON(s) versionnés (ou provisioning files),
  - variables d’environnement/namespace,
  - panels liés aux métriques techniques et SLO,
  - un set d’alertes minimum:
    - backlog élevé,
    - âge pending élevé,
    - stale jobs > 0,
    - dead letters > 0,
    - scrape metrics en échec,
    - ratio 5xx enroll trop élevé.

4) Déploiement
- Mettre à jour:
  - infra-minimal/docker-compose.yml
  - deploy-dgx/docker-compose.yml
  - manifests k8s (base + overlays si nécessaire)
- Ajouter le worker comme service/deployment séparé.
- Mettre à jour variables d’environnement nécessaires dans exemples (.env.example etc.).

5) Tests obligatoires (créer ET exécuter)
- Validation fonctionnelle:
  - tests unitaires + intégration (enqueue, claim, ack, retry, dead-letter, dedupe).
- Montée de charge:
  - script de charge (k6 ou Locust ou pytest benchmark) simulant pics réalistes.
  - mesurer débit, latence, taux d’échec, backlog, temps de résorption.
- Sécurité:
  - tests d’injection payload SQL/JSON,
  - tests anti-rejeu/idempotence,
  - tests d’accès non autorisé aux endpoints queue/ops,
  - tests de robustesse face payloads volumineux/malfomés.
- Résilience distribuée:
  - tests de coupure AZ simulée, perte de nœud, latence réseau inter-cluster, cohérence post-reprise.
- Exécuter tous les tests localement et fournir les commandes exactes + résultats.

6) Correction des bogues
- Corriger tous les bugs détectés par les tests jusqu’à obtenir un état stable.
- Si un bug ne peut pas être corrigé immédiatement, documenter précisément la cause, l’impact, le contournement temporaire, et ouvrir un TODO traçable.

7) Rapport final obligatoire (Markdown)
- Résumé exécutif (ce qui a changé, pourquoi).
- SHA/tag du snapshot Git initial + procédure de rollback.
- Liste exacte des fichiers modifiés.
- Schéma d’architecture avant/après.
- Topologie multi-AZ/multi-cluster.
- Résultats de tests:
  - validation
  - charge (tableau métriques + interprétation)
  - sécurité
  - failover/synchronisation
- Observabilité:
  - liste des dashboards Grafana créés,
  - liste des alertes et seuils,
  - requêtes PromQL utilisées pour chaque panel critique.
- Bugs trouvés/corrigés (avec gravité).
- Risques résiduels et plan de mitigation.
- Runbook de déploiement/rollback.
- SLO/SLA cibles et observabilité associée.
- Commandes pour reproduire intégralement.

Contraintes de qualité:
- Pas de pseudo-implémentation: code exécutable uniquement.
- Pas de régression sur endpoints existants.
- Respecter style et conventions du repo.
- Ajouter commentaires uniquement là où la logique est non triviale.
- Fournir diffs clairs et atomiques.

Commence maintenant par:
1) créer le snapshot Git de sécurité,
2) analyser le repo et proposer un plan d’exécution concret,
3) implémenter,
4) tester,
5) corriger,
6) livrer le rapport final.
