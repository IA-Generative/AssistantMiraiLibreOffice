# Comparaison des modèles Scaleway — Writer menus

**Date d'exécution :** 2026-03-15 22:47:55 UTC

Scénarios testés :
- **ExtendSelection** — continuation d'un paragraphe administratif
- **SummarizeSelection** — résumé d'un extrait de rapport annuel
- **SimplifySelection** — reformulation d'un texte réglementaire complexe

Statuts : ✅ OK | ⚠️ TRUNCATED | 🔄 QUESTION | 🛑 STOP | ❌ ERROR

## Tableau récapitulatif

| Modèle | ExtendSelection | SummarizeSelection | SimplifySelection | Temps moy. |
| --- | --- | --- | --- | --- |
| `gpt-oss-120b` | ✅ OK | ✅ OK | ✅ OK | 2.3s |

---

## Résultats détaillés

### `gpt-oss-120b`

#### ExtendSelection — ✅ OK — 2.60s

**finish_reason :** `stop`  
**Longueur :** 2150 caractères

**Réponse :**

```
Le déploiement à plus grande échelle a donc été planifié en trois phases. La première consiste à étendre l’utilisation de l’IA aux services de traitement des demandes de titres d’identité, où les agents peuvent s’appuyer sur des algorithmes de classification pour trier automatiquement les dossiers selon leur degré de priorité et détecter les éventuelles incohérences de formulaire. La deuxième phase cible la centralisation des flux d’information entre les directions territoriales et le siège, en exploitant des chatbots capables de répondre aux questions récurrentes des usagers et de générer des
… [tronqué — 2150 caractères au total]
```

#### SummarizeSelection — ✅ OK — 2.68s

**finish_reason :** `stop`  
**Longueur :** 270 caractères

**Réponse :**

```
Rapport 2024 ministère de l'Intérieur : DSIC a déployé l'IA MIrAI (500+ agents), refondu l’intranet, créé un cloud souverain; incidents cyber -25 % vs 2023. 2025 : extension MIrAI à tous services déconcentrés, nouveaux cas d’usage documents réglementaires, +2 M€ budget.
```

#### SimplifySelection — ✅ OK — 1.59s

**finish_reason :** `stop`  
**Longueur :** 496 caractères

**Réponse :**

```
Le décret du 15 novembre 2023 impose aux services qui traitent les dossiers de les scanner.  
Tous les dossiers de leur compétence doivent être numérisés dans les six mois qui suivent l’entrée en vigueur du décret.  
Cette règle vaut même si des textes plus anciens prévoient autre chose.  
Elle ne remet pas en cause les règles qui concernent la conservation des archives publiques.  
Par exemple, le service des permis doit transformer chaque dossier papier en fichier numérique d’ici six mois.
```

---
*Généré par `tests/sim_scaleway_models.py`*