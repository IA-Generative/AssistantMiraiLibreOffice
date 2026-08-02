# Relation avec le dépôt upstream (`balisujohn/localwriter`)

> **Verdict : il n'y a rien à récupérer en amont, et aucun merge upstream n'est
> à prévoir.** Ce dépôt n'est plus un dérivé de LocalWriter : c'est un produit
> distinct qui en partage l'ancêtre. Ce document existe pour qu'on ne refasse
> pas l'analyse à chaque fois que la question se repose.

**Mesure effectuée le 2026-08-02.** Les compteurs ci-dessous bougent à chaque
commit ; la conclusion, elle, est stable. La procédure pour re-mesurer est en
fin de document.

## Identité

Ce dépôt (`IA-Generative/AssistantMiraiLibreOffice`) est un **fork GitHub** de
`balisujohn/localwriter` — *« A LibreOffice Writer extension that adds local
inference generative AI features »*. Le lien de fork existe toujours côté
GitHub (`isFork: true`), mais il n'a plus de portée technique.

Le remote `upstream` **n'est plus déclaré** dans les clones : il a été retiré
volontairement — décision tracée dans `prompts/plan-demonstrateur-moteur-mcp.md`,
§ retrait upstream (fichier porté par les branches de travail, pas par `master`).
Seul `origin` subsiste.

| | Ce dépôt | Upstream |
|---|---|---|
| Identifiant d'extension | `fr.gouv.interieur.mirai` | `org.extension.localwriter` |
| Versionnement | `0.0.1.0.22` | `0.0.9` |
| Branche par défaut | `master` | `master` |
| Dernier push amont | — | 2026-02-22 |

## Base commune

Le dernier ancêtre partagé est **`df1641b` — *Adds streaming (#34)*, du
2025-08-31**. Tout ce qui suit, des deux côtés, a divergé.

## Ampleur de la divergence

| Comparaison | Commits amont absents ici | Nos commits absents en amont |
|---|---|---|
| `origin/master` | **3** | **158** |
| `feat/telemetrie-fonctionnelle` | 3 | 220 |
| `exp-jetable/demonstrateur-v2` | 3 | 205 |

`git diff upstream/master origin/master` : **188 fichiers, +27 566 / −2 320**
— dont 171 créations, 12 suppressions, 3 modifications, 2 renommages.

Toute l'arborescence amont à plat (`main.py`, `Addons.xcu`, `build.sh`,
`pythonpath/llm.py`, `test_llm.py`, `prompt_function.py`…) a été supprimée ou
déplacée vers [src/mirai/](../src/mirai/) et [oxt/](../oxt/).

**Trois fichiers seulement sont encore modifiés en place** — `.gitignore`,
`README.md`, et `main.py`, ce dernier réduit à un shim de 14 lignes qui
redirige vers [entrypoint.py](../src/mirai/entrypoint.py).

Les ajouts sans équivalent amont couvrent l'essentiel du produit : enrôlement
et SSO, Device Management, mise à jour automatique, télémétrie,
`security_flow.py`, les profils [config/profiles/](../config/profiles/), et
toute la suite de tests (`tests/unit`, `tests/integration`, simulation de parc).

## Les 3 commits amont que nous n'avons pas

| Commit | Date | Contenu | Pourquoi il est sans objet ici |
|---|---|---|---|
| `d818fa0` | 2026-02-08 | Corrige une URL de clone dans le README (`balis-john` → `balisujohn`) | Notre README est entièrement réécrit (+324 / −134) ; la ligne visée n'existe plus |
| `2efe9ac` | 2026-02-15 | *Add advanced config, streaming, and settings* (PR #36, par `etiquet`) | **Contribution partie d'ici vers l'amont.** Le code correspondant existe déjà chez nous, sous une forme très divergée depuis |
| `c0486bf` | 2026-02-15 | Ajoute `PROMPT()` dans Calc + renomme l'extension en `org.extension.localwriter` | Fonction présente ici sous une forme plus riche (voir ci-dessous) ; le renommage est incompatible avec notre identifiant |

## Le cas `PROMPT()`

C'est le seul recouvrement fonctionnel réel, et il mérite d'être précis.

**Chronologie : l'amont a livré en premier** — `c0486bf` le 2026-02-15, contre
`34b0727` le 2026-03-14 ici, soit un mois plus tard. Les dates n'établissent
donc pas une conception indépendante, et ce document ne l'affirme pas.

En revanche les deux implémentations **diffèrent substantiellement**, au point
qu'aucune reprise de code n'est visible :

| | Ici | Upstream |
|---|---|---|
| Signature | `prompt(message, system_prompt, model, max_tokens)` | `prompt(message)` |
| Namespace | `fr.gouv.interieur.mirai` | `org.extension.localwriter` |
| Catégorie Calc | `Text` | `Add-In` |
| Langues | `en` + `fr` | `en-US` |
| Interface IDL | hérite de `com::sun::star::sheet::XAddIn` | hérite de `com::sun::star::uno::XInterface` |

Fichiers concernés :
[calc_prompt_function.py](../src/mirai/calc_prompt_function.py),
[XPromptFunction.idl](../src/mirai/idl/XPromptFunction.idl),
[CalcAddIn.xcu](../oxt/CalcAddIn.xcu),
[test_calc_prompt_function.py](../tests/unit/test_calc_prompt_function.py).

## Licence

**`balisujohn/localwriter` ne publie aucune licence** — ni fichier
`LICENSE`/`COPYING`, ni licence déclarée dans les métadonnées GitHub (vérifié
via l'API le 2026-08-02, `license: null`).

Les mentions upstream (John Balis / localwriter) ont été retirées du README et
de [license.txt](../oxt/registration/license.txt) — c'est le constat **D-03**
du rapport `docs/QUALIFICATION-master-2026-07-26.md` (porté par les branches de
travail), soldé par `fea611b`. Elles ne subsistent aujourd'hui que dans les
documents historiques et le plan, ce qui est normal : ce sont des archives.

> ⚠️ L'absence de licence amont est un point à garder en tête si du code
> dérivé devait réapparaître. En l'état, la réécriture est telle que la
> question ne se pose pas en pratique — mais elle se reposerait au premier
> `cherry-pick` depuis l'amont. **Ne pas en faire sans arbitrage.**

## Conséquence outillage : `gh` visait le mauvais dépôt

Le lien de fork subsistant, `gh` résolvait les commandes sur
`balisujohn/localwriter`. Symptôme classique : `gh pr create` échouait avec
*« No commits between master and \<branche\> »*, et `gh pr list` remontait les
PR d'un autre projet.

Corrigé le 2026-08-02 :

```bash
gh repo set-default IA-Generative/AssistantMiraiLibreOffice
```

Cela écrit `remote.origin.gh-resolved = base` dans `.git/config`. Le passage
systématique de `--repo IA-Generative/AssistantMiraiLibreOffice` n'est donc
plus nécessaire.

> **Cette correction est locale au clone.** Un nouveau clone repart sans elle
> et le symptôme revient — rejouer la commande ci-dessus.

## Re-mesurer le delta

Sans déclarer de remote permanent, ni toucher à la configuration :

```bash
# Récupérer l'amont dans une ref temporaire
git fetch https://github.com/balisujohn/localwriter.git \
    master:refs/tmp/upstream-master --force

# Base commune
git merge-base refs/tmp/upstream-master origin/master

# Compteurs (gauche = amont seul | droite = nous seuls)
git rev-list --left-right --count refs/tmp/upstream-master...origin/master

# Ce que l'amont a et que nous n'avons pas
git log --oneline origin/master..refs/tmp/upstream-master

# Nettoyage
git update-ref -d refs/tmp/upstream-master
```
