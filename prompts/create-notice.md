peux-tu m'aider à créer un prompt pour créer une notice de l'application pour 2 personnaes, le  novice et l'expert  en IA dans un fichier markdown spécifique. proposer un plan et une navigation adaptée à ces Deux personnae. Le plan doit inclure un brief rapide sur ce que peut faire l'utilisateur, la phase éventuelle d'installation et aussi la présentation des fonctionnalités

-----

# Prompt de génération de la notice utilisateur MIrAI

> Utilise ce prompt avec un LLM pour générer le fichier `docs/notice-utilisateur.md`.
> Copie-colle le bloc ci-dessous tel quel.

---

## Prompt

Tu es un rédacteur technique spécialisé dans la documentation logicielle grand public.
Rédige une **notice utilisateur complète** pour l'extension LibreOffice **MIrAI** (assistant IA intégré à Writer et Calc) au format Markdown.

### Contraintes

- Langue : français
- Ton : professionnel, bienveillant, concret
- Deux personas cibles naviguent dans le même document grâce à des repères visuels :
  - 🟢 **Novice** — n'a jamais utilisé d'IA, veut juste savoir quel bouton cliquer
  - 🔵 **Expert** — connaît les LLM, veut comprendre les paramètres, les prompts système, le fonctionnement interne
- Chaque section qui contient du contenu spécifique à un persona doit être marquée avec le badge correspondant. Le contenu commun n'a pas de badge.
- Ne pas inventer de fonctionnalités. Se baser **uniquement** sur la liste fournie ci-dessous.

### Plan imposé

```
# MIrAI — Notice utilisateur

## Sommaire rapide par profil
<!-- Deux colonnes : Novice / Expert, chaque colonne liste les sections pertinentes avec ancres -->

## 1. Ce que MIrAI peut faire pour vous
<!-- 5-6 phrases max, pas de jargon, exemples concrets du quotidien -->
<!-- 🔵 Expert : un paragraphe supplémentaire sur l'architecture (extension OXT, backend OpenAI-compatible, Device Management) -->

## 2. Installation
### 2.1 Prérequis
<!-- LibreOffice 7.x+, accès réseau au backend, Python inclus -->
### 2.2 Installer l'extension
<!-- 🟢 Novice : pas-à-pas avec Outils → Gestionnaire d'extensions → Ajouter -->
<!-- 🔵 Expert : installation CLI via scripts/dev-launch.sh, profils de config -->
### 2.3 Premier lancement
<!-- Wizard d'enrôlement, vérification de la connexion, indicateur de statut -->

## 3. Fonctionnalités Writer
<!-- Pour chaque fonctionnalité : titre, raccourci clavier, ce que ça fait en 1 phrase,
     🟢 mode d'emploi pas-à-pas (sélectionner → menu → résultat),
     🔵 détail technique (prompt système, tokens, retry, délimiteurs) -->
### 3.1 ✨ Générer la suite (⌘Q)
### 3.2 🖊️ Modifier la sélection (⌘E)
#### Boîte de dialogue d'édition
#### Suggestions contextuelles IA
### 3.3 📏 Ajuster la longueur (⌘J)
#### Mini-dialogue − / +
#### Fonctionnement itératif
### 3.4 📝 Résumer la sélection (⌘R)
### 3.5 💬 Reformuler la sélection (⌘L)

## 4. Fonctionnalités Calc
### 4.1 🔄 Transformer → colonne résultat (⌘T)
### 4.2 🧮 Générer une formule (⌘G)
### 4.3 📊 Analyser la plage (⌘K)

## 5. Paramètres et configuration
### 5.1 🟢 Via le menu MIrAI → Paramètres
### 5.2 🔵 Fichiers de configuration et profils
### 5.3 🔵 Proxy et certificats SSL
### 5.4 🔵 Personnaliser les prompts système

## 6. Bonnes pratiques
<!-- 🟢 Conseils simples : sélectionner avant d'agir, Ctrl+Z pour annuler, relire le résultat -->
<!-- 🔵 Conseils avancés : choix du modèle, température, limites de tokens, prompt.txt -->

## 7. Résolution de problèmes
<!-- FAQ : "rien ne se passe", "le texte est en anglais", "le modèle pose une question",
     "erreur de connexion", "token invalide" -->
<!-- 🔵 Expert : logs ~/log.txt, deepseek-r1 think blocks, limitations connues -->

## 8. Raccourcis clavier (aide-mémoire)
<!-- Tableau : Raccourci | Action | Contexte (Writer/Calc) -->
```

### Données de référence (fonctionnalités exactes)

**Writer :**
| Raccourci | Action | Description |
|-----------|--------|-------------|
| ⌘Q | Générer la suite | Insère la continuation naturelle du texte sélectionné |
| ⌘E | Modifier la sélection | Ouvre un dialogue avec champ d'instruction libre + suggestions IA contextuelles |
| ⌘J | Ajuster la longueur | Mini-dialogue flottant avec boutons − (réduire ~35%) et + (développer ~40%), remplace la sélection en place, itératif |
| ⌘R | Résumer la sélection | Génère un résumé concis inséré après la sélection avec délimiteurs |
| ⌘L | Reformuler la sélection | Réécrit en langage clair et accessible, inséré après avec délimiteurs |

**Calc :**
| Raccourci | Action | Description |
|-----------|--------|-------------|
| ⌘T | Transformer → colonne résultat | Applique une instruction sur une plage, résultat dans la colonne adjacente libre |
| ⌘G | Générer une formule | Crée une formule Calc à partir d'une description en langage naturel, avec correction automatique |
| ⌘K | Analyser la plage | Résumé des tendances et anomalies inséré sous la sélection |

**Comportements transversaux :**
- Le texte original n'est jamais supprimé (sauf Ajuster la longueur qui remplace en place, annulable par Ctrl+Z)
- Les balises `<think>` des modèles de raisonnement sont filtrées automatiquement
- Détection et retry si le modèle pose une question au lieu de produire du contenu
- Annulation par Ctrl+Z (groupée en un seul undo)

### Format de sortie

- Un seul fichier Markdown
- Titres avec ancres navigables
- Utiliser des blocs `> 🟢 **Novice**` et `> 🔵 **Expert**` pour les sections spécifiques
- Inclure des exemples concrets (ex. : "Sélectionnez un paragraphe de votre rapport, puis ⌘R pour obtenir un résumé")
- Pas de captures d'écran (le document est textuel)
