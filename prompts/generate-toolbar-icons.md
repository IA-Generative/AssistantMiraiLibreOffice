# Prompt — Génération des icônes de barre d'outils MIrAI

> Utilise ce prompt avec DALL-E, Midjourney, ou un générateur d'images.
> Génère chaque icône séparément, puis redimensionne en 16x16 et 26x26 px.

---

## Description de la mascotte de référence

La mascotte MIrAI est un **personnage sphérique bleu** (bleu France #000091 / bleu clair #6B7FD7) avec :
- Un corps rond comme une boule
- Des **lunettes** rondes
- De petits **bras** bleu foncé
- Un sourire discret
- Un style **flat design** / illustration vectorielle
- Fond transparent

Voir l'image de référence : `oxt/assets/logo.png` et `oxt/icons/icon128.png`

---

## Icônes à générer (9 icônes)

Chaque icône doit :
- Être sur **fond transparent**
- Style **flat design minimaliste**, trait épais, lisible en 16x16 px
- Reprendre la **silhouette simplifiée** de la mascotte (boule bleue avec lunettes) en micro-version
- L'action est symbolisée par un **petit attribut** sur ou à côté de la mascotte
- Palette : bleu France (#000091), bleu clair (#6B7FD7), blanc, rouge France (#CE0500) pour les accents

### 1. `toolbar-mirai.png` — Logo MIrAI (bouton identité)
La mascotte seule, vue de face, simplifiée au maximum. Juste la boule bleue avec les lunettes. Pas d'accessoire.

### 2. `toolbar-extend.png` — Générer la suite (Writer)
La mascotte avec un **crayon** qui écrit vers la droite, ou une flèche pointant vers la droite (→) symbolisant la continuation de texte.

### 3. `toolbar-edit.png` — Modifier la sélection (Writer)
La mascotte avec un **stylo d'édition** ou un symbole de modification (petit crayon avec des lignes).

### 4. `toolbar-resize.png` — Ajuster la longueur (Writer)
La mascotte avec des **flèches horizontales** ← → (expansion/contraction), ou un symbole ± (plus/moins).

### 5. `toolbar-summarize.png` — Résumer (Writer)
La mascotte avec un **document compressé** : plusieurs lignes qui se réduisent à une seule, ou un symbole de compression (lignes → point).

### 6. `toolbar-simplify.png` — Reformuler (Writer)
La mascotte avec une **bulle de dialogue** ou des guillemets, symbolisant la réécriture.

### 7. `toolbar-transform.png` — Transformer colonne (Calc)
La mascotte avec un **tableau** et une flèche vers la droite (→ colonne), ou un symbole de grille avec transformation.

### 8. `toolbar-formula.png` — Générer une formule (Calc)
La mascotte avec le symbole **Σ** (sigma) ou **f(x)** à côté.

### 9. `toolbar-analyze.png` — Analyser la plage (Calc)
La mascotte avec un **graphique** simplifié (barres ou courbe) ou une loupe.

---

## Contraintes techniques

- **Résolution de sortie** : 256x256 px minimum (sera redimensionné ensuite)
- **Fond** : transparent (PNG)
- **Style** : flat design, pas de dégradés complexes, pas d'ombres portées
- **Lisibilité** : l'icône doit être reconnaissable à 16x16 px — donc formes simples et contrastées
- **Cohérence** : toutes les icônes doivent avoir le même style et les mêmes proportions de mascotte

## Prompt DALL-E (à copier)

Pour chaque icône, utilise ce prompt de base en remplaçant `[ACTION]` :

```
A tiny flat-design toolbar icon of a round blue mascot character (sphere with round glasses, simple arms, friendly face) [ACTION]. Minimalist vector style, bold outlines, transparent background, blue (#000091 and #6B7FD7) and white palette, designed to be readable at 16x16 pixels. No text. Square composition.
```

Remplacements `[ACTION]` :

| Icône | [ACTION] |
|-------|----------|
| toolbar-mirai | standing alone, front view, just the character |
| toolbar-extend | holding a pencil writing to the right, with a small arrow → |
| toolbar-edit | holding an editing pen with small text lines |
| toolbar-resize | with horizontal arrows ← → on both sides |
| toolbar-summarize | next to a document being compressed into fewer lines |
| toolbar-simplify | with a speech bubble containing quotation marks |
| toolbar-transform | next to a small table grid with a right arrow |
| toolbar-formula | next to a Σ (sigma) symbol |
| toolbar-analyze | holding a magnifying glass over a small bar chart |

---

## Post-traitement

Après génération, redimensionner chaque icône en deux tailles :
```bash
# Avec ImageMagick :
for img in toolbar-*.png; do
  convert "$img" -resize 16x16 -strip "${img%.png}-16.png"
  convert "$img" -resize 26x26 -strip "${img%.png}-26.png"
done
```

Placer les fichiers 16x16 dans `oxt/icons/` et mettre à jour les `ImageIdentifier` dans `Addons.xcu`.
