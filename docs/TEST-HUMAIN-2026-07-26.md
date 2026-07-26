# Recette utilisateur — assistant MIrAI pour LibreOffice

**Version testée : 0.0.1.0.29** · Document du 2026-07-26

Ce document sert à **vérifier que l'assistant fonctionne**, en le faisant marcher comme un
utilisateur normal. Aucune compétence technique n'est nécessaire : chaque scénario dit quoi
faire, ce que vous devez voir, et vous cochez.

Comptez environ **45 minutes**. Faites les scénarios dans l'ordre : certains préparent les
suivants.

> **Une seule chose à retenir avant de commencer** : si un scénario ne se passe pas comme
> décrit, ce n'est pas grave — c'est justement ce qu'on cherche. Notez ce que vous avez vu,
> passez au suivant. La dernière section explique quoi rapporter.

---

## Avant de commencer

### Ce qu'il vous faut

- LibreOffice installé (version 25.8 ou plus récente).
- L'extension `mirai.oxt` fournie.
- Une connexion au service MIrAI (votre identifiant habituel).

### Installer l'extension

1. **Fermez complètement LibreOffice** (tous les documents).
2. Double-cliquez sur le fichier `mirai.oxt`. LibreOffice s'ouvre et propose l'installation.
3. Acceptez. Un message confirme que l'extension est installée.
4. **Fermez LibreOffice, puis rouvrez-le.** Cette seconde ouverture est nécessaire :
   l'extension ne devient active qu'au lancement suivant.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### Comment ouvrir l'assistant

Trois moyens, tous équivalents :

- le raccourci **Ctrl+Alt+Espace** (sur Mac : **Ctrl+Option+Espace**) ;
- le menu **🤖 MIrAI** en haut de la fenêtre ;
- le **clic droit** sur du texte sélectionné, dans Writer.

> Les anciens raccourcis par fonction (Ctrl+E, Ctrl+R, Ctrl+J…) ont été **supprimés
> volontairement** : ils empêchaient des commandes de LibreOffice de fonctionner. Si vous
> aviez l'habitude de les utiliser, c'est normal qu'ils ne fassent plus rien de spécial.

---

## 1 — Premier démarrage et connexion

### 1.1 L'assistant demande à vous connecter

**Faites :** ouvrez LibreOffice Writer, créez un document vide, appuyez sur
**Ctrl+Alt+Espace**.

**Vous devez voir :** une fenêtre de connexion s'ouvre et vous invite à vous authentifier.
Votre navigateur s'ouvre sur la page de connexion MIrAI.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 1.2 La connexion aboutit

**Faites :** connectez-vous dans le navigateur, puis **revenez dans LibreOffice**.

**Vous devez voir :** l'écran indique que la connexion a réussi, et la fenêtre de l'assistant
s'ouvre.

> Si le navigateur affiche « Callback invalide » ou si rien ne se passe côté LibreOffice au
> bout de 3 minutes : fermez tous les onglets de connexion MIrAI et recommencez avec **un
> seul** onglet.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 2 — La fenêtre de l'assistant

### 2.1 Elle s'ouvre et affiche ce sur quoi elle va travailler

**Faites :** dans un document Writer contenant du texte, cliquez dans un paragraphe (sans
rien sélectionner), puis **Ctrl+Alt+Espace**.

**Vous devez voir :** une fenêtre flottante avec, de haut en bas — une rangée de boutons
d'action, une ligne indiquant **« Paragraphe courant : « … » »** avec le début de votre
paragraphe, un champ de saisie, et une zone de réponse.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 2.2 Les boutons d'action tiennent sur une seule ligne

**Faites :** regardez la rangée de boutons en haut de la fenêtre.

**Vous devez voir :** tous les boutons sur **une seule ligne**, aucun texte coupé, aucun
bouton qui déborde ou passe à la ligne suivante.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 2.3 L'indicateur suit votre sélection

**Faites :** sans fermer la fenêtre de l'assistant, sélectionnez une phrase dans votre
document. Puis déplacez le curseur dans un autre paragraphe.

**Vous devez voir :** la ligne d'indication change à chaque fois — **« Sélection : « … » »**
quand du texte est sélectionné, **« Paragraphe courant : « … » »** sinon.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 2.4 La fenêtre se ferme proprement

**Faites :** appuyez sur **Échap**, ou fermez la fenêtre.

**Vous devez voir :** la fenêtre disparaît. Votre document est intact. Aucun message d'erreur.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 3 — Les actions dans Writer

Pour chacune : ouvrez `sample.odt` (ou un document à vous), **sélectionnez un paragraphe
entier**, ouvrez l'assistant, cliquez sur le bouton indiqué.

### 3.1 Résumer

**Vous devez voir :** un résumé apparaît **dans le document**, juste après votre sélection,
encadré par des repères `---début-du-texte-généré---` et `---fin-du-texte-généré---`. Le
texte arrive progressivement, mot après mot.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 3.2 Une seule annulation suffit

**Faites :** juste après le scénario 3.1, appuyez **une seule fois** sur **Ctrl+Z**.

**Vous devez voir :** tout le texte ajouté disparaît d'un coup — repères compris. Pas besoin
d'appuyer dix fois.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 3.3 Simplifier · 3.4 Raccourcir · 3.5 Allonger

**Faites :** même méthode pour chacun de ces boutons, sur une sélection.

**Vous devez voir :** un résultat cohérent avec l'intitulé du bouton. « Raccourcir » et
« Allonger » **remplacent** votre sélection ; « Simplifier » **ajoute** du texte après elle.

| Bouton | Conforme | Non conforme | Observations |
|---|---|---|---|
| Simplifier | ☐ | ☐ | |
| Raccourcir | ☐ | ☐ | |
| Allonger | ☐ | ☐ | |

> Il n'y a que quatre boutons : « Continuer » et « Modifier » ont été retirés
> volontairement — le champ de saisie libre les remplace avantageusement
> (scénario 3.8).

### 3.6 Sans rien sélectionner

**Faites :** cliquez simplement dans un paragraphe (sans sélectionner), ouvrez l'assistant,
cliquez sur **Résumer**.

**Vous devez voir :** l'action porte sur **le paragraphe où se trouve le curseur** — c'est le
comportement attendu, pas un défaut.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 3.7 Une demande libre

**Faites :** sélectionnez un paragraphe, ouvrez l'assistant, tapez dans le champ de saisie :
`Réécris ce passage sur un ton plus formel`, puis **Entrée**.

**Vous devez voir :** la demande est prise en compte et le résultat correspond.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 3.8 Une demande qui porte sur tout le document

**Faites :** ouvrez un document de plusieurs paragraphes. **Ne sélectionnez rien.**
Ouvrez l'assistant et tapez : `Restructure ce document en deux paragraphes`, puis
**Entrée**.

**Vous devez voir :** le **document lui-même** est réorganisé en deux paragraphes.
L'assistant doit AGIR, pas se contenter de vous décrire ce qu'il ferait. Un seul
**Ctrl+Z** annule l'ensemble.

> C'est le scénario qui a révélé un défaut : l'assistant répondait un texte
> expliquant la restructuration en laissant le document intact. Si vous revoyez
> ce comportement, notez-le — c'est important.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 4 — Le menu du clic droit

### 4.1 Sur un document ouvert depuis un fichier

**Faites :** ouvrez un document `.odt` enregistré sur votre disque. Sélectionnez une phrase.
**Clic droit** dessus.

**Vous devez voir :** un sous-menu **MIrAI** dans le menu contextuel, avec *Résumer la
sélection*, *Reformuler*, *Corriger*, *Traduire*.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 4.2 Sur un document tout neuf

**Faites :** créez un **nouveau** document Writer, tapez deux phrases, sélectionnez-les,
**clic droit**.

**Vous devez voir :** le même sous-menu MIrAI. *(Ce cas est testé séparément parce qu'il
emprunte un chemin technique différent.)*

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 4.3 Une entrée du menu fonctionne

**Faites :** cliquez sur **Corriger**.

**Vous devez voir :** la correction s'applique **directement**, sans que la fenêtre de
l'assistant s'ouvre.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 4.4 L'ouverture des documents reste rapide

**Faites :** fermez tout, puis ouvrez un document d'une dizaine de pages. Comptez
mentalement.

**Vous devez voir :** une ouverture aussi rapide qu'avant l'installation de l'extension. Si
vous percevez un ralentissement net (plus d'une seconde), c'est à signaler.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 5 — Les actions dans Calc

**Préparez :** un classeur avec une colonne de dix noms de villes en A1:A10, et une colonne
de nombres en B1:B10.

### 5.1 L'indicateur affiche la plage

**Faites :** sélectionnez A1:A10, ouvrez l'assistant.

**Vous devez voir :** **« 10 cellules sélectionnées (A1:A10) »**.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 5.2 Transformer

**Faites :** sélection A1:A10, bouton **Transformer**, demande : `Mets en majuscules`.

**Vous devez voir :** les résultats dans une **nouvelle colonne** à côté. Vos données
d'origine ne sont **pas** modifiées.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 5.3 Formule

**Faites :** cliquez sur une cellule vide, bouton **Formule**, demande :
`la moyenne des nombres de la colonne B`.

**Vous devez voir :** une formule est écrite dans la cellule et affiche un résultat — pas un
message d'erreur type `#NOM?` ou `Err:`.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 5.4 Analyser

**Faites :** sélectionnez B1:B10, bouton **Analyser**.

**Vous devez voir :** un commentaire sur vos chiffres, inséré sous la plage.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 6 — Pendant que l'assistant travaille

Ces trois scénarios vérifient le changement le plus important de cette version.

### 6.1 LibreOffice reste utilisable

**Faites :** lancez une demande longue (par exemple : sélectionnez une page entière et
cliquez sur **Allonger**). **Pendant que le texte arrive**, tapez dans votre document, faites
défiler la page, changez d'onglet.

**Vous devez voir :** LibreOffice répond **normalement**, sans à-coup, pendant que le texte
continue d'arriver. C'est le point le plus important de cette recette : dans les versions
précédentes, l'application se figeait.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6.2 On peut arrêter

**Faites :** relancez une demande longue. Pendant la génération, cliquez sur le bouton
**Arrêter**.

**Vous devez voir :** la génération s'interrompt, le statut l'indique, et **plus aucun texte
ne s'ajoute** ensuite.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6.3 Fermer pendant le travail ne casse rien

**Faites :** relancez une demande longue, et fermez la fenêtre de l'assistant pendant qu'elle
travaille.

**Vous devez voir :** la fenêtre se ferme, LibreOffice continue de fonctionner normalement.
Aucun plantage, aucun message d'erreur.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 6bis — La zone du bas et la taille de la fenêtre

### 6bis.1 Les trois onglets

**Faites :** en bas de la fenêtre, cliquez successivement sur **Historique**,
**Suggestions**, puis **Actions**.

**Vous devez voir :** le contenu change **dans le même cadre** — la fenêtre ne
s'agrandit pas. L'onglet actif est écrit en bleu. *Historique* montre vos échanges,
*Suggestions* des propositions adaptées à ce qui est sélectionné, *Actions* le détail
de ce que l'assistant a fait.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6bis.2 L'onglet actif est mémorisé

**Faites :** placez-vous sur **Suggestions**, fermez la fenêtre, rouvrez-la.

**Vous devez voir :** l'onglet **Suggestions** est toujours actif.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6bis.3 Les suggestions s'adaptent

**Faites :** allez sur l'onglet **Suggestions**. Sélectionnez une phrase courte, puis
un long passage, puis rien du tout. Rouvrez l'onglet à chaque fois.

**Vous devez voir :** les propositions changent — un long passage suggère de résumer,
une phrase courte de développer.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6bis.4 Redimensionner la fenêtre

**Faites :** attrapez un coin de la fenêtre et agrandissez-la.

**Vous devez voir :** **seule la zone du bas grandit** ; les boutons du haut restent
sur **une seule ligne**. Rétrécissez : rien ne doit se chevaucher ni être tronqué.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6bis.5 La taille est mémorisée

**Faites :** redimensionnez, fermez la fenêtre, rouvrez-la.

**Vous devez voir :** la fenêtre retrouve sa taille et sa position.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 6bis.6 Fermer avec la croix

**Faites :** cliquez la **croix** de la fenêtre. Rouvrez, puis fermez avec **Échap**.

**Vous devez voir :** la fenêtre se ferme dans les deux cas. Essayez aussi Échap après
avoir cliqué dans la zone du bas — cela doit marcher aussi.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 7 — Quand ça se passe mal

L'assistant doit **toujours** vous dire ce qui ne va pas. Un bouton qui ne fait rien du tout
est un défaut, même si l'ordinateur n'a pas planté.

### 7.1 Sans réseau

**Faites :** coupez le Wi-Fi (ou débranchez le câble). Sélectionnez du texte, cliquez sur
**Résumer**.

**Vous devez voir :** un message d'erreur **lisible et coloré** en moins de quelques
secondes, du type « Le serveur IA est injoignable… ». Et LibreOffice ne doit **pas** se
figer.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 7.2 Sur un document vide

**Faites :** rétablissez le réseau. Créez un document **entièrement vide**. Ouvrez
l'assistant, cliquez sur **Résumer**.

**Vous devez voir :** un message vous invitant à placer le curseur ou à sélectionner du
texte. **Pas** un silence total.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

### 7.3 Le statut se voit

**Faites :** observez la ligne de statut pendant et après une demande.

**Vous devez voir :** « L'assistant travaille… » pendant, puis **« Terminé »** en vert à la
fin — ou un message d'erreur **en rouge** en cas de problème.

☐ Conforme ☐ Non conforme — *observations :* ______________________________

---

## 8 — Le menu MIrAI

**Faites :** ouvrez le menu **🤖 MIrAI** et essayez chaque entrée, **dans Writer puis dans
Calc**.

| Entrée | Ce que vous devez voir | Writer | Calc |
|---|---|---|---|
| ⚙️ Paramètres | La fenêtre de réglages s'ouvre | ☐ | ☐ |
| ℹ️ À propos | Les informations de version s'affichent | ☐ | ☐ |
| 📚 Documentation | La documentation s'ouvre dans le navigateur | ☐ | ☐ |
| 🌐 Site mirai | Le portail s'ouvre dans le navigateur | ☐ | ☐ |

> **Point de vigilance :** essayez aussi ces quatre entrées **sans rien avoir sélectionné**,
> et **dans Calc**. Dans la version précédente, plusieurs ne faisaient rien du tout dans ces
> conditions. Elles doivent toutes fonctionner.

*Observations :* ______________________________

---

## 9 — Que faire si ça ne marche pas

### Le fichier à récupérer

L'assistant écrit tout ce qu'il fait dans un fichier appelé **`log.txt`**, dans votre dossier
personnel :

- **macOS** : `/Users/<votre-nom>/log.txt`
- **Windows** : `C:\Users\<votre-nom>\log.txt`
- **Linux** : `/home/<votre-nom>/log.txt`

Le plus simple : ouvrez ce fichier avec un éditeur de texte, allez tout **en bas**, et copiez
les **cinquante dernières lignes**.

### Ce qu'on peut y lire sans être technicien

| Si vous voyez… | Cela veut dire |
|---|---|
| `mirai extension registered successfully` | L'extension est bien chargée. |
| `401` ou `Unauthorized` | Problème de connexion : reconnectez-vous par **⚙️ Paramètres**. |
| `Missing credentials` | Votre poste n'est plus enrôlé — à signaler, il faut refaire l'enrôlement. |
| `[palette] ouverte` | La fenêtre de l'assistant s'est bien ouverte. |
| `Traceback` | Une vraie erreur technique : **c'est le passage le plus utile à transmettre**. |

### Ce qu'il faut rapporter

Pour chaque anomalie, ces cinq éléments suffisent :

1. **Le numéro du scénario** (par exemple « 6.1 »).
2. **Ce que vous avez fait**, en une phrase.
3. **Ce que vous attendiez**, et **ce qui s'est passé à la place**.
4. **Une capture d'écran**, si quelque chose est visible à l'écran.
5. **Les 50 dernières lignes de `log.txt`**.

Précisez aussi votre **système** (macOS / Windows / Linux) et la **version de LibreOffice**
(menu *LibreOffice ▸ À propos*).

### Deux cas particuliers, déjà connus

- **Une fenêtre de mise à jour s'ouvre et interrompt la connexion.** Fermez-la, terminez
  votre connexion, puis relancez la mise à jour ensuite. C'est un défaut connu.
- **« Callback invalide (state inconnu) » dans le navigateur.** Fermez **tous** les onglets
  de connexion MIrAI et recommencez avec un seul. Ce message ne vient jamais de l'extension.

---

## Récapitulatif

| Partie | Scénarios | Conformes | Non conformes |
|---|---|---|---|
| Installation et connexion | 3 | | |
| La fenêtre de l'assistant | 4 | | |
| Actions Writer | 8 | | |
| Menu du clic droit | 4 | | |
| Actions Calc | 4 | | |
| Pendant le travail | 3 | | |
| Zone du bas et fenêtre | 6 | | |
| Quand ça se passe mal | 3 | | |
| Menu MIrAI | 8 | | |
| **Total** | **43** | | |

**Testeur :** ____________________  **Date :** ____________________

**Impression générale** (utilisable au quotidien ? gênant ? bloquant ?) :

______________________________________________________________________

______________________________________________________________________
