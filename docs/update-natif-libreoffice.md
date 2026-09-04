# Mise à jour native LibreOffice (`<update-information>`) — contrat & fonctionnement

Réfs : issue plugin [#5](https://github.com/IA-Generative/AssistantMiraiLibreOffice/issues/5)
(brancher le mécanisme natif), issue plugin [#9](https://github.com/IA-Generative/AssistantMiraiLibreOffice/issues/9)
(fiabilité de bout en bout), feed côté DM : IA-Generative/device-management#23.

## Vue d'ensemble — trois routes, un seul point d'installation

Toutes les routes convergent vers **`ExtensionManager.addExtension` exécuté sur le
thread principal de soffice** — le code exact du Gestionnaire des extensions, la
seule voie validée comme fiable sur plusieurs cycles. Aucune route par défaut ne
spawne de processus enfant (immunisé WinError 5 / AppLocker / Defender ASR).

| Route | Déclencheur | Installation | Cohorte/canary |
|---|---|---|---|
| **1. Pilotée DM** (principale) | Directive `update` du DM (polling config) | Download + checksum par le plugin → `addExtension` main-thread → fermeture propre → réconciliation au redémarrage | ✅ oui |
| **2. Native LibreOffice** | Bouton « Vérifier les mises à jour » du Gestionnaire des extensions (ou check périodique LO si activé) | LibreOffice fait tout : fetch du feed, download, install, redémarrage | ❌ feed anonyme |
| **3. Manuelle** (fallback validé GPO) | Message « mise à jour bloquée » + bouton « Ouvrir le dossier » | L'utilisateur double-clique l'OXT stagé → Gestionnaire des extensions | ✅ (directive) |

Point établi en vérifiant les sources LibreOffice (`desktop/source/deployment/gui/`) :
le dialogue « Vérifier les mises à jour » **n'est pas un service UNO créable**
(seuls `PackageManagerDialog`, `LicenseDialog`, `UpdateRequiredDialog` le sont).
Le « push » programmatique passe donc par la route 1 (directive DM + `addExtension`),
pas par l'ouverture du dialogue natif.

## Ce que le build bake dans `description.xml`

`scripts/inject_update_feed.py` (appelé par `02-build-oxt.sh`) ajoute au staging :

```xml
<update-information>
  <src xlink:href="https://<bootstrap-1>/catalog/mirai-libreoffice/update.xml"/>
  <src xlink:href="https://<bootstrap-2>/catalog/mirai-libreoffice/update.xml"/>
</update-information>
```

- Une entrée `<src>` par `bootstrap_urls` du profil embarqué — LibreOffice les
  essaie **dans l'ordre** (failover natif, même sémantique que le multi-bootstrap
  du plugin).
- Override build : `MIRAI_UPDATE_FEED_URL=<url>` (une seule entrée).
- Profil offline (`enabled: false`) : aucun bloc — le bouton natif répond
  « aucune mise à jour ».

## Contrat du feed `update.xml` (à servir par le DM — device-management#23)

`GET <bootstrap>/catalog/mirai-libreoffice/update.xml` — anonyme, `Content-Type`
indifférent (`text/xml` recommandé). Namespace **obligatoire**
`http://openoffice.org/extensions/update/2006` :

```xml
<?xml version="1.0" encoding="UTF-8"?>
<description xmlns="http://openoffice.org/extensions/update/2006"
             xmlns:xlink="http://www.w3.org/1999/xlink">
  <identifier value="fr.gouv.interieur.mirai"/>
  <version value="0.0.1.0.32"/>
  <update-download>
    <src xlink:href="https://<bootstrap>/artifacts/mirai-libreoffice/0.0.1.0.32/mirai.oxt"/>
  </update-download>
</description>
```

- `identifier` : doit être strictement `fr.gouv.interieur.mirai` (sinon LO ignore le feed).
- `version` : la dernière version publiée du tier. LibreOffice compare segment
  par segment (numérique) — le schéma à 5 segments `0.0.1.0.NN` est géré.
  LO propose la MAJ ssi `version(feed) > version(installée)`.
- `update-download/src` : URL de l'OXT, téléchargée par LibreOffice lui-même
  (anonymement). Plusieurs `<src>` possibles (miroirs, essayés dans l'ordre).
- Optionnel : `<release-notes><src xlink:href="…" lang="fr"/></release-notes>`.

## Vérification sur poste (checklist qualif)

1. Installer une version N, publier N+1 côté DM (feed à jour).
2. Outils → Gestionnaire des extensions → **Vérifier les mises à jour** :
   la MAJ doit apparaître ; installer ; redémarrer quand LO le propose.
3. Répéter 3 cycles consécutifs : l'extension doit rester visible et
   fonctionnelle (pas d'entrées fantômes dans `registrymodifications.xcu`).
4. Points durs à valider sur poste durci MI :
   - **proxy** : LibreOffice récupère le feed avec sa propre pile HTTP
     (Options → Internet → Proxy, ou proxy système) — pas celle du plugin ;
   - **GPO « Mise à jour en ligne »** : si désactivée, seul le bouton manuel
     du Gestionnaire des extensions déclenche le check (pas de périodique) ;
   - certificats : la chaîne TLS du bootstrap doit être reconnue par LO.

## Fiabilité route 1 (issue #9) — décisions implémentées

- **Install sur le main thread via `theExtensionManager.addExtension`**, sans
  remove-avant-add : le remplacement même-identifiant est atomique
  (`VersionException` auto-approuvée). Les cycles `removePackage`/`addPackage`
  bas niveau depuis le thread worker — la cause des entrées fantômes — sont
  relégués en tout dernier recours.
- **Scripts `.bat`/`.sh` désactivés par défaut** (spawn d'enfant = WinError 5 +
  cycle unopkg corrupteur). Réactivation diagnostic : `MIRAI_UPDATE_ALLOW_SCRIPT=1`.
- **Rapport DM véridique** : `deferred` au staging, `installed` seulement quand
  la nouvelle version est **réellement active** (réconciliation au démarrage
  suivant, `_reconcile_update_state`), qui purge aussi `pending_update` et lève
  l'anti-boucle. Un état périmé (> 14 j) est purgé silencieusement.
- **Pas de re-exec** : fermeture propre de LO (main thread), réouverture par
  l'utilisateur — comportement validé sur toutes les plateformes.
