# Mirai: A LibreOffice Writer extension for generative AI

## About

This is a LibreOffice Writer extension that enables inline generative editing with AI language models. It's compatible with OpenAI API, OpenWebUI, Ollama, and other OpenAI-compatible endpoints.

**Origin and Attribution:**

This application is an Béta version developed as part of the French Ministry of Interior's MirAI program. It is based on the work of **John Balis**, author of the **LocalWriter extension**, which served as the technical foundation for this adaptation.

For complete information about sources and attributions, please refer to `registration/license.txt`.

Key repositories:
- Original LocalWriter project by John Balis: [https://github.com/balisujohn/localwriter](https://github.com/balisujohn/localwriter)
- LibreOffice code portions (MPL 2.0): [https://gerrit.libreoffice.org/c/core/+/159938](https://gerrit.libreoffice.org/c/core/+/159938)
- MirAI experimental version source code: [https://github.com/IA-Generative/AssistantMiraiLibreOffice](https://github.com/IA-Generative/AssistantMiraiLibreOffice)

## Table of Contents

*   [About](#about)
*   [Table of Contents](#table-of-contents)
*   [Fonctionnalités](#fonctionnalités)
    *   [Générer la suite de la sélection](#-générer-la-suite-de-la-sélection)
    *   [Modifier la sélection](#-modifier-la-sélection)
    *   [Résumer la sélection](#-résumer-la-sélection)
    *   [Reformuler la sélection](#-reformuler-la-sélection)
*   [Setup](#setup)
    *   [LibreOffice Extension Installation](#libreoffice-extension-installation)
    *   [Backend Setup](#backend-setup)
        *   [text-generation-webui](#text-generation-webui)
        *   [Ollama](#ollama)
        *   [OpenWebUI](#openwebui)
*   [Settings](#settings)
*   [Contributing](#contributing)
    *   [Local Development Setup](#local-development-setup)
    *   [Building the Extension Package](#building-the-extension-package)
*   [License](#license)

## Fonctionnalités

Cette extension fournit quatre fonctionnalités puissantes pour LibreOffice Writer, vous permettant d'intégrer l'intelligence artificielle directement dans votre flux de travail d'écriture :

### ✨ Générer la suite de la sélection

**Raccourci clavier :** `CTRL + Q`

Cette fonctionnalité utilise un modèle de langage pour prédire et générer ce qui suit le texte sélectionné. Les possibilités d'utilisation sont nombreuses :

*   **Rédaction créative** : Continuer une histoire, un récit ou développer une idée
*   **Assistance à l'écriture** : Compléter un email, une lettre ou un document professionnel
*   **Génération de listes** : Ajouter des éléments à une liste de courses, d'actions ou d'idées
*   **Brainstorming** : Explorer différentes façons de poursuivre un texte

**Résultat :** Le texte généré est ajouté immédiatement après votre sélection, en conservant la mise en forme.

---

### ✏️ Modifier la sélection

**Raccourci clavier :** `CTRL + E`

Cette commande ouvre une boîte de dialogue où vous pouvez donner des instructions sur la façon de modifier le texte sélectionné. L'IA transforme ensuite votre texte selon vos directives.

**Cas d'usage courants :**

*   **Ajustement du ton** : Rendre un email plus formel ou plus décontracté
*   **Traduction** : Traduire le texte dans une autre langue
*   **Correction stylistique** : Améliorer la grammaire, l'orthographe ou le style
*   **Adaptation** : Modifier le niveau de langage (technique, vulgarisé, académique)
*   **Révision créative** : Réécrire une scène dans un autre style ou point de vue

**Comment l'utiliser :**
1. Sélectionnez le texte à modifier
2. Appuyez sur `CTRL + E`
3. Entrez vos instructions (ex: "Traduis en anglais", "Rends ce texte plus professionnel", "Corrige les fautes")
4. Le texte modifié est ajouté après votre sélection avec des délimiteurs clairs

**Résultat :** Le texte original est conservé, et la modification est ajoutée juste en dessous avec des délimiteurs visibles :
```
---modification-de-la-sélection---
[Votre texte modifié apparaît ici]
---fin-de-la-modification---
```

---

### 📝 Résumer la sélection

**Raccourci clavier :** `CTRL + R`

Cette fonctionnalité génère un résumé concis du texte sélectionné. Idéale pour extraire les points clés d'un long document, préparer une synthèse ou obtenir une vue d'ensemble rapide.

**Cas d'usage :**

*   **Synthèse de documents** : Résumer un rapport, un article ou une note de réunion
*   **Extraction d'informations** : Obtenir les points essentiels d'un texte long
*   **Préparation de présentations** : Créer des points de présentation à partir d'un contenu détaillé
*   **Révision rapide** : Vérifier rapidement le contenu principal d'un texte

**Comment l'utiliser :**
1. Sélectionnez le texte à résumer
2. Appuyez sur `CTRL + R`
3. Le résumé est automatiquement généré et ajouté après votre sélection

**Résultat :** Le résumé est ajouté avec des délimiteurs distincts :
```
---début-du-résumé---
[Le résumé concis de votre texte apparaît ici]
---fin-du-résumé---
```

---

### 💬 Reformuler la sélection

**Raccourci clavier :** `CTRL + L`

Cette fonctionnalité reformule le texte sélectionné dans un langage plus clair et accessible, tout en conservant le sens original. Parfait pour améliorer la lisibilité et la compréhension.

**Cas d'usage :**

*   **Simplification** : Rendre un texte technique accessible au grand public
*   **Clarification** : Améliorer la compréhension d'un texte complexe
*   **Vulgarisation** : Adapter un contenu spécialisé pour un public non-expert
*   **Amélioration de la communication** : Rendre vos écrits plus directs et compréhensibles

**Comment l'utiliser :**
1. Sélectionnez le texte à reformuler
2. Appuyez sur `CTRL + L`
3. La reformulation est automatiquement générée dans la même langue que votre texte

**Résultat :** La reformulation est ajoutée avec des délimiteurs :
```
---début-de-la-reformulation---
[Votre texte reformulé de manière plus claire apparaît ici]
---fin-de-la-reformulation---
```

---

### 🌐 Accéder au site MirAI

Accédez directement au site web officiel de MirAI (https://mirai.interieur.gouv.fr) depuis le menu de l'extension pour obtenir plus d'informations sur le programme et les outils disponibles.

---

### ⚙️ Paramètres

Configurez l'extension selon vos besoins : point de terminaison de l'API, modèle de langage, clé API, et options avancées.

---

## Comportement des fonctionnalités

### Conservation du texte original

**Important :** Les fonctionnalités "Modifier", "Résumer" et "Reformuler" **n'effacent jamais** votre texte original. Elles ajoutent le résultat généré juste après votre sélection, avec des délimiteurs clairs. Cela vous permet de :

- Comparer facilement l'original et la version générée
- Choisir la version qui vous convient
- Conserver une trace de vos modifications
- Supprimer manuellement ce qui ne vous convient pas

Seule la fonction "Générer la suite" ajoute directement du texte sans délimiteur, car elle est conçue pour prolonger naturellement votre texte.

### Conservation de la mise en forme

L'extension **préserve autant que possible la mise en forme** de votre texte (gras, italique, couleurs, etc.). Cependant, selon le modèle de langage utilisé (OpenAI, Mistral, Ollama, OpenWebUI, etc.), la mise en forme peut légèrement varier.

### ⚠️ Limitations connues

- **Mise en forme** : Certains modèles peuvent modifier les sauts de lignes ou la ponctuation
- **Comportement des modèles** : L'IA peut parfois poser des questions au lieu de suivre les instructions. L'extension détecte automatiquement ces cas et vous demande de reformuler votre demande
- **Langue** : Les modèles fonctionnent mieux dans les langues sur lesquelles ils ont été entraînés (généralement l'anglais et le français)

---

## Télémétrie et monitoring

### OpenTelemetry

L'extension intègre désormais **OpenTelemetry** pour le suivi d'utilisation et le monitoring. Cette fonctionnalité permet de collecter des traces anonymisées sur l'utilisation des différentes fonctionnalités.

**⚡ Télémétrie asynchrone (non-bloquante) :**

Les appels de télémétrie sont **entièrement asynchrones** et s'exécutent dans des threads séparés (daemon threads). Cela garantit que :

- ✅ Le plug-in **ne se bloque jamais** en attendant une réponse du serveur de télémétrie
- ✅ Les fonctionnalités restent **totalement réactives** même si le backend Tempo est indisponible
- ✅ L'utilisateur ne subit **aucun ralentissement** lié à la télémétrie (timeout de 5s dans un thread séparé)
- ✅ Les erreurs de télémétrie n'affectent pas le fonctionnement normal de l'extension
- ✅ Les threads se terminent automatiquement à la fermeture de LibreOffice

**Configuration de la télémétrie :**

Dans votre fichier `mirai.json`, vous pouvez configurer :

```json
{
  "telemetryEnabled": true,
  "telemetryEndpoint": "https://traces.cpin.numerique-interieur.com/v1/traces",
  "telemetryAuthorizationType": "Basic",
  "telemetryKey": "votre-clé-encodée-en-base64",
  "telemetrylogJson": false
}
```

**Paramètres disponibles :**

| Paramètre | Description | Valeur par défaut |
|-----------|-------------|-------------------|
| `telemetryEnabled` | Activer/désactiver la télémétrie | `true` |
| `telemetryEndpoint` | URL de l'endpoint OpenTelemetry/Tempo | `https://traces.cpin.numerique-interieur.com/v1/traces` |
| `telemetryAuthorizationType` | Type d'authentification | `Basic` ou `Bearer` |
| `telemetryKey` | Clé d'authentification base64 | `""` (utilise la clé obfusquée) |
| `telemetrylogJson` | Logs détaillés avec headers HTTP complets | `false` (activez pour debug) |
| `telemetrySel` | Salt pour la télémétrie | `mirai_salt` |
| `telemetryHost` | Hôte personnalisé | `""` (optionnel) |
| `telemetryFormatProtobuf` | Format protobuf | `false` (non implémenté) |

**🔒 Sécurité et authentification :**

L'extension utilise un système d'authentification robuste pour la télémétrie :

- **Clé par défaut obfusquée** : Une clé de télémétrie est intégrée dans le code, protégée par un système de double encodage (inversion + Base64)
- **Décodage automatique** : Si `telemetryKey` est vide dans `mirai.json`, la clé obfusquée est automatiquement décodée et utilisée
- **Clé personnalisée** : Vous pouvez fournir votre propre clé encodée en base64 dans `telemetryKey`
- **Logs détaillés** : Avec `telemetrylogJson: true`, tous les headers HTTP sont loggés (y compris la clé d'authentification pour le debug)

Pour encoder votre propre clé d'authentification :
```bash
echo -n "username:password" | base64
```

Pour plus de détails sur le système d'obfuscation, consultez [SECURITY.md](SECURITY.md).

**UUID d'extension :**

Au premier lancement, l'extension génère automatiquement un UUID unique qui est stocké dans la configuration. Cet identifiant permet de suivre l'utilisation sans identifier personnellement l'utilisateur.

**Événements tracés :**

- `ExtensionLoaded` : Chargement de l'extension
- `ExtendSelection` : Utilisation de la génération de texte
- `EditSelection` : Utilisation de la modification de texte
- `SummarizeSelection` : Utilisation du résumé
- `SimplifySelection` : Utilisation de la reformulation
- `OpenMiraiWebsite` : Accès au site web
- `OpenSettings` : Ouverture des paramètres

**Données collectées :**

Les traces incluent uniquement :

- L'UUID de l'extension (anonyme)
- Le nom de l'action effectuée
- La longueur du texte traité (pas le contenu)
- Les métadonnées techniques (timestamps, IDs de trace)

**⚠️ Aucun contenu textuel n'est jamais envoyé** dans les traces de télémétrie.

**Debug et logs :**

Pour activer les logs détaillés de télémétrie (utile pour déboguer l'authentification) :

```json
{
  "telemetrylogJson": true
}
```

Cela affichera dans `~/log.txt` :

- Les payloads JSON complets envoyés à Tempo
- Tous les headers HTTP (y compris Authorization)
- Les réponses complètes du serveur
- Les erreurs détaillées avec codes HTTP

**Désactiver la télémétrie :**

Pour désactiver complètement la télémétrie, ajoutez dans votre configuration :

```json
{
  "telemetryEnabled": false
}
```

---

## Feuille de route

- ✅ **Implémenté** : Intégration d'OpenTelemetry pour le monitoring
- ⏳ **À venir** : Automatisation de l'intégration avec Mirai Chat
- ⏳ **À venir** : Lecture de la configuration depuis un serveur réseau (gestion de versions via GitLab/GitHub)

---

## Fonctionnalités (Description en français)

Cette extension offre deux commandes puissantes pour LibreOffice Writer, permettant d'intégrer l'intelligence artificielle directement dans votre flux de travail d'écriture :

### Generer la suite (de la sélection )

**Raccourci clavier :** `CTRL + q`

Cette fonctionnalité utilise un modèle de langage pour prédire et générer ce qui suit le texte sélectionné. Les possibilités d'utilisation sont nombreuses :

*   **Rédaction créative** : Continuer une histoire, un récit ou développer une idée
*   **Assistance à l'écriture** : Compléter un email, une lettre ou un document professionnel
*   **Génération de listes** : Ajouter des éléments à une liste de courses, d'actions ou d'idées
*   **Résumé** : Générer un résumé du texte sélectionné
*   **Brainstorming** : Explorer différentes façons de poursuivre un texte

### Éditer la sélection

**Raccourci clavier :** `CTRL + e`

Cette commande ouvre une boîte de dialogue où vous pouvez donner des instructions sur la façon de modifier le texte sélectionné. L'IA transforme ensuite votre texte selon vos directives.

**Cas d'usage courants :**

*   **Ajustement du ton** : Rendre un email plus formel ou plus décontracté
*   **Traduction** : Traduire le texte dans une autre langue
*   **Reformulation** : Simplifier, clarifier ou restructurer un paragraphe
*   **Correction stylistique** : Améliorer la grammaire, l'orthographe ou le style
*   **Adaptation** : Modifier le niveau de langage (technique, vulgarisé, académique)
*   **Révision créative** : Réécrire une scène dans un autre style ou point de vue

**Comment l'utiliser :**
1. Sélectionnez le texte à modifier
2. Appuyez sur `CTRL + e`
3. Entrez vos instructions (ex: "Traduis en anglais", "Rends ce texte plus professionnel", "Simplifie ce paragraphe")
4. Le texte est automatiquement remplacé par la version modifiée

### ⚠️ Limitation connue

Selon le modèle de langage utilisé (OpenAI, Mistral, Ollama, OpenWebUI, etc.), la **mise en forme du texte généré peut varier**.  
Certains modèles peuvent modifier légèrement les sauts de lignes, la ponctuation, ou la structure des paragraphes.  
Cela ne relève pas d’un dysfonctionnement de l’extension, mais du comportement propre au modèle choisi.
Les évolutions du plug-in à venir tâcheront de corriger ce défaut.
todo : automatiser l'enrollement du plug-in dans Mirai Chat.
todo : lecture de la configuration sur un serveur de configuration réseau (géré en version via gitlab/hub)
todo : ajouter opentelemetry

---

## Setup

### LibreOffice Extension Installation

1. Download the latest version of Mirai via the (https://github.com/IA-Generative/AssistantMiraiLibreOffice/dist).
2.  Open LibreOffice.
3.  Navigate to `Tools > Extensions`.
4.  Click `Add` and select the downloaded `.oxt` file.
5.  Follow the on-screen instructions to install the extension.

### Backend Setup

To use Mirai, you need a backend model runner.  Options include `text-generation-webui` and `Ollama`. Choose the backend that best suits your needs. Ollama is generally easier to set up. In either of these options, you will have to download and set a model. 

#### text-generation-webui

*   Installation instructions can be found [here](https://github.com/oobabooga/text-generation-webui).
*   Docker image available [here](https://github.com/Atinoda/text-generation-webui-docker).

After installation and model setup:

1.  Enable the local OpenAI API (this ensures the API responds in a format similar to OpenAI).
2.  Verify that the intended model is working (e.g., openchat3.5, suitable for 8GB VRAM setups).
3.  Set the endpoint in Mirai to `localhost:5000` (or the configured port).

#### Ollama

*   Installation instructions are available [here](https://ollama.com/).
*   Download and use a model (gemma3 isn't bad)
*   Ensure the API is enabled.
*   Set the endpoint in Mirai to `localhost:11434` (or the configured port).
*   Manually set the model name. ([This is required for Ollama to work](https://ask.libreoffice.org/t/localwriter-0-0-5-installation-and-usage/122241/5?u=jbalis))

#### OpenWebUI

[OpenWebUI](https://github.com/open-webui/open-webui) is a user-friendly web interface that can serve as a gateway to multiple LLM backends (Ollama, OpenAI, and others).

**Installation and Setup:**

*   Follow the installation instructions on the [OpenWebUI documentation](https://docs.openwebui.com/).
*   OpenWebUI typically runs on `http://localhost:3000` by default.
*   You can connect OpenWebUI to various backends (Ollama, OpenAI API, etc.).

**Configuring Mirai for OpenWebUI:**

1.  **Enable the OpenWebUI checkbox**: In Mirai settings, check **"Is OpenWebUI endpoint?"**
2.  **Set the endpoint**: Use `http://localhost:3000` (or your custom port)
3.  **API Type**: Select `chat` (OpenWebUI uses the chat format)
4.  **Model Name**: Enter the exact model name as it appears in OpenWebUI (e.g., `llama2`, `mistral:latest`)
5.  **API Key**: If you've configured authentication in OpenWebUI, enter your API key. Otherwise, leave it empty for local setups.

**OpenWebUI Specifics:**

*   **API Path Difference**: OpenWebUI uses `/api/` instead of the standard OpenAI `/v1/` path. Mirai automatically handles this when the OpenWebUI checkbox is enabled.
*   **Model Selection**: Unlike OpenAI, the model name must match exactly what's available in your OpenWebUI instance. You can find available models in the OpenWebUI interface under Models.
*   **Authentication**: OpenWebUI can be configured with or without authentication. For local use, authentication is often disabled. For remote access, you should enable it and use the generated API key.
*   **Backend Flexibility**: Since OpenWebUI can connect to multiple backends, you can easily switch between different LLM providers without changing Mirai settings—just change the model name.

**Example Configuration:**
```json
{
  "endpoint": "http://localhost:3000",
  "model": "llama3.2:latest",
  "api_key": "",
  "api_type": "chat",
  "is_openwebui": true,
  "openai_compatible_endpoint": true
}
```

## Settings

### Configuration Priority

Mirai loads configuration in the following order (highest priority first):

1. **Environment Variables** (prefixed with `MIRAI_`) - useful for keeping secrets out of files
2. **Configuration File** (`mirai.json`)
3. **Default Values**

Example using environment variables:
```bash
export MIRAI_API_KEY="sk-your-secret-key"
export MIRAI_ENDPOINT="https://api.openai.com"
/Applications/LibreOffice.app/Contents/MacOS/soffice --writer
```

### Configuration Files

See [CONFIG_EXAMPLES.md](CONFIG_EXAMPLES.md) for ready-to-use configuration examples.

Configuration file location:
- macOS: `~/Library/Application Support/LibreOffice/4/user/mirai.json`
- Linux: `~/.config/libreoffice/4/user/mirai.json`
- Windows: `%APPDATA%\LibreOffice\4\user\mirai.json`

### Available Settings

In the settings dialog, you can configure:

*   **Endpoint URL**: The URL of your LLM server (e.g., `http://localhost:3000` for OpenWebUI, `https://api.openai.com` for OpenAI)
*   **Model**: The model name (e.g., `llama2`, `gpt-3.5-turbo`)
*   **API Key**: Authentication key for OpenAI-compatible endpoints (optional for local servers)
*   **API Type**: `chat` or `completions` (see explanation below ⭐)
*   **Is OpenWebUI endpoint?**: Check this if using OpenWebUI (changes API path from `/v1/` to `/api/`)
*   **OpenAI Compatible Endpoint?**: Check this for servers that strictly follow OpenAI format
*   **Extend Selection Max Tokens**: Maximum number of tokens for text extension
*   **Extend Selection System Prompt**: Instructions prepended to guide the model's style for extension
*   **Edit Selection Max New Tokens**: Additional tokens allowed above original selection length
*   **Edit Selection System Prompt**: Instructions for guiding text editing behavior

### ⭐ Understanding API Type (chat vs completions)

The **API Type** setting determines the format of requests sent to your LLM server:

#### `chat` (Recommended - Modern Format)
Uses structured messages with roles:
```json
{
  "messages": [
    {"role": "system", "content": "You are a helpful assistant"},
    {"role": "user", "content": "Hello"}
  ]
}
```
**Use `chat` for:**
- OpenAI (GPT-4, GPT-3.5-turbo)
- OpenWebUI
- Ollama with `/api/chat` endpoint
- Most modern LLM APIs

#### `completions` (Legacy Format)
Uses a simple text prompt:
```json
{
  "prompt": "SYSTEM: You are a helpful assistant\nUSER: Hello"
}
```
**Use `completions` for:**
- Older OpenAI models (GPT-3 base)
- Simple local inference servers
- Some LM Studio configurations

**Simple rule:** If your server has a `/chat/completions` endpoint, use `chat`. Otherwise use `completions`.

## Contributing

Help with development is always welcome. Mirai has a number of outstanding feature requests by users. Feel free to work on any of them, and you can help improve freedom-respecting local AI.

### Local Development Setup

For developers who want to modify or contribute to Mirai, you can run and test the extension directly from your source code without packaging it into an `.oxt` file. This allows for quick iteration and seeing changes reflected in the LibreOffice UI.

1. **Clone the Repository (if not already done):**
   - Clone the Mirai repository to your local machine if you haven't already:
     ```
     git clone https://github.com/IA-Generative/localwriter.git
     cd localwriter
     ```

2. **Register the Extension Temporarily:**
   - Use the `unopkg` tool to register the extension directly from your repository folder. This avoids the need to package the extension as an `.oxt` file during development.
   - Run the following command, replacing `/path/to/mirai/` with the path to your cloned repository:
     ```
     unopkg add /path/to/mirai/
     ```
   - On Linux, `unopkg` is often located at `/usr/lib/libreoffice/program/unopkg`. Adjust the command if needed:
     ```
     /usr/lib/libreoffice/program/unopkg add /path/to/mirai/
     ```

3. **Restart LibreOffice:**
   - Close and reopen LibreOffice Writer or Calc. You should see the "Mirai" menu with options like "Extend Selection", "Edit Selection", and "Settings" in the menu bar.

4. **Make and Test Changes:**
   - Edit the source files (e.g., `main.py`) directly in your repository folder using your preferred editor.
   - After making changes, restart LibreOffice to reload the updated code. Test the functionality and UI elements (dialogs, menu actions) directly in LibreOffice.
   - Note: Restarting is often necessary for Python script changes to take effect, as LibreOffice caches modules.

5. **Commit Changes to Git:**
   - Since you're working directly in your Git repository, commit your changes as needed:
     ```
     git add main.py
     git commit -m "Updated extension logic for ExtendSelection"
     ```

6. **Unregister the Extension (Optional):**
   - If you need to remove the temporary registration, use:
     ```
     unopkg remove org.extension.sample
     ```
   - Replace `org.extension.sample` with the identifier from `description.xml` if different.

### Building the Extension Package

To create a distributable `.oxt` package:

In a terminal, change directory into the Mirai repository top-level directory, then run the following command:

````
zip -r mirai.oxt \
  Accelerators.xcu \
  Addons.xcu \
  assets \
  description.xml \
  main.py \
  META-INF \
  registration \
  README.md
````

This will create the file `mirai.oxt` which you can open with libreoffice to install the Mirai extension. You can also change the file extension to .zip and manually unzip the extension file, if you want to inspect a Mirai `.oxt` file yourself. It is all human-readable, since python is an interpreted language.



## License 

(See `License.txt` for the full license text)

Except where otherwise noted in source code, this software is provided with a MPL 2.0 license.

The code not released with an MPL2.0 license is released under the following terms.
License: Creative Commons Attribution-ShareAlike 3.0 Unported License,
License: The Document Foundation  https://creativecommons.org/licenses/by-sa/3.0/

A large amount of code is derived from the following MPL2.0 licensed code from the Document Foundation
https://gerrit.libreoffice.org/c/core/+/159938 


MPL2.0

Copyright (c) 2024 John Balis
