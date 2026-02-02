# mirai: A LibreOffice Writer extension for generative AI

## About

This LibreOffice extension integrates a writing assistant directly into Writer: it can **continue a text**, **edit a selection**, **summarize**, and **rephrase** without leaving the document. It connects to an OpenAI‑compatible backend (OpenWebUI, Ollama, etc.) and preserves formatting as much as possible. It also includes a **simplified enrollment mechanism** via Device Management to preconfigure key parameters (base URLs, API tokens, default models, etc.).

This is a LibreOffice Writer extension that enables inline generative editing with AI language models. It's compatible with OpenAI API, OpenWebUI, Ollama, and other OpenAI-compatible endpoints.

**Origin and Attribution:**

This application is a beta version developed as part of the French Ministry of Interior's mirai program. It is based on the work of **John Balis**, author of the **mirai extension**, which served as the technical foundation for this adaptation.

For complete information about sources and attributions, please refer to `registration/license.txt`.

Key repositories:
- Original mirai project by John Balis: [https://github.com/balisujohn/mirai](https://github.com/balisujohn/mirai)
- LibreOffice code portions (MPL 2.0): [https://gerrit.libreoffice.org/c/core/+/159938](https://gerrit.libreoffice.org/c/core/+/159938)
- mirai experimental version source code: [https://github.com/IA-Generative/AssistantmiraiLibreOffice](https://github.com/IA-Generative/AssistantmiraiLibreOffice)

---

## Résumé en français

Cette extension LibreOffice intègre un assistant d’écriture : génération de suite, modification, résumé et reformulation directement dans Writer. Elle se connecte à un backend compatible OpenAI/OpenWebUI et inclut un enrôlement simplifié via Device Management. Les prochaines étapes sont l’enrôlement silencieux, la récupération automatique du token OpenWebUI, l’externalisation de tous les prompts et la mise à jour automatique de l’extension.


## Table of Contents

*   [About](#about)
*   [Table of Contents](#table-of-contents)
*   [Features](#features)
    *   [Continue the selection](#-continue-the-selection)
    *   [Edit the selection](#-edit-the-selection)
    *   [Summarize the selection](#-summarize-the-selection)
    *   [Rephrase the selection](#-rephrase-the-selection)
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
*   [Update History (Summary)](#update-history-summary)
*   [Device Management (Status & TODO)](#device-management-status--todo)
*   [Résumé en français](#résumé-en-français)

## Features

This extension provides four powerful features for LibreOffice Writer, allowing you to integrate generative AI directly into your writing workflow:

### ✨ Continue the selection

**Keyboard shortcut:** `CTRL + Q`

This feature uses a language model to predict and generate what follows the selected text. Common use cases include:

*   **Creative writing**: Continue a story, narrative, or develop an idea
*   **Writing assistance**: Complete an email, letter, or professional document
*   **List generation**: Add items to a list of tasks, ideas, or actions
*   **Brainstorming**: Explore different ways to continue a text

**Result:** The generated text is appended immediately after your selection, preserving formatting.

---

### ✏️ Edit the selection

**Keyboard shortcut:** `CTRL + E`

This command opens a dialog where you can specify how to modify the selected text. The AI then transforms your text according to your instructions.

**Common use cases:**

*   **Tone adjustment**: Make an email more formal or more casual
*   **Translation**: Translate text into another language
*   **Style correction**: Improve grammar, spelling, or style
*   **Adaptation**: Change the level of language (technical, simplified, academic)
*   **Creative revision**: Rewrite a scene in a different style or point of view

**How to use:**
1. Select the text to modify
2. Press `CTRL + E`
3. Enter your instructions (e.g., "Translate to English", "Make it more professional", "Fix typos")
4. The modified text is added after your selection with clear delimiters

**Result:** The original text is preserved, and the modification is appended below with visible delimiters:
```
---modification-de-la-sélection---
[Your edited text appears here]
---fin-de-la-modification---
```

---

### 📝 Summarize the selection

**Keyboard shortcut:** `CTRL + R`

This feature generates a concise summary of the selected text. Ideal for extracting key points from long documents, preparing a synthesis, or getting a quick overview.

**Use cases:**

*   **Document synthesis**: Summarize a report, article, or meeting note
*   **Information extraction**: Get essential points from long text
*   **Presentation prep**: Create slide bullet points from detailed content
*   **Quick review**: Check the main content of a text quickly

**How to use:**
1. Select the text to summarize
2. Press `CTRL + R`
3. The summary is automatically generated and added after your selection

**Result:** The summary is inserted with distinct delimiters:
```
---début-du-résumé---
[The concise summary appears here]
---fin-du-résumé---
```

---

### 💬 Rephrase the selection

**Keyboard shortcut:** `CTRL + L`

This feature rewrites the selected text in a clearer, more accessible form while preserving the original meaning. Perfect for improving readability and comprehension.

**Use cases:**

*   **Simplification**: Make technical text accessible to a general audience
*   **Clarification**: Improve comprehension of complex text
*   **Popularization**: Adapt specialized content for non‑experts
*   **Communication improvement**: Make writing more direct and clear

**How to use:**
1. Select the text to rephrase
2. Press `CTRL + L`
3. The rephrased text is generated in the same language as your text

**Result:** The rephrasing is added with delimiters:
```
---début-de-la-reformulation---
[Your clearer rephrased text appears here]
---fin-de-la-reformulation---
```

---

### 🌐 Access the mirai website

Access the official mirai website (https://mirai.interieur.gouv.fr) from the extension menu for more information about the program and available tools.

---

### ⚙️ Settings

Configure the extension to your needs: LLM base URL(s), default model(s), API token(s), and advanced options.

---

## Feature behavior

### Preservation of original text

**Important:** The “Edit”, “Summarize”, and “Rephrase” features **never delete** your original text. They append the generated result right after your selection with clear delimiters. This lets you:

- Compare the original and generated versions
- Choose the version that suits you
- Keep a trace of changes
- Manually remove what you don’t want

Only “Continue the selection” inserts text without delimiters because it is designed to flow naturally.

### Formatting preservation

The extension **preserves formatting as much as possible** (bold, italics, colors, etc.). However, depending on the model used (OpenAI, Mistral, Ollama, OpenWebUI, etc.), formatting may vary slightly.

### ⚠️ Known limitations

- **Formatting**: Some models may change line breaks or punctuation
- **Model behavior**: The AI may sometimes ask questions instead of following instructions; the extension detects this and asks you to reformulate your request
- **Language**: Models generally perform best in English and French

---

## Telemetry and monitoring

### OpenTelemetry

The extension now integrates **OpenTelemetry** for usage tracking and monitoring. This feature collects anonymized traces about feature usage.

**⚡ Asynchronous telemetry (non‑blocking):**

Telemetry calls are **fully asynchronous** and run in separate daemon threads. This ensures:

- ✅ The plugin **never blocks** while waiting for telemetry
- ✅ Features remain **responsive** even if the backend is down
- ✅ The user experiences **no slowdown** (5s timeout in a separate thread)
- ✅ Telemetry errors do not affect normal operation
- ✅ Threads terminate automatically when LibreOffice closes

**Telemetry configuration:**

In your `mirai.json` (or config file), you can configure:

```json
{
  "telemetryEnabled": true,
  "telemetryEndpoint": "https://traces.cpin.numerique-interieur.com/v1/traces",
  "telemetryAuthorizationType": "Basic",
  "telemetryKey": "your-base64-encoded-key",
  "telemetrylogJson": false
}
```

**Available parameters:**

| Parameter | Description | Default |
|-----------|-------------|---------|
| `telemetryEnabled` | Enable/disable telemetry | `true` |
| `telemetryEndpoint` | OpenTelemetry/Tempo endpoint URL | `https://traces.cpin.numerique-interieur.com/v1/traces` |
| `telemetryAuthorizationType` | Authentication type | `Basic` or `Bearer` |
| `telemetryKey` | Base64 auth key | `""` (uses obfuscated key) |
| `telemetrylogJson` | Detailed logs with full HTTP headers | `false` (enable for debug) |
| `telemetrySel` | Telemetry salt | `mirai_salt` |
| `telemetryHost` | Custom host | `""` (optional) |
| `telemetryFormatProtobuf` | Protobuf format | `false` (not implemented) |

---

## Update History (Summary)

This project has gone through many iterations. Here is a summary of the most recent changes:

- **Configuration**: `config.default.json` is now packaged with the extension, with auto‑init of the user `config.json` if missing or empty, and merge/upgrade based on `configVersion`.
- **Device Management**: bootstrap `/config/...` integration with local sync; empty values no longer overwrite local config.
- **OpenWebUI**: full support for LLM settings (base URLs, API tokens, headers). Added diagnostics (logs/curl) for model and chat calls.
- **Keycloak/SSO**: Authorization Code + PKCE flow with local redirect; multi‑URI handling; improved re‑login UX.
- **Preferences UI**: simplified dialog, model dropdown, dynamic description, API status indicator, reload button, splash image, masked token with reveal toggle.
- **Editing**: new “Edit selection” dialog always on top, resizable, with send button and system close handling.
- **Logs & diagnostics**: better network logs, HTTP error handling, user notification when token expired.

## Device Management (Status & TODO)

Device Management integration is in place, but several items remain:

**TODO:**
- Finalize **silent enrollment**.
- Implement **automatic OpenWebUI token retrieval**.
- **Externalize all prompts** via Device Management (all prompts must become configurable).
- Implement the **automatic update mechanism** for the extension.
