# localwriter: A LibreOffice Writer extension for local generative AI

Consider donating to support development: https://ko-fi.com/johnbalis

## About

This is a LibreOffice Writer extension that enables inline generative editing with local inference. It's compatible with language models supported by `text-generation-webui` and `ollama`.

## Table of Contents

*   [About](#about)
*   [Table of Contents](#table-of-contents)
*   [Features](#features)
    *   [Extend Selection](#extend-selection)
    *   [Edit Selection](#edit-selection)
*   [Setup](#setup)
    *   [LibreOffice Extension Installation](#libreoffice-extension-installation)
    *   [Backend Setup](#backend-setup)
        *   [text-generation-webui](#text-generation-webui)
        *   [Ollama](#ollama)
*   [Settings](#settings)
*   [License](#license)

## Features

This extension provides two powerful commands for LibreOffice Writer:

### Extend Selection

**Hotkey:** `CTRL + q`

*   This uses a language model to predict what comes after the selected text. There are a lot of ways to use this.
*   Some example use cases for this include: writing a story or an email given a particular prompt, adding additional possible items to a grocery list, or summarizing the selected text.

### Edit Selection

**Hotkey:** `CTRL + e`

*   A dialog box appears to prompt the user for instructions about how to edit the selected text, then the selected text is replaced by the edited text.
*   Some examples for use cases for this include changing the tone of an email, translating text to a different language, and semantically editing a scene in a story.

## Setup

### LibreOffice Extension Installation

1.  Download the latest version of Localwriter via the [releases page](https://github.com/balis-john/localwriter/releases).
2.  Open LibreOffice.
3.  Navigate to `Tools > Extensions`.
4.  Click `Add` and select the downloaded `.oxt` file.
5.  Follow the on-screen instructions to install the extension.

### Backend Setup

To use Localwriter, you need a backend model runner.  Options include `text-generation-webui` and `Ollama`. Choose the backend that best suits your needs. Ollama is generally easier to set up. In either of these options, you will have to download and set a model. 

#### text-generation-webui

*   Installation instructions can be found [here](https://github.com/oobabooga/text-generation-webui).
*   Docker image available [here](https://github.com/Atinoda/text-generation-webui-docker).

After installation and model setup:

1.  Enable the local OpenAI API (this ensures the API responds in a format similar to OpenAI).
2.  Verify that the intended model is working (e.g., openchat3.5, suitable for 8GB VRAM setups).
3.  Set the endpoint in Localwriter to `localhost:5000` (or the configured port).

#### Ollama

*   Installation instructions are available [here](https://ollama.com/).
*   Download and use a model (gemma3 isn't bad)
*   Ensure the API is enabled.
*   Set the endpoint in Localwriter to `localhost:11434` (or the configured port).
*   Manually set the model name. ([This is required for Ollama to work](https://ask.libreoffice.org/t/localwriter-0-0-5-installation-and-usage/122241/5?u=jbalis))

## Settings

In the settings, you can configure:

*   Maximum number of additional tokens for "Extend Selection."
*   Maximum number of additional tokens (above the number of letters in the original selection) for "Edit Selection."
*   Custom "system prompts" for both "Extend Selection" and "Edit Selection." These prompts are prepended to the selection before sending it to the language model.  For example, you can use a sample of your writing to guide the model's style.

## Contributing

Help with development is always welcome. localwriter has a number of outstanding feature requests by users. Feel free to work on any of them, and you can help improve freedom-respecting local AI. 

### Building localwriter

In a terminal, change directory into the localwriter repository top-level directory, then run the following command:

````
zip -r localwriter.oxt \
  Accelerators.xcu \
  Addons.xcu \
  assets \
  description.xml \
  main.py \
  META-INF \
  registration \
  README.md
````

This will create the file `localwriter.oxt` which you can open with libreoffice to install the localwriter extension. You can also change the file extension to .zip and manually unzip the extension file, if you want to inspect a localwriter `.oxt` file yourself. It is all human-readable, since python is an interpreted language. 



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
