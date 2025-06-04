# localwriter: A LibreOffice Writer extension for local generative AI

Consider donating to support development: https://ko-fi.com/johnbalis

## About

This is a libreoffice writer extension to allow for inline generative editing with local inference. It can be used with
any language model supported by text-generation-webui.

## Table of contents
<!-- TOC -->
  * [About](#about)
  * [Table of contents](#table-of-contents)
  * [Features](#features-)
    * [Extend Selection](#extend-selection)
    * [Edit Selection](#edit-selection)
  * [Setup](#setup)
    * [Libreoffice (Where you'll be using this extension)](#libreoffice-where-youll-be-using-this-extension)
    * [Backend Setup](#backend-setup)
      * [text-generation-webui](#text-generation-webui)
      * [Ollama](#ollama)
  * [Settings](#settings)
  * [License](#license)
<!-- TOC -->

## Features 

This extension adds two powerful commands to libreoffice writer:

### Extend Selection

**Hotkey Default** `CTRL + q`

Uses a language model to predict what comes after the selected text. There are a lot of ways to use this.

Some example use cases for this include, writing a story or an email given a particular prompt, adding additional
possible items to a grocery list, or summarizing the selected text.

### Edit Selection

**Hotkey Default** `CTRL + e` 

A dialog box appears to prompt the user for instructions about how to edit the selected text, then the selected text is
replaced by the edited text.

Some examples for use cases for this include changing the tone of an email, translating text to a different language,
and semantically editing a scene in a story.

## Setup

Download the most recent version of Localwriter via the [releases and "localwriter.oxt" file.](https://github.com/balisujohn/localwriter/releases)

### Libreoffice (Where you'll be using this extension)

 - Open up the Extension manager (under the Tools Menu)
 - Click on the `Add` button and find the `localwriter.oxt` file in your  filesystem. 
 - You will be directed to read the license then the extension should be installed.

### Backend Setup

To use this libreoffice extension, you must have a backend model runner installed. This is often done with either `text-generation-webui` or `Ollama.`

---

The backend supports either using `text-generation-webui` or `ollama.` Choose the backend that you like the best. Ollama
is probably the easier of the two to setup.

#### text-generation-webui

Instructions on how to install `text-generation-webui` can be found
here: [Github: oobabogga/text-generation-webui](https://github.com/oobabooga/text-generation-webui)

The docker image for this can be found
at: [Github:Atinoda/text-generation-webui-docker](https://github.com/Atinoda/text-generation-webui-docker)

After it's installed, a model is installed and working, please follow the following steps:

 - Enable the local openai API (This means that the API will respond in a similar format as OpenAI)
 - Setup and confirm that the intended model is working. (I'd recommend openchat3.5, it's meant for 8GB VRAM setups)
 - Set the endpoint in `Localwriter` to localhost:5000. (Unless this was changed in configuration)

#### Ollama

Instructions on how ot install `Ollama` can be found here: [Ollama.com](https://ollama.com/)

   - Make sure the API is enabled
   - Set the endpoint in `Localwriter` to localhost:11434. (Unless this was changed in the deployment)

## Settings

In the settings, you can set the maximum number of additional tokens for extend selection and the maximum additional
tokens (above the number of letters in the original selection) for edit selection. You can also individually set the "
system prompt" for edit selection and extend selection in settings, and this prompt will always be invisibly be appended
before the selection from your document send to the language model with each of these commands. For example, if you want
to use a particular writing style, you can place a sample of your writing in extend selection system prompt, along with
a directive to always write in a similar style.

## License

(See License.txt for the full license text)

Except where otherwise noted in source code, this software is provided with a MPL 2.0 license.

The code not released with an MPL2.0 license is released under the following terms.
License: Creative Commons Attribution-ShareAlike 3.0 Unported License,
License: The Document Foundation  https://creativecommons.org/licenses/by-sa/3.0/

A large amount of code is derived from the following MPL2.0 licensed code from the Document Foundation
https://gerrit.libreoffice.org/c/core/+/159938

MPL2.0

Copyright (c) 2024 John Balis
