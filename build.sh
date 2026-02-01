#!/bin/bash
# Script de création du package .oxt pour l'extension mirai

# Nom de l'extension
EXTENSION_NAME="mirai"

# Options
INSTALL_AFTER_BUILD=false
RESTART_LIBREOFFICE=false

for arg in "$@"; do
    case "$arg" in
        --install) INSTALL_AFTER_BUILD=true ;;
        --restart) RESTART_LIBREOFFICE=true ;;
        *)
            echo "Option inconnue: $arg"
            echo "Usage: $0 [--install] [--restart]"
            exit 1
            ;;
    esac
done

# Supprime l'ancien package s'il existe
if [ -f "${EXTENSION_NAME}.oxt" ]; then
    echo "Suppression de l'ancien package..."
    rm "${EXTENSION_NAME}.oxt"
fi

# Crée le nouveau package
echo "Création du package ${EXTENSION_NAME}.oxt..."
zip -r "${EXTENSION_NAME}.oxt" \
    Accelerators.xcu \
    Addons.xcu \
    description.xml \
    config.default.json \
    main.py \
    META-INF/ \
    registration/ \
    assets/ \
    icons/ \
    -x "*.git*" -x "*.DS_Store"

if [ $? -eq 0 ]; then
    echo "✅ Package créé avec succès : ${EXTENSION_NAME}.oxt"
    if [ "$INSTALL_AFTER_BUILD" = true ]; then
        OS_NAME="$(uname -s)"
        if [ "$OS_NAME" = "Darwin" ]; then
            osascript -e 'tell application "LibreOffice" to quit' >/dev/null 2>&1 || true
        elif [ "$OS_NAME" = "Linux" ]; then
            pkill -f soffice.bin >/dev/null 2>&1 || true
            pkill -f soffice >/dev/null 2>&1 || true
        else
            taskkill //IM soffice.bin //F >/dev/null 2>&1 || true
            taskkill //IM soffice.exe //F >/dev/null 2>&1 || true
        fi

        UNOPKG_BIN="$(command -v unopkg || true)"
        if [ -z "$UNOPKG_BIN" ]; then
            if [ "$OS_NAME" = "Darwin" ] && [ -x "/Applications/LibreOffice.app/Contents/MacOS/unopkg" ]; then
                UNOPKG_BIN="/Applications/LibreOffice.app/Contents/MacOS/unopkg"
            elif [ "$OS_NAME" = "Linux" ]; then
                for candidate in /usr/lib/libreoffice/program/unopkg /usr/bin/unopkg /snap/bin/unopkg; do
                    if [ -x "$candidate" ]; then
                        UNOPKG_BIN="$candidate"
                        break
                    fi
                done
            else
                for candidate in "/c/Program Files/LibreOffice/program/unopkg.com" "/c/Program Files/LibreOffice/program/unopkg.exe" "/c/Program Files (x86)/LibreOffice/program/unopkg.com" "/c/Program Files (x86)/LibreOffice/program/unopkg.exe"; do
                    if [ -x "$candidate" ]; then
                        UNOPKG_BIN="$candidate"
                        break
                    fi
                done
            fi
        fi
        if [ -z "$UNOPKG_BIN" ]; then
            echo "❌ unopkg introuvable. Installez manuellement via LibreOffice."
            exit 1
        fi
        echo "Installation de l'extension via unopkg..."
        "$UNOPKG_BIN" add --replace "${EXTENSION_NAME}.oxt" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            echo "Option --replace non supportée, tentative via remove + add..."
            "$UNOPKG_BIN" remove "fr.gouv.interieur.mirai" >/dev/null 2>&1 || true
            printf "yes\n" | "$UNOPKG_BIN" add "${EXTENSION_NAME}.oxt"
            if [ $? -ne 0 ]; then
                echo "❌ Erreur lors de l'installation avec unopkg"
                exit 1
            fi
        fi
        echo "✅ Extension installée"
        if [ "$RESTART_LIBREOFFICE" = true ]; then
            echo "Relance de LibreOffice..."
            open -a "LibreOffice"
        fi
    else
        echo ""
        echo "Pour installer :"
        echo "  1. Ouvrez LibreOffice"
        echo "  2. Outils → Gestionnaire des extensions"
        echo "  3. Ajouter → Sélectionnez ${EXTENSION_NAME}.oxt"
        echo ""
        echo "Ou via la ligne de commande :"
        echo "  unopkg add ${EXTENSION_NAME}.oxt"
    fi
else
    echo "❌ Erreur lors de la création du package"
    exit 1
fi
