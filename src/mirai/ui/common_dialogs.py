"""Common dialogs extracted from MainJob."""

from .base import DialogBuilder


def show_proxy_settings_box(job, title="Proxy", x=None, y=None, ui=None, log_func=None):
    ui = ui or {}
    log_func = log_func or (lambda _message: None)

    import unohelper
    from com.sun.star.awt import XActionListener

    width = 640
    hori_margin = 16
    vert_margin = 12
    label_height = 20
    edit_height = 28
    button_width = 140
    button_height = 30
    hori_sep = 10
    vert_sep = 8

    cfg = job._get_proxy_config()
    lo = job._lo_proxy_settings()
    proxy_url_value = cfg["proxy_url"]
    if not proxy_url_value and lo["host"]:
        proxy_url_value = f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]

    height = vert_margin * 2 + (label_height + edit_height + vert_sep) * 5 + button_height * 2 + vert_sep * 6 + 20
    builder = DialogBuilder(title, width, height, log_func=log_func)

    current_y = vert_margin
    builder.add("label_proxy", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": "Paramètres proxy", "NoLabel": True,
        "FontHeight": ui["font_section"],
        "TextColor": ui["primary"],
        "FontWeight": 150,
    })
    current_y += label_height + vert_sep

    builder.add("label_enabled", "FixedText", hori_margin, current_y, 200, label_height, {
        "Label": "Utiliser un proxy :", "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    chk_enabled = builder.add("chk_enabled", "CheckBox", hori_margin + 210, current_y, 50, label_height, {
        "State": 1 if cfg["enabled"] else 0,
    })
    current_y += label_height + vert_sep

    builder.add("label_url", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": "Proxy (host:port) :", "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    current_y += label_height + vert_sep
    edit_url = builder.add("edit_url", "Edit", hori_margin, current_y, width - hori_margin * 2, edit_height, {
        "Text": proxy_url_value,
        "BackgroundColor": ui["bg_input"],
    })
    current_y += edit_height + vert_sep * 2

    builder.add("label_user", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": "Login proxy (optionnel) :", "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text_secondary"],
    })
    current_y += label_height + vert_sep
    edit_user = builder.add("edit_user", "Edit", hori_margin, current_y, width - hori_margin * 2, edit_height, {
        "Text": cfg["username"],
        "BackgroundColor": ui["bg_input"],
    })
    current_y += edit_height + vert_sep * 2

    builder.add("label_pass", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": "Mot de passe proxy (optionnel) :", "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text_secondary"],
    })
    current_y += label_height + vert_sep
    edit_pass = builder.add("edit_pass", "Edit", hori_margin, current_y, width - hori_margin * 2, edit_height, {
        "Text": cfg["password"],
        "EchoChar": ord("*"),
        "BackgroundColor": ui["bg_input"],
    })
    current_y += edit_height + vert_sep * 2

    builder.add("label_insecure", "FixedText", hori_margin, current_y, 260, label_height, {
        "Label": "Autoriser HTTPS sans vérification (-k) :",
        "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    chk_insecure = builder.add("chk_insecure", "CheckBox", hori_margin + 270, current_y, 50, label_height, {
        "State": 1 if cfg["allow_insecure_ssl"] else 0,
    })
    current_y += label_height + vert_sep * 2

    builder.add("line_lo_info", "FixedLine", hori_margin, current_y, width - hori_margin * 2, 2, {})
    current_y += vert_sep

    lo_text = "Proxy LibreOffice : "
    if lo["enabled"] and lo["host"]:
        lo_text += f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]
    else:
        lo_text += "désactivé"
    builder.add("label_lo", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": lo_text,
        "NoLabel": True,
        "FontHeight": ui["font_small"],
        "TextColor": ui["text_light"],
    })
    current_y += label_height + vert_sep * 2

    btn_test = builder.add("btn_test", "Button", hori_margin, current_y, button_width + 20, button_height, {
        "Label": "Tester connexion",
        "Name": "test_proxy",
        "FontHeight": ui["font_small"],
    })
    btn_copy = builder.add("btn_copy", "Button", hori_margin + button_width + 30, current_y, button_width + 40, button_height, {
        "Label": "Copier depuis LibreOffice",
        "Name": "copy_lo",
        "FontHeight": ui["font_small"],
    })
    current_y += button_height + vert_sep * 2

    builder.add("line_before_proxy_btns", "FixedLine", hori_margin, current_y, width - hori_margin * 2, 2, {})
    current_y += vert_sep

    builder.add("btn_ok", "Button", width - hori_margin - button_width * 2 - hori_sep, current_y, button_width, button_height, {
        "PushButtonType": 1,
        "DefaultButton": True,
        "Label": "Enregistrer",
        "FontHeight": ui["font_label"],
    })
    builder.add("btn_cancel", "Button", width - hori_margin - button_width, current_y, button_width, button_height, {
        "PushButtonType": 2,
        "Label": "Annuler",
        "FontHeight": ui["font_label"],
    })

    window = builder.current_window()
    builder.create_peer(window)
    builder.position(x=x, y=y, window=window, use_twip=True)

    class ProxyActionListener(unohelper.Base, XActionListener):
        def actionPerformed(self, event):
            try:
                command = getattr(event, "ActionCommand", "") or ""
            except Exception:
                command = ""
            if not command:
                try:
                    source = getattr(event, "Source", None)
                    command = getattr(source.getModel(), "Name", "") if source else ""
                except Exception:
                    command = ""

            if command == "copy_lo":
                try:
                    if lo["enabled"] and lo["host"]:
                        url = f"{lo['host']}:{lo['port']}" if lo["port"] else lo["host"]
                        edit_url.getModel().Text = url
                        chk_enabled.getModel().State = 1
                    else:
                        chk_enabled.getModel().State = 0
                except Exception:
                    pass
            elif command == "test_proxy":
                try:
                    proxy_cfg = {
                        "enabled": bool(chk_enabled.getModel().State),
                        "proxy_url": str(edit_url.getModel().Text).strip(),
                        "username": str(edit_user.getModel().Text).strip(),
                        "password": str(edit_pass.getModel().Text),
                        "allow_insecure_ssl": bool(chk_insecure.getModel().State),
                    }
                    ok, message = job._test_proxy_connection(proxy_cfg)
                    job._show_message("Test proxy", message if ok else f"Échec: {message}")
                except Exception as exc:
                    job._show_message("Test proxy", f"Échec: {str(exc)}")

        def disposing(self, event):
            return

    listener = ProxyActionListener()
    if btn_test:
        try:
            btn_test.addActionListener(listener)
            btn_test.getModel().ActionCommand = "test_proxy"
        except Exception:
            pass
    if btn_copy:
        try:
            btn_copy.addActionListener(listener)
            btn_copy.getModel().ActionCommand = "copy_lo"
        except Exception:
            pass

    result = {}
    if builder.execute():
        try:
            result["proxy_enabled"] = bool(chk_enabled.getModel().State)
            result["proxy_url"] = str(edit_url.getModel().Text).strip()
            result["proxy_username"] = str(edit_user.getModel().Text).strip()
            result["proxy_password"] = str(edit_pass.getModel().Text)
            result["proxy_allow_insecure_ssl"] = bool(chk_insecure.getModel().State)
            job.set_config("proxy_enabled", result["proxy_enabled"])
            job.set_config("proxy_url", result["proxy_url"])
            job.set_config("proxy_username", result["proxy_username"])
            job.set_config("proxy_password", result["proxy_password"])
            job.set_config("proxy_allow_insecure_ssl", result["proxy_allow_insecure_ssl"])
        except Exception:
            pass
    builder.dispose()
    return result


def show_input_box(
    job,
    message,
    title="",
    default="",
    x=None,
    y=None,
    ok_label="OK",
    cancel_label="Annuler",
    always_on_top=False,
    ui=None,
    log_func=None,
):
    del job, cancel_label

    ui = ui or {}
    log_func = log_func or (lambda _message: None)

    width = 720
    hori_margin = 8
    vert_margin = 8
    button_width = 100
    button_height = 30
    vert_sep = 8
    label_height = 26
    edit_height = 80
    height = vert_margin * 2 + label_height + vert_sep + edit_height + vert_sep + button_height + vert_margin

    builder = DialogBuilder(title, width, height, background_color=ui.get("bg"), log_func=log_func)
    if always_on_top:
        try:
            builder.model.AlwaysOnTop = True
        except Exception:
            pass
        try:
            builder.model.Closeable = True
        except Exception:
            pass
    try:
        builder.dialog.getModel().Sizeable = True
    except Exception:
        pass

    edit_y = vert_margin + label_height + vert_sep
    btn_y = edit_y + edit_height + vert_sep
    builder.add("label", "FixedText", hori_margin, vert_margin, width - hori_margin * 2, label_height, {
        "Label": str(message),
        "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    builder.add("edit", "Edit", hori_margin, edit_y, width - hori_margin * 2, edit_height, {
        "Text": str(default),
        "MultiLine": True,
        "BackgroundColor": ui["bg_input"],
    })
    builder.add("btn_ok", "Button", width - hori_margin - button_width, btn_y, button_width, button_height, {
        "PushButtonType": 1,
        "DefaultButton": True,
        "Label": ok_label,
    })

    window = builder.current_window()
    builder.create_peer(window)
    builder.position(x=x, y=y, window=window, use_twip=True)

    edit = builder.dialog.getControl("edit")
    edit.setSelection(builder._uno.createUnoStruct("com.sun.star.awt.Selection", 0, len(str(default))))
    edit.setFocus()
    result = edit.getModel().Text if builder.execute() else ""
    builder.dispose()
    return result


def show_credentials_box(job, title="Device Management", login_label="Login", password_label="Mot de passe", ui=None, log_func=None):
    del job

    ui = ui or {}
    log_func = log_func or (lambda _message: None)

    import unohelper
    from com.sun.star.awt import XActionListener

    width = 540
    hori_margin = 16
    vert_margin = 14
    button_width = 110
    button_height = 30
    hori_sep = 10
    vert_sep = 8
    label_height = 20
    edit_height = 28
    toggle_width = 90
    height = vert_margin * 2 + (label_height + edit_height + vert_sep) * 2 + button_height + vert_sep * 2

    builder = DialogBuilder(title, width, height, background_color=ui.get("bg"), log_func=log_func)

    current_y = vert_margin
    builder.add("section_auth", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": "Authentification",
        "NoLabel": True,
        "FontHeight": ui["font_section"],
        "TextColor": ui["primary"],
        "FontWeight": 150,
    })
    current_y += label_height + vert_sep

    builder.add("label_login", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": str(login_label),
        "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    current_y += label_height + vert_sep
    builder.add("edit_login", "Edit", hori_margin, current_y, width - hori_margin * 2, edit_height, {
        "Text": "",
        "BackgroundColor": ui["bg_input"],
    })
    current_y += edit_height + vert_sep

    builder.add("label_password", "FixedText", hori_margin, current_y, width - hori_margin * 2, label_height, {
        "Label": str(password_label),
        "NoLabel": True,
        "FontHeight": ui["font_label"],
        "TextColor": ui["text"],
    })
    current_y += label_height + vert_sep
    password_width = width - hori_margin * 2 - toggle_width - hori_sep
    builder.add("edit_password", "Edit", hori_margin, current_y, password_width, edit_height, {
        "Text": "",
        "EchoChar": ord("*"),
        "BackgroundColor": ui["bg_input"],
    })
    builder.add("btn_toggle", "Button", hori_margin + password_width + hori_sep, current_y, toggle_width, edit_height, {
        "Label": "Afficher",
        "FontHeight": ui["font_small"],
    })

    current_y += edit_height + vert_sep * 2
    builder.add("line_before_btns", "FixedLine", hori_margin, current_y, width - hori_margin * 2, 2, {})
    current_y += vert_sep

    builder.add("btn_ok", "Button", width - hori_margin - button_width * 2 - hori_sep, current_y, button_width, button_height, {
        "PushButtonType": 1,
        "DefaultButton": True,
        "FontHeight": ui["font_label"],
    })
    builder.add("btn_cancel", "Button", width - hori_margin - button_width, current_y, button_width, button_height, {
        "PushButtonType": 2,
        "Label": "Annuler",
        "FontHeight": ui["font_label"],
    })

    window = builder.current_window()
    builder.create_peer(window)
    builder.position(window=window)

    edit_login = builder.dialog.getControl("edit_login")
    edit_password = builder.dialog.getControl("edit_password")
    btn_toggle = builder.dialog.getControl("btn_toggle")
    is_masked = {"value": True}

    class ToggleListener(unohelper.Base, XActionListener):
        def actionPerformed(self, event):
            is_masked["value"] = not is_masked["value"]
            try:
                edit_password.getModel().EchoChar = ord("*") if is_masked["value"] else 0
            except Exception:
                pass
            try:
                btn_toggle.getModel().Label = "Afficher" if is_masked["value"] else "Masquer"
            except Exception:
                pass

        def disposing(self, event):
            return

    try:
        btn_toggle.addActionListener(ToggleListener())
    except Exception:
        pass

    edit_login.setFocus()
    ok = builder.execute()
    username = edit_login.getModel().Text.strip() if ok else ""
    password = edit_password.getModel().Text if ok else ""
    builder.dispose()
    return username, password
