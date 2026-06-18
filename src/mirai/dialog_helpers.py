"""Compatibility layer for dialog helpers moved under `mirai.ui`."""

from .ui.common_dialogs import (
    show_credentials_box,
    show_input_box,
    show_proxy_settings_box,
)

__all__ = [
    "show_credentials_box",
    "show_input_box",
    "show_proxy_settings_box",
]
