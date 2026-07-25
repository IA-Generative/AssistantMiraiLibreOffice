"""Enregistrement des tools UNO du moteur."""

from . import calc_tools, writer_tools


def register_all(registry):
    writer_tools.register(registry)
    calc_tools.register(registry)
    return registry
