"""Enregistrement des tools UNO du moteur."""

from . import writer_tools, calc_tools


def register_all(registry):
    writer_tools.register(registry)
    calc_tools.register(registry)
    return registry
