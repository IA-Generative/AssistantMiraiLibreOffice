# Moteur MCP interne — voir docs/ARCHITECTURE.md.
# Ce package ne doit JAMAIS importer le module coquille (MainJob) — règle
# d'architecture vérifiée par un test dédié (tests/unit/core/). Aucun import au
# chargement : le pythonloader de LibreOffice charge la coquille à chaque
# démarrage et ne doit payer aucun coût tant que la palette n'est pas ouverte.
