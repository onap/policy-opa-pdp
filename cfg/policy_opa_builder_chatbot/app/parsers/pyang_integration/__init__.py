# pyang_integration/__init__.py
"""
YANG-specific parser implementation and helpers.

This package depends on pyang and contains:
- YangParser: concrete Parser for the YANG workflow
- pyang repository wrapper
- module discovery (module name extraction + precedence)
- pathing utilities (prefix-less path rendering)
- type utilities (union/leafref/range/length/default/description)
- MO selection logic (local and augment; Object-Parent rule)
- walkers (augment first, then local)
"""
