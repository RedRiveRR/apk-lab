"""Bundled plugins.

Every ``*.py`` here is imported once at start-up and may register one or more
checks with ``websec.registry.module``. A plugin that fails to import is listed by
``websec plugins`` and never stops a scan. External plugin folders use absolute
imports (``from websec.registry import module``) because they are not part of
this package.
"""
