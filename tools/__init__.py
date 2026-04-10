"""
Aegis tools package — module capability detection.

Every tool module in this package exposes some subset of these functions:

    install()    — install the package(s) for this tool
    configure()  — write config files / enable services
    check()      — return True if the tool is present/active
    status()     — return a human-readable status string

Not all modules implement every function (e.g. a tool may have no
meaningful configure() step).  Rather than crashing when setup.py
calls a missing function, use the helpers here to introspect modules
before calling them.
"""

import importlib
import types
from pathlib import Path
from typing import Callable, Optional

# The four standard functions every module may (or may not) implement.
MODULE_FUNCTIONS = ("install", "configure", "check", "status")


def has_function(module: types.ModuleType, fn_name: str) -> bool:
    """Return True if *module* exposes a callable named *fn_name*."""
    return callable(getattr(module, fn_name, None))


def get_function(module: types.ModuleType, fn_name: str) -> Optional[Callable]:
    """
    Return the callable *fn_name* from *module*, or None if absent.

    Usage::

        fn = get_function(isolation, "configure")
        if fn:
            fn()
    """
    attr = getattr(module, fn_name, None)
    return attr if callable(attr) else None


def call_if_present(module: types.ModuleType, fn_name: str, *args, **kwargs):
    """
    Call *module*.*fn_name*(*args, **kwargs) if it exists.

    Returns the function's return value, or None if the function is absent.
    """
    fn = get_function(module, fn_name)
    return fn(*args, **kwargs) if fn is not None else None


def capabilities(module: types.ModuleType) -> dict:
    """
    Return a dict describing which standard functions *module* implements.

    Example::

        >>> capabilities(isolation)
        {'install': True, 'configure': False, 'check': True, 'status': True}
    """
    return {fn: has_function(module, fn) for fn in MODULE_FUNCTIONS}


def capabilities_report() -> str:
    """
    Scan every .py file in this directory and return a formatted table
    showing which standard functions each module implements.

    Useful for debugging and the --status view.
    """
    tools_dir = Path(__file__).parent
    lines = [
        f"{'Module':<22} {'install':>7} {'configure':>9} {'check':>5} {'status':>6}",
        "-" * 55,
    ]

    for py_file in sorted(tools_dir.glob("*.py")):
        if py_file.name == "__init__.py":
            continue
        mod_name = f"tools.{py_file.stem}"
        try:
            mod = importlib.import_module(mod_name)
            caps = capabilities(mod)
            row = (
                f"{py_file.stem:<22}"
                f" {'yes' if caps['install'] else '-':>7}"
                f" {'yes' if caps['configure'] else '-':>9}"
                f" {'yes' if caps['check'] else '-':>5}"
                f" {'yes' if caps['status'] else '-':>6}"
            )
            lines.append(row)
        except Exception as exc:
            lines.append(f"{py_file.stem:<22}  [import error: {exc}]")

    return "\n".join(lines)
