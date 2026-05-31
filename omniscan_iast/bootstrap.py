"""Bootstrap entrypoint for injecting the IAST agent at app start.

Matches the injection snippet the platform issues for the Python runtime:

    OMNISCAN_IAST_SESSION=<sid> OMNISCAN_COLLECTOR_URL=<url> OMNISCAN_IAST_TOKEN=<tok> \
        python -m omniscan_iast.bootstrap your_module:app

It instruments sinks (reporting to the collector from the env) and, if an
``app`` is named, wraps it as WSGI so request context is bound for taint correlation.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

from omniscan_iast.agent import instrument
from omniscan_iast.context import wrap_wsgi


def load_app(spec: str) -> Any:
    module_name, _, attr = spec.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, attr or "app")


def main(argv: list[str] | None = None) -> Any:
    argv = argv if argv is not None else sys.argv[1:]
    instrument()  # reads OMNISCAN_IAST_* from the environment
    if argv:
        app = load_app(argv[0])
        return wrap_wsgi(app)
    return None


if __name__ == "__main__":  # pragma: no cover
    main()
