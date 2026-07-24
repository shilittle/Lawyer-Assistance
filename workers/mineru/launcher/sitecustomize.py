"""Start the managed worker before CPython enters interactive mode."""

from __future__ import annotations

import os
import sys


sys.dont_write_bytecode = True

if os.environ.get("LA_MINERU_PROTOCOL_VERSION") == "la-mineru-worker-v1":
    from lawyer_assistance_mineru_worker.main import bootstrap

    bootstrap()
