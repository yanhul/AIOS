"""AIOS executable entry point.

Usage:
    python aios.py inspect RX50
    python aios.py snapshot RX50 [--id SNAP-...]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli.aios import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
