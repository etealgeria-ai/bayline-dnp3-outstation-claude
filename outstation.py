"""Windows-friendly launcher. Run: python outstation.py"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from bayline.__main__ import main

if __name__ == "__main__":
    main()
