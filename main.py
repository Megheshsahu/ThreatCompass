#!/usr/bin/env python3
"""
ThreatCompass Launcher
Main entry point for the ThreatCompass security reconnaissance tool.
"""

import sys
from pathlib import Path

# Import the main ThreatCompass module
try:
    from threatcompass import main
except ImportError:
    # If we can't import, try to run the module directly
    import subprocess
    script_path = Path(__file__).parent / "threatcompass.py"
    subprocess.run([sys.executable, str(script_path)] + sys.argv[1:])
    sys.exit(0)

if __name__ == "__main__":
    main()
