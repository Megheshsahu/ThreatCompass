#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ThreatCompass - Security Reconnaissance Tool
# Author: Meghesh Sahu (GitHub: @Megheshsahu)
# Repository: https://github.com/Megheshsahu/ThreatCompass
# Copyright (c) 2025 Meghesh Sahu. All rights reserved.
#
# This software is protected by copyright. Unauthorized removal of attribution
# or modification of copyright notices is prohibited.
#
# Build Hash: 0x4d534832303235  (MS-H-2025)
# Project ID: TC-1.0-MEGHESH-SAHU
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
