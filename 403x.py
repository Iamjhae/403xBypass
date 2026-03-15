#!/usr/bin/env python3
"""
403x - Advanced 403 Bypass Recon Framework
Entry point — delegates to forbiddenx.cli
"""
import sys
import os

# Locate the forbiddenx package relative to this script,
# regardless of which directory the user runs from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from forbiddenx.cli import main

if __name__ == "__main__":
    main()
