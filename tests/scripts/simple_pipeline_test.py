#!/usr/bin/env python3
# Moved from project root for pytest-friendly discovery

from pathlib import Path
import runpy

orig = Path(__file__).resolve().parents[2] / 'simple_pipeline_test.py'
if orig.exists():
    runpy.run_path(str(orig), run_name='__main__')
