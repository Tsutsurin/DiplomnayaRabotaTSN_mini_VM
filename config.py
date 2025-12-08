# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import sys
from pathlib import Path


def _root_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(os.path.dirname(sys.executable)).resolve()
    return Path(__file__).parent.resolve()


ROOT_DIR = _root_dir()
BROWSER_DIR = ROOT_DIR / 'browser'
RESULTS_DIR = ROOT_DIR / 'results'

EDGE_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
)

for d in (BROWSER_DIR, RESULTS_DIR):
    d.mkdir(exist_ok=True)
