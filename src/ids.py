# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from typing import Tuple, List

_ID_RE = re.compile(r'^\d{4}-\d+$')


def validate_vuln_id(vuln_id: str) -> bool:
    return bool(_ID_RE.match(vuln_id))


def _split_id(vuln_id: str) -> Tuple[int, int, int]:
    year_str, num_str = vuln_id.split('-')
    return int(year_str), int(num_str), len(num_str)


def subtract_steps(last_id: str, steps: int) -> str:
    year, num, width = _split_id(last_id)
    num = max(0, num - max(0, steps))
    return f'{year}-{num:0{width}d}'


def iter_ids(start_id: str, end_id: str) -> List[str]:
    y1, n1, w1 = _split_id(start_id)
    y2, n2, w2 = _split_id(end_id)
    if y1 != y2 or n2 < n1:
        raise ValueError('Диапазон должен быть в рамках одного года и end ≥ start.')
    width = max(w1, w2)
    return [f'{y1}-{i:0{width}d}' for i in range(n1, n2 + 1)]
