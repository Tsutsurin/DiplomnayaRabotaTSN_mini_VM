# -*- coding: utf-8 -*-
from __future__ import annotations

import os
import multiprocessing as mp
from typing import List, Optional, Dict

import pandas as pd

from src.html_parser import BrowserHTMLParser
from src.vulnerability_parser import VulnerabilityParser
from src.exceptions import PageNotFoundError, PageLoadError


def _emit(status_q: Optional[mp.Queue], text: str) -> None:
    if status_q is None:
        return
    try:
        status_q.put(text, block=False)
    except Exception:
        pass


def _flush_parts(
    out_dir: str,
    rows: List[dict],
    reserved: List[str],
    missed404: List[str],
    prefix: str = '',
) -> None:
    os.makedirs(out_dir, exist_ok=True)
    pid = os.getpid()

    if rows:
        pd.DataFrame(rows).to_csv(
            os.path.join(out_dir, f'{prefix}part_{pid}.csv'),
            index=False,
            encoding='utf-8-sig',
        )

    if reserved:
        with open(
            os.path.join(out_dir, f'{prefix}reserved_part_{pid}.txt'),
            'w',
            encoding='utf-8',
        ) as f:
            f.write('\n'.join(reserved))

    if missed404:
        with open(
            os.path.join(out_dir, f'{prefix}missed404_part_{pid}.txt'),
            'w',
            encoding='utf-8',
        ) as f:
            f.write('\n'.join(missed404))


def worker_loop(
    task_ids: List[str],
    out_dir: str,
    progress_q: Optional[mp.Queue],
    status_q: Optional[mp.Queue],
) -> None:
    base_url = 'https://bdu.fstec.ru/vul/'
    rows: List[Dict] = []
    reserved: List[str] = []
    missed404: List[str] = []

    try:
        driver = BrowserHTMLParser(headless=True)
        for w in getattr(driver, 'warnings', []) or []:
            _emit(status_q, w)
    except Exception:
        for vid in task_ids:
            url = f'{base_url}{vid}'
            _emit(status_q, f'Сбор информации с {url}... Пропущено!')
            reserved.append(url)
            if progress_q is not None:
                try:
                    progress_q.put(1, block=False)
                except Exception:
                    pass
        _flush_parts(out_dir, rows, reserved, missed404)
        return

    parser = VulnerabilityParser()

    for vuln_id in task_ids:
        url = f'{base_url}{vuln_id}'
        status_sent = False
        try:
            html = None
            try:
                html = driver.fetch_html(url, wait_time=5)
            except PageNotFoundError:
                _emit(status_q, f'Сбор информации с {url}... Ошибка 404')
                missed404.append(url)
                status_sent = True
            except PageLoadError:
                _emit(status_q, f'Сбор информации с {url}... Пропущено!')
                reserved.append(url)
                status_sent = True
            except Exception:
                _emit(status_q, f'Сбор информации с {url}... Пропущено!')
                reserved.append(url)
                status_sent = True

            if html:
                try:
                    df = parser.parse_vulnerability_data(html, url)
                    has_skip = (
                        ('should_skip' in df.columns)
                        or ('should_stop' in df.columns)
                    )
                    if not df.empty and not has_skip:
                        rows.extend(df.to_dict(orient='records'))
                        _emit(status_q, f'Сбор информации с {url}... Успешно!')
                        status_sent = True
                    else:
                        _emit(status_q, f'Сбор информации с {url}... Пропущено!')
                        reserved.append(url)
                        status_sent = True
                except Exception:
                    _emit(status_q, f'Сбор информации с {url}... Пропущено!')
                    reserved.append(url)
                    status_sent = True
        finally:
            if not status_sent:
                _emit(status_q, f'Сбор информации с {url}... Пропущено!')
                reserved.append(url)
            if progress_q is not None:
                try:
                    progress_q.put(1, block=False)
                except Exception:
                    pass

    _flush_parts(out_dir, rows, reserved, missed404)
    try:
        driver.close()
    except Exception:
        pass
