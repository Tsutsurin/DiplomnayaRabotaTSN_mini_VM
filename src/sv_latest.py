# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

import pandas as pd
from bs4 import BeautifulSoup
from selenium.webdriver.common.by import By
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located,
)
from selenium.webdriver.support.ui import WebDriverWait

from .html_parser import BrowserHTMLParser
from .db import url_exists

BASE_URL = 'https://securityvulnerability.io'
LATEST_URL = f'{BASE_URL}/vulnerability/latest'


# ---------------------------------------------------------------------------
# Вспомогательные утилиты
# ---------------------------------------------------------------------------

def _text_or_none(node) -> Optional[str]:
    if not node:
        return None
    txt = ' '.join(str(node.get_text(' ', strip=True)).split())
    return txt or None


def _get_main_text(soup: BeautifulSoup) -> str:
    main = soup.find('main') or soup.body or soup
    text = main.get_text(' ', strip=True)
    return ' '.join(text.split())


def _scroll_latest_page(
    parser: BrowserHTMLParser,
    wait_seconds: int = 30,
    pause: float = 1.0,
    max_rounds: int = 80,
    stable_rounds: int = 5,
) -> str:
    driver = parser.driver
    driver.get(LATEST_URL)

    WebDriverWait(driver, wait_seconds).until(
        presence_of_element_located((By.CSS_SELECTOR, 'a[href^="/vulnerability/CVE-"]')),
    )

    last_height = 0
    same_count = 0
    rounds = 0

    while rounds < max_rounds and same_count < stable_rounds:
        new_height = driver.execute_script('return document.body.scrollHeight') or 0
        if new_height <= last_height:
            same_count += 1
        else:
            same_count = 0
            last_height = new_height

        driver.execute_script('window.scrollTo(0, document.body.scrollHeight);')
        time.sleep(pause)
        rounds += 1

    return driver.page_source or ''


def _extract_latest_links(html: str) -> List[str]:
    soup = BeautifulSoup(html, 'html.parser')
    urls: List[str] = []

    for a in soup.select('a[href*="/vulnerability/CVE-"]'):
        href = a.get('href') or ''
        if '/vulnerability/CVE-' not in href:
            continue
        full = href if href.startswith('http') else BASE_URL + href
        urls.append(full)

    # удаляем дубликаты, сохраняя порядок
    seen: set[str] = set()
    uniq: List[str] = []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        uniq.append(u)
    return uniq


def _parse_vendor_product_from_vendor_links(
    soup: BeautifulSoup,
) -> tuple[Optional[str], Optional[str]]:
    vendor_links = soup.select('a[href^="/vendor/"]')
    vendors: List[str] = []
    products: List[str] = []

    for a in vendor_links:
        href = a.get('href') or ''
        if not href.startswith('/vendor/'):
            continue
        parts = href.split('/')
        if len(parts) < 4:
            continue
        vendor_raw = parts[2] or ''
        product_raw = parts[3] or ''

        if vendor_raw:
            v = vendor_raw.replace('%20', ' ')
            v = re.sub(r'\s+', ' ', v).strip()
            if v:
                vendors.append(v)

        if product_raw:
            p = product_raw.replace('%20', ' ')
            p = p.replace('-', ' ')
            p = re.sub(r'\s+', ' ', p).strip()
            if p:
                products.append(p)

    vendors_str = ', '.join(sorted(set(vendors))) if vendors else None
    products_str = ', '.join(sorted(set(products))) if products else None
    return vendors_str, products_str


# ---------------------------------------------------------------------------
# CVSS / severity
# ---------------------------------------------------------------------------

def _parse_cvss_and_severity(
    soup: BeautifulSoup,
) -> tuple[Optional[str], Optional[str]]:
    cvss_block = soup.find(
        lambda tag: tag.name in ('section', 'div', 'article')
        and 'CVSS' in tag.get_text(),
    )
    if not cvss_block:
        cvss_block = soup

    score_val: Optional[str] = None
    severity_val: Optional[str] = None

    for s in cvss_block.stripped_strings:
        m = re.search(r'\b(CRITICAL|HIGH|MEDIUM|LOW)\b', s, re.IGNORECASE)
        if m:
            severity_val = m.group(1).upper()
            break

    for tag in cvss_block.find_all(string=re.compile(r'(Score|CVSS)', re.IGNORECASE)):
        txt = tag.parent.get_text(' ', strip=True)
        m = re.search(r'(?:Score|CVSS)\s*[:\-]?\s*([0-9]{1,2}(?:\.[0-9])?)', txt)
        if m:
            score_val = m.group(1)
            break

    if score_val is None:
        for el in cvss_block.find_all(['span', 'div', 'p']):
            txt = el.get_text(strip=True)
            if not re.fullmatch(r'[0-9]{1,2}(?:\.[0-9])?', txt):
                continue
            parent_txt = el.parent.get_text(' ', strip=True)
            if re.search(r'(Score|CVSS)', parent_txt, re.IGNORECASE):
                score_val = txt
                break

    return score_val, severity_val


# ---------------------------------------------------------------------------
# Разбор даты Published
# ---------------------------------------------------------------------------

_MONTHS = {
    'january': 1,
    'february': 2,
    'march': 3,
    'april': 4,
    'may': 5,
    'june': 6,
    'july': 7,
    'august': 8,
    'september': 9,
    'october': 10,
    'november': 11,
    'december': 12,
    'jan': 1,
    'feb': 2,
    'mar': 3,
    'apr': 4,
    'jun': 6,
    'jul': 7,
    'aug': 8,
    'sep': 9,
    'sept': 9,
    'oct': 10,
    'nov': 11,
    'dec': 12,
}


def _format_date_ddmmyyyy(day: int, month: int, year: int) -> str:
    return f'{day:02d}.{month:02d}.{year:04d}'


def _extract_date_from_chunk(chunk: str) -> Optional[str]:
    m = re.search(r'(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})', chunk)
    if m:
        day = int(m.group(1))
        month_name = m.group(2).lower()
        year = int(m.group(3))
        month = _MONTHS.get(month_name)
        if month:
            return _format_date_ddmmyyyy(day, month, year)

    m = re.search(r'([A-Za-z]+)\s+(\d{1,2}),\s*(\d{4})', chunk)
    if m:
        month_name = m.group(1).lower()
        day = int(m.group(2))
        year = int(m.group(3))
        month = _MONTHS.get(month_name)
        if month:
            return _format_date_ddmmyyyy(day, month, year)

    return None


def _parse_published(soup: BeautifulSoup) -> Optional[str]:
    text = _get_main_text(soup)
    low = text.lower()
    idx = low.find('published')
    if idx == -1:
        return None

    start = max(0, idx)
    end = min(len(text), idx + 120)
    chunk = text[start:end]

    return _extract_date_from_chunk(chunk)


def _parse_versions(soup: BeautifulSoup) -> Optional[str]:
    text = _get_main_text(soup)
    m = re.search(
        r'Affected Version\(s\)\s*(.+?)\s*References',
        text,
        flags=re.IGNORECASE,
    )
    if not m:
        return None
    versions = m.group(1).strip()
    return versions or None


# ---------------------------------------------------------------------------
# Основной разбор страницы CVE
# ---------------------------------------------------------------------------

def _parse_detail_html(html: str, url: str) -> Dict[str, Any]:
    """Парсит страницу конкретной уязвимости."""
    soup = BeautifulSoup(html, 'html.parser')

    result: Dict[str, Any] = {
        'CVE': None,
        'Заголовок': None,
        'Вендор': None,
        'Продукт': None,
        'Опубликовано': None,
        'CVSS': None,
        'Критичность': None,
        'Источник': url,
    }

    # CVE: сперва из URL
    m = re.search(r'(CVE-\d{4}-\d+)', url, re.IGNORECASE)
    if m:
        result['CVE'] = m.group(1).upper()
    else:
        node = soup.find(string=re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE))
        if node:
            m2 = re.search(r'CVE-\d{4}-\d+', node, re.IGNORECASE)
            if m2:
                result['CVE'] = m2.group(0).upper()

    # заголовок
    h1 = soup.find('h1')
    result['Заголовок'] = _text_or_none(h1) or _text_or_none(soup.find('title'))

    # вендор и базовый продукт
    vendor_str, base_product_str = _parse_vendor_product_from_vendor_links(soup)
    result['Вендор'] = vendor_str

    # версии (между Affected Version(s) и References) -> 'продукт + версия'
    versions_str = _parse_versions(soup)
    result['Продукт'] = versions_str or base_product_str

    # дата публикации
    result['Опубликовано'] = _parse_published(soup)

    # CVSS / severity
    score, sev = _parse_cvss_and_severity(soup)
    result['CVSS'] = score
    result['Критичность'] = sev

    return result


# ---------------------------------------------------------------------------
# Раскрытие кнопок 'View more...'
# ---------------------------------------------------------------------------

def _expand_view_more(driver) -> None:
    for _ in range(3):
        try:
            buttons = driver.find_elements(
                By.XPATH,
                "//*[contains(translate(normalize-space(.), "
                "'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), "
                "'view more')]",
            )
        except Exception:
            break

        if not buttons:
            break

        for btn in buttons:
            try:
                driver.execute_script(
                    'arguments[0].scrollIntoView({block:"center"});',
                    btn,
                )
                time.sleep(0.2)
                btn.click()
                time.sleep(0.5)
            except Exception:
                continue


def _fetch_detail(
    parser: BrowserHTMLParser,
    url: str,
    wait_seconds: int = 30,
) -> Dict[str, Any]:
    driver = parser.driver
    driver.get(url)
    WebDriverWait(driver, wait_seconds).until(
        presence_of_element_located((By.CSS_SELECTOR, 'h1, h2')),
    )

    _expand_view_more(driver)

    html = driver.page_source or ''
    return _parse_detail_html(html, url)


# ---------------------------------------------------------------------------
# Публичная функция
# ---------------------------------------------------------------------------

def scrape_latest(
    headless: bool = True,
    wait_seconds: int = 30,
    status_q: Optional[Any] = None,
    progress_q: Optional[Any] = None,
) -> pd.DataFrame:
    parser = BrowserHTMLParser(headless=headless)
    try:
        if status_q:
            status_q.put('[sv_latest] Открываю страницу последних уязвимостей...')

        html = _scroll_latest_page(parser, wait_seconds=wait_seconds)

        urls = _extract_latest_links(html)
        if status_q:
            status_q.put(f'[sv_latest] Найдено ссылок на уязвимости: {len(urls)}')

        if progress_q:
            progress_q.put(('TOTAL', len(urls)))

        rows: List[Dict[str, Any]] = []
        total = len(urls)

        for idx, url in enumerate(urls, start=1):
            try:
                if url_exists(url, source='news'):
                    if status_q:
                        status_q.put(
                            f'[sv_latest] URL уже есть в БД ({url}), '
                            'останавливаю парсинг новостей.',
                        )
                    break

                data = _fetch_detail(parser, url, wait_seconds=wait_seconds)
                rows.append(data)
                if status_q:
                    cve = data.get('CVE') or ''
                    status_q.put(f'[sv_latest] [{idx}/{total}] {cve} OK')
            except Exception as exc:
                if status_q:
                    status_q.put(f'[sv_latest] Ошибка парсинга {url}: {exc}')
            finally:
                if progress_q:
                    progress_q.put(1)

        return pd.DataFrame.from_records(rows)

    finally:
        try:
            parser.close()
        except Exception:
            pass
