from __future__ import annotations

import time
import re
import json as _json
import html as _html
from typing import Optional, List

from selenium.webdriver import Chrome
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions

from src.exceptions import DriverNotFoundError, PageLoadError, PageNotFoundError
from src.browser_env import find_chrome_binaries
from config import EDGE_UA


class BrowserHTMLParser:
    def __init__(
        self,
        user_agent: Optional[str] = None,
        headless: bool = True,
        ignore_cert_errors: bool = True,
    ):
        self.driver = None
        self.warnings: List[str] = []
        last_err: Optional[Exception] = None

        chrome_path, chromedriver_path = find_chrome_binaries()
        if chrome_path and chromedriver_path:
            try:
                ua = user_agent or EDGE_UA
                options = ChromeOptions()
                if headless:
                    options.add_argument('--headless=new')
                options.add_argument('--disable-gpu')
                options.add_argument('--log-level=3')
                options.add_argument('--no-sandbox')
                options.add_argument('--window-size=1920,1080')
                options.add_argument('--disable-blink-features=AutomationControlled')
                if ignore_cert_errors:
                    options.add_argument('--ignore-certificate-errors')
                    options.add_argument('--allow-running-insecure-content')
                if ua:
                    options.add_argument(f'--user-agent={ua}')
                options.binary_location = str(chrome_path)

                self.driver = Chrome(
                    service=ChromeService(executable_path=str(chromedriver_path)),
                    options=options,
                )
            except Exception as e:
                last_err = e
                self.driver = None

        if self.driver is None:
            msg = (
                'Не удалось запустить Chrome (chrome + chromedriver).\n'
                'Проверьте содержимое папки browser/ и соответствие версий.\n'
                f'Последняя ошибка: {last_err!r}'
            )
            raise DriverNotFoundError(msg)

    def fetch_html(self, url: str, wait_time: int = 10, max_retries: int = 3) -> str:
        for attempt in range(max_retries):
            try:
                self.driver.get(url)
                time.sleep(wait_time)
                src = self.driver.page_source or ''
                if 'Ошибка 404' in src:
                    raise PageNotFoundError('Page not found (404)')
                return src
            except PageNotFoundError:
                raise
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(5)
                else:
                    raise PageLoadError(f'Failed to load {url} after {max_retries} attempts: {e}')

    def close(self) -> None:
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass


def _strip_bom_and_leading_junk(s: str) -> str:
    if not s:
        return s
    s = s.lstrip('\ufeff').strip()
    m = re.search(r'[\{\[]', s)
    if not m:
        return s
    return s[m.start():].strip()


def _extract_json_block(text: str) -> Optional[str]:
    if not text:
        return None

    in_tag = False
    in_str = False
    esc = False
    stack: List[str] = []

    start = -1
    for i, ch in enumerate(text):
        if in_tag:
            if ch == '>':
                in_tag = False
            continue

        if not in_str and ch == '<':
            in_tag = True
            continue

        if not in_str and ch in '{[':
            if start == -1:
                start = i
            stack.append(ch)
            continue

        if start != -1:
            if in_str:
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch in '}]':
                    if not stack:
                        end = i + 1
                        return text[start:end]
                    top = stack.pop()
                    if (top == '{' and ch == '}') or (top == '[' and ch == ']'):
                        if not stack:
                            end = i + 1
                            return text[start:end]

    return None


def _extract_json_from_page_source(src: str):
    if not src:
        return None

    txt = _strip_bom_and_leading_junk(src)
    if txt.startswith(('{', '[')):
        try:
            return _json.loads(txt)
        except Exception:
            pass

    m = re.search(r'<pre[^>]*>(.*?)</pre>', src, flags=re.IGNORECASE | re.DOTALL)
    if m:
        inner = m.group(1)
        inner = _html.unescape(re.sub(r'<[^>]+>', '', inner)).strip()
        inner = _strip_bom_and_leading_junk(inner)
        if inner.startswith(('{', '[')):
            try:
                return _json.loads(inner)
            except Exception:
                pass

    block = _extract_json_block(src)
    if block:
        block = _strip_bom_and_leading_junk(block)
        try:
            return _json.loads(block)
        except Exception:
            return None

    return None


def fetch_json_via_browser(
    url: str,
    *,
    parser: BrowserHTMLParser | None = None,
    wait_time: int = 4,
    retries: int = 3,
    status_q=None,
):
    p = parser or BrowserHTMLParser()
    owned = parser is None

    try:
        html = p.fetch_html(url, wait_time=wait_time, max_retries=retries)
    except Exception as e:
        if status_q:
            status_q.put(f'[html_parser] fetch_json_via_browser: ошибка загрузки {url}: {e}')
        return None
    finally:
        if owned:
            try:
                p.close()
            except Exception:
                pass

    data = _extract_json_from_page_source(html or '')
    if data is None and status_q:
        snippet = (re.sub(r'\s+', ' ', html or '')[:260] + '...') if html else '(пусто)'
        status_q.put(f'[html_parser] ответ не распознан как JSON: {snippet}')
    return data
