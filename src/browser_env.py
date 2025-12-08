# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple, List
import fnmatch

from config import BROWSER_DIR

# ---- Файловые паттерны ----
_CHROME_PATTERNS: List[str] = ['chrome.exe', 'chrome*.exe', 'chromium*.exe']
_CHROMEDRIVER_PATTERNS: List[str] = ['chromedriver.exe', 'chromedriver*.exe']

# Для Chrome for Testing рядом с chrome.exe должны лежать эти файлы + каталог locales/
_REQUIRED_NEIGHBORS = ['chrome.dll', 'icudtl.dat']


# ===================== ФАЙЛОВЫЙ ПОИСК =====================

def _iter_files_recursive(root: Path) -> list[Path]:
    files: list[Path] = []
    try:
        for p in root.rglob('*'):
            if p.is_file():
                files.append(p)
    except Exception:
        # на случай проблем с правами/симлинками и т.п.
        pass
    return files


def _match_first(files: list[Path], patterns: list[str]) -> Optional[Path]:
    for pat in patterns:
        for f in files:
            if fnmatch.fnmatch(f.name.lower(), pat.lower()):
                return f
    return None


# ===================== ЗАГЛУШКИ ДЛЯ EDGE (СОВМЕСТИМОСТЬ) =====================

def find_edge_driver(root: Optional[Path] = None) -> Optional[Path]:
    """
    Раньше здесь искался msedgedriver.exe.
    Теперь Edge не поддерживается, всегда возвращаем None.
    Функция оставлена только для совместимости импортов.
    """
    return None


def ensure_edge_driver_match_ui(parent=None) -> bool:
    """
    Раньше проверялась совместимость версий Edge/EdgeDriver и могло показываться окно.
    Сейчас Edge не используется — просто ничего не делаем и возвращаем True.
    """
    return True


# ===================== ПОИСК CHROME / CHROMEDRIVER =====================

def find_chrome_binaries(root: Optional[Path] = None) -> Tuple[Optional[Path], Optional[Path]]:
    """
    Ищет chrome.exe и chromedriver.exe (Chrome for Testing) в папке BROWSER_DIR.

    Возвращает:
      (chrome_path | None, chromedriver_path | None)
    """
    root_path = Path(root or BROWSER_DIR)
    if not root_path.exists():
        return None, None

    files = _iter_files_recursive(root_path)
    chrome = _match_first(files, _CHROME_PATTERNS)
    chromedriver = _match_first(files, _CHROMEDRIVER_PATTERNS)
    return chrome, chromedriver


def _has_required_neighbors(chrome_path: Path) -> bool:
    base = chrome_path.parent
    for fname in _REQUIRED_NEIGHBORS:
        if not (base / fname).exists():
            return False
    return (base / 'locales').exists()


def browser_ready() -> bool:
    """
    Проверяем, что есть рабочая конфигурация Chrome for Testing:
      - chrome.exe (или аналог по паттерну)
      - chromedriver.exe той же версии
      - рядом с chrome.exe лежат chrome.dll, icudtl.dat и каталог locales/
    """
    chrome, cdrv = find_chrome_binaries()
    if chrome and cdrv and _has_required_neighbors(chrome):
        return True
    return False


def browser_requirements_text() -> str:
    """
    Возвращает человекочитаемое описание требований к папке browser/.
    Учитывает только Chrome for Testing.
    """
    chrome, cdrv = find_chrome_binaries()
    ok = bool(chrome and cdrv and (chrome and _has_required_neighbors(chrome)))

    lines = [
        'Не удалось обнаружить корректную конфигурацию Chrome.',
        '',
        'Нужна следующая конфигурация (Chrome for Testing):',
        '  - chrome.exe (или chromium, собранный как Chrome for Testing)',
        '  - chromedriver.exe той же версии',
        '  - рядом с chrome.exe должны лежать файлы:',
        '      chrome.dll, icudtl.dat и каталог locales/',
        '',
        f'Папка BROWSER_DIR: {Path(BROWSER_DIR).resolve()}',
        '',
        'Сейчас обнаружено:',
        f'  - chrome + chromedriver: {"OK" if ok else "нет"}',
    ]
    return '\n'.join(lines)
