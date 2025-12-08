# -*- coding: utf-8 -*-
from __future__ import annotations

"""
processing.py

Обработка результатов ФСТЭК.

Главные изменения:
- Вместо сохранения результатов в XLSX все данные по ФСТЭК складываются
  в одну SQLite-базу (см. модуль src.db).
- Таблица БД создаётся ТОЛЬКО в db.py (через init_db), здесь мы её не описываем.
"""

import os
import glob
import sys
import multiprocessing as mp
from pathlib import Path
from datetime import datetime
from typing import List, Iterable, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

import numpy as np
import pandas as pd

# --- пути проекта ---
try:
    # В реальном проекте config лежит рядом с src/*
    from config import RESULTS_DIR  # type: ignore[attr-defined]
except Exception:
    # фоллбек, если config недоступен (например, при сборке в один exe)
    ROOT_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)).resolve()
    RESULTS_DIR = ROOT_DIR / "results"
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

# --- зависимости проекта ---
from src.ids import iter_ids
from src.workers import worker_loop

# --- работа с БД ---
from .db import init_db, insert_vulnerabilities, DB_PATH


# =============================================================================
# Вспомогательные утилиты для логов / прогресса
# =============================================================================

def _emit_status(q: Optional[mp.Queue], msg: str) -> None:
    """Пишем строку статуса в очередь (если есть)."""
    if q is None:
        return
    try:
        q.put(msg, block=False)
    except Exception:
        # Лог не обязателен, поэтому молча игнорируем сбой очереди
        pass


def _emit_progress_total(progress_q: Optional[mp.Queue], n: int) -> None:
    """
    Сообщаем GUI об общем количестве шагов.
    В progress_q попадает ('TOTAL', n).
    """
    if progress_q is None:
        return
    try:
        progress_q.put(("TOTAL", int(n)), block=False)
    except Exception:
        pass


# =============================================================================
# Чтение и объединение частей
# =============================================================================

def _read_part(path: str) -> pd.DataFrame:
    """
    Универсальное чтение части результатов.
    Обычно воркеры пишут CSV, но поддержим и xlsx/parquet.
    """
    ext = os.path.splitext(path)[1].lower()
    try:
        if ext == ".csv":
            # Важно: dtype=str, чтобы не ломать формат BDU-ID и прочие текстовые поля
            return pd.read_csv(path, dtype=str, encoding="utf-8-sig")
        if ext in {".xlsx", ".xls"}:
            return pd.read_excel(path, dtype=str)
        if ext == ".parquet":
            return pd.read_parquet(path)
        # Фоллбек — как обычный CSV
        return pd.read_csv(path, dtype=str)
    except Exception:
        # Если совсем не получилось — вернём пустой DataFrame
        return pd.DataFrame()


def _combine_parts(parts_paths: Iterable[str],
                   status_q: Optional[mp.Queue] = None) -> pd.DataFrame:
    """
    Склеиваем все части одним concat (быстро, без лишних копий).
    """
    paths = list(parts_paths)
    if not paths:
        return pd.DataFrame()

    dfs: List[pd.DataFrame] = []
    for p in paths:
        try:
            df_part = _read_part(p)
        except Exception as e:
            _emit_status(status_q, f"[processing] Не удалось прочитать {p}: {e}")
            continue
        if not df_part.empty:
            dfs.append(df_part)

    if not dfs:
        return pd.DataFrame()

    return pd.concat(dfs, ignore_index=True, copy=False, sort=False)


# =============================================================================
# Нормализация колонок и URL
# =============================================================================

def _unify_source_column(df: pd.DataFrame) -> pd.DataFrame:
    """
    Приводим разные варианты названия колонки с URL к единому 'Источник'.
    """
    if df is None or df.empty:
        return df

    if "Источник" in df.columns:
        return df

    rename_map = {}
    for col in df.columns:
        low = str(col).strip().lower()
        if low in {"url", "link", "address", "адрес источника", "источник"}:
            rename_map[col] = "Источник"
            break

    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def _normalize_url(url: object) -> object:
    """
    Нормализуем URL для дедупликации:
    - убираем utm_* параметры;
    - убираем якорь (#...).

    Если не строка — возвращаем как есть.
    """
    if not isinstance(url, str) or not url:
        return url

    try:
        parts = urlsplit(url)
    except Exception:
        return url

    # фильтруем UTM-параметры
    query_pairs = [
        (k, v)
        for (k, v) in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_")
    ]
    new_query = urlencode(query_pairs, doseq=True)

    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))


def _apply_output_order(df: pd.DataFrame,
                        friendly_order: Optional[List[str]]) -> pd.DataFrame:
    """
    Приводим колонки к порядку, заданному в GUI (friendly_order).
    Остальные колонки добавляем в конец в исходном порядке.
    """
    if df is None or df.empty:
        return df

    if not friendly_order:
        return df.copy()

    existing = list(df.columns)
    ordered = [c for c in friendly_order if c in existing]
    tail = [c for c in existing if c not in ordered]
    return df[ordered + tail]


def _sort_and_renumber(df: pd.DataFrame,
                       friendly_order: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Сортировка + нумерация '№'.
    Если есть колонка 'Дата' — сортируем по ней (по убыванию).
    Иначе сортируем по 'CVE' или по 'Источник'.
    """
    if df is None or df.empty:
        return df

    df = df.copy()

    # Сортировка
    if "Дата" in df.columns:
        # Не падаем, если формат странный
        try:
            df["_sort_date"] = pd.to_datetime(df["Дата"], errors="coerce")
            df = df.sort_values("_sort_date", ascending=False, kind="mergesort")
        except Exception:
            df = df.sort_values("Дата", ascending=False, kind="mergesort")
    elif "CVE" in df.columns:
        df = df.sort_values("CVE", ascending=True, kind="mergesort")
    elif "Источник" in df.columns:
        df = df.sort_values("Источник", ascending=True, kind="mergesort")

    # Нумерация
    df = df.reset_index(drop=True)
    n = len(df)

    if "№" in df.columns:
        df = df.drop(columns=["№"])

    pos = 0
    if friendly_order:
        try:
            pos = max(0, int(friendly_order.index("№")))
        except ValueError:
            pos = 0

    df.insert(loc=pos, column="№", value=np.arange(1, n + 1, dtype=np.int64))

    # Техническую колонку сортировки удалим
    if "_sort_date" in df.columns:
        df = df.drop(columns=["_sort_date"])

    return df


def _cleanup_temp_parts(status_q: Optional[mp.Queue] = None) -> None:
    """
    Удаляем временные файлы part_*.csv / reserved_part_*.txt / missed404_part_*.txt
    из RESULTS_DIR после успешной обработки.
    """
    patterns = [
        "part_*.csv",
        "retry_part_*.csv",
        "part_*.parquet",
        "retry_part_*.parquet",
        "part_*.xlsx",
        "retry_part_*.xlsx",
        "reserved_part_*.txt",
        "missed404_part_*.txt",
    ]
    removed = 0
    for pat in patterns:
        for p in Path(RESULTS_DIR).glob(pat):
            try:
                p.unlink()
                removed += 1
            except OSError:
                continue

    if removed and status_q is not None:
        _emit_status(status_q, f"[processing] Временные файлы удалены: {removed} шт.")


# =============================================================================
# Запуск воркеров
# =============================================================================

def _chunkify(items: List[str], n_chunks: int) -> List[List[str]]:
    """
    Делим список items на n_chunks (примерно) равных частей.
    Пустых чанков не создаём.
    """
    if not items:
        return []

    n_chunks = max(1, int(n_chunks))
    n_chunks = min(n_chunks, len(items))

    avg = (len(items) + n_chunks - 1) // n_chunks  # ceil(len/n_chunks)
    return [items[i: i + avg] for i in range(0, len(items), avg)]


def _start_workers(ids: List[str],
                   workers: int,
                   progress_q: Optional[mp.Queue],
                   status_q: Optional[mp.Queue]) -> None:
    """
    Запускаем несколько процессов worker_loop, каждый пишет part_*.csv в RESULTS_DIR.
    """
    chunks = _chunkify(ids, max(1, workers))
    procs: List[mp.Process] = []

    for chunk in chunks:
        p = mp.Process(target=worker_loop,
                       args=(chunk, str(RESULTS_DIR), progress_q, status_q))
        p.start()
        procs.append(p)

    # Ждём завершения всех процессов
    for p in procs:
        p.join()


# =============================================================================
# Сборка итоговой таблицы и запись в БД
# =============================================================================

def _build_final_dataframe(parts_paths: Iterable[str],
                           friendly_order: Optional[List[str]],
                           status_q: Optional[mp.Queue] = None) -> pd.DataFrame:
    """
    Чтение частей → объединение → унификация 'Источник'
    → дедуп по нормализованной ссылке → порядок/нумерация по GUI.
    """
    run_raw = _combine_parts(parts_paths, status_q=status_q)

    if run_raw.empty:
        _emit_status(status_q, "[processing] Не найдено частей с данными, итоговая таблица пуста.")
        return pd.DataFrame()

    # Всегда работаем с колонкой 'Источник'
    run_raw = _unify_source_column(run_raw)

    if "Источник" in run_raw.columns:
        norm = run_raw["Источник"].map(_normalize_url)
        run_raw = run_raw.assign(_src_norm=norm)
        # Дедуп: оставляем последнюю запись по нормализованному URL
        run_raw = run_raw.drop_duplicates(subset=["_src_norm"], keep="last")
        run_raw = run_raw.drop(columns=["_src_norm"])

    # Применяем порядок колонок, заданный в GUI
    view = _apply_output_order(run_raw, friendly_order=friendly_order)

    # Сортировка и нумерация '№'
    view = _sort_and_renumber(view, friendly_order=friendly_order)

    return view


# =============================================================================
# Публичные функции
# =============================================================================

def process_ids_parallel(ids: List[str],
                         workers: int,
                         friendly_order: Optional[List[str]],
                         progress_q: Optional[mp.Queue],
                         status_q: Optional[mp.Queue],
                         update_master_vuln: bool = True,
                         update_master_reserved: bool = False) -> str:
    """
    Основная точка запуска для ФСТЭК:
    - запускает воркеров по BDU-ID,
    - ждёт окончания,
    - собирает части в единый DataFrame,
    - пишет результат в общую БД (src.db),
    - возвращает путь к файлу БД.

    Параметры update_master_* сохранены для обратной совместимости,
    но в новой версии не используются (мастером является сама БД).
    """
    if friendly_order is None:
        friendly_order = []

    if not ids:
        _emit_status(status_q, "[processing] Пустой список идентификаторов.")
        # Всё равно убедимся, что БД существует
        init_db()
        return str(DB_PATH)

    # Инициализируем БД (создаст таблицу, если её ещё нет)
    init_db()

    _emit_progress_total(progress_q, len(ids))
    _emit_status(status_q, f"[processing] Старт обработки: {len(ids)}")

    # 1) Запуск воркеров
    _start_workers(ids=ids,
                   workers=max(1, int(workers or 1)),
                   progress_q=progress_q,
                   status_q=status_q)

    # 2) Сбор частей
    parts = sorted(
        glob.glob(str(RESULTS_DIR / "part_*.csv")) +
        glob.glob(str(RESULTS_DIR / "retry_part_*.csv")) +
        glob.glob(str(RESULTS_DIR / "part_*.parquet")) +
        glob.glob(str(RESULTS_DIR / "retry_part_*.parquet")) +
        glob.glob(str(RESULTS_DIR / "part_*.xlsx")) +
        glob.glob(str(RESULTS_DIR / "retry_part_*.xlsx"))
    )

    if not parts:
        _emit_status(status_q, "[processing] Не найдено файлов частей (part_*.csv и др.).")
        _cleanup_temp_parts(status_q=status_q)
        return str(DB_PATH)

    # 3) Построение итоговой таблицы
    final_df = _build_final_dataframe(parts, friendly_order=friendly_order, status_q=status_q)

    if final_df.empty:
        _emit_status(status_q, "[processing] Итоговая таблица пуста, записывать в БД нечего.")
        _cleanup_temp_parts(status_q=status_q)
        return str(DB_PATH)

    # 4) Запись в БД
    try:
        inserted = insert_vulnerabilities(final_df, source="fstek")
        _emit_status(status_q, f"[processing] В БД добавлено записей: {inserted}. Файл: {DB_PATH}")
    except Exception as e:
        _emit_status(status_q, f"[processing] Ошибка записи результатов в БД: {e}")

    # 5) Чистим временные файлы
    _cleanup_temp_parts(status_q=status_q)

    return str(DB_PATH)


def process_range_from_to(start_id: str,
                          end_id: str,
                          workers: int,
                          friendly_order: Optional[List[str]],
                          progress_q: Optional[mp.Queue],
                          status_q: Optional[mp.Queue],
                          update_master_vuln: bool = True,
                          update_master_reserved: bool = False) -> Optional[str]:
    """
    Обёртка для UI и авто-режима:
    - принимает границы BDU-ID,
    - строит список,
    - запускает параллельную обработку,
    - публикует результат в статус-очередь как {"result_path": "<путь к БД>"}.
    """
    if friendly_order is None:
        friendly_order = []

    try:
        ids_list = list(iter_ids(start_id, end_id))
    except Exception as e:
        _emit_status(status_q, f"[processing] Ошибка диапазона BDU-ID: {e}")
        if status_q is not None:
            try:
                status_q.put({"result_path": None})
            except Exception:
                pass
        return None

    result_path = process_ids_parallel(
        ids=ids_list,
        workers=workers,
        friendly_order=friendly_order,
        progress_q=progress_q,
        status_q=status_q,
        update_master_vuln=update_master_vuln,
        update_master_reserved=update_master_reserved,
    )

    if status_q is not None and result_path:
        try:
            status_q.put({"result_path": str(result_path)})
        except Exception:
            pass

    return result_path
