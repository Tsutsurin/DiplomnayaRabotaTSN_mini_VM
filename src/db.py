# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path
from typing import Optional, Any, List, Dict
from datetime import datetime
import sys
import sqlite3
import re

import pandas as pd

try:
    from config import RESULTS_DIR  # type: ignore[attr-defined]
except Exception:
    ROOT_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent)).resolve()
    RESULTS_DIR = ROOT_DIR / 'results'
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = RESULTS_DIR / 'vuln.db'

DESIRED_COLUMNS = [
    'id',
    'source',
    'bdu_id',
    'cve',
    'cvss',
    'severity',
    'vendor',
    'product',
    'type',
    'title',
    'url',
    'publication_date',
    'raw_date',
    'created_date',
]


def _get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('PRAGMA journal_mode=WAL;')
    conn.execute('PRAGMA synchronous=NORMAL;')
    return conn


def _create_fresh_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        '''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            source           TEXT NOT NULL,
            bdu_id           TEXT,
            cve              TEXT,
            cvss             TEXT,
            severity         TEXT,
            vendor           TEXT,
            product          TEXT,
            type             TEXT,
            title            TEXT,
            url              TEXT,
            publication_date TEXT,
            raw_date         TEXT,
            created_date     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source);
        CREATE INDEX IF NOT EXISTS idx_vuln_cve    ON vulnerabilities(cve);
        CREATE INDEX IF NOT EXISTS idx_vuln_url    ON vulnerabilities(url);
        '''
    )
    conn.commit()


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        'SELECT name FROM sqlite_master WHERE type="table" AND name=?',
        (name,),
    )
    return cur.fetchone() is not None


def _get_existing_columns(conn: sqlite3.Connection) -> List[str]:
    cur = conn.execute('PRAGMA table_info(vulnerabilities)')
    return [row[1] for row in cur.fetchall()]


def _needs_migration(existing_cols: List[str]) -> bool:
    return existing_cols != DESIRED_COLUMNS


def _migrate_old_schema(conn: sqlite3.Connection, existing_cols: List[str]) -> None:
    if not existing_cols:
        _create_fresh_schema(conn)
        return

    if not _needs_migration(existing_cols):
        return

    conn.execute('ALTER TABLE vulnerabilities RENAME TO vulnerabilities_old;')
    _create_fresh_schema(conn)

    old_cols = set(existing_cols)
    select_parts: List[str] = []

    # id
    select_parts.append('id' if 'id' in old_cols else 'NULL AS id')
    # source
    select_parts.append('source' if 'source' in old_cols else 'NULL AS source')
    # bdu_id
    select_parts.append('bdu_id' if 'bdu_id' in old_cols else 'NULL AS bdu_id')
    # cve / cvss
    select_parts.append('cve' if 'cve' in old_cols else 'NULL AS cve')
    select_parts.append('cvss' if 'cvss' in old_cols else 'NULL AS cvss')
    # severity
    select_parts.append('severity' if 'severity' in old_cols else 'NULL AS severity')

    for col in ('vendor', 'product', 'type', 'title', 'url'):
        if col in old_cols:
            select_parts.append(col)
        else:
            select_parts.append(f'NULL AS {col}')

    if 'publication_date' in old_cols:
        select_parts.append('publication_date')
    elif 'published' in old_cols:
        select_parts.append('published AS publication_date')
    else:
        select_parts.append('NULL AS publication_date')

    select_parts.append('raw_date' if 'raw_date' in old_cols else 'NULL AS raw_date')

    if 'created_date' in old_cols:
        select_parts.append('created_date')
    elif 'created_at' in old_cols:
        select_parts.append('created_at AS created_date')
    else:
        select_parts.append('NULL AS created_date')

    select_sql = 'SELECT ' + ', '.join(select_parts) + ' FROM vulnerabilities_old;'

    insert_sql = '''
        INSERT INTO vulnerabilities
            (id, source, bdu_id, cve, cvss, severity,
             vendor, product, type, title, url,
             publication_date, raw_date, created_date)
        ''' + select_sql

    conn.execute(insert_sql)
    conn.commit()
    conn.execute('DROP TABLE vulnerabilities_old;')
    conn.commit()


def _ensure_agent_schema(conn: sqlite3.Connection) -> None:
    """
    Создание (при необходимости) таблиц для агентов и их ПО.
    """
    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS agents (
            agent_id    TEXT PRIMARY KEY,
            hostname    TEXT,
            os_type     TEXT,
            os_release  TEXT,
            os_version  TEXT,
            architecture TEXT,
            ip_address  TEXT,
            first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        '''
    )

    conn.execute(
        '''
        CREATE TABLE IF NOT EXISTS agent_software (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT NOT NULL,
            name        TEXT NOT NULL,
            version     TEXT,
            publisher   TEXT,
            first_seen  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE CASCADE
        )
        '''
    )

    conn.execute(
        '''
        CREATE INDEX IF NOT EXISTS idx_agent_software_agent_name
        ON agent_software(agent_id, name)
        '''
    )


def init_db() -> None:
    conn = _get_connection()
    try:
        if not _table_exists(conn, 'vulnerabilities'):
            _create_fresh_schema(conn)
        else:
            existing = _get_existing_columns(conn)
            _migrate_old_schema(conn, existing)

        _ensure_agent_schema(conn)
        conn.commit()
    finally:
        conn.close()


def _strip_vendor_from_product(prod: Any, vend: Any) -> Any:
    if prod is None or vend is None:
        return prod

    s = str(prod).strip()
    v = str(vend).strip()
    if not s or not v:
        return prod

    if s.lower().startswith((v + ',').lower()):
        return s[len(v):].lstrip(' ,\u00A0-')

    pattern = r'^\s*' + re.escape(v) + r'[\s,\u00A0\-]+'
    cleaned = re.sub(pattern, '', s, flags=re.IGNORECASE).strip()
    return cleaned or s


def url_exists(url: str, source: Optional[str] = None) -> bool:
    if not url:
        return False
    init_db()
    conn = _get_connection()
    try:
        if source:
            cur = conn.execute(
                'SELECT 1 FROM vulnerabilities WHERE url = ? AND source = ? LIMIT 1',
                (url, source),
            )
        else:
            cur = conn.execute(
                'SELECT 1 FROM vulnerabilities WHERE url = ? LIMIT 1',
                (url,),
            )
        return cur.fetchone() is not None
    finally:
        conn.close()


def insert_vulnerabilities(df: pd.DataFrame, source: str, bdu_id: Optional[str] = None) -> int:
    if df is None or df.empty:
        return 0

    df = df.copy()

    for tech_col in ('should_skip', 'should_stop'):
        if tech_col in df.columns:
            df = df[df[tech_col] != True].drop(columns=[tech_col])  # noqa: E712

    if df.empty:
        return 0

    cols = df.columns

    def col(name: str) -> Optional[pd.Series]:
        return df[name] if name in cols else None

    cve_col = col('CVE')
    cvss_col = col('CVSS')
    prod_col = col('Продукт')
    vend_col = col('Вендор')
    type_col = col('Тип')
    title_col = col('Заголовок')
    url_col = col('Источник')
    date_col = col('Дата')
    pub_news = col('Опубликовано')
    pub_bdu = col('Дата публикации')
    det_bdu = col('Дата выявления')
    sev_col = col('Критичность')

    bdu_col: Optional[pd.Series] = None
    for name in ('BDU-ID', 'BDU_ID'):
        if name in cols:
            bdu_col = df[name]
            break

    records: List[Dict[str, Any]] = []
    n = len(df)

    for i in range(n):
        if pub_news is not None and i < len(pub_news):
            publication_val = pub_news.iloc[i]
        elif pub_bdu is not None and i < len(pub_bdu):
            publication_val = pub_bdu.iloc[i]
        elif date_col is not None and i < len(date_col):
            publication_val = date_col.iloc[i]
        else:
            publication_val = None

        if det_bdu is not None and i < len(det_bdu):
            raw_date_val = det_bdu.iloc[i]
        elif date_col is not None and i < len(date_col):
            raw_date_val = date_col.iloc[i]
        else:
            raw_date_val = None

        if bdu_col is not None and i < len(bdu_col):
            bdu_val = bdu_col.iloc[i]
        else:
            bdu_val = bdu_id

        vend_val = vend_col.iloc[i] if vend_col is not None and i < len(vend_col) else None
        prod_val = prod_col.iloc[i] if prod_col is not None and i < len(prod_col) else None
        prod_val = _strip_vendor_from_product(prod_val, vend_val)

        created_date_val = datetime.now().strftime('%d.%m.%Y')

        records.append(
            {
                'source': source,
                'bdu_id': bdu_val,
                'cve': cve_col.iloc[i] if cve_col is not None and i < len(cve_col) else None,
                'cvss': cvss_col.iloc[i] if cvss_col is not None and i < len(cvss_col) else None,
                'severity': sev_col.iloc[i] if sev_col is not None and i < len(sev_col) else None,
                'vendor': vend_val,
                'product': prod_val,
                'type': type_col.iloc[i] if type_col is not None and i < len(type_col) else None,
                'title': title_col.iloc[i] if title_col is not None and i < len(title_col) else None,
                'url': url_col.iloc[i] if url_col is not None and i < len(url_col) else None,
                'publication_date': publication_val,
                'raw_date': raw_date_val,
                'created_date': created_date_val,
            }
        )

    init_db()
    conn = _get_connection()
    try:
        conn.executemany(
            '''
            INSERT INTO vulnerabilities
                (source, bdu_id, cve, cvss, severity,
                 vendor, product, type, title, url,
                 publication_date, raw_date, created_date)
            VALUES
                (:source, :bdu_id, :cve, :cvss, :severity,
                 :vendor, :product, :type, :title, :url,
                 :publication_date, :raw_date, :created_date)
            ''',
            records,
        )
        conn.commit()
    finally:
        conn.close()

    return len(records)


def upsert_agent_inventory(
    agent_id: str,
    hostname: Optional[str],
    os_type: Optional[str],
    os_release: Optional[str],
    os_version: Optional[str],
    architecture: Optional[str],
    ip_address: Optional[str],
    software_list: List[Dict[str, Any]],
) -> None:
    """
    Обновление информации об агенте и его ПО.
    ОС + IP идут в таблицу agents, ПО — в agent_software.
    """
    init_db()
    conn = _get_connection()
    try:
        conn.execute(
            '''
            INSERT INTO agents (
                agent_id, hostname, os_type, os_release,
                os_version, architecture, ip_address
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET
                hostname     = excluded.hostname,
                os_type      = excluded.os_type,
                os_release   = excluded.os_release,
                os_version   = excluded.os_version,
                architecture = excluded.architecture,
                ip_address   = excluded.ip_address,
                last_seen    = CURRENT_TIMESTAMP
            ''',
            (
                agent_id,
                hostname,
                os_type,
                os_release,
                os_version,
                architecture,
                ip_address,
            ),
        )

        # простая стратегия: удаляем старый список ПО и пишем новый
        conn.execute('DELETE FROM agent_software WHERE agent_id = ?', (agent_id,))

        if software_list:
            now = datetime.utcnow().isoformat(timespec='seconds')
            rows: List[tuple] = []
            for item in software_list:
                name = (item.get('name') or '').strip()
                if not name:
                    continue
                version = (item.get('version') or '').strip() or None
                publisher = (item.get('publisher') or '').strip() or None
                rows.append((agent_id, name, version, publisher, now, now))

            if rows:
                conn.executemany(
                    '''
                    INSERT INTO agent_software (
                        agent_id, name, version, publisher, first_seen, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ''',
                    rows,
                )

        conn.commit()
    finally:
        conn.close()


def fetch_all(limit: Optional[int] = None) -> pd.DataFrame:
    init_db()
    conn = _get_connection()
    try:
        query = 'SELECT * FROM vulnerabilities ORDER BY id DESC'
        if limit is not None:
            query += f' LIMIT {int(limit)}'
        df = pd.read_sql_query(query, conn)
    finally:
        conn.close()
    return df
