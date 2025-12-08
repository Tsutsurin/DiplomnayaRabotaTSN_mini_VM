from __future__ import annotations

import time
import multiprocessing as mp
from typing import Optional, List

from config import RESULTS_DIR
from src.ids import subtract_steps
from src.processing import process_range_from_to
from src.top_vulnerability import get_latest_bdu_id, get_latest_from_news_count


def autonomous_loop(
    workers: int,
    interval_hours: int,
    friendly_order: List[str],
    update_master_vuln: bool,
    update_master_reserved: bool,
    status_q: Optional[mp.Queue] = None,
) -> None:
    def emit(msg: str) -> None:
        if status_q is None:
            return
        try:
            status_q.put(msg, block=False)
        except Exception:
            pass

    emit(f'[*] Автоматический режим: каждые {interval_hours} ч проверяем обновления.')

    while True:
        try:
            news = get_latest_from_news_count(headless=True)
            news_url = news.get('news_url')
            count = news.get('count') or 0

            if not news_url or count <= 0:
                emit('[WARN] Верхняя новость не распознана. Повторим позже.')
            else:
                stamp = RESULTS_DIR / 'last_seen_news.txt'
                last_seen = stamp.read_text(encoding='utf-8').strip() if stamp.exists() else None

                if last_seen != news_url:
                    latest = get_latest_bdu_id(headless=True)
                    first = subtract_steps(latest, count - 1)
                    emit(
                        f'[*] Новое обновление! {news_url}\n'
                        f'    Диапазон: {first} … {latest} (count={count})'
                    )

                    process_range_from_to(
                        first,
                        latest,
                        workers,
                        friendly_order,
                        progress_q=None,
                        status_q=status_q,
                        update_master_vuln=update_master_vuln,
                        update_master_reserved=update_master_reserved,
                    )

                    stamp.write_text(news_url, encoding='utf-8')
                else:
                    emit('[*] Новостей нет.')
        except KeyboardInterrupt:
            emit('[!] Остановка авто режима')
            break
        except Exception as e:
            emit(f'[WARN] Ошибка авто цикла: {e}')

        try:
            minutes = max(1, int(interval_hours)) * 60
            for _ in range(minutes):
                time.sleep(60)
        except KeyboardInterrupt:
            emit('[!] Остановка авто режима')
            break
