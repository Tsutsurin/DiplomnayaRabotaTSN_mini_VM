# -*- coding: utf-8 -*-
from __future__ import annotations

import threading
import multiprocessing as mp
import os
import re
import sqlite3
import sys
import json
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

from config import ROOT_DIR
from src.ids import iter_ids
from src.processing import process_range_from_to
from src.top_vulnerability import get_latest_bdu_id
from src.sv_latest import scrape_latest
from src.db import init_db, DB_PATH, insert_vulnerabilities
from src.browser_env import browser_ready, browser_requirements_text
from src.key_utils import generate_rsa_keypair
import agent_api
from src.reporting import generate_vulnerability_report


BDU_RE = re.compile(r'^\d{4}-\d+$')


class UnifiedApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title('Парсер уязвимостей')
        self.geometry('980x720')
        self.minsize(940, 640)

        self.use_fstek = tk.BooleanVar(value=False)
        self.use_news = tk.BooleanVar(value=False)

        self.var_fstek_hours = tk.StringVar(value='24')
        self.var_news_hours = tk.StringVar(value='24')

        self.var_from = tk.StringVar()
        self.var_to = tk.StringVar()

        self.agent_api_enabled = tk.BooleanVar(value=True)
        self.agent_api_port = tk.IntVar(value=8000)
        self.private_key_path = tk.StringVar()

        self._progress_q: Optional[mp.Queue] = None
        self._status_q: Optional[mp.Queue] = None
        self._status_running = False
        self._progress_total = 0
        self._progress_done = 0

        self._agent_api_thread: Optional[threading.Thread] = None
        self._settings_path = ROOT_DIR / 'app_settings.json'

        self._load_settings()
        self._build_ui()
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    def _build_ui(self) -> None:
        sources = ttk.LabelFrame(self, text='Источники')
        sources.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(10, 4))

        row = 0
        chk_fstek = ttk.Checkbutton(
            sources,
            text='ФСТЭК (bdu.fstec.ru)',
            variable=self.use_fstek,
        )
        chk_fstek.grid(row=row, column=0, sticky='w', padx=(6, 4), pady=2)
        ttk.Label(sources, text='раз в').grid(row=row, column=1, sticky='w')
        ttk.Entry(sources, textvariable=self.var_fstek_hours, width=5).grid(
            row=row, column=2, padx=(2, 2),
        )
        ttk.Label(sources, text='час(ов)').grid(row=row, column=3, sticky='w', padx=(2, 6))

        row = 1
        chk_news = ttk.Checkbutton(
            sources,
            text='Новости (securityvulnerability.io)',
            variable=self.use_news,
        )
        chk_news.grid(row=row, column=0, sticky='w', padx=(6, 4), pady=2)
        ttk.Label(sources, text='раз в').grid(row=row, column=1, sticky='w')
        ttk.Entry(sources, textvariable=self.var_news_hours, width=5).grid(
            row=row, column=2, padx=(2, 2),
        )
        ttk.Label(sources, text='час(ов)').grid(row=row, column=3, sticky='w', padx=(2, 6))

        api_frame = ttk.LabelFrame(self, text='API для агентов')
        api_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 4))

        chk_api = ttk.Checkbutton(
            api_frame,
            text='Поднять HTTP API для агентов',
            variable=self.agent_api_enabled,
        )
        chk_api.grid(row=0, column=0, sticky='w', padx=(6, 4), pady=2)

        ttk.Label(api_frame, text='Порт').grid(row=0, column=1, sticky='w')
        ttk.Entry(api_frame, textvariable=self.agent_api_port, width=6).grid(
            row=0,
            column=2,
            padx=(2, 6),
        )

        ttk.Label(api_frame, text='Приватный ключ').grid(
            row=1, column=0, sticky='w', padx=(6, 4), pady=(2, 4),
        )
        entry_key = ttk.Entry(api_frame, textvariable=self.private_key_path, width=60)
        entry_key.grid(row=1, column=1, columnspan=2, sticky='we', padx=(0, 4), pady=(2, 4))
        btn_browse = ttk.Button(api_frame, text='Выбрать...', command=self._on_browse_private_key)
        btn_browse.grid(row=1, column=3, sticky='w', padx=(0, 6), pady=(2, 4))

        btn_gen = ttk.Button(api_frame, text='Сгенерировать ключ', command=self._on_generate_keys)
        btn_gen.grid(row=2, column=0, columnspan=4, sticky='w', padx=6, pady=(0, 4))

        api_frame.columnconfigure(1, weight=1)
        api_frame.columnconfigure(2, weight=0)

        fstek_range = ttk.LabelFrame(self, text='ФСТЭК: диапазон BDU-ID (опционально)')
        fstek_range.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 6))

        ttk.Label(fstek_range, text='От:').grid(row=0, column=0, sticky='e', padx=(6, 2), pady=4)
        ttk.Entry(fstek_range, textvariable=self.var_from, width=14).grid(
            row=0, column=1, sticky='w', padx=(0, 10), pady=4,
        )

        ttk.Label(fstek_range, text='До:').grid(row=0, column=2, sticky='e', padx=(6, 2), pady=4)
        ttk.Entry(fstek_range, textvariable=self.var_to, width=14).grid(
            row=0, column=3, sticky='w', padx=(0, 10), pady=4,
        )

        ttk.Label(
            fstek_range,
            text='Если оставить пустым — диапазон будет вычислен автоматически\n'
                 'на основе данных в БД и последней записи на сайте.',
        ).grid(row=1, column=0, columnspan=4, sticky='w', padx=6, pady=(0, 4))

        top = ttk.LabelFrame(self, text='Управление')
        top.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(6, 6))
        frm_btn = ttk.Frame(top)
        frm_btn.pack(side=tk.TOP, fill=tk.X, padx=6, pady=6)
        self.btn_start = ttk.Button(frm_btn, text='Start', command=self._on_start_click, width=18)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_report = ttk.Button(
            frm_btn,
            text='Выпустить отчёт',
            command=self._on_report_click,
            width=18,
        )
        self.btn_report.pack(side=tk.LEFT, padx=(6, 0))

        prog = ttk.Frame(top)
        prog.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(0, 6))
        ttk.Label(prog, text='Прогресс:').pack(side=tk.LEFT, padx=(0, 6))
        self.pb = ttk.Progressbar(prog, mode='determinate')
        self.pb.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.pb_style_name = 'text.Horizontal.TProgressbar'
        style = ttk.Style(self)
        style.layout(self.pb_style_name, [
            ('Horizontal.Progressbar.trough', {
                'children': [('Horizontal.Progressbar.pbar', {'side': 'left', 'sticky': 'ns'})],
                'sticky': 'nswe',
            }),
            ('Horizontal.Progressbar.label', {'sticky': ''}),
        ])
        style.configure(self.pb_style_name, text='0 / 0', anchor='center')
        self.pb.configure(style=self.pb_style_name)

        out = ttk.LabelFrame(self, text='Вывод')
        out.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.txt_out = scrolledtext.ScrolledText(
            out,
            state='disabled',
            height=16,
            font=('Consolas', 10),
        )
        self.txt_out.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self._reset_progress_view()

    def _reset_progress_view(self, total: int = 0) -> None:
        self._progress_total = total
        self._progress_done = 0
        self.pb.configure(mode='determinate', maximum=max(1, total), value=0)
        ttk.Style().configure(self.pb_style_name, text=f'0 / {total}')

    def _progress_set_total(self, total: int) -> None:
        self._progress_total = max(0, int(total))
        self._progress_done = 0
        self.pb.configure(mode='determinate', maximum=max(1, self._progress_total), value=0)
        ttk.Style().configure(self.pb_style_name, text=f'0 / {self._progress_total}')

    def _progress_inc(self) -> None:
        if self._progress_done < self._progress_total:
            self._progress_done += 1
            self.pb['value'] = self._progress_done
            ttk.Style().configure(
                self.pb_style_name,
                text=f'{self._progress_done} / {self._progress_total}',
            )

    def _progress_finish(self) -> None:
        if self._progress_total > 0:
            self._progress_done = self._progress_total
            self.pb['value'] = self._progress_total
            ttk.Style().configure(
                self.pb_style_name,
                text=f'{self._progress_total} / {self._progress_total}',
            )

    def _append_log(self, text: str) -> None:
        def append() -> None:
            self.txt_out.configure(state='normal')
            self.txt_out.insert(tk.END, text)
            self.txt_out.configure(state='disabled')
            self.txt_out.yview(tk.END)

        self.txt_out.after(0, append)

    def _status_listener(self, q: mp.Queue) -> None:
        self._status_running = True
        while self._status_running:
            try:
                item = q.get(timeout=0.5)
            except Exception:
                continue

            if isinstance(item, str):
                msg = item
                if not msg.endswith('\n'):
                    msg += '\n'
                self._append_log(msg)

    def _progress_listener(self, q: mp.Queue) -> None:
        self._status_running = True
        while self._status_running:
            try:
                item = q.get(timeout=0.5)
            except Exception:
                continue

            if isinstance(item, tuple) and len(item) == 2 and item[0] == 'TOTAL':
                try:
                    total = int(item[1])
                except Exception:
                    total = 0
                self._progress_set_total(total)
            else:
                self._progress_inc()

    @staticmethod
    def _inc_bdu_id(bdu_id: str) -> str:
        try:
            year_str, num_str = bdu_id.split('-')
            year = int(year_str)
            width = len(num_str)
            new_num = int(num_str) + 1
            return f'{year}-{new_num:0{width}d}'
        except Exception:
            return bdu_id

    @staticmethod
    def _parse_bdu_id(bdu_id: str) -> tuple[int, str, int]:
        year_str, num_str = bdu_id.split('-', 1)
        year = int(year_str)
        width = len(num_str)
        return year, num_str, width

    def _get_last_bdu_id_from_db(self) -> Optional[str]:
        init_db()
        conn = sqlite3.connect(str(DB_PATH))
        try:
            cur = conn.execute(
                'SELECT bdu_id FROM vulnerabilities '
                'WHERE source = ? AND bdu_id IS NOT NULL '
                'ORDER BY id DESC LIMIT 1',
                ('fstek',),
            )
            row = cur.fetchone()
            return row[0] if row and row[0] else None
        finally:
            conn.close()

    def _bdu_id_exists_in_db(self, bdu_id: str) -> bool:
        if not bdu_id:
            return False
        init_db()
        conn = sqlite3.connect(str(DB_PATH))
        try:
            cur = conn.execute(
                'SELECT 1 FROM vulnerabilities '
                'WHERE source = ? AND bdu_id = ? '
                'LIMIT 1',
                ('fstek', bdu_id),
            )
            return cur.fetchone() is not None
        finally:
            conn.close()

    def _validate_inputs(self) -> bool:
        use_fstek = self.use_fstek.get()
        use_news = self.use_news.get()

        if not (use_fstek or use_news):
            messagebox.showerror(
                'Ошибка',
                'Выберите хотя бы один источник: ФСТЭК и/или Новости.',
            )
            return False

        def _check_hours(var: tk.StringVar, label: str) -> bool:
            raw = (var.get() or '').strip()
            if not raw:
                return True
            try:
                val = float(raw.replace(',', '.'))
                if val < 0:
                    raise ValueError
            except Exception:
                messagebox.showerror(
                    'Ошибка',
                    f'Поле "{label}" должно быть неотрицательным числом (часы).',
                )
                return False
            return True

        if use_fstek and not _check_hours(self.var_fstek_hours, 'ФСТЭК — раз в'):
            return False
        if use_news and not _check_hours(self.var_news_hours, 'Новости — раз в'):
            return False

        if not browser_ready():
            messagebox.showerror('Браузер не найден', browser_requirements_text())
            return False

        if self.agent_api_enabled.get():
            key_path = (self.private_key_path.get() or '').strip()
            if not key_path:
                messagebox.showerror(
                    'Ошибка',
                    'Для API агентов необходимо указать путь к приватному ключу.',
                )
                return False
            if not Path(key_path).is_file():
                messagebox.showerror(
                    'Ошибка',
                    f'Файл приватного ключа не найден:\n{key_path}',
                )
                return False

        return True

    def _maybe_start_agent_api(self) -> None:
        if not self.agent_api_enabled.get():
            return
        if self._agent_api_thread is not None and self._agent_api_thread.is_alive():
            return

        key_path_str = (self.private_key_path.get() or '').strip()
        path = Path(key_path_str)
        if not path.is_file():
            self._append_log(f'[agent_api] Файл приватного ключа не найден: {path}\n')
            return

        try:
            port = int(self.agent_api_port.get() or 8000)
        except Exception:
            port = 8000
            self.agent_api_port.set(port)

        def target() -> None:
            try:
                agent_api.PRIVATE_KEY_PATH = path
                agent_api.run_agent_api(host='0.0.0.0', port=port)
            except Exception as exc:
                self._append_log(f'[agent_api] Ошибка запуска API: {exc}\n')

        self._agent_api_thread = threading.Thread(target=target, daemon=True)
        self._agent_api_thread.start()
        self._append_log(f'[agent_api] HTTP API для агентов запущен на порту {port}\n')

    def _on_browse_private_key(self) -> None:
        initial_dir = os.path.dirname(self.private_key_path.get() or str(ROOT_DIR))
        filename = filedialog.askopenfilename(
            title='Выбор приватного ключа',
            initialdir=initial_dir,
            filetypes=[('PEM файлы', '*.pem'), ('Все файлы', '*.*')],
        )
        if filename:
            self.private_key_path.set(filename)

    def _on_generate_keys(self) -> None:
        private_path = ROOT_DIR / 'server_private_key.pem'
        public_path = ROOT_DIR / 'server_public_key.pem'
        try:
            generate_rsa_keypair(private_path, public_path)
        except Exception as exc:
            messagebox.showerror('Ошибка', f'Не удалось сгенерировать ключи:\n{exc}')
            return
        self.private_key_path.set(str(private_path))
        self._append_log(
            f'[agent_api] Сгенерирован приватный ключ: {private_path}\n'
            f'[agent_api] Сгенерирован публичный ключ: {public_path}\n',
        )

    def _on_start_click(self) -> None:
        if not self._validate_inputs():
            return

        self.txt_out.configure(state='normal')
        self.txt_out.delete('1.0', tk.END)
        self.txt_out.configure(state='disabled')

        self._reset_progress_view(0)
        self.btn_start.configure(state=tk.DISABLED)

        manager = mp.Manager()
        self._status_q = manager.Queue()
        self._progress_q = manager.Queue()

        threading.Thread(
            target=self._status_listener,
            args=(self._status_q,),
            daemon=True,
        ).start()
        threading.Thread(
            target=self._progress_listener,
            args=(self._progress_q,),
            daemon=True,
        ).start()

        self._maybe_start_agent_api()

        use_fstek = self.use_fstek.get()
        use_news = self.use_news.get()

        user_from = self.var_from.get().strip()
        user_to = self.var_to.get().strip()

        def run_one() -> None:
            try:
                if use_fstek:
                    try:
                        self._append_log('[ФСТЭК] Определяю последнюю уязвимость на сайте...\n')
                        last_site_id = get_latest_bdu_id(headless=True)
                        if not last_site_id or not BDU_RE.match(last_site_id):
                            self._append_log('[ФСТЭК] Не удалось получить корректный BDU-ID с сайта.\n')
                        else:
                            self._append_log(f'[ФСТЭК] Последний BDU-ID на сайте: {last_site_id}\n')

                            if user_from and user_to:
                                if not (BDU_RE.match(user_from) and BDU_RE.match(user_to)):
                                    self._append_log(
                                        '[ФСТЭК] Некорректный формат "от/до". Ожидается ГГГГ-НННН.\n',
                                    )
                                else:
                                    start_id = user_from
                                    end_id = user_to
                                    self._append_log(
                                        f'[ФСТЭК] Использую диапазон, указанный пользователем: '
                                        f'{start_id} … {end_id}\n',
                                    )
                                    self._run_fstek_range(start_id, end_id)
                            else:
                                if self._bdu_id_exists_in_db(last_site_id):
                                    self._append_log(
                                        f'[ФСТЭК] Новых уязвимостей нет: {last_site_id} уже есть в БД.\n',
                                    )
                                else:
                                    last_db_id = self._get_last_bdu_id_from_db()
                                    y_site, num_site_str, _ = self._parse_bdu_id(last_site_id)

                                    if last_db_id:
                                        self._append_log(
                                            f'[ФСТЭК] Последний BDU-ID в БД: {last_db_id}\n',
                                        )
                                        y_db, _, _ = self._parse_bdu_id(last_db_id)

                                        if y_db == y_site:
                                            start_id = self._inc_bdu_id(last_db_id)
                                        else:
                                            width = len(num_site_str)
                                            start_id = f'{y_site}-{0:0{width}d}'

                                        end_id = last_site_id
                                    else:
                                        self._append_log(
                                            '[ФСТЭК] В БД ещё нет записей ФСТЭК. '
                                            'Будет обработана только последняя уязвимость с сайта.\n',
                                        )
                                        start_id = last_site_id
                                        end_id = last_site_id

                                    self.var_from.set(start_id)
                                    self.var_to.set(end_id)
                                    self._append_log(
                                        f'[ФСТЭК] Автоматически выбран диапазон: {start_id} … {end_id}\n',
                                    )
                                    self._run_fstek_range(start_id, end_id)
                    except Exception as e:
                        self._append_log(f'[ФСТЭК] Ошибка: {e}\n')

                if use_news:
                    try:
                        if self._status_q is not None:
                            self._status_q.put('[Новости] Старт парсинга /vulnerability/latest')
                        df = scrape_latest(
                            headless=True,
                            status_q=self._status_q,
                            progress_q=self._progress_q,
                        )
                        if df is not None and not df.empty:
                            inserted = insert_vulnerabilities(df, source='news')
                            self._append_log(f'[Новости] Вставлено в БД записей: {inserted}\n')
                        else:
                            self._append_log('[Новости] Новых уязвимостей не найдено.\n')
                    except Exception as e:
                        self._append_log(f'[Новости] Ошибка: {e}\n')

            finally:
                self._status_running = False
                self._progress_finish()
                # очистка диапазона после завершения всей работы
                self.var_from.set('')
                self.var_to.set('')
                self.btn_start.after(
                    0,
                    lambda: self.btn_start.configure(state=tk.NORMAL),
                )

        threading.Thread(target=run_one, daemon=True).start()

    def _run_fstek_range(self, start_id: str, end_id: str) -> None:
        if not (BDU_RE.match(start_id) and BDU_RE.match(end_id)):
            self._append_log('[ФСТЭК] Диапазон не соответствует формату ГГГГ-НННН.\n')
            return

        try:
            try:
                ids = iter_ids(start_id, end_id)
                total = len(ids)
            except Exception as e:
                self._append_log(f'[ФСТЭК] Ошибка диапазона: {e}\n')
                total = 0

            if self._progress_q is not None and total > 0:
                self._progress_q.put(('TOTAL', total))

            workers = max(1, mp.cpu_count() // 2)
            process_range_from_to(
                start_id=start_id,
                end_id=end_id,
                workers=workers,
                friendly_order=None,
                progress_q=self._progress_q,
                status_q=self._status_q,
                update_master_vuln=False,
                update_master_reserved=False,
            )
        except Exception as e:
            self._append_log(f'[ФСТЭК] Ошибка при обработке диапазона: {e}\n')

    def _load_settings(self) -> None:
        try:
            if not self._settings_path.exists():
                return
            data = json.loads(self._settings_path.read_text(encoding='utf-8'))
        except Exception:
            return
        
    def _on_report_click(self) -> None:
        """
        Сформировать отчёт по БД (агенты + их ПО + уязвимости) в .docx.
        """
        try:
            path = generate_vulnerability_report()
        except Exception as exc:
            messagebox.showerror('Ошибка', f'Не удалось сформировать отчёт:\n{exc}')
            return

        self._append_log(f'[Отчёт] Отчёт сформирован: {path}\n')
        messagebox.showinfo('Отчёт', f'Отчёт сформирован:\n{path}')

        self.use_fstek.set(bool(data.get('use_fstek', self.use_fstek.get())))
        self.use_news.set(bool(data.get('use_news', self.use_news.get())))

        self.var_fstek_hours.set(str(data.get('fstek_hours', self.var_fstek_hours.get())))
        self.var_news_hours.set(str(data.get('news_hours', self.var_news_hours.get())))

        # диапазон не восстанавливаем
        self.var_from.set('')
        self.var_to.set('')

        self.agent_api_enabled.set(bool(data.get('agent_api_enabled', self.agent_api_enabled.get())))
        self.agent_api_port.set(int(data.get('agent_api_port', self.agent_api_port.get())))
        self.private_key_path.set(str(data.get('private_key_path', self.private_key_path.get())))

    def _save_settings(self) -> None:
        data = {
            'use_fstek': bool(self.use_fstek.get()),
            'use_news': bool(self.use_news.get()),
            'fstek_hours': self.var_fstek_hours.get(),
            'news_hours': self.var_news_hours.get(),
            'agent_api_enabled': bool(self.agent_api_enabled.get()),
            'agent_api_port': int(self.agent_api_port.get() or 8000),
            'private_key_path': self.private_key_path.get(),
        }
        try:
            self._settings_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding='utf-8',
            )
        except Exception:
            pass

    def _on_close(self) -> None:
        self._save_settings()
        self.destroy()


def main() -> None:
    mp.freeze_support()
    try:
        mp.set_start_method('spawn', force=True)
    except RuntimeError:
        pass
    app = UnifiedApp()
    app.mainloop()


if __name__ == '__main__':
    main()
