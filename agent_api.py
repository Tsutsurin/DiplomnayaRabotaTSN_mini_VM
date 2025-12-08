# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any, Dict

from flask import Flask, jsonify, request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from config import ROOT_DIR
from src.db import upsert_agent_inventory  # ← ВАЖНО: src.db, а не db

app = Flask(__name__)
log = logging.getLogger(__name__)

# По умолчанию кладём сюда, но app_unified потом переопределяет:
PRIVATE_KEY_PATH: Path = ROOT_DIR / 'server_private_key.pem'
LOG_PATH: Path = ROOT_DIR / 'agent_api.log'


def _setup_logging() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_PATH, encoding='utf-8'),
            logging.StreamHandler(),
        ],
    )


def _load_private_key(path: Path):
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)


def _decrypt_payload(
    priv_key,
    enc_key_b64: str,
    enc_data_b64: str,
) -> Dict[str, Any]:
    """
    Расшифровка данных от агента:
    1) RSA-OAEP: enc_key -> AES-ключ
    2) AES-GCM: enc_data -> JSON
    """
    enc_key = base64.b64decode(enc_key_b64)
    enc_data = base64.b64decode(enc_data_b64)

    aes_key = priv_key.decrypt(
        enc_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Формат: nonce(12) + tag(16) + ciphertext
    if len(enc_data) < 12 + 16:
        raise ValueError('enc_data too short')

    nonce = enc_data[:12]
    tag = enc_data[12:28]
    ciphertext = enc_data[28:]

    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(nonce, tag),
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return json.loads(plaintext.decode('utf-8'))


@app.route('/api/agent/report', methods=['POST'])
def agent_report() -> Any:
    """
    Приём отчёта от агента.
    Ждём JSON:
    {
      "enc_key": "...",
      "enc_data": "..."
    }
    """
    try:
        raw = request.get_json(force=True, silent=False)
    except Exception as exc:
        log.error('bad json: %r', exc)
        return jsonify({'error': 'bad_json'}), 400

    enc_key = (raw or {}).get('enc_key')
    enc_data = (raw or {}).get('enc_data')
    if not enc_key or not enc_data:
        return jsonify({'error': 'enc_key_or_enc_data_missing'}), 400

    try:
        priv_key = _load_private_key(PRIVATE_KEY_PATH)
    except Exception as exc:
        log.error('cannot load private key %s: %r', PRIVATE_KEY_PATH, exc)
        return jsonify({'error': 'private_key_error'}), 500

    try:
        payload = _decrypt_payload(priv_key, enc_key, enc_data)
    except Exception as exc:
        log.error('decrypt_failed: %r', exc)
        return jsonify({'error': 'decrypt_failed'}), 400

    agent_id = payload.get('agent_id')
    os_info = payload.get('os_info') or {}
    software = payload.get('software') or []
    ip_address = payload.get('ip_address') or None

    if not agent_id:
        return jsonify({'error': 'agent_id_missing'}), 400

    try:
        upsert_agent_inventory(
            agent_id=str(agent_id),
            hostname=os_info.get('hostname'),
            os_type=os_info.get('os_type'),
            os_release=os_info.get('os_release'),
            os_version=os_info.get('os_version'),
            architecture=os_info.get('architecture'),
            ip_address=ip_address,
            software_list=software,
        )
    except Exception as exc:
        log.exception('db_error while saving agent report: %r', exc)
        return jsonify({'error': 'db_error'}), 500

    log.info(
        'Принят отчёт от агента %s (%s), ПО: %d записей',
        agent_id,
        ip_address or os_info.get('hostname') or 'unknown',
        len(software),
    )
    return jsonify({'status': 'ok'}), 200


def run_agent_api(host: str = '0.0.0.0', port: int = 8000) -> None:
    """
    Запуск Flask-приложения (вызывается из app_unified).
    """
    _setup_logging()
    logging.info('Запуск agent API на %s:%d', host, port)
    # threaded=True — чтобы не блокировать основной поток GUI
    app.run(host=host, port=port, threaded=True, use_reloader=False)
