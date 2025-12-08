# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_rsa_keypair(private_path: Path,
                         public_path: Path,
                         key_size: int = 2048) -> None:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.write_bytes(priv_bytes)
    public_path.write_bytes(pub_bytes)
