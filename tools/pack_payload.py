#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
pack_payload.py — Empacota svc.dll em blob cifrado para distribuição via
GitHub (P3.x transport + P7.1 polimorfismo).

Wire format (binário, little-endian):
    [0..31]   HMAC-SHA256(salt || iv || tag || ciphertext)
    [32..47]  salt (16B, random per-build, reserved para KDF futuro)
    [48..59]  IV  (12B, AES-GCM nonce)
    [60..75]  GCM tag (16B)
    [76..N-1] ciphertext

Plaintext (antes do AES) — header de polimorfismo P7.1:
    [0..3]    magic 'SP01'
    [4..7]    real_size (uint32 LE) — tamanho útil dos bytes do PE
    [8..]     svc.dll bytes
    [end]     padding random até múltiplo de 4096 (ofusca tamanho real)

Random salt + random padding garantem blob ÚNICO por build mesmo com
mesmo svc.dll (defesa contra hash-blocking pelo BattlEye/AC).

Uso:
    python tools/pack_payload.py svc.dll out.bin <aes_key_hex32> <hmac_key_hex32>

Chaves devem coincidir EXATAMENTE com as servidas pelo KeyAuth (type=var)
para o cliente.  Para gerar chaves novas:
    python -c "import secrets; print(secrets.token_hex(32))"
"""
import sys, os, struct, hmac, hashlib, secrets

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("ERROR: pip install cryptography", file=sys.stderr)
    sys.exit(2)

MAGIC = b'SP01'
PAD_ALIGN = 4096

def main():
    if len(sys.argv) != 5:
        print("usage: pack_payload.py <svc.dll> <out.bin> <aes_hex64> <hmac_hex64>",
              file=sys.stderr)
        return 2
    src, dst, aes_hex, hmac_hex = sys.argv[1:]
    aes_key  = bytes.fromhex(aes_hex)
    hmac_key = bytes.fromhex(hmac_hex)
    if len(aes_key) != 32 or len(hmac_key) != 32:
        print("ERROR: aes_key and hmac_key must be 32 bytes (hex 64)", file=sys.stderr)
        return 2

    with open(src, 'rb') as f:
        pe_bytes = f.read()

    # Header de polimorfismo + payload + padding random
    header = MAGIC + struct.pack('<I', len(pe_bytes))
    plain = header + pe_bytes
    pad_len = (-len(plain)) % PAD_ALIGN
    if pad_len < 64:           # garante mínimo 64B de variação
        pad_len += PAD_ALIGN
    plain += secrets.token_bytes(pad_len)

    salt = secrets.token_bytes(16)
    iv   = secrets.token_bytes(12)

    aead = AESGCM(aes_key)
    ct_with_tag = aead.encrypt(iv, plain, None)
    ciphertext = ct_with_tag[:-16]
    tag        = ct_with_tag[-16:]

    # HMAC sobre salt || iv || tag || ciphertext
    h = hmac.new(hmac_key, salt + iv + tag + ciphertext, hashlib.sha256).digest()

    blob = h + salt + iv + tag + ciphertext
    with open(dst, 'wb') as f:
        f.write(blob)

    print(f"pack_payload.py: wrote {dst}")
    print(f"  pe_size={len(pe_bytes)}  pad={pad_len}  total_plain={len(plain)}")
    print(f"  blob={len(blob)} bytes  hmac={h.hex()[:16]}...")
    return 0

if __name__ == '__main__':
    sys.exit(main())
