#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
embed_hash.py — Post-link script para P6.1 (Self-integrity check).

Lê um PE x64 (Stub.exe ou svc.dll), encontra o placeholder com magic
0xFE 0xED 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE + 32 bytes 0xAA, calcula o SHA256
combinado das seções `.text` e `.rdata` (SHA256(.text || .rdata)),
e sobrescreve o placeholder com o hash computado.

Nota: a magic é composta de bytes não-ASCII para não aparecer em
scanners de strings (`strings` exige sequências de >= 4 ASCII imprimíveis).

Nota: `.rdata` é incluído para cobrir tabelas de AOB, chaves XOR e outras
constantes que estão em .rdata — não apenas o código em .text.
Se .rdata não existir no binário, o hash é calculado só de .text.

Uso:
    python tools/embed_hash.py <path-to-exe-or-dll>

Sai com código != 0 em qualquer falha (placeholder não encontrado,
seção `.text` inexistente, IO error).
"""
import sys, os, hashlib, struct

# Magic: 8 bytes não-ASCII (0xFE 0xED 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE)
# Deve corresponder exatamente aos bytes em self_hash.c g_selfHashBlock.
MAGIC = bytes([0xFE, 0xED, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
PLACEHOLDER = MAGIC + b'\xAA' * 32

def parse_pe_sections(data: bytes):
    """Retorna dict nome -> (raw_offset, raw_size, virt_size) das seções do PE."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    nt_sig = struct.unpack_from('<I', data, e_lfanew)[0]
    if nt_sig != 0x00004550:  # 'PE\0\0'
        raise RuntimeError("not a PE file")
    file_hdr = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, file_hdr + 2)[0]
    size_opt = struct.unpack_from('<H', data, file_hdr + 16)[0]
    sect_table = file_hdr + 20 + size_opt
    sections = {}
    for i in range(num_sections):
        s = sect_table + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size = struct.unpack_from('<I', data, s + 8)[0]
        raw_size  = struct.unpack_from('<I', data, s + 16)[0]
        raw_off   = struct.unpack_from('<I', data, s + 20)[0]
        sections[name] = (raw_off, raw_size, virt_size)
    return sections

def main():
    if len(sys.argv) != 2:
        print("usage: embed_hash.py <pe-file>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    sections = parse_pe_sections(data)

    if '.text' not in sections:
        print("ERROR: .text section not found", file=sys.stderr)
        return 3

    def section_bytes(name):
        raw_off, raw_size, virt_size = sections[name]
        b = bytes(data[raw_off:raw_off + raw_size])
        # Pad com zeros até virt_size (igual ao que o runtime vê após mapeamento)
        if virt_size > raw_size:
            b = b + b'\x00' * (virt_size - raw_size)
        return b

    # SHA256(.text || .rdata) — se .rdata não existir, hash só de .text
    h = hashlib.sha256()
    h.update(section_bytes('.text'))
    if '.rdata' in sections:
        h.update(section_bytes('.rdata'))
        print(f"embed_hash.py: hashing .text + .rdata")
    else:
        print(f"embed_hash.py: .rdata not found, hashing .text only")
    digest = h.digest()

    # Localizar placeholder
    idx = data.find(PLACEHOLDER)
    if idx < 0:
        print("ERROR: placeholder (0xFE 0xED 0xBE 0xEF 0xCA 0xFE 0xBA 0xBE) + 0xAA*32 not found in binary",
              file=sys.stderr)
        return 4
    # Sobrescrever os 32 bytes após o magic
    data[idx + len(MAGIC):idx + len(MAGIC) + 32] = digest

    with open(path, 'wb') as f:
        f.write(bytes(data))

    print(f"embed_hash.py: SHA256({path}) .text+.rdata = {digest.hex()}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
