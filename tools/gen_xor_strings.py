#!/usr/bin/env python3
"""
gen_xor_strings.py
Pre-encrypts strings with the same XOR key used in XorStr.h (key=0x55, rolling).
Output: C literal arrays ready to paste as EXOR_A / EXOR_W macros.

Usage:
    python gen_xor_strings.py
"""

KEY = 0x55

def xor_encrypt_a(s: str) -> list[int]:
    b = s.encode('ascii')
    return [(byte ^ ((KEY + i) & 0xFF)) for i, byte in enumerate(b)]

def xor_encrypt_w(s: str) -> list[int]:
    # wchar_t: only XOR the low byte (matches the C impl which casts key to wchar_t)
    result = []
    for i, ch in enumerate(s):
        result.append(ord(ch) ^ ((KEY + i) & 0xFF))
    return result

def emit_a(name: str, s: str):
    enc = xor_encrypt_a(s)
    # +1 for null terminator (0 ^ key != 0, so we store 0 plaintext at end)
    arr = '{' + ', '.join(f'0x{b:02X}' for b in enc) + ', 0x00}'
    print(f"// \"{s}\"")
    print(f"static const char {name}[] = {arr};")
    print(f"// Usage: xor_pool_a({name}, {len(enc)+1}, 0x55)")
    print()

def emit_w(name: str, s: str):
    enc = xor_encrypt_w(s)
    arr = '{' + ', '.join(f'0x{w:04X}' for w in enc) + ', 0x0000}'
    print(f"// L\"{s}\"")
    print(f"static const wchar_t {name}[] = {arr};")
    print(f"// Usage: xor_pool_w({name}, {len(enc)+1}, 0x55)")
    print()

if __name__ == "__main__":
    print("=" * 60)
    print("keyauth.c strings — pre-encrypted with key=0x55 rolling XOR")
    print("=" * 60)
    print()

    # ANSI strings (GetProcAddress names)
    strings_a = [
        ("ENC_WinHttpOpen",               "WinHttpOpen"),
        ("ENC_WinHttpConnect",            "WinHttpConnect"),
        ("ENC_WinHttpOpenRequest",        "WinHttpOpenRequest"),
        ("ENC_WinHttpSendRequest",        "WinHttpSendRequest"),
        ("ENC_WinHttpReceiveResponse",    "WinHttpReceiveResponse"),
        ("ENC_WinHttpQueryDataAvailable", "WinHttpQueryDataAvailable"),
        ("ENC_WinHttpReadData",           "WinHttpReadData"),
        ("ENC_WinHttpCloseHandle",        "WinHttpCloseHandle"),
        ("ENC_success_true",              "\"success\":true"),
    ]

    # Wide strings (LoadLibraryW / WinHttp params)
    strings_w = [
        ("ENC_winhttp_dll",        "winhttp.dll"),
        ("ENC_WinHTTP_ua",         "WinHTTP/2.0"),
        ("ENC_keyauth_host",       "keyauth.win"),
        ("ENC_POST",               "POST"),
        ("ENC_api_path",           "/api/1.2/"),
        ("ENC_content_type",       "Content-Type: application/json\r\n"),
    ]

    print("/* ---------- ANSI ---------- */")
    for name, s in strings_a:
        emit_a(name, s)

    print("/* ---------- WIDE ---------- */")
    for name, s in strings_w:
        emit_w(name, s)
