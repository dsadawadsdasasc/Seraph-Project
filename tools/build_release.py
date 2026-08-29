#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
build_release.py — Orquestrador de release P7.4.

Pipeline:
    1. Verifica/gera chaves AES-256 + HMAC-SHA256 (release/keys.json).
    2. Roda build_payload.bat   → svc.dll
    3. Empacota svc.dll          → release/svc.bin via pack_payload.py
    4. Roda build_stub.bat       → Stub.exe (com SHA256 .text embedded)
    5. (Opcional) git commit + push do svc.bin se --push.
    6. Imprime checklist de KeyAuth vars que precisam ser atualizadas
       (aes_key, hmac_key, payload_url, min_stub_version).

Uso:
    python tools/build_release.py [--push] [--keys release/keys.json]
"""
import os, sys, json, subprocess, argparse, secrets, hashlib, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cmd, **kw):
    print(f"[RUN] {cmd}")
    rc = subprocess.call(cmd, shell=True, cwd=str(ROOT), **kw)
    if rc != 0:
        sys.exit(f"[FAIL] command exited {rc}: {cmd}")

def load_or_make_keys(path: Path):
    if path.exists():
        with open(path) as f:
            d = json.load(f)
        if len(bytes.fromhex(d['aes']))  != 32: sys.exit("aes_key not 32B")
        if len(bytes.fromhex(d['hmac'])) != 32: sys.exit("hmac_key not 32B")
        return d
    print(f"[INFO] generating new keys → {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    d = {
        'aes':  secrets.token_hex(32),
        'hmac': secrets.token_hex(32),
    }
    with open(path, 'w') as f:
        json.dump(d, f, indent=2)
    return d

def bump_build_ver():
    ver_file = ROOT / "build_ver.txt"
    cur = int(ver_file.read_text().strip()) if ver_file.exists() else 0
    cur += 1
    ver_file.write_text(f"{cur}\n")
    return cur

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keys', default='release/keys.json')
    ap.add_argument('--push', action='store_true',
                    help="git add+commit+push svc.bin to releases repo")
    ap.add_argument('--release-repo', default=None,
                    help="path to local clone of releases repo (for --push)")
    args = ap.parse_args()

    keys_path = ROOT / args.keys
    keys = load_or_make_keys(keys_path)
    ver = bump_build_ver()
    print(f"[INFO] release version: {ver}")

    # 1) build payload
    run("build_payload.bat")

    svc = ROOT / "svc.dll"
    if not svc.exists():
        sys.exit("svc.dll missing after build_payload.bat")

    # 2) pack
    out_bin = ROOT / "release" / "svc.bin"
    out_bin.parent.mkdir(parents=True, exist_ok=True)
    run(f'C:\\Users\\leona\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe tools\\pack_payload.py "{svc}" "{out_bin}" {keys["aes"]} {keys["hmac"]}')

    # 3) build stub
    run("build_stub.bat")

    # 4) (optional) push to releases repo
    if args.push:
        if not args.release_repo:
            sys.exit("--push requires --release-repo <path>")
        rr = Path(args.release_repo)
        dst = rr / "svc.bin"
        dst.write_bytes(out_bin.read_bytes())
        run(f'git -C "{rr}" add svc.bin && git -C "{rr}" commit -m "release v{ver}" && git -C "{rr}" push')

    # 5) checklist
    sha = hashlib.sha256(out_bin.read_bytes()).hexdigest()
    print("\n========= RELEASE CHECKLIST =========")
    print(f"version:     {ver}")
    print(f"svc.bin sha: {sha}")
    print(f"")
    print(f"Update these KeyAuth vars (type=var) on the panel:")
    print(f"  aes_key            = {keys['aes']}")
    print(f"  hmac_key           = {keys['hmac']}")
    print(f"  payload_url        = <host>|<path/to/svc.bin>")
    print(f"  min_stub_version   = {ver}")
    print(f"=====================================")

if __name__ == '__main__':
    main()
