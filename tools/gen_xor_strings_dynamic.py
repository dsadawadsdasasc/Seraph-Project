#!/usr/bin/env python3
"""
gen_xor_strings_dynamic.py
Generate pre-encrypted strings with 4 random XOR keys per build.
Outputs a C header file with encrypted arrays and defines SERAPH_KEY1..4.
"""

import sys
import random

def get_arx_byte(i: int, k1: int, k2: int, k3: int, k4: int) -> int:
    v0 = (i ^ k1) & 0xFFFFFFFF
    v1 = (v0 + k2) & 0xFFFFFFFF
    rot = (k3 + i) & 31
    v2 = ((v1 << rot) | (v1 >> (32 - rot))) & 0xFFFFFFFF
    v3 = v2 ^ k4
    return v3 & 0xFF

def get_arx_word(i: int, k1: int, k2: int, k3: int, k4: int) -> int:
    v0 = (i ^ k1) & 0xFFFFFFFF
    v1 = (v0 + k2) & 0xFFFFFFFF
    rot = (k3 + i) & 31
    v2 = ((v1 << rot) | (v1 >> (32 - rot))) & 0xFFFFFFFF
    v3 = v2 ^ k4
    return v3 & 0xFFFF

def xor_encrypt_a(s: str, k1: int, k2: int, k3: int, k4: int) -> list[int]:
    b = s.encode('ascii')
    return [(byte ^ get_arx_byte(i, k1, k2, k3, k4)) for i, byte in enumerate(b)]

def xor_encrypt_w(s: str, k1: int, k2: int, k3: int, k4: int) -> list[int]:
    return [(ord(ch) ^ get_arx_word(i, k1, k2, k3, k4)) for i, ch in enumerate(s)]

def emit_a(name: str, s: str, k1: int, k2: int, k3: int, k4: int) -> str:
    enc = xor_encrypt_a(s, k1, k2, k3, k4)
    arr = '{' + ', '.join(f'0x{b:02X}' for b in enc) + ', 0x00}'
    lines = []
    lines.append(f"// \"{s}\"")
    lines.append(f"static const char {name}[] = {arr};")
    return '\n'.join(lines)

def emit_w(name: str, s: str, k1: int, k2: int, k3: int, k4: int) -> str:
    enc = xor_encrypt_w(s, k1, k2, k3, k4)
    arr = '{' + ', '.join(f'0x{w:04X}' for w in enc) + ', 0x0000}'
    lines = []
    lines.append(f"// L\"{s}\"")
    lines.append(f"static const wchar_t {name}[] = {arr};")
    return '\n'.join(lines)

def main():
    # We ignore the key argument if 'random' is passed or derive it randomly
    k1 = random.randint(100000, 0x7FFFFFFF)
    k2 = random.randint(100000, 0x7FFFFFFF)
    k3 = random.randint(100000, 0x7FFFFFFF)
    k4 = random.randint(100000, 0x7FFFFFFF)
    
    output_header = sys.argv[2] if len(sys.argv) > 2 else "Loader\\xor_strings.h"
    
    # Strings used in keyauth.c and other modules
    strings_a = [
        ("ENC_WinHttpOpen",               "WinHttpOpen"),
        ("ENC_WinHttpConnect",            "WinHttpConnect"),
        ("ENC_WinHttpOpenRequest",        "WinHttpOpenRequest"),
        ("ENC_WinHttpSendRequest",        "WinHttpSendRequest"),
        ("ENC_WinHttpReceiveResponse",    "WinHttpReceiveResponse"),
        ("ENC_WinHttpQueryDataAvailable", "WinHttpQueryDataAvailable"),
        ("ENC_WinHttpReadData",           "WinHttpReadData"),
        ("ENC_WinHttpCloseHandle",        "WinHttpCloseHandle"),
        ("ENC_WinHttpSetTimeouts",        "WinHttpSetTimeouts"),
        ("ENC_success_true",              "\"success\":true"),
        ("ENC_sessionid_key",             "\"sessionid\":"),
        ("ENC_sandbox_key",               "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie"),
        ("ENC_K32EnumDeviceDrivers",      "K32EnumDeviceDrivers"),
        ("ENC_K32GetDeviceDriverBaseNameA","K32GetDeviceDriverBaseNameA"),
        ("ENC_NtClose",                   "NtClose"),
        ("ENC_reg_hvci",                  "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"),
        ("ENC_reg_secureboot",            "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
        ("ENC_reg_ci_config",             "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"),
        ("ENC_joyGetPosEx",               "joyGetPosEx"),
        ("ENC_XInputGetState",            "XInputGetState"),
        ("ENC_xinput1_4_dll",             "xinput1_4.dll"),
        ("ENC_xinput1_3_dll",             "xinput1_3.dll"),
        ("ENC_xinput9_1_0_dll",           "xinput9_1_0.dll"),
        ("ENC_RtlInitUnicodeString",      "RtlInitUnicodeString"),
        ("ENC_NtDelayExecution",           "NtDelayExecution"),
        ("ENC_LoadLibraryW",              "LoadLibraryW"),
        ("ENC_LoadLibraryExW",            "LoadLibraryExW"),
        ("ENC_kmbox_default_ip",          "192.168.2.188"),
        ("ENC_kmbox_default_port",        "6666"),
        ("ENC_kmbox_default_com",         "3"),
        ("ENC_kmbox_default_baud",         "115200"),
        ("ENC_kmbox_com_path_fmt",        "\\\\.\\COM%d"),
        ("ENC_kmbox_cmd_move",            "km.move(%d,%d)"),
        ("ENC_kmbox_cmd_mouse_move",      "km.mouse_move(%d,%d)"),
        ("ENC_kmbox_cmd_left",            "km.left(%d)"),
    ]
    
    strings_w = [
        ("ENC_winhttp_dll",        "winhttp.dll"),
        ("ENC_WinHTTP_ua",         "WinHTTP/2.0"),
        ("ENC_keyauth_host",       "keyauth.win"),
        ("ENC_POST",               "POST"),
        ("ENC_api_path",           "/api/1.2/"),
        ("ENC_content_type",       "Content-Type: application/x-www-form-urlencoded"),
        ("ENC_discord_ua",         "DiscordBot (https://discord.com, 1.0)"),
        ("ENC_discord_host",       "discord.com"),
        ("ENC_webhooks_path_pfx",  "/api/webhooks/"),
        ("ENC_discord_ct_json",    "Content-Type: application/json"),
        ("ENC_kernel32_dll",       "kernel32.dll"),
        ("ENC_ntdll_dll",          "ntdll.dll"),
        ("ENC_reg_bios_path",      "HARDWARE\\DESCRIPTION\\System\\BIOS"),
        ("ENC_reg_baseboard_val",  "BaseBoardSerialNumber"),
        ("ENC_reg_systemserial_val","SystemSerialNumber"),
        ("ENC_drive_root",         "C:\\"),
        ("ENC_winmm_dll",          "winmm.dll"),
    ]
    
    # RVA offsets to obfuscate at compile-time (Value Obfuscation)
    # Note: These values are stored as offset (rel to module base) and encrypted.
    offsets = [
        ("Damage",           0x286ea0),
        ("HealthRegen",      0x10b0e8f),
        ("InstaKill",        0x1649cfa),
        ("Fly_Cam",          0x1938792),
        ("Havok",            0x1478225),
        ("RapidFire",        0xbac0dc),
        ("InstAbils",        0xa331c6),
        ("NoTurnBack",       0xf16452),
        ("NoJoinAllies",     0x5e44de),
        ("KillAura",         0x16e6859),
        ("GameSpeed",        0x21e6f00),
        ("Guardian",         0x334b68c),
        ("ImmuneBoss",       0x1d182c),
        ("InteractAura",     0x3333dd),
        ("ImmuneAura",       0xabb60e),
        ("InfiniteAmmo",     0xb97cc3),
        ("PlayerCloner",     0x2beebe),
        ("AmmoBrick",        0x84bbbf),
        ("HSpeed",           0xbac0e4),
        ("MSpeed",           0xb9ca86),
        ("NoRecoil",         0x1021b26),
        ("SilentAim",        0x2beeba),
        ("ThirdPerson",      0x194c604),
        ("SpinBot",          0x322A6E),
        
        # d2_patches.c RVAs
        ("Pat_InfStacks",    0xefacd4),
        ("Pat_Sparrow",      0x1229b4),
        ("Pat_ShootWalls",   0x12affb8),
        ("Pat_InfTimers",    0xd1f2ea),
        ("Pat_InfDash",      0x1882419),
        ("Pat_Godmode",      0x10b0d32),
        ("Pat_InfTokens",    0xb4d27c),
        ("Pat_InfSword",     0x310a27),
        ("Pat_Spread",       0x1449640),
        ("Pat_Fusion",       0x1de12b),
        ("Pat_HealthRegen",  0x10b0fdc),
        ("Pat_PvpSparrow",   0x715571),

        # esp.c
        ("Schindler",        0xc0b85b),

        # local_player.c
        ("LocalIdentity",    0x3B19BD0),
        ("CharMotionVtable", 0x186D870),

        # tigerlist.c / sobject_list.c
        ("TigerListBase",    0x42976C8),
        ("SObjectListBase",  0x27F5778),
        ("HandlePoolRoot",   0x27F5784),

        # ammo.c
        ("AmmoHookVA",       0xb97cf3),
        ("GetKeyVA",         0xb98160),

        # matchmaking.c
        ("MatchmakingBase",  0x1944e84),

        # fly.c direct LP hook
        ("DirectLpHook",     0xF0E820),

        # activity_loader.c
        ("ActivityLoader",   0x4f62c2),

        # namechanger.c placeholders/RVAs
        ("NC_GetterCall",    0x4f391f),
        ("NC_CopyCall",      0x4f3942),
        ("NC_DecodeCall",    0x4f3dfc),

        # noinactivity.c placeholder
        ("NoInactivity",     0xBAADF00D),

        # esp.h datum table anchor instruction offset
        ("DatumTable",       0x165F30D),
    ]

    # Helper Python functions that mirror the C Speck32/LCG cryptography logic
    def rotl16(x: int, r: int) -> int:
        r = r & 15
        if r == 0:
            return x & 0xFFFF
        return ((x << r) | (x >> (16 - r))) & 0xFFFF

    def rotr16(x: int, r: int) -> int:
        r = r & 15
        if r == 0:
            return x & 0xFFFF
        return ((x >> r) | (x << (16 - r))) & 0xFFFF

    def hash_context(mask: int, storage: int) -> int:
        mix = (mask ^ storage) & 0xFFFFFFFFFFFFFFFF
        mix ^= mix >> 33
        mix = (mix * 0xFF51AFD7ED558CCD) & 0xFFFFFFFFFFFFFFFF
        mix ^= mix >> 33
        mix = (mix * 0xC4CEB9FE1A85EC53) & 0xFFFFFFFFFFFFFFFF
        mix ^= mix >> 33
        return mix & 0xFFFFFFFF

    def encrypt_static_val(real_value: int, mask: int) -> tuple[int, int]:
        L = (real_value >> 16) & 0xFFFF
        R = real_value & 0xFFFF
        
        # storage address is 0 for static offsets
        ks = hash_context(mask, 0)
        
        LCG_A = 0x343FD5
        LCG_C = 0x269EC3
        
        for r in range(16):
            ks = (ks * LCG_A + LCG_C) & 0xFFFFFFFF
            round_key = (ks ^ (ks >> 16)) & 0xFFFF
            
            L = (rotr16(L, 7) + R) & 0xFFFF
            L = (L ^ round_key) & 0xFFFF
            R = (rotl16(R, 2) ^ L) & 0xFFFF
            
        obfuscated_data = (L << 16) | R
        verification = (hash_context(real_value, 0) ^ mask) & 0xFFFFFFFF
        return obfuscated_data, verification
    
    content = f"""// Auto-generated encrypted strings and offsets with random keys
// This file is generated by gen_xor_strings_dynamic.py
// DO NOT EDIT MANUALLY

#ifndef XOR_STRINGS_H
#define XOR_STRINGS_H

#include "seraph_secure_val.h"

#define SERAPH_KEY1 {k1}u
#define SERAPH_KEY2 {k2}u
#define SERAPH_KEY3 {k3}u
#define SERAPH_KEY4 {k4}u

/* ---------- ANSI ---------- */
"""
    
    for name, s in strings_a:
        content += emit_a(name, s, k1, k2, k3, k4) + "\n\n"
    
    content += "/* ---------- WIDE ---------- */\n"
    for name, s in strings_w:
        content += emit_w(name, s, k1, k2, k3, k4) + "\n\n"
    
    content += "/* ---------- OBFUSCATED OFFSETS ---------- */\n"
    for name, val in offsets:
        # Generate a random mask for the offset
        mask = random.randint(10000, 0xFFFFFFFF)
        obf_data, verification = encrypt_static_val(val, mask)
        content += f"// {name} = {hex(val)}\n"
        content += f"static const SecureVal96 OBF_OFF_{name} = {{ {hex(obf_data)}u, {hex(mask)}u, {hex(verification)}u }};\n\n"

    content += "#endif // XOR_STRINGS_H\n"
    
    with open(output_header, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Generated {output_header} with 4 XOR keys successfully.")

if __name__ == "__main__":
    main()