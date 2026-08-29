#!/usr/bin/env python3
import sys

def main():
    try:
        with open('payload.dll', 'rb') as f:
            data = bytearray(f.read())
        for i in range(len(data)):
            data[i] ^= 0xAA
        with open('payload.bin', 'wb') as f:
            f.write(data)
        print("[PAYLOAD] payload.bin generated successfully.")
    except Exception as e:
        print(f"[ERRO] Failed to encrypt payload: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
