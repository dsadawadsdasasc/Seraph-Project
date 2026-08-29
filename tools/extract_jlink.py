#!/usr/bin/env python3
"""
Extract jlinkarm.sys from JLink_Windows_x86_64.exe (NSIS installer).
"""
import os
import sys
import subprocess
import tempfile
import shutil

def extract_nsis(exe_path, output_dir):
    """Use 7-Zip command line to extract NSIS installer."""
    # Try to find 7z.exe
    seven_z = None
    for path in [
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
        r"C:\Program Files\7-Zip\7z.exe",
        "7z"
    ]:
        if os.path.exists(path):
            seven_z = path
            break
    if not seven_z:
        # Try using 7z from PATH
        try:
            subprocess.run(["7z", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            seven_z = "7z"
        except FileNotFoundError:
            print("ERROR: 7-Zip not found. Install 7-Zip or add to PATH.")
            return False
    
    cmd = [seven_z, "x", exe_path, f"-o{output_dir}", "-y"]
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"7z extraction failed: {result.stderr}")
        return False
    print("Extraction successful.")
    return True

def find_jlink_sys(root_dir):
    """Recursively find jlinkarm.sys."""
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for f in filenames:
            if f.lower() == "jlinkarm.sys":
                return os.path.join(dirpath, f)
    return None

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    loader_dir = os.path.join(script_dir, "..", "Loader")
    exe_path = os.path.join(loader_dir, "JLink_Windows_x86_64.exe")
    if not os.path.exists(exe_path):
        print(f"ERROR: {exe_path} not found.")
        sys.exit(1)
    
    # Create temporary extraction directory
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Extracting to {tmpdir}")
        if not extract_nsis(exe_path, tmpdir):
            sys.exit(1)
        
        sys_path = find_jlink_sys(tmpdir)
        if not sys_path:
            print("ERROR: jlinkarm.sys not found in extracted files.")
            # List files for debugging
            for root, dirs, files in os.walk(tmpdir):
                for f in files:
                    print(os.path.join(root, f))
            sys.exit(1)
        
        # Copy to Loader directory
        dest = os.path.join(loader_dir, "jlinkarm.sys")
        shutil.copy2(sys_path, dest)
        print(f"Copied jlinkarm.sys to {dest}")
        
        # Also copy to Driver directory for reference
        driver_dir = os.path.join(script_dir, "..", "Driver")
        if os.path.exists(driver_dir):
            shutil.copy2(sys_path, os.path.join(driver_dir, "jlinkarm.sys"))
            print(f"Copied to Driver directory.")

if __name__ == "__main__":
    main()