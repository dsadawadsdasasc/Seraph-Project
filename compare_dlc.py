import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

old_dump_path = r"C:\Users\leona\Downloads\Seraph folder\Seraph\TBH\DUMP 1.00.23\dump.cs.txt"
new_dump_path = r"C:\Users\leona\Downloads\Seraph folder\Seraph\TBH\DUMP 1.00.24\dump.cs.txt"

def get_dlc_manager_methods(path, label):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    pattern = re.compile(r"public class DLCManager\b", re.IGNORECASE)
    match = pattern.search(content)
    if match:
        pos = match.start()
        chunk = content[pos:pos+4000]
        print(f"=== {label} ===")
        print(chunk)
    else:
        print(f"=== {label} (NOT FOUND) ===")

get_dlc_manager_methods(old_dump_path, "1.00.23")
get_dlc_manager_methods(new_dump_path, "1.00.24")
