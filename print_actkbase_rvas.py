def print_lines(path, start_line, num_lines):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= start_line and i < start_line + num_lines:
                print(f"{i}: {line.rstrip()}")

dump_path = r"C:\Users\leona\Downloads\Seraph folder\Seraph\TBH\DUMP 1.00.23\dump.cs.txt"
print_lines(dump_path, 1214150, 50)
