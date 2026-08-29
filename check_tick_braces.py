import sys

with open(r"C:\Users\leona\Downloads\Seraph folder\Seraph\Loader\fly.c", "r", encoding="utf-8") as f:
    lines = f.readlines()

in_func = False
func_start = -1
depth = 0
braces_log = []

for idx, line in enumerate(lines):
    line_num = idx + 1
    if "void Fly_Tick(" in line:
        in_func = True
        func_start = line_num
        depth = 0
        braces_log = []
        print(f"Function Fly_Tick starts at line {line_num}")
    
    if in_func:
        # Strip comments
        l = line.split("//")[0]
        l = l.split("/*")[0] # naive, but let's be careful
        
        for char in l:
            if char == '{':
                depth += 1
                braces_log.append(('{', line_num, depth))
            elif char == '}':
                depth -= 1
                braces_log.append(('}', line_num, depth))
                if depth == 0:
                    print(f"Function Fly_Tick ends at line {line_num}")
                    in_func = False
                    break
                elif depth < 0:
                    print(f"Negative depth {depth} at line {line_num}: {line.strip()}")
                    in_func = False
                    break

print("Remaining open braces:")
for b in braces_log:
    print(b)
