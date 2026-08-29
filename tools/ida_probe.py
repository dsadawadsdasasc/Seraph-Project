import http.client, json

code = """
import idc, ida_ida, ida_search

# In IDA Pro Python, ida_search.find_imm or search_imm is used
hashes = [
    0x80C304B1, # Hop 0
    0x80CC788B, # Hop 1
    0x80A680C5, # Hop 2
    0x80A6806C, # Hop 3 (Physics / Motion)
    0x80A5A74D, # Hop 4
    0x80C2F62B, # Hop 5
    0x80A5B133, # Hop 6
    0x80A5B95D, # Hop 7
    0x80C37847, # Hop 8
    0x80C3B719, # Hop 9
    0x80C36DD1, # Hop 10
    0x80C37B91, # Hop 11
    0x80C37B8D, # Hop 12
    0x80C324B9, # Hop 13
    0x80A5A024, # Hop 14
    0x80FA8AA5, # Hop 15
    0x80C542CF, # Hop 16
    0x80F9097D, # Hop 17
    0x80C60311, # Hop 18
    0x80F89379, # Hop 19
    0x80A5A1BA, # Hop 20
    0x80C340D7, # Hop 21
    0x80C3492D, # Hop 22
    0x80CED811, # Hop 23
]

results = {}
for h in hashes[:6]:
    # Look for functions querying this component
    ea = ida_search.find_imm(ida_ida.inf_get_min_ea(), ida_search.SEARCH_DOWN, h)
    if ea[0] != idc.BADADDR:
        fn = idc.get_func_name(ea[0])
        results[f"0x{h:08X}"] = f"EA=0x{ea[0]:X} func={fn}"
    else:
        results[f"0x{h:08X}"] = "not found"

print(json.dumps(results, indent=2))
"""

conn = http.client.HTTPConnection('127.0.0.1', 13337, timeout=60)
conn.request('POST', '/mcp', json.dumps({'jsonrpc':'2.0','method':'tools/call','params':{'name':'py_eval','arguments':{'code': code}},'id':1}), {'Content-Type':'application/json'})
res = conn.getresponse()
out = json.loads(res.read().decode())
print(out["result"]["content"][0]["text"])
