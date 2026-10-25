"""Read-only targeted MTGA memory inspection of [ID, metadata, ID, value] records.

Requires find_arena.py and search_card_memory.py in the same directory.
No memory is written. Observed values are not assumed to represent ownership.
"""
import argparse
import ctypes
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
    raise SystemExit('Run with 64-bit Windows Python (py.exe -3).')
from find_arena import find_arena_pid
from search_card_memory import (CHUNK, MEM_COMMIT, PAGE_GUARD, READABLE,
    MEMORY_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    kernel32, read_bytes)

CARDS = {75446: ('Charmed Stray', 4), 93726: ('Fleeting Flight', 2),
         93855: ("Healer's Hawk", 2), 103481: ("Last Light of Durin's Day", 1),
         76519: ('Devouring Tendrils', 0), 76644: ('Spirit Summoning', 0)}
DEFAULT_ADDRESSES = [0x2457595F490, 0x24547B4F830]


def inspect_region(handle, address, max_region_mb, max_examples):
    mbi = MEMORY_BASIC_INFORMATION()
    if not kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)):
        return {'probe': hex(address), 'error': 'VirtualQueryEx failed'}
    base, size = int(mbi.BaseAddress or 0), int(mbi.RegionSize)
    result = {'probe': hex(address), 'region_base': hex(base), 'region_size': size,
              'readable': bool(mbi.State == MEM_COMMIT and
                  (mbi.Protect & 0xFF) in READABLE and not (mbi.Protect & PAGE_GUARD)),
              'truncated': size > max_region_mb * 1024 * 1024,
              'records': {}, 'short_reads': 0}
    if not result['readable']:
        result['error'] = 'Address is not in a readable committed region'
        return result
    if result['truncated']:
        result['error'] = 'Region exceeds safety cap; use --max-region-mb to increase deliberately'
        return result
    patterns = {cid: struct.pack('<I', cid) for cid in CARDS}
    records = defaultdict(lambda: {'pair_count': 0, 'repeat_count': 0,
                                    'pair_values': {}, 'examples': []})
    pos, end = base, base + size
    while pos < end:
        primary = min(CHUNK, end - pos)
        data = read_bytes(handle, pos, min(primary + 64, end - pos))
        if len(data) < primary:
            result['short_reads'] += 1
        limit = min(primary, len(data))
        for cid, pattern in patterns.items():
            offset = data.find(pattern)
            while offset != -1 and offset < limit:
                addr = pos + offset
                if addr % 4 == 0 and offset + 16 <= len(data):
                    a, b, c, d = struct.unpack_from('<IIII', data, offset)
                    if a == c == cid:
                        r = records[cid]
                        if b == 0xFFFFFFFF:
                            r['repeat_count'] += 1
                        else:
                            r['pair_count'] += 1
                        key = f'{b}:{d}'
                        r['pair_values'][key] = r['pair_values'].get(key, 0) + 1
                        if len(r['examples']) < max_examples:
                            start = max(0, offset - 32)
                            stop = min(len(data), offset + 48)
                            r['examples'].append({'address': hex(addr),
                                'field_1': b, 'field_2': d,
                                'hex_start': hex(pos + start),
                                'hex': data[start:stop].hex(' ')})
                offset = data.find(pattern, offset + 1)
        pos += primary
    result['records'] = {str(cid): dict(records[cid]) for cid in CARDS}
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--pid', type=int)
    p.add_argument('--address', action='append', type=lambda s: int(s, 0),
                   help='Probe address (repeatable). Default: two prior-session leads')
    p.add_argument('--max-region-mb', type=int, default=64)
    p.add_argument('--max-examples', type=int, default=4)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    if args.max_region_mb < 1 or args.max_examples < 0:
        p.error('Invalid scan limits')
    pid = args.pid or find_arena_pid()
    if not pid:
        raise SystemExit('MTGA.exe not found')
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        results = [inspect_region(handle, a, args.max_region_mb, args.max_examples)
                   for a in (args.address or DEFAULT_ADDRESSES)]
    finally:
        kernel32.CloseHandle(handle)
    report = {'pid': pid, 'warning': 'Read-only observations; not ownership proof',
              'cards': {str(k): {'name': v[0], 'ui_quantity': v[1]} for k, v in CARDS.items()},
              'regions': results}
    print(f'MTGA PID {pid} | paired-record inspection (read-only)')
    for region in results:
        print(f"\nProbe {region['probe']} | region {region.get('region_base', '?')} "
              f"size={region.get('region_size', '?')}")
        if 'error' in region:
            print('  WARNING:', region['error'])
            continue
        print('  short reads:', region['short_reads'])
        for cid, (name, expected) in CARDS.items():
            r = region['records'][str(cid)]
            print(f'  {name} ({cid}) UI x{expected}: '
                  f"pair={r['pair_count']} repeated={r['repeat_count']} "
                  f"fields={r['pair_values']}")
            for e in r['examples']:
                print(f"    {e['address']}: [{cid}, {e['field_1']}, {cid}, {e['field_2']}]")
                print(f"      context {e['hex_start']}: {e['hex']}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(f'\nSaved {args.output}')

if __name__ == '__main__':
    main()
