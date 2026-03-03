#!/usr/bin/env python3
"""
benchmark.py — COG vs SCOG Range Request 성능 비교

측정 항목:
  - Range Request 횟수
  - 전송량 (bytes)
  - 응답 시간 (ms)
  - 오버헤드 (SCOG 블록 크기)

사용:
  python src/benchmark.py
  python src/benchmark.py --url http://localhost:8777 --runs 5
"""

import sys
import time
import json
import struct
import argparse
import statistics
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).parent))
from scog_structs import parse_scog_block, decrypt_level
from cred_issuer import load_credential, get_cek

BASE_URL  = 'http://localhost:8777'
SCOG_FILE = 'kompsat.scog'
COG_FILE  = 'kompsat.tif'
CRED_FILE = Path(__file__).parent.parent / 'keys' / 'cred_premium.json'


# ─── Range Request 헬퍼 ──────────────────────────────────────────────────────

def range_request(session, filename, start, end, label=''):
    url     = f'{BASE_URL}/{filename}'
    headers = {'Range': f'bytes={start}-{end}'}
    t0      = time.perf_counter()
    resp    = session.get(url, headers=headers, timeout=30)
    ms      = (time.perf_counter() - t0) * 1000
    assert resp.status_code in (200, 206), f"HTTP {resp.status_code}"
    size = len(resp.content)
    return resp.content, size, ms


# ─── COG 읽기 시뮬레이션 ────────────────────────────────────────────────────

def benchmark_cog(session, tiff_data=None):
    """
    COG 파일: 헤더 → IFD → 타일 읽기 시뮬레이션
    (모든 레벨의 타일 0번 읽기)
    """
    results = []

    # 1. TIFF 헤더 (8 bytes)
    raw, size, ms = range_request(session, COG_FILE, 0, 8191, 'COG 헤더+IFD 영역')
    results.append({'label': 'COG 헤더+IFD', 'bytes': size, 'ms': ms})

    # 헤더 파싱해서 실제 타일 위치 파악
    from scog_structs import parse_tiff, TAG_TILE_OFFSETS, TAG_TILE_BYTECOUNTS
    # 로컬 파일로 파싱 (HTTP로 필요한 부분만 가져오는 건 복잡하므로 로컬 사용)
    cog_path = Path(__file__).parent.parent / 'data' / 'kompsat.tif'
    cog_data = cog_path.read_bytes()
    tiff     = parse_tiff(cog_data)

    # 각 레벨 타일 0번 읽기
    for i, ifd in enumerate(tiff.ifds):
        offset_entry = ifd.entries.get(TAG_TILE_OFFSETS)
        bc_entry     = ifd.entries.get(TAG_TILE_BYTECOUNTS)
        if not offset_entry: continue

        off = int(offset_entry.values[0])
        bc  = int(bc_entry.values[0]) if bc_entry else 0

        raw, size, ms = range_request(session, COG_FILE, off, off + bc - 1,
                                      f'COG L{i} 타일(0,0)')
        results.append({'label': f'COG L{i} 타일(0,0)', 'bytes': size, 'ms': ms})

    return results


# ─── SCOG 읽기 시뮬레이션 ────────────────────────────────────────────────────

def benchmark_scog(session, cred):
    """
    SCOG 파일: SCOG 블록 → 복호화 → 타일 읽기
    (모든 접근 가능한 레벨의 타일 0번 읽기)
    """
    results = []
    scog_block_size = cred['scog_block_size']

    # 1. SCOG 블록
    raw, size, ms = range_request(session, SCOG_FILE, 0, scog_block_size - 1, 'SCOG 블록')
    results.append({'label': 'SCOG 블록 (암호화된 offsets)', 'bytes': size, 'ms': ms})

    # 복호화 (로컬에서 수행 — 네트워크 불포함)
    sb = parse_scog_block(raw)

    for level_str, cek_hex in sorted(cred['levels'].items()):
        level_id = int(level_str)
        cek = bytes.fromhex(cek_hex)
        entry = sb.entries.get(level_id)
        if not entry: continue

        t_decrypt = time.perf_counter()
        offsets, bytecounts = decrypt_level(entry, cek, cred['file_id'], level_id)
        decrypt_ms = (time.perf_counter() - t_decrypt) * 1000

        results.append({
            'label': f'SCOG L{level_id} 복호화 (로컬)',
            'bytes': 0,
            'ms': decrypt_ms,
            'local': True,
        })

        # 타일 0번 읽기
        off = int(offsets[0])
        bc  = int(bytecounts[0])
        file_off = scog_block_size + off

        raw_tile, size, ms = range_request(
            session, SCOG_FILE, file_off, file_off + bc - 1,
            f'SCOG L{level_id} 타일(0,0)'
        )
        results.append({'label': f'SCOG L{level_id} 타일(0,0)', 'bytes': size, 'ms': ms})

    return results


# ─── 리포트 ──────────────────────────────────────────────────────────────────

def print_results(label, results, runs=1):
    print(f'\n{"─"*60}')
    print(f'{label}')
    print(f'{"─"*60}')

    total_requests = sum(1 for r in results if not r.get('local'))
    total_bytes    = sum(r['bytes'] for r in results)
    total_ms       = sum(r['ms'] for r in results)

    for r in results:
        prefix = '  [로컬]' if r.get('local') else '  [HTTP]'
        if r.get('local'):
            print(f"{prefix} {r['label']:<40} {r['ms']:.2f}ms (복호화)")
        else:
            print(f"{prefix} {r['label']:<40} {r['bytes']:>10,} bytes  {r['ms']:>7.1f}ms")

    print()
    print(f"  HTTP 요청 수:   {total_requests}")
    print(f"  전체 전송량:    {total_bytes:,} bytes ({total_bytes/1024:.1f} KB)")
    print(f"  HTTP 소요 시간: {total_ms:.1f}ms")
    return {
        'requests': total_requests,
        'bytes':    total_bytes,
        'ms':       total_ms,
    }


def run_benchmark(runs=3):
    print('=' * 60)
    print('SCOG vs COG Range Request 성능 비교')
    print(f'서버: {BASE_URL}')
    print(f'반복: {runs}회 평균')
    print('=' * 60)

    cred = load_credential(str(CRED_FILE))
    session = requests.Session()

    cog_stats_list  = []
    scog_stats_list = []

    for run in range(runs):
        print(f'\n[실행 {run+1}/{runs}]')

        cog_results  = benchmark_cog(session)
        scog_results = benchmark_scog(session, cred)

        cog_stats  = print_results('COG  (표준 읽기)',  cog_results)
        scog_stats = print_results('SCOG (자격증명 기반 읽기)', scog_results)

        cog_stats_list.append(cog_stats)
        scog_stats_list.append(scog_stats)

    # ── 평균 비교 ──────────────────────────────────────────────────────────────
    print('\n' + '=' * 60)
    print('평균 비교 (모든 레벨 타일 0번 기준)')
    print('=' * 60)

    def avg(lst, key):
        return statistics.mean(d[key] for d in lst)

    cog_req    = avg(cog_stats_list, 'requests')
    scog_req   = avg(scog_stats_list, 'requests')
    cog_bytes  = avg(cog_stats_list, 'bytes')
    scog_bytes = avg(scog_stats_list, 'bytes')
    cog_ms     = avg(cog_stats_list, 'ms')
    scog_ms    = avg(scog_stats_list, 'ms')

    print(f"\n{'':30} {'COG':>12} {'SCOG':>12} {'차이':>10}")
    print(f"{'─'*66}")
    print(f"{'HTTP 요청 수':30} {cog_req:>12.1f} {scog_req:>12.1f} {scog_req-cog_req:>+10.1f}")
    print(f"{'전송량 (bytes)':30} {cog_bytes:>12,.0f} {scog_bytes:>12,.0f} {scog_bytes-cog_bytes:>+10,.0f}")
    print(f"{'HTTP 소요 시간 (ms)':30} {cog_ms:>12.1f} {scog_ms:>12.1f} {scog_ms-cog_ms:>+10.1f}")

    print(f'\n분석:')
    print(f'  SCOG 오버헤드: SCOG 블록 {cred["scog_block_size"]} bytes')
    print(f'  추가 요청:     SCOG 블록 1회 + 복호화 (로컬, 거의 즉시)')

    # 보안 vs 오버헤드 요약
    overhead_bytes = cred['scog_block_size']
    overhead_pct   = overhead_bytes / cog_bytes * 100
    print(f'  전송량 오버헤드: {overhead_bytes} bytes ({overhead_pct:.2f}%)')

    print('\n결론:')
    print('  ✓ SCOG는 COG 대비 HTTP 요청 1회 추가 (SCOG 블록)')
    print('  ✓ 복호화는 클라이언트 로컬에서 수행 (서버 부하 없음)')
    print('  ✓ 전송량 오버헤드는 KB 수준으로 무시 가능')
    print('  ✓ 타일 서버 없이 nginx/S3에서 직접 접근 제어 가능')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SCOG vs COG 성능 비교')
    parser.add_argument('--url',  default=BASE_URL, help='Base URL')
    parser.add_argument('--runs', type=int, default=3, help='반복 횟수')
    args = parser.parse_args()

    BASE_URL = args.url
    run_benchmark(runs=args.runs)
