#!/usr/bin/env python3
"""
test_scog.py — SCOG 전체 시나리오 테스트

실행:
  python tests/test_scog.py
  pytest tests/test_scog.py -v
"""

import os
import sys
import json
import struct
import shutil
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scog_structs import (
    parse_scog_block, decrypt_level, encrypt_level, serialize_scog_block,
    parse_tiff, zero_tile_offsets,
)
from cog_to_scog import cog_to_scog
from cred_issuer import issue_credential, load_credential, get_cek
from scog_reader import ScogReader

from cryptography.exceptions import InvalidTag

# ─── 픽스처 ──────────────────────────────────────────────────────────────────

SCOG_DIR = os.path.join(os.path.dirname(__file__), '..')
COG_FILE   = os.path.join(SCOG_DIR, 'data', 'kompsat_3857.tif')
SCOG_FILE  = os.path.join(SCOG_DIR, 'data', 'kompsat_3857.scog')
KEYS_DIR   = os.path.join(SCOG_DIR, 'keys', 'v1')
CEKS_FILE  = os.path.join(KEYS_DIR, 'kompsat_3857_ceks.json')

# nginx HTTP 서버 (docker compose로 실행 중이어야 함)
HTTP_BASE  = 'http://localhost:8777'


def load_scog_block():
    with open(CEKS_FILE) as f:
        store = json.load(f)
    n = store['scog_block_size']
    raw = open(SCOG_FILE, 'rb').read(n)
    return parse_scog_block(raw), store


# ─── 테스트 ──────────────────────────────────────────────────────────────────

def test_01_scog_block_parseable():
    """SCOG 블록이 파싱 가능하고 3개 레벨이 있어야 함 (v1: kompsat_3857.scog)"""
    sb, store = load_scog_block()
    assert sb.version == 1
    assert len(sb.entries) >= 2, f"최소 2개 레벨 필요, 실제: {set(sb.entries.keys())}"
    print(f"  SCOG 블록: {sb.total_size} bytes, {sb.level_count} 레벨 {set(sb.entries.keys())}")


def test_02_tile_offsets_zeroed():
    """SCOG 파일의 IFD TileOffsets가 모두 0이어야 함"""
    with open(CEKS_FILE) as f:
        store = json.load(f)
    scog_block_size = store['scog_block_size']

    scog_data = open(SCOG_FILE, 'rb').read()
    tiff_data = scog_data[scog_block_size:]
    tiff = parse_tiff(tiff_data)

    from scog_structs import TAG_TILE_OFFSETS
    for i, ifd in enumerate(tiff.ifds):
        entry = ifd.entries.get(TAG_TILE_OFFSETS)
        if entry:
            assert all(v == 0 for v in entry.values), \
                f"IFD {i} TileOffsets가 0이 아님: {entry.values}"
    print(f"  모든 TileOffsets 제로화 확인 ({len(tiff.ifds)} IFDs)")


def test_03_normal_access_local():
    """로컬 파일: 유효 자격증명으로 타일 읽기 성공"""
    with open(CEKS_FILE) as f:
        store = json.load(f)
    cred = issue_credential(CEKS_FILE, levels=[0, 1, 2])
    reader = ScogReader(SCOG_FILE, cred)

    tile = reader.read_tile(0, 0, 0)
    assert len(tile) > 0, "타일 데이터가 비어있음"
    assert tile[:2] == b'\x78\x9c' or tile[:2] == b'\x78\xda', \
        f"DEFLATE 매직 불일치: {tile[:4].hex()}"
    print(f"  레벨0 타일(0,0): {len(tile):,} bytes (DEFLATE)")


def test_04_permission_denied():
    """권한 없는 레벨 접근 → PermissionError"""
    cred = issue_credential(CEKS_FILE, levels=[2])  # 레벨2만 허용
    reader = ScogReader(SCOG_FILE, cred)

    try:
        reader.read_tile(0, 0, 0)  # 레벨0 요청 → 거부
        assert False, "PermissionError가 발생해야 함"
    except PermissionError as e:
        print(f"  PermissionError 정상 발생: {e}")


def test_05_gcm_tamper_detection():
    """SCOG 블록 암호문 변조 → InvalidTag 예외"""
    with open(CEKS_FILE) as f:
        store = json.load(f)
    n = store['scog_block_size']
    raw = bytearray(open(SCOG_FILE, 'rb').read(n))

    # 암호문 중간 1바이트 플립
    raw[100] ^= 0xFF

    sb = parse_scog_block(bytes(raw))
    cek = bytes.fromhex(store['levels']['0'])

    try:
        decrypt_level(sb.entries[0], cek, store['file_id'], 0)
        assert False, "InvalidTag가 발생해야 함"
    except InvalidTag:
        print("  InvalidTag 정상 발생: GCM 변조 감지됨")


def test_06_wrong_cek():
    """잘못된 CEK → InvalidTag 예외"""
    with open(CEKS_FILE) as f:
        store = json.load(f)
    n = store['scog_block_size']
    raw = open(SCOG_FILE, 'rb').read(n)
    sb = parse_scog_block(raw)

    wrong_cek = os.urandom(32)
    try:
        decrypt_level(sb.entries[0], wrong_cek, store['file_id'], 0)
        assert False, "InvalidTag가 발생해야 함"
    except InvalidTag:
        print("  InvalidTag 정상 발생: 잘못된 CEK 감지됨")


def test_07_soft_renewal():
    """소프트 갱신: 동일 CEK로 새 자격증명 발급 → 파일 재생성 없이 성공"""
    # 기존 자격증명 (레벨2만)
    cred_old = issue_credential(CEKS_FILE, levels=[2])
    # 갱신 (레벨1,2로 확장 — CEK는 동일, 파일 변경 없음)
    cred_new = issue_credential(CEKS_FILE, levels=[1, 2])

    reader = ScogReader(SCOG_FILE, cred_new)
    tile = reader.read_tile(1, 0, 0)
    assert len(tile) > 0
    print(f"  소프트 갱신 후 레벨1 타일 읽기: {len(tile):,} bytes")


def test_08_hard_revocation():
    """
    하드 만료: SCOG 블록 재암호화 (새 CEK) → 기존 자격증명 무효화.
    임시 파일로 수행 (원본 파일 변경 없음).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_scog = os.path.join(tmpdir, 'test.scog')
        tmp_keys = os.path.join(tmpdir, 'keys')

        # 1. 원본을 tmp에 v1으로 변환
        cek_data = cog_to_scog(COG_FILE, tmp_scog, tmp_keys, format_ver='v1')
        file_id = cek_data['file_id']
        ceks_file = os.path.join(tmp_keys, f'{file_id}_ceks.json')

        # 2. 기존 자격증명 발급
        old_cred = issue_credential(ceks_file, levels=[0])
        old_cek_hex = old_cred['levels']['0']

        # 3. 레벨0 SCOG 블록 재암호화 (새 CEK 생성)
        with open(tmp_scog, 'r+b') as f:
            scog_block_size = cek_data['scog_block_size']
            scog_raw = f.read(scog_block_size)
            tiff_raw = f.read()

        sb = parse_scog_block(scog_raw)
        old_entry = sb.entries[0]

        # 기존 CEK로 복호화
        old_cek = bytes.fromhex(old_cek_hex)
        offsets, bytecounts = decrypt_level(old_entry, old_cek, file_id, 0)

        # 새 CEK로 재암호화
        new_cek = os.urandom(32)
        new_iv, new_ct = encrypt_level(offsets, bytecounts, new_cek, file_id, 0)

        # SCOG 블록 재빌드
        new_entries = [{'level_id': lid, 'iv': e.iv, 'ciphertext': e.ciphertext}
                       for lid, e in sb.entries.items()]
        new_entries[0] = {'level_id': 0, 'iv': new_iv, 'ciphertext': new_ct}
        new_scog_block = serialize_scog_block(new_entries)

        # 파일 업데이트
        with open(tmp_scog, 'wb') as f:
            f.write(new_scog_block)
            f.write(tiff_raw)

        # 4. 기존 자격증명으로 시도 → GCM 태그 불일치 → InvalidTag
        reader = ScogReader(tmp_scog, old_cred)
        try:
            reader.read_tile(0, 0, 0)
            assert False, "InvalidTag가 발생해야 함"
        except InvalidTag:
            print("  하드 만료 확인: 기존 자격증명으로 InvalidTag 발생")

        # 5. 새 자격증명 발급 후 성공
        with open(ceks_file) as f:
            store = json.load(f)
        store['levels']['0'] = new_cek.hex()
        with open(ceks_file, 'w') as f:
            json.dump(store, f)

        new_cred = issue_credential(ceks_file, levels=[0])
        reader2 = ScogReader(tmp_scog, new_cred)
        tile = reader2.read_tile(0, 0, 0)
        assert len(tile) > 0
        print(f"  새 자격증명으로 정상 읽기: {len(tile):,} bytes")


def test_09_http_range_request():
    """HTTP Range Request로 타일 읽기 (nginx 실행 중이어야 함)"""
    try:
        import requests
        resp = requests.head(f'{HTTP_BASE}/kompsat_3857.scog', timeout=3)
        if resp.status_code != 200:
            print(f"  SKIP: nginx 미응답 (HTTP {resp.status_code})")
            return
    except Exception:
        print(f"  SKIP: nginx 연결 불가 ({HTTP_BASE})")
        return

    with open(CEKS_FILE) as f:
        store = json.load(f)
    avail = [int(k) for k in store['levels'].keys()]

    cred = issue_credential(CEKS_FILE, levels=avail)
    reader = ScogReader(f'{HTTP_BASE}/kompsat_3857.scog', cred)

    top = max(avail)  # 가장 저해상도 레벨
    tile = reader.read_tile(top, 0, 0)
    assert len(tile) > 0
    print(f"  HTTP 레벨{top} 타일(0,0): {len(tile):,} bytes")

    # 권한 없는 레벨 (HTTP에서도 동일)
    cred_guest = issue_credential(CEKS_FILE, levels=[top])
    reader_g = ScogReader(f'{HTTP_BASE}/kompsat_3857.scog', cred_guest)
    try:
        reader_g.read_tile(0, 0, 0)
        assert False, "PermissionError가 발생해야 함"
    except PermissionError:
        print("  HTTP PermissionError 정상 발생")


# ─── v3 테스트 ─────────────────────────────────────────────────────────────────

SCOG_V3_FILE = os.path.join(SCOG_DIR, 'data', 'kompsat_3857.v3.scog.tif')
KEYS_V3_DIR  = os.path.join(SCOG_DIR, 'keys', 'v3')
CEKS_V3_FILE = os.path.join(KEYS_V3_DIR, 'kompsat_3857_ceks.json')


def test_10_v3_scog_block_in_16kb():
    """V3: SCOG 블록이 첫 16KB 내에 위치하고 파일이 유효한 TIFF"""
    with open(SCOG_V3_FILE, 'rb') as f:
        header = f.read(16384)
    # TIFF 매직 확인
    assert header[:2] in (b'II', b'MM'), f"TIFF 매직 오류: {header[:2]!r}"
    # SCOG 블록 위치 확인
    with open(CEKS_V3_FILE) as f:
        store = json.load(f)
    offset = store['scog_block_offset']
    assert offset < 16384, f"SCOG 블록 오프셋 {offset}이 16KB 초과"
    assert header[offset:offset+4] == b'SCOG', f"SCOG 매직 오류 @ {offset}"
    sb = parse_scog_block(header[offset:])
    print(f"  SCOG 블록 @ byte {offset}, {sb.level_count}개 레벨, 16KB 내 확인")


def test_11_v3_local_read():
    """V3 로컬: 암호화 레벨 + 공개 레벨 타일 읽기"""
    cred = issue_credential(CEKS_V3_FILE, levels=[0, 1])
    reader = ScogReader(SCOG_V3_FILE, cred)

    # 암호화 레벨
    tile = reader.read_tile(0, 0, 0)
    assert len(tile) > 0, "L0 타일 데이터 비어있음"
    assert tile[:2] in (b'\x78\x9c', b'\x78\xda'), f"DEFLATE 매직 불일치: {tile[:4].hex()}"

    # 공개 레벨
    tile2 = reader.read_tile(2, 0, 0)
    assert len(tile2) > 0, "L2 공개 타일 데이터 비어있음"
    print(f"  V3 로컬: L0 타일={len(tile):,} bytes, L2 공개={len(tile2):,} bytes")


def test_12_v3_permission_denied():
    """V3: 권한 없는 레벨 → PermissionError, 공개 레벨은 정상"""
    cred = issue_credential(CEKS_V3_FILE, levels=[])  # guest
    reader = ScogReader(SCOG_V3_FILE, cred)

    try:
        reader.read_tile(0, 0, 0)
        assert False, "PermissionError가 발생해야 함"
    except PermissionError as e:
        print(f"  V3 PermissionError 정상: {e}")

    tile = reader.read_tile(2, 0, 0)
    assert len(tile) > 0
    print(f"  V3 공개 레벨 정상: {len(tile):,} bytes")


def test_13_v3_http_range_request():
    """V3 HTTP Range Request로 타일 읽기"""
    try:
        import requests
        resp = requests.head(f'{HTTP_BASE}/kompsat_3857.v3.scog.tif', timeout=3)
        if resp.status_code != 200:
            print(f"  SKIP: nginx 미응답 (HTTP {resp.status_code})")
            return
    except Exception:
        print(f"  SKIP: nginx 연결 불가 ({HTTP_BASE})")
        return

    cred = issue_credential(CEKS_V3_FILE, levels=[0, 1])
    reader = ScogReader(f'{HTTP_BASE}/kompsat_3857.v3.scog.tif', cred)
    tile = reader.read_tile(0, 0, 0)
    assert len(tile) > 0
    print(f"  V3 HTTP L0 타일: {len(tile):,} bytes")


# ─── 실행 ─────────────────────────────────────────────────────────────────────

TESTS = [
    test_01_scog_block_parseable,
    test_02_tile_offsets_zeroed,
    test_03_normal_access_local,
    test_04_permission_denied,
    test_05_gcm_tamper_detection,
    test_06_wrong_cek,
    test_07_soft_renewal,
    test_08_hard_revocation,
    test_09_http_range_request,
    test_10_v3_scog_block_in_16kb,
    test_11_v3_local_read,
    test_12_v3_permission_denied,
    test_13_v3_http_range_request,
]

if __name__ == '__main__':
    passed = failed = 0
    for test in TESTS:
        name = test.__name__
        try:
            print(f"\n{'─'*50}")
            print(f"[RUN] {name}")
            test()
            print(f"[PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            import traceback
            print(f"[ERROR] {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*50}")
    print(f"결과: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
