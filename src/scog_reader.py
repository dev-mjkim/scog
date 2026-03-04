#!/usr/bin/env python3
"""
scog_reader.py — SCOG 파일 리더 (로컬 파일 + HTTP Range Request)

동작:
  1. SCOG 블록 읽기 (파일 앞 N bytes or Range: bytes=0-N)
  2. 자격증명에서 CEK 꺼내기
  3. 해당 레벨 TileOffsets 복호화
  4. 타일 데이터 읽기 (offset + scog_block_size 위치)

중요: SCOG 파일에서 타일 실제 위치 = scog_block_size + tiff_tile_offset

사용:
  # 로컬 파일
  python src/scog_reader.py data/kompsat.scog keys/cred_premium.json --level 0 --tile 0 0

  # HTTP (nginx)
  python src/scog_reader.py http://localhost:8777/kompsat.scog keys/cred_basic.json --level 1 --tile 0 0
"""

import sys
import struct
import argparse
import math
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scog_structs import (
    parse_scog_block, decrypt_level, parse_scog_footer,
    decrypt_tile_partial,
    parse_tiff, parse_ifd,
    derive_next_key,
    TAG_TILE_OFFSETS, TAG_TILE_BYTECOUNTS,
    TAG_IMAGEWIDTH, TAG_IMAGELENGTH, TAG_TILEWIDTH, TAG_TILELENGTH,
    get_ifd_scalar,
)
from cred_issuer import load_credential, get_cek
from cryptography.exceptions import InvalidTag


# ─── 파일 어댑터 (로컬 / HTTP) ──────────────────────────────────────────────

class LocalAdapter:
    """로컬 파일 Range Read 어댑터"""
    def __init__(self, path: str):
        self.path = path

    def read_range(self, start: int, length: int) -> bytes:
        with open(self.path, 'rb') as f:
            f.seek(start)
            return f.read(length)

    def file_size(self) -> int:
        return Path(self.path).stat().st_size


class HttpAdapter:
    """HTTP Range Request 어댑터 (nginx/S3)"""
    def __init__(self, url: str):
        import requests as req_lib
        self.url = url
        self._req = req_lib

    def read_range(self, start: int, length: int) -> bytes:
        end = start + length - 1
        headers = {'Range': f'bytes={start}-{end}'}
        resp = self._req.get(self.url, headers=headers, timeout=30)
        if resp.status_code not in (200, 206):
            raise IOError(f"HTTP {resp.status_code}: {self.url} Range={start}-{end}")
        return resp.content

    def file_size(self) -> int:
        resp = self._req.head(self.url, timeout=10)
        return int(resp.headers.get('Content-Length', 0))


def make_adapter(source: str):
    """source가 http(s):// 이면 HttpAdapter, 아니면 LocalAdapter"""
    if source.startswith('http://') or source.startswith('https://'):
        return HttpAdapter(source)
    return LocalAdapter(source)


# ─── SCOG 리더 ───────────────────────────────────────────────────────────────

class ScogReader:
    """
    SCOG 파일 리더.

    사용 예:
        reader = ScogReader('data/kompsat.scog', cred)
        tile_bytes = reader.read_tile(level=0, col=0, row=0)
    """

    def __init__(self, source: str, cred: dict):
        self.adapter = make_adapter(source)
        self.cred    = cred
        self._scog   = None          # ScogBlock (lazy load)
        self._cache  = {}            # level_id → (offsets, bytecounts)
        self._v3_ifds = None         # v3: 원본 IFD 리스트 (parse_ifd 결과)
        self._v3_header = None       # v3: 16KB raw 데이터
        self._v4_tiff = None         # v4: 파싱된 TIFF 구조
        self._v4_level_ceks = None   # v4: {level_id: bytes} — trial decryption 결과

    def _is_v4(self) -> bool:
        # v4 감지: 'key' 필드 있음, 또는 v1/v2/v3 마커 모두 없음
        if 'key' in self.cred:
            return True
        # guest: key/levels/scog_block_size/public_level/scog_block_offset 모두 없음
        v_markers = ('key', 'levels', 'scog_block_size', 'public_level', 'scog_block_offset')
        return not any(k in self.cred for k in v_markers)

    def _is_v3(self) -> bool:
        return 'scog_block_offset' in self.cred and not self._is_v4()

    def _is_v2(self) -> bool:
        return 'public_level' in self.cred and not self._is_v3() and not self._is_v4()

    def _load_v4(self):
        """v4: 16KB fetch → TIFF IFD 파싱 (SCOG 블록 없음)"""
        if self._v4_tiff is not None:
            return
        raw = self.adapter.read_range(0, 16384)
        tiff = parse_tiff(bytes(raw))
        self._v4_tiff = tiff

    def _resolve_v4_keys(self):
        """v4 Trial Decryption: HKDF 키 체인 → 타일 0 시도 → 레벨 매핑 캐시.

        클라이언트는 key가 어떤 레벨의 CEK인지 모름.
        키 체인 [key, HKDF(key), HKDF(HKDF(key)), ...] 생성 후
        각 레벨의 타일 0을 순서대로 시도하여 매핑.
        """
        if self._v4_level_ceks is not None:
            return
        self._load_v4()

        # guest: 키 없음
        if 'key' not in self.cred:
            self._v4_level_ceks = {}
            return

        root = bytes.fromhex(self.cred['key'])
        num_levels = len(self._v4_tiff.ifds)
        file_id = self.cred['file_id']

        # 키 체인 생성
        chain = [root]
        for _ in range(num_levels - 1):
            chain.append(derive_next_key(chain[-1]))

        self._v4_level_ceks = {}

        for level_id in range(num_levels):
            ifd = self._v4_tiff.ifds[level_id]
            off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
            bc_entry = ifd.entries.get(TAG_TILE_BYTECOUNTS)
            if off_entry is None:
                continue

            # 타일 0 fetch
            tile_off = int(off_entry.values[0])
            tile_bc = int(bc_entry.values[0]) if bc_entry else 0
            if tile_off == 0 or tile_bc == 0:
                continue
            enc_tile = self.adapter.read_range(tile_off, tile_bc)

            # 후보 키 순서대로 시도
            for candidate in chain:
                try:
                    decrypt_tile_partial(enc_tile, candidate, file_id,
                                         level_id, 0, 1024)
                    self._v4_level_ceks[level_id] = candidate
                    break
                except InvalidTag:
                    continue

    def _load_scog_block(self):
        if self._scog is not None:
            return
        if self._is_v4():
            return  # v4: SCOG 블록 없음
        if self._is_v3():
            self._load_v3()
        elif self._is_v2():
            # v2: 파일 끝 8바이트 푸터에서 SCOG 블록 크기 읽기
            file_size = self.adapter.file_size()
            footer = self.adapter.read_range(file_size - 8, 8)
            n = parse_scog_footer(footer)
            raw = self.adapter.read_range(file_size - 8 - n, n)
            self._scog = parse_scog_block(raw)
            assert self._scog.total_size == n, \
                f"SCOG 블록 크기 불일치: {self._scog.total_size} != {n}"
            return
        else:
            # v1: 파일 앞에서 scog_block_size bytes 읽기
            n = self.cred['scog_block_size']
            raw = self.adapter.read_range(0, n)
            self._scog = parse_scog_block(raw)
            assert self._scog.total_size == n, \
                f"SCOG 블록 크기 불일치: {self._scog.total_size} != {n}"

    def _load_v3(self):
        """v3: 첫 16KB에서 SCOG 블록 + TIFF IFDs 모두 파싱"""
        if self._v3_ifds is not None:
            return
        offset = self.cred['scog_block_offset']
        raw = self.adapter.read_range(0, max(offset + 4096, 16384))
        self._v3_header = raw
        self._scog = parse_scog_block(raw[offset:])

        # 원본 IFD 체인 파싱 (first_ifd_offset에서 시작)
        first_ifd = self.cred['first_ifd_offset']
        # endian + bigtiff 감지
        endian = '<' if raw[:2] == b'II' else '>'
        import struct as _st
        magic = _st.unpack_from(endian + 'H', raw, 2)[0]
        bigtiff = (magic == 43)

        self._v3_ifds = []
        curr = first_ifd
        while curr != 0 and curr < len(raw):
            ifd = parse_ifd(raw, curr, endian, bigtiff)
            self._v3_ifds.append(ifd)
            curr = ifd.next_ifd_offset

    def _v3_ifd_meta(self, level_id: int) -> dict:
        """v3: 파싱된 IFD에서 레벨 메타데이터 추출"""
        self._load_v3()
        if level_id >= len(self._v3_ifds):
            raise IndexError(f"IFD {level_id} 없음 (총 {len(self._v3_ifds)}개)")
        ifd = self._v3_ifds[level_id]
        return {
            'image_width':  get_ifd_scalar(ifd, TAG_IMAGEWIDTH),
            'image_height': get_ifd_scalar(ifd, TAG_IMAGELENGTH),
            'tile_width':   get_ifd_scalar(ifd, TAG_TILEWIDTH),
            'tile_height':  get_ifd_scalar(ifd, TAG_TILELENGTH),
        }

    def _decrypt_level(self, level_id: int):
        if level_id in self._cache:
            return self._cache[level_id]

        # v4: HKDF trial decryption → 레벨 매핑
        if self._is_v4():
            self._resolve_v4_keys()
            if level_id not in self._v4_level_ceks:
                available = sorted(self._v4_level_ceks.keys())
                raise PermissionError(
                    f"레벨 {level_id}에 대한 접근 권한 없음. "
                    f"보유 레벨: {available}"
                )
            ifd = self._v4_tiff.ifds[level_id]
            off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
            bc_entry  = ifd.entries.get(TAG_TILE_BYTECOUNTS)
            if off_entry is None:
                raise ValueError(f"IFD {level_id}에 TileOffsets 없음")
            offsets    = [int(v) for v in off_entry.values]
            bytecounts = [int(v) for v in bc_entry.values] if bc_entry else [0]*len(offsets)
            self._cache[level_id] = (offsets, bytecounts)
            return offsets, bytecounts

        # v3: IFD의 TileOffsets로 공개 여부 판단 (non-zero = 공개)
        if self._is_v3():
            self._load_v3()
            if level_id < len(self._v3_ifds):
                ifd = self._v3_ifds[level_id]
                off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
                bc_entry  = ifd.entries.get(TAG_TILE_BYTECOUNTS)
                if off_entry and any(int(v) != 0 for v in off_entry.values):
                    # 공개 레벨: TileOffsets가 0이 아님
                    offsets    = [int(v) for v in off_entry.values]
                    bytecounts = [int(v) for v in bc_entry.values] if bc_entry else [0]*len(offsets)
                    self._cache[level_id] = (offsets, bytecounts)
                    return offsets, bytecounts
            # 암호화 레벨: SCOG 블록에서 복호화
            entry = self._scog.entries.get(level_id)
            if entry is None:
                raise PermissionError(
                    f"레벨 {level_id}에 대한 접근 권한 없음. "
                    f"보유 레벨: {sorted(self.cred['levels'].keys())}"
                )
            cek     = get_cek(self.cred, level_id)
            file_id = self.cred['file_id']
            offsets, bytecounts = decrypt_level(entry, cek, file_id, level_id)
            self._cache[level_id] = (offsets, bytecounts)
            return offsets, bytecounts

        # v2: level_meta의 tile_offsets로 공개 판단
        if self._is_v2() and level_id >= self.cred.get('public_level', 999):
            meta = self.cred.get('level_meta', {}).get(str(level_id), {})
            tile_offsets = meta.get('tile_offsets')
            if tile_offsets is not None:
                tile_bytecounts = meta.get('tile_bytecounts', [0] * len(tile_offsets))
                self._cache[level_id] = (tile_offsets, tile_bytecounts)
                return tile_offsets, tile_bytecounts
            offsets, bytecounts = self._read_public_level_from_tiff(level_id)
            self._cache[level_id] = (offsets, bytecounts)
            return offsets, bytecounts

        # v1 / v2 암호화 레벨
        self._load_scog_block()

        entry = self._scog.entries.get(level_id)
        if entry is None:
            raise KeyError(f"SCOG 블록에 레벨 {level_id} 없음")

        cek      = get_cek(self.cred, level_id)  # PermissionError if no access
        file_id  = self.cred['file_id']
        offsets, bytecounts = decrypt_level(entry, cek, file_id, level_id)

        self._cache[level_id] = (offsets, bytecounts)
        return offsets, bytecounts

    def _read_public_level_from_tiff(self, level_id: int):
        """v2 공개 레벨: TIFF IFD에서 TileOffsets 직접 읽기"""
        header_size = min(32768, self.adapter.file_size())
        raw = self.adapter.read_range(0, header_size)
        tiff = parse_tiff(bytes(raw))
        if level_id >= len(tiff.ifds):
            raise IndexError(f"TIFF에 IFD {level_id} 없음 (총 {len(tiff.ifds)}개)")
        ifd = tiff.ifds[level_id]
        offset_entry = ifd.entries.get(TAG_TILE_OFFSETS)
        bc_entry     = ifd.entries.get(TAG_TILE_BYTECOUNTS)
        if offset_entry is None:
            raise ValueError(f"IFD {level_id}에 TileOffsets 없음")
        offsets    = [int(v) for v in offset_entry.values]
        bytecounts = [int(v) for v in bc_entry.values] if bc_entry else [0]*len(offsets)
        return offsets, bytecounts

    def tile_index(self, level_id: int, col: int, row: int) -> int:
        """(col, row) → flat tile index"""
        if self._is_v4():
            meta = self.level_info(level_id)
        elif self._is_v3():
            meta = self._v3_ifd_meta(level_id)
        else:
            meta = self.cred.get('level_meta', {}).get(str(level_id))
        if meta is None:
            raise KeyError(f"레벨 {level_id} 메타데이터 없음")
        tile_w = meta['tile_width']
        img_w  = meta['image_width']
        tiles_x = math.ceil(img_w / tile_w)
        return row * tiles_x + col

    def read_tile(self, level_id: int, col: int, row: int) -> bytes:
        """
        특정 타일 바이트 반환.
        잘못된 CEK → cryptography.exceptions.InvalidTag
        권한 없음  → PermissionError
        """
        offsets, bytecounts = self._decrypt_level(level_id)
        idx = self.tile_index(level_id, col, row)

        if idx >= len(offsets):
            raise IndexError(f"타일 인덱스 {idx} 범위 초과 (총 {len(offsets)}개)")

        tiff_offset = offsets[idx]
        bytecount   = bytecounts[idx]

        if tiff_offset == 0 or bytecount == 0:
            raise ValueError(f"레벨 {level_id} 타일 ({col},{row})의 offset/bytecount가 0 — 빈 타일")

        if self._is_v4():
            file_offset = tiff_offset
        elif self._is_v2() or self._is_v3():
            file_offset = tiff_offset
        else:
            file_offset = self.cred['scog_block_size'] + tiff_offset

        raw_tile = self.adapter.read_range(file_offset, bytecount)

        # v4: 타일 복호화 (trial decryption으로 매핑된 CEK 사용)
        if self._is_v4():
            cek = self._v4_level_ceks[level_id]
            raw_tile = decrypt_tile_partial(raw_tile, cek, self.cred['file_id'],
                                            level_id, idx, 1024)

        return raw_tile

    def level_info(self, level_id: int) -> dict:
        """레벨 메타데이터 반환"""
        if self._is_v4():
            self._load_v4()
            if level_id >= len(self._v4_tiff.ifds):
                raise IndexError(f"IFD {level_id} 없음")
            ifd = self._v4_tiff.ifds[level_id]
            return {
                'image_width':  get_ifd_scalar(ifd, TAG_IMAGEWIDTH),
                'image_height': get_ifd_scalar(ifd, TAG_IMAGELENGTH),
                'tile_width':   get_ifd_scalar(ifd, TAG_TILEWIDTH),
                'tile_height':  get_ifd_scalar(ifd, TAG_TILELENGTH),
            }
        if self._is_v3():
            return self._v3_ifd_meta(level_id)
        return self.cred.get('level_meta', {}).get(str(level_id), {})

    def available_levels(self) -> list:
        if self._is_v4():
            self._resolve_v4_keys()
            return sorted(self._v4_level_ceks.keys())
        levels = set(int(k) for k in self.cred['levels'].keys())
        if self._is_v3():
            # v3: IFD에서 공개 레벨 발견 (TileOffsets ≠ 0)
            self._load_v3()
            for i, ifd in enumerate(self._v3_ifds):
                off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
                if off_entry and any(int(v) != 0 for v in off_entry.values):
                    levels.add(i)
        elif self._is_v2():
            pub = self.cred.get('public_level')
            if pub is not None:
                for k in self.cred.get('level_meta', {}):
                    if int(k) >= pub:
                        levels.add(int(k))
        return sorted(levels)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='SCOG 파일 리더 (로컬/HTTP)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 로컬 - 레벨0 타일(0,0) 읽기
  python src/scog_reader.py data/kompsat.scog keys/cred_premium.json --level 0 --tile 0 0

  # HTTP - 레벨1 타일(1,0) 읽기
  python src/scog_reader.py http://localhost:8777/kompsat.scog keys/cred_basic.json --level 1 --tile 1 0

  # 권한 없는 레벨 시도 (PermissionError 예상)
  python src/scog_reader.py data/kompsat.scog keys/cred_guest.json --level 0 --tile 0 0
        """
    )
    parser.add_argument('source',   help='SCOG 파일 경로 또는 http(s):// URL')
    parser.add_argument('cred',     help='자격증명 JSON 파일 경로')
    parser.add_argument('--level',  type=int, required=True, help='오버뷰 레벨 번호')
    parser.add_argument('--tile',   type=int, nargs=2, metavar=('COL', 'ROW'), required=True)
    parser.add_argument('--out',    help='타일 데이터 저장 경로 (기본: 출력 안 함)')
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    cred = load_credential(args.cred)
    reader = ScogReader(args.source, cred)

    col, row = args.tile
    level_id = args.level

    print(f"소스:  {args.source}")
    print(f"레벨:  {level_id}")
    print(f"타일:  col={col}, row={row}")
    print(f"보유 레벨: {reader.available_levels()}")
    print()

    try:
        tile_data = reader.read_tile(level_id, col, row)
        print(f"타일 읽기 성공: {len(tile_data):,} bytes")
        if args.verbose:
            print(f"  앞 16바이트 (hex): {tile_data[:16].hex()}")

        if args.out:
            with open(args.out, 'wb') as f:
                f.write(tile_data)
            print(f"저장: {args.out}")

    except PermissionError as e:
        print(f"[PermissionError] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[{type(e).__name__}] {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
