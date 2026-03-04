"""
scog_structs.py — TIFF 파서 + SCOG 블록 직렬화/역직렬화

SCOG 파일 레이아웃:
  [SCOG Block (N bytes)]  ← magic + version + encrypted TileOffsets per level
  [TIFF content]          ← 원본 COG, TileOffsets는 0으로 초기화됨
                             TIFF 내부 offset은 TIFF 시작(=파일 내 N 위치) 기준
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ─── 상수 ────────────────────────────────────────────────────────────────────

SCOG_MAGIC   = b'SCOG'
SCOG_VERSION = 1

# TIFF type → (bytes per element, struct format char)
TIFF_TYPE_INFO = {
    1:  (1, 'B'),   # BYTE
    2:  (1, 's'),   # ASCII
    3:  (2, 'H'),   # SHORT
    4:  (4, 'I'),   # LONG
    5:  (8, None),  # RATIONAL (2× LONG) — treated as raw bytes for our purposes
    7:  (1, 'B'),   # UNDEFINED
    11: (4, 'f'),   # FLOAT  (IEEE 754 32-bit)
    12: (8, 'd'),   # DOUBLE (IEEE 754 64-bit) — ModelPixelScale, ModelTiepoint 등
    16: (8, 'Q'),   # LONG8  (BigTIFF)
    17: (8, 'q'),   # SLONG8 (BigTIFF)
    18: (8, 'Q'),   # IFD8   (BigTIFF)
}

TAG_TILE_OFFSETS    = 324
TAG_TILE_BYTECOUNTS = 325
TAG_IMAGEWIDTH      = 256
TAG_IMAGELENGTH     = 257
TAG_TILEWIDTH       = 322
TAG_TILELENGTH      = 323
TAG_BITSPERSAMPLE   = 258
TAG_SAMPLESPERPIXEL = 277
TAG_COMPRESSION     = 259

# GeoTIFF 지오태그 — IFD 0에만 존재, 공개 메인 IFD 빌드 시 복사 대상
GEO_TAGS = {33550, 33922, 34735, 34736, 34737}   # ModelPixelScale, ModelTiepoint,
                                                   # GeoKeyDirectory, GeoDoubleParams,
                                                   # GeoAsciiParams


# ─── TIFF 파서 ───────────────────────────────────────────────────────────────

@dataclass
class TiffEntry:
    tag: int
    field_type: int
    count: int
    values: list
    entry_pos: int          # 이 entry가 파일 내 어디에 위치하는지
    data_offset: Optional[int]  # 값이 inline이면 None, 아니면 값 배열의 file offset


@dataclass
class TiffIfd:
    file_offset: int        # IFD 자체의 file offset
    entries: dict           # tag → TiffEntry
    next_ifd_offset: int    # 다음 IFD offset (없으면 0)


@dataclass
class TiffInfo:
    endian: str             # '<' (little) or '>' (big)
    bigtiff: bool
    first_ifd_offset: int
    ifds: list              # list of TiffIfd


def decode_values(raw: bytes, endian: str, field_type: int, count: int) -> list:
    """TIFF field raw bytes → Python 값 리스트"""
    if field_type == 2:  # ASCII
        return [raw[:count].decode('latin-1').rstrip('\x00')]
    info = TIFF_TYPE_INFO.get(field_type)
    if info is None or info[1] is None:
        return list(raw)
    size_each, fmt_char = info
    total = size_each * count
    return list(struct.unpack_from(endian + f'{count}{fmt_char}', raw[:total]))


def parse_ifd(data: bytes, offset: int, endian: str, bigtiff: bool) -> TiffIfd:
    """주어진 offset에서 IFD 하나 파싱"""
    pos = offset

    if bigtiff:
        entry_count = struct.unpack_from(endian + 'Q', data, pos)[0]
        pos += 8
        entry_size = 20
        max_inline = 8
    else:
        entry_count = struct.unpack_from(endian + 'H', data, pos)[0]
        pos += 2
        entry_size = 12
        max_inline = 4

    entries = {}
    for i in range(entry_count):
        ep = pos + i * entry_size

        if bigtiff:
            tag, ftype, count = struct.unpack_from(endian + 'HHQ', data, ep)
            val_raw = data[ep + 12: ep + 20]
        else:
            tag, ftype, count = struct.unpack_from(endian + 'HHI', data, ep)
            val_raw = data[ep + 8: ep + 12]

        tinfo = TIFF_TYPE_INFO.get(ftype, (1, 'B'))
        total_size = tinfo[0] * count

        if total_size <= max_inline:
            values = decode_values(val_raw[:total_size], endian, ftype, count)
            data_offset = None
        else:
            if bigtiff:
                data_offset = struct.unpack_from(endian + 'Q', val_raw)[0]
            else:
                data_offset = struct.unpack_from(endian + 'I', val_raw)[0]
            values = decode_values(
                data[data_offset: data_offset + total_size],
                endian, ftype, count
            )

        entries[tag] = TiffEntry(
            tag=tag, field_type=ftype, count=count,
            values=values, entry_pos=ep, data_offset=data_offset,
        )

    # next IFD offset
    next_pos = pos + entry_count * entry_size
    if bigtiff:
        next_ifd = struct.unpack_from(endian + 'Q', data, next_pos)[0]
    else:
        next_ifd = struct.unpack_from(endian + 'I', data, next_pos)[0]

    return TiffIfd(file_offset=offset, entries=entries, next_ifd_offset=next_ifd)


def parse_tiff(data: bytes) -> TiffInfo:
    """TIFF 전체 구조 파싱 (모든 IFD 포함)"""
    if data[:2] == b'II':
        endian = '<'
    elif data[:2] == b'MM':
        endian = '>'
    else:
        raise ValueError(f"TIFF 매직 오류: {data[:2]!r}")

    magic = struct.unpack_from(endian + 'H', data, 2)[0]
    if magic == 42:
        bigtiff = False
        first_ifd_offset = struct.unpack_from(endian + 'I', data, 4)[0]
    elif magic == 43:
        bigtiff = True
        first_ifd_offset = struct.unpack_from(endian + 'Q', data, 8)[0]
    else:
        raise ValueError(f"TIFF 매직 오류: {magic}")

    ifds = []
    current = first_ifd_offset
    while current != 0:
        ifd = parse_ifd(data, current, endian, bigtiff)
        ifds.append(ifd)
        current = ifd.next_ifd_offset

    return TiffInfo(endian=endian, bigtiff=bigtiff,
                    first_ifd_offset=first_ifd_offset, ifds=ifds)


def get_ifd_scalar(ifd: TiffIfd, tag: int, default=None):
    """IFD에서 단일 값 태그 꺼내기"""
    entry = ifd.entries.get(tag)
    if entry is None:
        return default
    return entry.values[0] if entry.values else default


# ─── TIFF 수정: TileOffsets 제로화 ───────────────────────────────────────────

def zero_tile_offsets(data: bytearray, tiff: TiffInfo,
                       skip_ifd_indices=None) -> bytearray:
    """
    모든 IFD의 TileOffsets(324)와 TileByteCounts(325)를 0으로 채움.
    data는 bytearray (in-place 수정).
    skip_ifd_indices: 건너뛸 IFD 인덱스 집합 (v2 공개 레벨 보존용)
    """
    max_inline = 8 if tiff.bigtiff else 4
    skip = set(skip_ifd_indices or [])

    for ifd_idx, ifd in enumerate(tiff.ifds):
        if ifd_idx in skip:
            continue
        for tag in (TAG_TILE_OFFSETS, TAG_TILE_BYTECOUNTS):
            entry = ifd.entries.get(tag)
            if entry is None:
                continue

            tinfo = TIFF_TYPE_INFO.get(entry.field_type, (1, 'B'))
            total_size = tinfo[0] * entry.count

            if entry.data_offset is None:
                # inline: entry_pos + 8 (classic) or +12 (bigtiff)
                val_start = entry.entry_pos + (12 if tiff.bigtiff else 8)
                data[val_start: val_start + total_size] = b'\x00' * total_size
            else:
                data[entry.data_offset: entry.data_offset + total_size] = b'\x00' * total_size

    return data


# ─── SCOG 블록 빌더 ──────────────────────────────────────────────────────────

@dataclass
class ScogLevelEntry:
    level_id: int
    iv: bytes           # 12 bytes
    ciphertext: bytes   # ciphertext + 16-byte GCM auth_tag appended


@dataclass
class ScogBlock:
    version: int
    level_count: int
    total_size: int     # SCOG 블록 전체 크기 (이 헤더 포함)
    entries: dict       # level_id → ScogLevelEntry


SCOG_HEADER_SIZE = 4 + 2 + 2 + 8  # magic(4) + version(2) + level_count(2) + total_size(8)


def build_plaintext(offsets: list, bytecounts: list) -> bytes:
    """TileOffsets + TileByteCounts → 암호화할 평문 bytes"""
    tile_count = len(offsets)
    assert len(bytecounts) == tile_count
    buf = struct.pack('>I', tile_count)
    buf += struct.pack(f'>{tile_count}Q', *offsets)
    buf += struct.pack(f'>{tile_count}Q', *bytecounts)
    return buf


def parse_plaintext(plaintext: bytes) -> tuple:
    """평문 bytes → (offsets, bytecounts) 튜플"""
    tile_count = struct.unpack_from('>I', plaintext, 0)[0]
    offset_end = 4 + 8 * tile_count
    offsets    = list(struct.unpack_from(f'>{tile_count}Q', plaintext, 4))
    bytecounts = list(struct.unpack_from(f'>{tile_count}Q', plaintext, offset_end))
    return offsets, bytecounts


def encrypt_level(offsets: list, bytecounts: list,
                  cek: bytes, file_id: str, level_id: int) -> tuple:
    """
    한 레벨의 TileOffsets를 AES-256-GCM으로 암호화.
    Returns: (iv, ciphertext_with_tag)
    """
    plaintext = build_plaintext(offsets, bytecounts)
    iv  = os.urandom(12)
    aad = file_id.encode() + struct.pack('>H', level_id)
    aesgcm = AESGCM(cek)
    ct = aesgcm.encrypt(iv, plaintext, aad)  # ct = ciphertext + 16-byte auth_tag
    return iv, ct


def decrypt_level(entry: ScogLevelEntry,
                  cek: bytes, file_id: str, level_id: int) -> tuple:
    """
    SCOG 블록 엔트리를 복호화 → (offsets, bytecounts).
    잘못된 CEK → InvalidTag 예외 발생.
    """
    aad = file_id.encode() + struct.pack('>H', level_id)
    aesgcm = AESGCM(cek)
    plaintext = aesgcm.decrypt(entry.iv, entry.ciphertext, aad)
    return parse_plaintext(plaintext)


def serialize_scog_block(entries: list, version: int = SCOG_VERSION) -> bytes:
    """
    ScogLevelEntry 리스트 → SCOG 블록 bytes.
    각 entry: {'level_id', 'iv', 'ciphertext'}
    """
    # 총 크기 계산 (first pass)
    entries_size = sum(
        2 + 2 + 4 + 12 + len(e['ciphertext'])   # level_id + reserved + ct_len + iv + ct
        for e in entries
    )
    total_size = SCOG_HEADER_SIZE + entries_size

    buf = bytearray()
    buf += SCOG_MAGIC
    buf += struct.pack('>H', version)
    buf += struct.pack('>H', len(entries))
    buf += struct.pack('>Q', total_size)

    for e in entries:
        ct = e['ciphertext']
        buf += struct.pack('>H', e['level_id'])
        buf += struct.pack('>H', 0)             # reserved
        buf += struct.pack('>I', len(ct))       # ct_len (iv 제외)
        buf += e['iv']                          # 12 bytes
        buf += ct                               # ciphertext + auth_tag

    assert len(buf) == total_size
    return bytes(buf)


def parse_scog_block(data: bytes) -> ScogBlock:
    """bytes 또는 file-like 객체에서 SCOG 블록 파싱"""
    if data[:4] != SCOG_MAGIC:
        raise ValueError(f"SCOG 매직 오류: {data[:4]!r}")

    version     = struct.unpack_from('>H', data, 4)[0]
    level_count = struct.unpack_from('>H', data, 6)[0]
    total_size  = struct.unpack_from('>Q', data, 8)[0]

    entries = {}
    pos = SCOG_HEADER_SIZE

    for _ in range(level_count):
        level_id, _reserved, ct_len = struct.unpack_from('>HHI', data, pos)
        pos += 8
        iv         = data[pos: pos + 12]
        pos += 12
        ciphertext = data[pos: pos + ct_len]
        pos += ct_len
        entries[level_id] = ScogLevelEntry(level_id=level_id, iv=iv, ciphertext=ciphertext)

    return ScogBlock(version=version, level_count=level_count,
                     total_size=total_size, entries=entries)


# ─── SCOG v2 푸터 ────────────────────────────────────────────────────────────

def make_scog_footer(scog_block_size: int) -> bytes:
    """SCOG v2 파일 끝에 붙는 8바이트 푸터 (SCOG 블록 크기, big-endian uint64)"""
    return struct.pack('>Q', scog_block_size)


def parse_scog_footer(footer: bytes) -> int:
    """8바이트 푸터에서 SCOG 블록 크기 추출"""
    return struct.unpack('>Q', footer)[0]


# ─── SCOG v2: 공개 메인 IFD 빌더 ─────────────────────────────────────────────

def _pack_inline_value(values: list, field_type: int, count: int, endian: str) -> bytes:
    """IFD 엔트리 inline 값 4바이트 직렬화."""
    tinfo = TIFF_TYPE_INFO.get(field_type, (1, 'B'))
    size_each, fmt_char = tinfo
    if field_type == 2:  # ASCII
        text = values[0] if isinstance(values[0], str) else chr(values[0])
        raw = (text.encode('latin-1') + b'\x00')[:count]
    elif fmt_char and fmt_char != 's':
        raw = struct.pack(endian + f'{count}{fmt_char}', *values[:count])
    else:
        raw = bytes(values[:size_each * count])
    return (raw + b'\x00' * 4)[:4]


TAG_MODELSCALE = 33550   # ModelPixelScale


def build_public_main_ifd(tiff: TiffInfo,
                           img_ifd_idx: int, geo_ifd_idx: int,
                           next_ifd_offset: int,
                           ifd_file_pos: int) -> bytes:
    """
    공개 메인 IFD 빌드: img_ifd의 이미지 태그 + geo_ifd의 GEO_TAGS 조합.

    SCOG v2에서 암호화된 IFD 0을 숨기고, 공개 IFD (img_ifd_idx)에 IFD 0의
    지오태그를 붙여 QGIS/GDAL이 올바른 해상도와 geo-referencing으로 파일을
    인식하게 만든다.

    변경 사항:
      - SUBFILETYPE(254) → 0 (reduced→main 으로 승격)
      - GEO_TAGS 복사 (33550/33922/34735/34736/34737)
      - ModelPixelScale(33550): img_ifd 해상도에 맞게 비율 스케일 후 extra_data로 첨부
        (geo_ifd의 원본 값 × geo_width/img_width, geo_height/img_height)
      - 나머지 out-of-line 데이터: 기존 파일 내 data_offset 그대로 참조

    Args:
        tiff:             parse_tiff()로 파싱한 원본 TIFF 구조
        img_ifd_idx:      이미지 데이터를 가져올 IFD 인덱스 (보통 public_level)
        geo_ifd_idx:      지오태그를 가져올 IFD 인덱스 (보통 0)
        next_ifd_offset:  새 IFD가 가리킬 다음 IFD 파일 오프셋
        ifd_file_pos:     새 IFD가 파일 내 위치할 바이트 오프셋
                          (스케일된 ModelPixelScale extra_data의 data_offset 계산에 사용)

    Returns:
        [IFD bytes][스케일된 ModelPixelScale 24bytes]
        → 파일 끝에 append 후 redirect_tiff_first_ifd() 호출
    """
    assert not tiff.bigtiff, "BigTIFF 미지원 (build_public_main_ifd)"
    endian     = tiff.endian
    max_inline = 4

    img_ifd = tiff.ifds[img_ifd_idx]
    geo_ifd = tiff.ifds[geo_ifd_idx]

    # ─ 픽셀 스케일 계산 (img_ifd가 geo_ifd보다 저해상도이므로 스케일 > 1) ────
    img_w0 = get_ifd_scalar(geo_ifd, TAG_IMAGEWIDTH,  1)
    img_h0 = get_ifd_scalar(geo_ifd, TAG_IMAGELENGTH, 1)
    img_w1 = get_ifd_scalar(img_ifd, TAG_IMAGEWIDTH,  1)
    img_h1 = get_ifd_scalar(img_ifd, TAG_IMAGELENGTH, 1)
    scale_x = img_w0 / img_w1 if img_w1 else 1.0
    scale_y = img_h0 / img_h1 if img_h1 else 1.0

    # ─ 1. 이미지 태그 수집 ────────────────────────────────────────────────────
    combined = dict(img_ifd.entries)

    # SUBFILETYPE(254) → 0 (main image로 승격)
    if 254 in combined:
        e = combined[254]
        combined[254] = TiffEntry(
            tag=254, field_type=e.field_type, count=e.count,
            values=[0], entry_pos=0, data_offset=None,
        )
    else:
        combined[254] = TiffEntry(
            tag=254, field_type=4, count=1, values=[0], entry_pos=0, data_offset=None,
        )

    # ─ 2. 지오태그 추가 (geo_ifd에서, 이미지 태그와 중복 없는 것만) ──────────
    for tag in GEO_TAGS:
        if tag in geo_ifd.entries and tag not in combined:
            combined[tag] = geo_ifd.entries[tag]

    # ─ 3. 태그 오름차순 정렬 ─────────────────────────────────────────────────
    entries = [combined[tag] for tag in sorted(combined.keys())]

    # ─ 4. IFD 크기 계산 → extra_data 오프셋 결정 ────────────────────────────
    ifd_size      = 2 + len(entries) * 12 + 4
    extra_data_off = ifd_file_pos + ifd_size   # 스케일된 ModelPixelScale이 놓일 파일 위치

    # ─ 5. ModelPixelScale 스케일 (DOUBLE × 3 = 24 bytes extra_data) ──────────
    extra_data = b''
    ps_entry = combined.get(TAG_MODELSCALE)
    if ps_entry is not None and ps_entry.values:
        vals = list(ps_entry.values)   # DOUBLE 3개: [dx, dy, dz]
        if len(vals) >= 1:
            vals[0] = vals[0] * scale_x
        if len(vals) >= 2:
            vals[1] = vals[1] * scale_y
        extra_data = struct.pack(endian + f'{len(vals)}d', *vals)

    # ─ 6. IFD 직렬화 ─────────────────────────────────────────────────────────
    buf = bytearray()
    buf += struct.pack(endian + 'H', len(entries))

    for entry in entries:
        tinfo      = TIFF_TYPE_INFO.get(entry.field_type, (1, 'B'))
        total_size = tinfo[0] * entry.count

        buf += struct.pack(endian + 'H', entry.tag)
        buf += struct.pack(endian + 'H', entry.field_type)
        buf += struct.pack(endian + 'I', entry.count)

        if entry.tag == TAG_MODELSCALE and extra_data:
            # 스케일된 값이 extra_data에 있으므로 그 위치를 가리킴
            buf += struct.pack(endian + 'I', extra_data_off)
        elif total_size <= max_inline:
            buf += _pack_inline_value(entry.values, entry.field_type, entry.count, endian)
        else:
            assert entry.data_offset is not None, \
                f"태그 {entry.tag}: out-of-line이나 data_offset 없음"
            buf += struct.pack(endian + 'I', entry.data_offset)

    buf += struct.pack(endian + 'I', next_ifd_offset)
    assert len(buf) == ifd_size, f"IFD 크기 불일치: {len(buf)} != {ifd_size}"
    return bytes(buf) + extra_data


def find_min_tile_offset(tiff: TiffInfo) -> int:
    """모든 IFD의 TileOffsets 중 양수 최소값 → SCOG v3 블록 삽입 지점."""
    min_off = None
    for ifd in tiff.ifds:
        entry = ifd.entries.get(TAG_TILE_OFFSETS)
        if entry is None:
            continue
        for v in entry.values:
            off = int(v)
            if off > 0 and (min_off is None or off < min_off):
                min_off = off
    if min_off is None:
        raise ValueError("TileOffsets를 찾을 수 없습니다.")
    return min_off


def pre_calculate_scog_block_size(level_tile_counts: list) -> int:
    """암호화 전 SCOG 블록 크기 미리 계산 (v3 오프셋 시프트량 결정에 필요)."""
    total = SCOG_HEADER_SIZE
    for tc in level_tile_counts:
        plaintext_size = 4 + tc * 8 * 2          # tile_count(4) + offsets(8*N) + bytecounts(8*N)
        ciphertext_size = plaintext_size + 16     # + GCM auth tag
        entry_size = 2 + 2 + 4 + 12 + ciphertext_size  # level_id + reserved + ct_len + iv + ct
        total += entry_size
    return total


def write_ifd_tag_values(data: bytearray, tiff: TiffInfo,
                          ifd_idx: int, tag: int, new_values: list) -> None:
    """
    IFD 태그의 값을 in-place로 업데이트. new_values 길이는 기존 count와 같아야 함.
    """
    ifd = tiff.ifds[ifd_idx]
    entry = ifd.entries.get(tag)
    if entry is None:
        raise KeyError(f"IFD {ifd_idx}에 태그 {tag} 없음")
    if len(new_values) != entry.count:
        raise ValueError(f"태그 {tag}: 기존 {entry.count}개 vs 새 {len(new_values)}개")

    tinfo = TIFF_TYPE_INFO.get(entry.field_type, (1, 'B'))
    size_each, fmt_char = tinfo
    max_inline = 8 if tiff.bigtiff else 4
    total_size = size_each * entry.count

    if total_size <= max_inline:
        base = entry.entry_pos + (12 if tiff.bigtiff else 8)
    else:
        base = entry.data_offset

    for j, val in enumerate(new_values):
        struct.pack_into(tiff.endian + fmt_char, data, base + j * size_each, val)


def encrypt_tile_partial(tile_data: bytes, cek: bytes,
                         file_id: str, level_id: int, tile_index: int,
                         encrypt_size: int = 1024) -> bytes:
    """타일 앞 encrypt_size 바이트를 AES-256-GCM으로 암호화.

    결과: [IV 12B][AES-GCM(앞 min(encrypt_size, tile_size)) + tag 16B][나머지 평문...]
    오버헤드: 28 bytes (IV 12 + tag 16)
    """
    actual = min(encrypt_size, len(tile_data))
    iv = os.urandom(12)
    aad = file_id.encode() + struct.pack('>H', level_id) + struct.pack('>I', tile_index)
    head_ct = AESGCM(cek).encrypt(iv, tile_data[:actual], aad)  # actual + 16 bytes (tag)
    return iv + head_ct + tile_data[actual:]


def decrypt_tile_partial(enc_tile: bytes, cek: bytes,
                         file_id: str, level_id: int, tile_index: int,
                         encrypt_size: int = 1024) -> bytes:
    """암호화된 타일 복호화 → 원본 타일 반환.

    enc_tile: [IV 12B][ciphertext + tag 16B][평문 tail...]
    """
    iv = enc_tile[:12]
    actual = min(encrypt_size, len(enc_tile) - 28)  # 원본 encrypt된 부분 크기
    ct = enc_tile[12:12 + actual + 16]               # ciphertext + 16B tag
    tail = enc_tile[12 + actual + 16:]
    aad = file_id.encode() + struct.pack('>H', level_id) + struct.pack('>I', tile_index)
    head = AESGCM(cek).decrypt(iv, ct, aad)
    return head + tail


def redirect_tiff_first_ifd(data: bytearray, tiff: TiffInfo, new_offset: int) -> None:
    """TIFF 헤더의 첫 IFD 오프셋을 new_offset으로 in-place 변경."""
    if tiff.bigtiff:
        struct.pack_into(tiff.endian + 'Q', data, 8, new_offset)
    else:
        struct.pack_into(tiff.endian + 'I', data, 4, new_offset)
