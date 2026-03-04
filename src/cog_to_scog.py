#!/usr/bin/env python3
"""
cog_to_scog.py — COG → SCOG 변환기

동작:
  1. COG 파일 전체를 읽는다
  2. 각 IFD(레벨)에서 TileOffsets + TileByteCounts 추출
  3. 레벨별 CEK 생성 → AES-256-GCM으로 암호화
  4. SCOG 블록 빌드
  5. 원본 TIFF의 TileOffsets를 0으로 초기화
  6. [SCOG 블록 + 수정된 TIFF] 를 .scog 파일로 저장
  7. CEK를 keys/<file_id>_ceks.json 에 저장

사용:
  python cog_to_scog.py data/kompsat.tif data/kompsat.scog
  python cog_to_scog.py data/kompsat.tif data/kompsat.scog --keys keys/
"""

import os
import sys
import json
import struct
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scog_structs import (
    parse_tiff, zero_tile_offsets,
    encrypt_level, serialize_scog_block,
    make_scog_footer,
    build_public_main_ifd, redirect_tiff_first_ifd,
    find_min_tile_offset, pre_calculate_scog_block_size,
    write_ifd_tag_values,
    encrypt_tile_partial,
    TAG_TILE_OFFSETS, TAG_TILE_BYTECOUNTS,
    TAG_IMAGEWIDTH, TAG_IMAGELENGTH, TAG_TILEWIDTH, TAG_TILELENGTH,
    get_ifd_scalar,
)


def cog_to_scog(input_path: str, output_path: str,
                keys_dir: str = 'keys', format_ver: str = 'v1',
                public_level_arg: int = None,
                encrypt_size: int = 1024) -> dict:
    """
    COG 파일을 SCOG로 변환.
    format_ver: 'v1' | 'v2' | 'v3' | 'v4' (부분 타일 암호화)
    Returns: cek_store dict (저장 경로 포함)
    """
    file_id = Path(input_path).stem

    # ─ 1. 파일 읽기 ─────────────────────────────────────────────────────────
    print(f"[1/6] 파일 읽는 중: {input_path}")
    with open(input_path, 'rb') as f:
        original_data = f.read()
    print(f"      파일 크기: {len(original_data):,} bytes")

    # ─ 2. TIFF 파싱 ─────────────────────────────────────────────────────────
    print(f"[2/6] TIFF 구조 파싱 중...")
    tiff = parse_tiff(original_data)
    endian_str = 'little-endian' if tiff.endian == '<' else 'big-endian'
    print(f"      바이트 순서: {endian_str}, BigTIFF: {tiff.bigtiff}")
    print(f"      IFD 개수: {len(tiff.ifds)}")

    for i, ifd in enumerate(tiff.ifds):
        w = get_ifd_scalar(ifd, TAG_IMAGEWIDTH, '?')
        h = get_ifd_scalar(ifd, TAG_IMAGELENGTH, '?')
        tw = get_ifd_scalar(ifd, TAG_TILEWIDTH, '?')
        th = get_ifd_scalar(ifd, TAG_TILELENGTH, '?')
        tile_entry = ifd.entries.get(TAG_TILE_OFFSETS)
        tile_count = tile_entry.count if tile_entry else 0
        print(f"      IFD {i}: {w}×{h} px, 타일 {tw}×{th}, {tile_count}개 타일")

    # ─ v4: 부분 타일 암호화 (별도 경로) ─────────────────────────────────────
    if format_ver == 'v4':
        return _cog_to_scog_v4(input_path, output_path, keys_dir,
                                file_id, original_data, tiff, encrypt_size)

    # ─ 3. 레벨별 TileOffsets 추출 + 암호화 ─────────────────────────────────
    print(f"[3/6] TileOffsets 추출 + 암호화 중...")
    scog_entries = []
    cek_store    = {}
    level_meta   = {}

    # v2/v3: public_level 이상은 공개 (QGIS 호환)
    if format_ver in ('v2', 'v3'):
        public_level = public_level_arg if public_level_arg is not None else (len(tiff.ifds) - 1)
        if public_level >= len(tiff.ifds) or not tiff.ifds[public_level].entries.get(TAG_TILE_OFFSETS):
            raise ValueError(f"IFD {public_level}이 없거나 타일이 없습니다. COG 포맷 확인 필요.")
        print(f"      {format_ver} 공개 레벨: IFD {public_level}+ (IFD ≥ {public_level} 암호화 안 함, QGIS 호환)")
    else:
        public_level = None

    # v3: SCOG 블록 삽입 지점 및 시프트량 미리 계산
    v3_shift = 0
    v3_insert_point = 0
    if format_ver == 'v3':
        v3_insert_point = find_min_tile_offset(tiff)
        encrypted_tile_counts = []
        for i, ifd in enumerate(tiff.ifds):
            if i < public_level:
                entry = ifd.entries.get(TAG_TILE_OFFSETS)
                if entry:
                    encrypted_tile_counts.append(entry.count)
        v3_shift = pre_calculate_scog_block_size(encrypted_tile_counts)
        print(f"      v3 삽입 지점: byte {v3_insert_point}, 시프트: +{v3_shift} bytes")

    for i, ifd in enumerate(tiff.ifds):
        offset_entry = ifd.entries.get(TAG_TILE_OFFSETS)
        bc_entry     = ifd.entries.get(TAG_TILE_BYTECOUNTS)

        if offset_entry is None:
            print(f"      IFD {i}: TileOffsets 없음 (건너뜀)")
            continue

        offsets    = [int(v) for v in offset_entry.values]
        bytecounts = [int(v) for v in bc_entry.values] if bc_entry else [0] * len(offsets)

        # v3: 삽입 지점 이후의 타일 오프셋을 시프트
        if format_ver == 'v3':
            offsets = [o + v3_shift if o >= v3_insert_point else o for o in offsets]

        level_meta[str(i)] = {
            'tile_count':   len(offsets),
            'image_width':  get_ifd_scalar(ifd, TAG_IMAGEWIDTH),
            'image_height': get_ifd_scalar(ifd, TAG_IMAGELENGTH),
            'tile_width':   get_ifd_scalar(ifd, TAG_TILEWIDTH),
            'tile_height':  get_ifd_scalar(ifd, TAG_TILELENGTH),
        }

        if format_ver in ('v2', 'v3') and i >= public_level:
            # 공개 레벨: tile_offsets/bytecounts를 자격증명에 저장 (클라이언트 직접 접근용)
            level_meta[str(i)]['tile_offsets']    = offsets
            level_meta[str(i)]['tile_bytecounts'] = bytecounts
            print(f"      레벨 {i}: 공개 레벨 — 암호화 건너뜀 ({len(offsets)}개 타일)")
            continue

        # CEK 생성 + 암호화 (v3: 시프트된 오프셋으로 암호화)
        cek = os.urandom(32)
        iv, ct = encrypt_level(offsets, bytecounts, cek, file_id, i)

        scog_entries.append({'level_id': i, 'iv': iv, 'ciphertext': ct})
        cek_store[str(i)] = cek.hex()
        print(f"      레벨 {i}: {len(offsets)}개 타일 암호화 완료 (ct={len(ct)} bytes)")

    if not scog_entries and format_ver == 'v1':
        raise ValueError("타일 IFD가 없습니다. 입력이 COG인지 확인하세요.")

    # ─ 4. SCOG 블록 직렬화 ───────────────────────────────────────────────────
    print(f"[4/6] SCOG 블록 빌드 중...")
    scog_block = serialize_scog_block(scog_entries)
    print(f"      SCOG 블록 크기: {len(scog_block):,} bytes ({len(scog_entries)}개 암호화 레벨)")

    # ─ 5. TIFF TileOffsets 제로화 ────────────────────────────────────────────
    print(f"[5/6] TIFF TileOffsets/ByteCounts 제로화 중...")
    if format_ver == 'v3':
        # v3: 공개 레벨은 보존 (클라이언트가 IFD에서 직접 읽음)
        skip = set(range(public_level, len(tiff.ifds)))
    elif format_ver == 'v2' and public_level is not None:
        skip = set(range(public_level, len(tiff.ifds)))
    else:
        skip = None
    modified_tiff = zero_tile_offsets(bytearray(original_data), tiff, skip_ifd_indices=skip)

    # ─ 5b. v2/v3: 공개 메인 IFD 추가 + TIFF 헤더 리디렉션 ────────────────────
    if format_ver in ('v2', 'v3'):
        # v3: SCOG 블록 삽입 (타일 데이터 앞에)
        if format_ver == 'v3':
            print(f"[5b] v3: SCOG 블록 삽입 @ byte {v3_insert_point}...")
            before = bytes(modified_tiff[:v3_insert_point])
            after  = bytes(modified_tiff[v3_insert_point:])
            modified_tiff = bytearray(before + scog_block + after)
            print(f"      삽입 완료: {len(before):,} + {len(scog_block):,} + {len(after):,} bytes")

            # 공개 레벨 TileOffsets를 시프트된 값으로 in-place 업데이트
            for ifd_idx in range(public_level, len(tiff.ifds)):
                ifd = tiff.ifds[ifd_idx]
                off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
                if off_entry is None:
                    continue
                shifted = [int(v) + v3_shift if int(v) >= v3_insert_point else int(v)
                           for v in off_entry.values]
                write_ifd_tag_values(modified_tiff, tiff, ifd_idx, TAG_TILE_OFFSETS, shifted)
                print(f"      IFD {ifd_idx} TileOffsets 시프트 완료: {off_entry.values} → {shifted}")

        print(f"[5c] 공개 메인 IFD 빌드 중 (IFD {public_level} + IFD 0 지오태그)...")
        img_ifd_idx  = public_level
        geo_ifd_idx  = 0

        # v3: 공개 IFD의 TileOffsets를 시프트된 값으로 갱신 (build_public_main_ifd가 읽을 수 있도록)
        if format_ver == 'v3':
            pub_ifd = tiff.ifds[img_ifd_idx]
            pub_off_entry = pub_ifd.entries.get(TAG_TILE_OFFSETS)
            if pub_off_entry:
                pub_off_entry.values = [int(v) + v3_shift if int(v) >= v3_insert_point else int(v)
                                        for v in pub_off_entry.values]

        new_ifd_pos   = len(modified_tiff)
        new_ifd_bytes = build_public_main_ifd(
            tiff, img_ifd_idx, geo_ifd_idx, 0, new_ifd_pos
        )

        redirect_tiff_first_ifd(modified_tiff, tiff, new_ifd_pos)
        modified_tiff.extend(new_ifd_bytes)

        print(f"      공개 메인 IFD: offset={new_ifd_pos}, size={len(new_ifd_bytes)} bytes")
        print(f"      TIFF 헤더 → {new_ifd_pos} (IFD 0 숨김, QGIS는 IFD {img_ifd_idx}부터 인식)")

    # ─ 6. SCOG 파일 저장 ─────────────────────────────────────────────────────
    print(f"[6/6] SCOG 파일 저장 중: {output_path}")
    os.makedirs(Path(output_path).parent, exist_ok=True)

    if format_ver == 'v1':
        # v1: [SCOG block][TIFF]
        with open(output_path, 'wb') as f:
            f.write(scog_block)
            f.write(modified_tiff)
        total_size = len(scog_block) + len(modified_tiff)
        print(f"      저장 완료 (v1): {total_size:,} bytes (SCOG prefix {len(scog_block):,} bytes)")
    elif format_ver == 'v2':
        # v2: [TIFF][SCOG block][8B footer]
        footer = make_scog_footer(len(scog_block))
        with open(output_path, 'wb') as f:
            f.write(modified_tiff)
            f.write(scog_block)
            f.write(footer)
        total_size = len(modified_tiff) + len(scog_block) + 8
        print(f"      저장 완료 (v2): {total_size:,} bytes (SCOG suffix {len(scog_block):,} bytes + 8B footer)")
    else:
        # v3: [TIFF(앞) + SCOG block + TIFF(뒤) + 새 메인 IFD] — 이미 modified_tiff에 포함
        with open(output_path, 'wb') as f:
            f.write(modified_tiff)
        total_size = len(modified_tiff)
        print(f"      저장 완료 (v3): {total_size:,} bytes (SCOG @ byte {v3_insert_point}, footer 없음)")

    # ─ CEK 저장 ──────────────────────────────────────────────────────────────
    os.makedirs(keys_dir, exist_ok=True)
    cek_file = Path(keys_dir) / f"{file_id}_ceks.json"

    if format_ver == 'v1':
        cek_data = {
            'file_id':         file_id,
            'scog_file':       str(output_path),
            'scog_block_size': len(scog_block),
            'levels':          cek_store,
            'level_meta':      level_meta,
        }
    elif format_ver == 'v2':
        cek_data = {
            'file_id':      file_id,
            'scog_file':    str(output_path),
            'public_level': public_level,
            'levels':       cek_store,
            'level_meta':   level_meta,
        }
    else:
        cek_data = {
            'file_id':           file_id,
            'scog_file':         str(output_path),
            'scog_block_offset': v3_insert_point,
            'first_ifd_offset':  tiff.first_ifd_offset,
            'levels':            cek_store,
            'level_meta':        level_meta,
        }

    with open(cek_file, 'w') as f:
        json.dump(cek_data, f, indent=2)
    print(f"      CEK 저장: {cek_file}")

    # ─ 요약 ──────────────────────────────────────────────────────────────────
    print()
    print(f"=== 변환 완료 (SCOG {format_ver}) ===")
    print(f"  입력:  {input_path}  ({len(original_data):,} bytes)")
    print(f"  출력:  {output_path}  ({total_size:,} bytes)")
    print(f"  SCOG 블록: {len(scog_block):,} bytes")
    if format_ver in ('v2', 'v3'):
        print(f"  공개 레벨: {public_level}+ (IFD ≥ {public_level}, QGIS 접근 가능)")
    if format_ver == 'v3':
        print(f"  SCOG 블록 위치: byte {v3_insert_point} (첫 16KB 내)")
    print(f"  암호화된 레벨: {sorted(cek_store.keys())}")

    return cek_data


def _cog_to_scog_v4(input_path, output_path, keys_dir,
                     file_id, original_data, tiff, encrypt_size=1024):
    """v4: 부분 타일 암호화 — 각 타일의 앞 encrypt_size 바이트를 AES-256-GCM으로 암호화."""
    from scog_structs import TIFF_TYPE_INFO

    OVERHEAD = 28  # IV(12) + GCM tag(16)

    print(f"[3/6] v4 부분 타일 암호화 중 (encrypt_size={encrypt_size})...")

    cek_store  = {}
    level_meta = {}

    # 헤더 영역 결정: 첫 타일 오프셋 이전이 헤더
    from scog_structs import find_min_tile_offset
    header_end = find_min_tile_offset(tiff)
    print(f"      헤더 영역: 0 ~ {header_end:,} bytes")

    # 모든 타일 수집 (IFD별, offset 순서대로)
    # 각 타일: (ifd_idx, tile_idx_in_ifd, original_offset, original_size)
    all_tiles = []
    for ifd_idx, ifd in enumerate(tiff.ifds):
        off_entry = ifd.entries.get(TAG_TILE_OFFSETS)
        bc_entry  = ifd.entries.get(TAG_TILE_BYTECOUNTS)
        if off_entry is None:
            continue
        offsets    = [int(v) for v in off_entry.values]
        bytecounts = [int(v) for v in bc_entry.values] if bc_entry else [0] * len(offsets)

        level_meta[str(ifd_idx)] = {
            'tile_count':   len(offsets),
            'image_width':  get_ifd_scalar(ifd, TAG_IMAGEWIDTH),
            'image_height': get_ifd_scalar(ifd, TAG_IMAGELENGTH),
            'tile_width':   get_ifd_scalar(ifd, TAG_TILEWIDTH),
            'tile_height':  get_ifd_scalar(ifd, TAG_TILELENGTH),
        }

        cek = os.urandom(32)
        cek_store[str(ifd_idx)] = cek.hex()

        for tile_idx, (off, bc) in enumerate(zip(offsets, bytecounts)):
            all_tiles.append((ifd_idx, tile_idx, off, bc))

    # offset 순으로 정렬
    all_tiles.sort(key=lambda t: t[2])

    # 암호화된 타일 데이터 생성 + 새 오프셋/바이트카운트 계산
    # new_offsets[ifd_idx] = [new_offset, ...]
    # new_bytecounts[ifd_idx] = [new_bytecount, ...]
    new_offsets    = {}
    new_bytecounts = {}
    encrypted_tiles = {}  # (ifd_idx, tile_idx) → encrypted_bytes

    current_offset = header_end
    for ifd_idx, tile_idx, orig_off, orig_bc in all_tiles:
        tile_data = original_data[orig_off:orig_off + orig_bc]
        cek = bytes.fromhex(cek_store[str(ifd_idx)])
        enc_tile = encrypt_tile_partial(tile_data, cek, file_id, ifd_idx, tile_idx, encrypt_size)

        if ifd_idx not in new_offsets:
            ifd = tiff.ifds[ifd_idx]
            tc = ifd.entries.get(TAG_TILE_OFFSETS).count
            new_offsets[ifd_idx] = [0] * tc
            new_bytecounts[ifd_idx] = [0] * tc

        new_offsets[ifd_idx][tile_idx] = current_offset
        new_bytecounts[ifd_idx][tile_idx] = len(enc_tile)
        encrypted_tiles[(ifd_idx, tile_idx)] = enc_tile
        current_offset += len(enc_tile)

    print(f"      {len(all_tiles)}개 타일 암호화 완료")

    # ─ 4. 파일 쓰기 ─────────────────────────────────────────────────────────
    print(f"[4/6] v4 파일 빌드 중...")
    # 헤더(IFD 포함) 복사
    output_data = bytearray(original_data[:header_end])

    # 암호화된 타일 순차 기록 (offset 순)
    for ifd_idx, tile_idx, _, _ in all_tiles:
        output_data += encrypted_tiles[(ifd_idx, tile_idx)]

    # ─ 5. IFD TileOffsets/TileByteCounts 업데이트 ────────────────────────────
    print(f"[5/6] IFD TileOffsets/TileByteCounts 업데이트 중...")
    for ifd_idx in sorted(new_offsets.keys()):
        write_ifd_tag_values(output_data, tiff, ifd_idx, TAG_TILE_OFFSETS, new_offsets[ifd_idx])
        write_ifd_tag_values(output_data, tiff, ifd_idx, TAG_TILE_BYTECOUNTS, new_bytecounts[ifd_idx])
        print(f"      IFD {ifd_idx}: {len(new_offsets[ifd_idx])}개 타일 오프셋/바이트카운트 업데이트")

    # ─ 6. 파일 저장 + CEK 저장 ────────────────────────────────────────────────
    print(f"[6/6] SCOG v4 파일 저장 중: {output_path}")
    os.makedirs(Path(output_path).parent, exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(output_data)

    os.makedirs(keys_dir, exist_ok=True)
    cek_data = {
        'file_id':      file_id,
        'format':       'v4',
        'encrypt_size': encrypt_size,
        'scog_file':    str(output_path),
        'levels':       cek_store,
        'level_meta':   level_meta,
    }
    cek_file = Path(keys_dir) / f"{file_id}_ceks.json"
    with open(cek_file, 'w') as f:
        json.dump(cek_data, f, indent=2)

    total_size = len(output_data)
    print()
    print(f"=== 변환 완료 (SCOG v4) ===")
    print(f"  입력:  {input_path}  ({len(original_data):,} bytes)")
    print(f"  출력:  {output_path}  ({total_size:,} bytes)")
    print(f"  오버헤드: {total_size - len(original_data):,} bytes ({len(all_tiles)}타일 × {OVERHEAD}B)")
    print(f"  암호화된 레벨: {sorted(cek_store.keys())}")
    print(f"  encrypt_size: {encrypt_size}")
    print(f"  CEK 저장: {cek_file}")

    return cek_data


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='COG → SCOG 변환기',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python src/cog_to_scog.py data/kompsat.tif data/kompsat.scog
  python src/cog_to_scog.py data/kompsat.tif data/kompsat.scog --keys keys/
        """
    )
    parser.add_argument('input',   help='입력 COG 파일 경로')
    parser.add_argument('output',  help='출력 SCOG 파일 경로')
    parser.add_argument('--keys',  help='CEK 저장 디렉토리 (기본: keys/v1 또는 keys/v2)')
    parser.add_argument('--format', dest='format_ver', choices=['v1', 'v2', 'v3', 'v4'], default='v1',
                        help='SCOG 포맷 버전 (v1=SCOG prefix, v2=TIFF-first QGIS 호환, v3=SCOG-in-header, v4=부분 타일 암호화)')
    parser.add_argument('--public-level', dest='public_level', type=int, default=None,
                        help='v2 전용: QGIS에 공개할 최소 IFD 인덱스 (기본: 마지막 IFD)')
    parser.add_argument('--encrypt-size', dest='encrypt_size', type=int, default=1024,
                        help='v4 전용: 타일 앞 암호화 크기 (기본: 1024)')
    args = parser.parse_args()

    keys_dir = args.keys or f'keys/{args.format_ver}'
    cog_to_scog(args.input, args.output, keys_dir, args.format_ver,
                args.public_level, args.encrypt_size)
