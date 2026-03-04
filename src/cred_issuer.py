#!/usr/bin/env python3
"""
cred_issuer.py — SCOG 자격증명 발급기

자격증명(Credential) = 특정 레벨 접근에 필요한 CEK 묶음 JSON

형식:
{
  "file_id": "kompsat",
  "scog_block_size": 360,
  "levels": {
    "1": "hex-cek...",
    "2": "hex-cek..."
  },
  "level_meta": {
    "1": { "tile_count": 4, "image_width": 649, ... },
    "2": { "tile_count": 1, "image_width": 324, ... }
  }
}

사용:
  # 전체 레벨 (프리미엄)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 0 1 2 --out keys/cred_premium.json

  # 저해상도만 (기본)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 1 2 --out keys/cred_basic.json

  # 최저해상도만 (게스트)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 2 --out keys/cred_guest.json
"""

import json
import argparse
import sys
from pathlib import Path


def issue_credential(cek_store_path: str, levels: list,
                     out_path: str = None, public_level_override: int = None) -> dict:
    """
    cek_store.json에서 지정 레벨만 추출하여 자격증명 생성.
    v1/v2 자동 감지: 스토어에 'scog_block_size' → v1, 'public_level' → v2

    Args:
        cek_store_path:       keys/v1/<file_id>_ceks.json 또는 keys/v2/<file_id>_ceks.json 경로
        levels:               접근 허용할 암호화 레벨 번호 리스트 (v2 guest는 빈 리스트 가능)
        out_path:             저장할 경로 (None이면 저장 안 함)
        public_level_override: v2 전용. 자격증명 내 public_level 값 덮어쓰기
                               (파일 실제 public_level 이상이어야 함)

    Returns:
        자격증명 dict
    """
    with open(cek_store_path) as f:
        store = json.load(f)

    is_v4 = store.get('format') == 'v4'
    is_v3 = 'scog_block_offset' in store and not is_v4
    is_v2 = 'public_level' in store and not is_v3 and not is_v4

    available = set(store['levels'].keys())
    requested = set(str(l) for l in levels)
    invalid   = requested - available

    if invalid:
        raise ValueError(f"존재하지 않는 레벨: {invalid}. 사용 가능: {sorted(available)}")

    level_meta_store = store.get('level_meta', {})
    selected_meta    = {lvl: level_meta_store[lvl]
                        for lvl in sorted(requested)
                        if lvl in level_meta_store}

    if is_v4:
        # v4 단일 키 자격증명: HKDF 키 체인으로 하위 레벨 유도
        # requested에서 가장 높은 레벨(=가장 작은 번호)의 CEK를 key로 발급
        if requested:
            top_level = min(int(l) for l in requested)
            cred = {
                'file_id': store['file_id'],
                'key':     store['levels'][str(top_level)],
            }
        else:
            # guest: 키 없음 → 접근 불가
            cred = {
                'file_id': store['file_id'],
            }
        fmt_label = 'v4'
    elif is_v3:
        # v3: 자격증명에 public_level/level_meta 없음 — 클라이언트가 TIFF IFD에서 발견
        cred = {
            'file_id':           store['file_id'],
            'scog_block_offset': store['scog_block_offset'],
            'first_ifd_offset':  store['first_ifd_offset'],
            'levels':            {lvl: store['levels'][lvl] for lvl in sorted(requested)},
        }
        fmt_label = 'v3'
    elif is_v2:
        file_pub = store['public_level']
        eff_pub  = public_level_override if public_level_override is not None else file_pub

        # 공개 레벨(eff_pub 이상) 메타는 모두 포함
        for k, v in level_meta_store.items():
            if int(k) >= eff_pub:
                selected_meta[k] = v

        cred = {
            'file_id':      store['file_id'],
            'public_level': eff_pub,
            'levels':       {lvl: store['levels'][lvl] for lvl in sorted(requested)},
            'level_meta':   selected_meta,
        }
        fmt_label = 'v2'
    else:
        cred = {
            'file_id':         store['file_id'],
            'scog_block_size': store['scog_block_size'],
            'levels':          {lvl: store['levels'][lvl] for lvl in sorted(requested)},
            'level_meta':      selected_meta,
        }
        fmt_label = 'v1'

    if out_path:
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, 'w') as f:
            json.dump(cred, f, indent=2)
        print(f"자격증명 저장 ({fmt_label}): {out_path}")
        print(f"  file_id: {cred['file_id']}")
        if is_v2:
            print(f"  공개 레벨: {cred['public_level']}+")
        if is_v3:
            print(f"  first_ifd_offset: {cred['first_ifd_offset']}")
        if is_v4:
            if 'key' in cred:
                print(f"  key: {cred['key'][:16]}... (단일 키)")
            else:
                print(f"  guest (키 없음 → 접근 불가)")
        else:
            print(f"  암호화 접근 레벨: {sorted(cred['levels'].keys()) or '없음 (공개 접근만)'}")

    return cred


def load_credential(cred_path: str) -> dict:
    """자격증명 JSON 파일 로드"""
    with open(cred_path) as f:
        return json.load(f)


def get_cek(cred: dict, level_id: int) -> bytes:
    """자격증명에서 특정 레벨의 CEK bytes 꺼내기. 없으면 PermissionError."""
    key = str(level_id)
    if key not in cred['levels']:
        available = sorted(cred['levels'].keys())
        raise PermissionError(
            f"레벨 {level_id}에 대한 접근 권한 없음. "
            f"보유 레벨: {available}"
        )
    return bytes.fromhex(cred['levels'][key])


# ─── CLI ─────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='SCOG 자격증명 발급기',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  # 프리미엄 (레벨 0~2 전체)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 0 1 2 --out keys/cred_premium.json

  # 기본 (저해상도만)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 1 2 --out keys/cred_basic.json

  # 게스트 (최저해상도만)
  python src/cred_issuer.py keys/kompsat_ceks.json --levels 2 --out keys/cred_guest.json
        """
    )
    parser.add_argument('cek_store',  help='CEK 저장소 경로 (keys/v1/<file>_ceks.json 등)')
    parser.add_argument('--levels',       nargs='*', type=int, default=[],
                        help='접근 허용할 암호화 레벨 번호 (v2 guest는 생략 가능)')
    parser.add_argument('--public-level', type=int, default=None,
                        help='v2 전용: 자격증명의 public_level 덮어쓰기 (파일 값 이상)')
    parser.add_argument('--out',          help='출력 자격증명 JSON 파일 경로')
    args = parser.parse_args()

    issue_credential(args.cek_store, args.levels, args.out, args.public_level)
