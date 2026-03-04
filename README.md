# SCOG — Secure Cloud Optimized GeoTIFF

> COG에 레벨별 AES-256-GCM 접근 제어를 추가한 포맷. 서버 로직 없이 HTTP Range Request만으로 동작.

---

## 개요

Cloud Optimized GeoTIFF (COG)는 HTTP Range Request로 필요한 타일만 가져올 수 있는 효율적인 래스터 포맷이다. 하지만 누구나 URL만 알면 원본 해상도 데이터에 접근할 수 있다는 보안 한계가 있다.

**SCOG**는 이 문제를 해결한다:

- 레벨별 AES-256-GCM 암호화로 해상도 계층별 접근 제어
- 자격증명(Credential)에 포함된 CEK(Content Encryption Key)로만 복호화 가능
- 서버는 정적 파일 서빙만 담당 (nginx, S3 등) — 별도 인증 로직 불필요
- 클라이언트 사이드 복호화 (WebCrypto API)

### 예시: 위성영상 3티어 접근 제어

| 티어  | 접근 가능 레벨 | 해상도                   |
| ----- | -------------- | ------------------------ |
| Admin | L0 + L1 + L2   | 1305×1107 (전해상도)     |
| User  | L1 + L2        | 652×553 (중해상도)       |
| Guest | L2만           | 326×276 (저해상도, 공개) |

---

## 포맷 버전

### v1 — 기본

```
[SCOG Block (N bytes)][TIFF with TileOffsets=0]
```

- 모든 레벨 암호화
- 자격증명: `{file_id, scog_block_size, levels, level_meta}`
- 타일 위치 = `scog_block_size + tiff_tile_offset`
- QGIS에서 열 수 없음 (TIFF 헤더 앞에 SCOG 블록이 있으므로)

### v2 — QGIS 호환

```
[TIFF bytes][새 메인 IFD][SCOG Block][8B Footer]
```

- TIFF가 byte 0에서 시작 → `.scog.tif` 확장자로 QGIS에서 바로 열림
- 공개 레벨(public_level) 지원: 지정 레벨 이상은 암호화 없이 공개
- IFD 체인 재구성: 암호화 레벨은 TIFF 체인에서 완전히 숨김
- 자격증명: `{file_id, public_level, levels, level_meta}`
- 클라이언트 로딩: footer(8B) → SCOG 블록 → 타일 (최소 2회 요청)

### v3 — 1-Request 메타데이터

```
[TIFF Header + IFDs][SCOG Block @ offset 1100][타일 데이터][새 메인 IFD]
```

- SCOG 블록을 IFD 바로 뒤(타일 데이터 앞)에 삽입
- **첫 16KB 1회 요청으로 IFD + SCOG 블록 모두 획득**
- QGIS 호환 유지 (v2와 동일한 새 메인 IFD)
- **자격증명 최소화**: `public_level`, `level_meta` 없음
  - 클라이언트가 TIFF IFD에서 공개/암호화 레벨 자동 판단
  - 이미지/타일 크기도 IFD에서 직접 파싱

```json
{
  "file_id": "kompsat_3857",
  "scog_block_offset": 1100,
  "first_ifd_offset": 192,
  "levels": {
    "0": "9c3a317e...",
    "1": "afc77515..."
  }
}
```

Guest 자격증명 (CEK 없음, 공개 레벨만 접근):

```json
{
  "file_id": "kompsat_3857",
  "scog_block_offset": 1100,
  "first_ifd_offset": 192,
  "levels": {}
}
```

### v4 — 타일 데이터 암호화 (Partial Tile Encryption)

v1~v3는 TileOffsets만 암호화하여 타일 위치를 숨기는 방식이다. 파일이 탈취되면 DEFLATE 시그니처(`0x78 0x9C`)를 바이트 스캔하여 타일 데이터를 추출할 수 있다.

v4는 **타일 데이터 자체를 암호화**한다. 각 타일의 앞 1KB를 AES-256-GCM으로 암호화하여 DEFLATE 압축 스트림의 시작을 파괴하므로, 전체 타일이 복원 불가능하다.

```
[TIFF Header][IFDs (TileOffsets/ByteCounts 업데이트됨)][암호화된 타일 데이터...]
```

#### 타일 구조

```
원본:  [compressed_tile_data .................]
v4:    [IV 12B][AES-GCM(앞 1KB) + tag 16B][나머지 평문...]
       └────── 28B 오버헤드 ─────────────┘
```

- `encrypt_size = min(1024, tile_size)` — 타일이 1KB 이하면 전체 암호화
- AAD = `file_id + level_id(2B BE) + tile_index(4B BE)` — 타일 위치까지 바인딩
- TileByteCounts = 원본 + 28 (타일마다)
- SCOG 블록 없음 — IFD 구조 그대로 유지 (유효한 TIFF)

#### v4 자격증명

```json
{
  "file_id": "kompsat_3857",
  "format": "v4",
  "encrypt_size": 1024,
  "levels": {
    "0": "hex_cek_level0...",
    "1": "hex_cek_level1...",
    "2": "hex_cek_level2..."
  }
}
```

- 키만 포함 — `level_meta` 없음 (클라이언트가 TIFF IFD에서 직접 파싱)
- 모든 레벨이 암호화됨 (공개 레벨 없음)
- `format: "v4"` 필드로 버전 감지
- Guest 자격증명은 `levels: {}` → 모든 레벨 접근 거부

#### v4 클라이언트 플로우

```
1. fetch(0, 16384)                    ← 16KB 1회 요청
   └── parseTiffIFDs() → IFD 0, 1, 2 파싱 (TileOffsets 유효)

2. fetchTile(level, col, row)
   └── fetch(offset, bytecount)       ← 암호화된 타일 수신
       ├── IV(12B) 분리
       ├── 앞 1KB + tag(16B) → AES-GCM 복호화 (WebCrypto)
       ├── 나머지 평문과 합침
       └── DEFLATE 해제 → 렌더링
```

#### 복호화 성능

브라우저 WebCrypto API 기준:

- CryptoKey 캐싱 적용 시 `crypto.subtle.decrypt` 단일 호출 ~10μs/tile
- 렌더링 성능에 실질적 영향 없음
- Cross-Origin Isolation (COOP/COEP) 헤더로 `performance.now()` 5μs 정밀도 활성화

#### v3 vs v4 보안 비교

| 공격 시나리오        | v3 (TileOffsets 암호화)         | v4 (타일 데이터 암호화)   |
| -------------------- | ------------------------------- | ------------------------- |
| 파일 탈취            | DEFLATE 스캔으로 타일 추출 가능 | 타일 데이터 자체가 암호문 |
| brute-force 바이트 스캔 | `0x78 0x9C` 패턴 매칭 가능   | 패턴 매칭 불가            |
| 타일 변조            | 감지 불가                       | AES-GCM tag → InvalidTag |
| 타일 위치 바인딩     | AAD에 level_id만                | AAD에 level_id + tile_index |

### 버전 비교

|                 | v1                   | v2                 | v3                  | v4                      |
| --------------- | -------------------- | ------------------ | ------------------- | ----------------------- |
| 암호화 대상     | TileOffsets          | TileOffsets        | TileOffsets         | **타일 데이터 (앞 1KB)** |
| QGIS 호환       | X                    | O                  | O                   | O (유효한 TIFF)         |
| 공개 레벨       | X                    | O                  | O                   | X (전 레벨 암호화)     |
| 메타데이터 요청 | 1회                  | 2회 (footer+block) | **1회 (16KB)**      | **1회 (16KB)**          |
| 자격증명 크기   | 큼 (level_meta 포함) | 큼                 | **최소** (키만)     | **최소** (키만)         |
| brute-force 내성 | 취약                | 취약               | 취약                | **강함**                |
| 타일 변조 감지  | X                    | X                  | X                   | **O (GCM tag)**         |
| 버전 감지       | `scog_block_size`    | `public_level`     | `scog_block_offset` | `format: "v4"`          |

---

## 암호화 구조

### SCOG 블록

```
+0   magic      4B   "SCOG"
+4   version    2B   BE uint16
+6   level_cnt  2B   BE uint16
+8   total_size 8B   BE uint64
+16  entries[]       레벨별 암호화 엔트리
```

각 엔트리:

```
+0   level_id       2B   BE uint16
+2   reserved       2B
+4   ciphertext_len 4B   BE uint32
+8   iv            12B   AES-GCM nonce
+20  ciphertext     NB   AES-256-GCM 암호문 (TileOffsets + TileByteCounts)
```

### 암호화 대상

레벨별 `TileOffsets[]` + `TileByteCounts[]` 배열을 하나의 plaintext로 직렬화 후 AES-256-GCM 암호화:

```
plaintext = tile_count(4B) + offsets[](8B each) + bytecounts[](8B each)
```

### AAD (Additional Authenticated Data)

```
AAD = file_id.encode('utf-8') + struct.pack('>H', level_id)
```

파일 ID와 레벨 번호를 바인딩하여, 다른 파일/레벨의 CEK로 복호화 시도 시 `InvalidTag` 발생.

### CEK (Content Encryption Key)

- 레벨당 1개, 32바이트 랜덤 생성 (AES-256)
- CEK 저장소(`*_ceks.json`)에 모든 레벨의 CEK 보관 — **서버 측 비밀**
- 자격증명(credential)에는 허가된 레벨의 CEK만 포함 — 클라이언트에 배포

```
ceks.json (서버 보관)              credential (클라이언트 배포)
┌───────────────────────┐         ┌───────────────────────┐
│ levels:               │         │ levels:               │
│   "0": "9c3a..." CEK  │ ──발급──▶│   "1": "afc7..."     │ ← L1만
│   "1": "afc7..." CEK  │         └───────────────────────┘
└───────────────────────┘
```

### 키 갱신

- **소프트 갱신**: 같은 CEK로 접근 레벨만 확장/축소 → SCOG 파일 변경 없음
- **하드 만료**: 새 CEK로 SCOG 파일 재암호화 → 기존 자격증명 무효화 (`InvalidTag`)

---

## 프로젝트 구조

```
scog/
├── data/
│   ├── kompsat_3857.tif             원본 COG (EPSG:3857, 3 overview)
│   ├── kompsat_3857.scog            v1 SCOG
│   ├── kompsat_3857.scog.tif        v2 SCOG (QGIS 호환)
│   ├── kompsat_3857.v3.scog.tif     v3 SCOG (1-request)
│   └── kompsat_3857.v4.scog.tif     v4 SCOG (타일 암호화)
│
├── keys/
│   ├── v1/
│   │   ├── kompsat_3857_ceks.json   CEK 저장소 (서버 비밀)
│   │   ├── cred_3857_admin.json     자격증명: L0+L1+L2
│   │   ├── cred_3857_user.json      자격증명: L1+L2
│   │   └── cred_3857_guest.json     자격증명: L2만
│   ├── v2/                          v2 CEK 저장소 + 자격증명
│   ├── v3/                          v3 CEK 저장소 + 자격증명
│   └── v4/                          v4 CEK 저장소 + 자격증명
│
├── src/
│   ├── scog_structs.py              TIFF 파서, SCOG 블록 직렬화/역직렬화
│   ├── cog_to_scog.py               COG → SCOG 변환기
│   ├── cred_issuer.py               자격증명 발급기
│   └── scog_reader.py               SCOG 타일 리더 (로컬/HTTP)
│
├── app/                             React + Vite 데모 앱
│   └── src/
│       ├── App.jsx                  5탭 UI (v1 / v2 / v3 / v4 / Zoom-Aware)
│       ├── credentials.js           자격증명 + URL 설정
│       ├── lib/
│       │   ├── scog-client.js       SCOG 클라이언트 (v1/v2/v3/v4 자동감지)
│       │   └── cog-client.js        COG 클라이언트 (비교용)
│       └── pages/
│           ├── SCOGDemo.jsx          v1 접근 제어 데모
│           ├── SCOGv2Demo.jsx        v2 데모
│           ├── SCOGv3Demo.jsx        v3 데모
│           ├── SCOGv4Demo.jsx        v4 데모 (타일별 복호화 성능 패널)
│           └── ZoomViewer.jsx        줌 연동 뷰어 (v4 복호화 시간 표시)
│
├── tests/
│   └── test_scog.py                 19개 테스트
│
└── docker/
    └── docker-compose.yml           nginx (포트 8777, Range Request + CORS)
```

---

## 빠른 시작

### 필수 요구사항

- Python 3.10+
- Node.js 18+
- Docker (nginx 서빙용)

### 1. Python 의존성 설치

```bash
pip install cryptography requests
```

### 2. SCOG 파일 생성

```bash
# v1: 모든 레벨 암호화
python3 src/cog_to_scog.py data/kompsat_3857.tif data/kompsat_3857.scog \
    --format v1

# v2: L2 공개, L0·L1 암호화 (QGIS 호환)
python3 src/cog_to_scog.py data/kompsat_3857.tif data/kompsat_3857.scog.tif \
    --format v2 --public-level 2

# v3: L2 공개, L0·L1 암호화 (1-request 메타데이터)
python3 src/cog_to_scog.py data/kompsat_3857.tif data/kompsat_3857.v3.scog.tif \
    --format v3 --public-level 2 --keys keys/v3

# v4: 전 레벨 타일 데이터 암호화 (앞 1KB)
python3 src/cog_to_scog.py data/kompsat_3857.tif data/kompsat_3857.v4.scog.tif \
    --format v4 --keys keys/v4
```

### 3. 자격증명 발급

```bash
# v3 예시
# Admin: L0 + L1 CEK
python3 src/cred_issuer.py keys/v3/kompsat_3857_ceks.json \
    --levels 0 1 --out keys/v3/cred_3857_admin.json

# User: L1 CEK만
python3 src/cred_issuer.py keys/v3/kompsat_3857_ceks.json \
    --levels 1 --out keys/v3/cred_3857_user.json

# Guest: CEK 없음 (공개 레벨만)
python3 src/cred_issuer.py keys/v3/kompsat_3857_ceks.json \
    --levels --out keys/v3/cred_3857_guest.json

# v4 예시
# Admin: 전 레벨 CEK
python3 src/cred_issuer.py keys/v4/kompsat_3857_ceks.json \
    --levels 0 1 2 --out keys/v4/cred_3857_admin.json

# User: L1+L2 CEK
python3 src/cred_issuer.py keys/v4/kompsat_3857_ceks.json \
    --levels 1 2 --out keys/v4/cred_3857_user.json

# Guest: CEK 없음 (모든 레벨 접근 거부)
python3 src/cred_issuer.py keys/v4/kompsat_3857_ceks.json \
    --levels --out keys/v4/cred_3857_guest.json
```

### 4. 타일 읽기 테스트 (CLI)

```bash
# 로컬 파일에서 타일 읽기
python3 src/scog_reader.py data/kompsat_3857.v3.scog.tif \
    keys/v3/cred_3857_admin.json --level 0 --tile 0 0

# HTTP Range Request로 읽기 (nginx 필요)
python3 src/scog_reader.py http://localhost:8777/kompsat_3857.v3.scog.tif \
    keys/v3/cred_3857_admin.json --level 0 --tile 0 0

# 권한 없는 레벨 시도 → PermissionError
python3 src/scog_reader.py data/kompsat_3857.v3.scog.tif \
    keys/v3/cred_3857_guest.json --level 0 --tile 0 0
```

### 5. nginx 시작

```bash
cd docker && docker compose up -d
# http://localhost:8777 에서 data/ 디렉토리 서빙
```

### 6. React 데모 앱 실행

```bash
cd app
npm install
npm run dev
# http://localhost:5173
```

### 7. 테스트 실행

```bash
python3 tests/test_scog.py
# 결과: 19 passed, 0 failed
```

---

## 테스트 시나리오

| #   | 테스트             | 검증 내용                                               |
| --- | ------------------ | ------------------------------------------------------- |
| 01  | SCOG 블록 파싱     | v1 SCOG 블록 구조 (360B, 3레벨)                         |
| 02  | TileOffsets 제로화 | 원본 TIFF의 모든 TileOffsets = 0                        |
| 03  | 정상 접근 (로컬)   | 유효한 CEK로 타일 복호화 성공                           |
| 04  | 권한 거부          | 권한 없는 레벨 접근 시 PermissionError                  |
| 05  | GCM 변조 감지      | 암호문 1비트 변조 → InvalidTag                          |
| 06  | 잘못된 CEK         | 다른 CEK 사용 → InvalidTag                              |
| 07  | 소프트 갱신        | 같은 CEK로 레벨 확장 → 정상 동작                        |
| 08  | 하드 만료          | 새 CEK 재암호화 → 기존 자격증명 무효화                  |
| 09  | HTTP Range Request | nginx 경유 v1 타일 읽기                                 |
| 10  | v3 SCOG 블록 위치  | SCOG 블록이 첫 16KB 내 존재                             |
| 11  | v3 로컬 읽기       | 암호화 + 공개 레벨 타일 읽기                            |
| 12  | v3 권한 거부       | Guest로 암호화 레벨 → PermissionError, 공개 레벨 → 성공 |
| 13  | v3 HTTP 읽기       | nginx 경유 v3 타일 읽기                                 |
| 14  | v4 변환            | COG → v4 변환 + 타일 데이터 암호화 확인                 |
| 15  | v4 로컬 읽기       | 유효 자격증명으로 타일 복호화 + 원본 바이트 일치         |
| 16  | v4 권한 거부       | CEK 없는 레벨 접근 → PermissionError                    |
| 17  | v4 변조 감지       | 암호화된 타일 1비트 변조 → InvalidTag                   |
| 18  | v4 잘못된 CEK      | 다른 CEK 사용 → InvalidTag                              |
| 19  | v4 HTTP 읽기       | nginx 경유 v4 타일 읽기                                 |

---

## 클라이언트 동작 흐름

### v3 클라이언트 (권장)

```
1. fetch(0, 16384)                    ← 16KB 1회 요청
   ├── parseTiffIFDs(first_ifd_offset) → IFD 0, 1, 2 파싱
   │   ├── IFD 0: TileOffsets=[0,0,...] → 암호화 레벨
   │   ├── IFD 1: TileOffsets=[0,0,...] → 암호화 레벨
   │   └── IFD 2: TileOffsets=[1404]   → 공개 레벨 (≠0)
   └── parseScogBlock(scog_block_offset) → 암호화 엔트리 2개

2. decryptLevel(levelId)
   ├── 공개 레벨: IFD TileOffsets 직접 사용 (CEK 불필요)
   └── 암호화 레벨: CEK로 SCOG 엔트리 복호화 → offsets, bytecounts

3. fetchTile(level, col, row)
   └── fetch(offset, bytecount)        ← 타일 1개당 1회 요청
```

### 요청 수 비교

```
COG  (L0, 9타일):  1 (헤더) + 9 (타일) = 10회
SCOG (L0, 9타일):  1 (16KB) + 9 (타일) = 10회  ← 동일!
```

---

## 주요 소스 모듈

### `scog_structs.py`

TIFF 파서와 SCOG 블록 처리:

- `parse_tiff(data)` — TIFF 파일 파싱 (IFD 체인, BigTIFF 지원)
- `parse_ifd(data, offset, endian, bigtiff)` — 개별 IFD 파싱
- `encrypt_level(offsets, bytecounts, cek, file_id, level_id)` — AES-256-GCM 암호화 (v1~v3)
- `decrypt_level(entry, cek, file_id, level_id)` — 복호화 (v1~v3)
- `encrypt_tile_partial(tile_data, cek, file_id, level_id, tile_index)` — v4 타일 암호화
- `decrypt_tile_partial(enc_tile, cek, file_id, level_id, tile_index)` — v4 타일 복호화
- `serialize_scog_block(entries)` — SCOG 블록 직렬화
- `parse_scog_block(data)` — SCOG 블록 역직렬화
- `zero_tile_offsets(data, tiff, skip)` — TileOffsets/ByteCounts 제로화
- `build_public_main_ifd(...)` — v2/v3 공개 메인 IFD 생성
- `redirect_tiff_first_ifd(data, tiff, offset)` — TIFF 헤더 IFD 포인터 변경
- `write_ifd_tag_values(data, tiff, ifd_idx, tag, values)` — v3 IFD 값 in-place 수정

### `cog_to_scog.py`

COG → SCOG 변환:

```bash
python3 src/cog_to_scog.py <input.tif> <output.scog> [options]

Options:
  --format {v1,v2,v3,v4}  출력 포맷 (기본: v1)
  --public-level N        N 이상 레벨을 공개 (v2/v3)
  --encrypt-size N        v4 전용: 타일당 암호화할 바이트 수 (기본: 1024)
  --keys DIR              CEK 저장소 출력 디렉토리 (기본: keys/)
```

### `cred_issuer.py`

CEK 저장소에서 자격증명 발급:

```bash
python3 src/cred_issuer.py <ceks.json> --levels L1 L2 ... --out <cred.json>

Options:
  --levels N [N ...]      접근 허용할 암호화 레벨 번호
  --public-level N        v2 전용: public_level 값 덮어쓰기
  --out PATH              출력 자격증명 파일 경로
```

### `scog_reader.py`

SCOG 타일 읽기 (로컬/HTTP):

```bash
python3 src/scog_reader.py <source> <cred.json> --level N --tile COL ROW

source:  로컬 파일 경로 또는 http(s):// URL
Options:
  --level N               오버뷰 레벨 번호
  --tile COL ROW          타일 좌표
  --out PATH              타일 데이터 저장 경로
  -v                      상세 출력
```

---

## React 데모 앱

5개 탭으로 구성:

| 탭         | 설명                                            |
| ---------- | ----------------------------------------------- |
| SCOG v1    | 기본 접근 제어 데모 (admin/user/guest 전환)     |
| SCOG v2    | QGIS 호환 포맷 데모 (공개 레벨 포함)            |
| SCOG v3    | 1-Request 메타데이터 데모                       |
| SCOG v4    | 타일 암호화 데모 (타일별 복호화 성능 패널 포함) |
| Zoom-Aware | 줌 레벨에 따른 자동 오버뷰 전환                 |

각 탭에서:

- 자격증명 티어 선택 (Admin / User / Guest)
- OpenLayers 지도 위에 SCOG 이미지 오버레이
- HTTP Range Request 로그 실시간 표시
- COG vs SCOG 비교 로딩

---

## nginx 설정

`docker/docker-compose.yml`로 실행:

```bash
cd docker && docker compose up -d
```

필수 CORS 헤더:

```
Access-Control-Expose-Headers: Content-Range, Content-Length, Accept-Ranges
```

v2 클라이언트는 `bytes=-8` suffix range 요청 시 `Content-Range` 헤더에서 파일 크기를 추출하므로, 이 헤더가 없으면 동작하지 않음.

---

## 라이선스

PoC / 발표 자료 용도.
