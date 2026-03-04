/**
 * scog-client.js — SCOG 파일 클라이언트 라이브러리 (ES Module)
 *
 * demo/scog-client.js와 동일한 로직, named export 추가
 */

// ─── SCOG 블록 파서 ──────────────────────────────────────────────────────────

export function parseScogBlock(data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  const magic = String.fromCharCode(data[0], data[1], data[2], data[3]);
  if (magic !== 'SCOG') throw new Error(`SCOG 매직 오류: "${magic}"`);

  const version    = view.getUint16(4, false);
  const levelCount = view.getUint16(6, false);

  let pos = 16;
  const entries = {};

  for (let i = 0; i < levelCount; i++) {
    const levelId = view.getUint16(pos,     false);
    const ctLen   = view.getUint32(pos + 4, false);
    const iv      = data.slice(pos + 8,  pos + 20);
    const cipher  = data.slice(pos + 20, pos + 20 + ctLen);
    entries[levelId] = { iv, ciphertext: cipher };
    pos += 2 + 2 + 4 + 12 + ctLen;
  }

  return { version, levelCount, entries };
}

// ─── AES-256-GCM 복호화 ──────────────────────────────────────────────────────

export async function decryptLevelEntry(entry, cekBytes, fileId, levelId) {
  const key = await crypto.subtle.importKey(
    'raw', cekBytes, { name: 'AES-GCM' }, false, ['decrypt']
  );

  const fileIdBytes = new TextEncoder().encode(fileId);
  const levelIdBuf  = new Uint8Array(2);
  new DataView(levelIdBuf.buffer).setUint16(0, levelId, false);
  const aad = new Uint8Array(fileIdBytes.length + 2);
  aad.set(fileIdBytes, 0);
  aad.set(levelIdBuf, fileIdBytes.length);

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: entry.iv, additionalData: aad, tagLength: 128 },
      key,
      entry.ciphertext
    );
  } catch (e) {
    throw new SCOGDecryptError(levelId, e.message);
  }

  const pv        = new DataView(plaintext);
  const tileCount = pv.getUint32(0, false);
  const offsets   = [];
  const bytecounts = [];

  for (let i = 0; i < tileCount; i++) {
    offsets.push(pv.getBigUint64(4 + i * 8, false));
  }
  for (let i = 0; i < tileCount; i++) {
    bytecounts.push(Number(pv.getBigUint64(4 + tileCount * 8 + i * 8, false)));
  }

  return { offsets, bytecounts };
}

// ─── 타일 디코더 ─────────────────────────────────────────────────────────────

export async function decompressZlib(compressed) {
  const ds     = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  writer.write(compressed);
  writer.close();

  const chunks = [];
  const reader = ds.readable.getReader();
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    chunks.push(value);
  }

  const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
  const result   = new Uint8Array(totalLen);
  let off = 0;
  for (const chunk of chunks) { result.set(chunk, off); off += chunk.length; }
  return result;
}

export async function tileToImageData(tileBytes, tileWidth, tileHeight) {
  const rgb  = await decompressZlib(tileBytes);
  const rgba = new Uint8ClampedArray(tileWidth * tileHeight * 4);

  for (let i = 0; i < tileWidth * tileHeight; i++) {
    rgba[i * 4 + 0] = rgb[i * 3 + 0];
    rgba[i * 4 + 1] = rgb[i * 3 + 1];
    rgba[i * 4 + 2] = rgb[i * 3 + 2];
    rgba[i * 4 + 3] = 255;
  }

  return new ImageData(rgba, tileWidth, tileHeight);
}

// ─── SCOG v2: 공개 레벨 TIFF IFD 파서 ──────────────────────────────────────

function parseTiffPublicLevel(buf, publicLevelIndex) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const le   = buf[0] === 0x49; // 'I' = little-endian
  const u16  = o => view.getUint16(o, le);
  const u32  = o => view.getUint32(o, le);

  // Walk IFD chain to reach publicLevelIndex
  let curr = u32(4);
  for (let ifdIdx = 0; ifdIdx < publicLevelIndex; ifdIdx++) {
    const ec = u16(curr);
    curr = u32(curr + 2 + ec * 12);
    if (!curr) return null;
  }

  // Read entries of target IFD
  const ec         = u16(curr);
  const offsets    = [];
  const bytecounts = [];

  for (let i = 0; i < ec; i++) {
    const e    = curr + 2 + i * 12;
    const tag  = u16(e);
    if (tag !== 324 && tag !== 325) continue;

    const type    = u16(e + 2);
    const cnt     = u32(e + 4);
    const sz      = type === 3 ? 2 : 4;
    const totalSz = sz * cnt;
    const vals    = [];

    if (totalSz <= 4) {
      for (let j = 0; j < cnt; j++) {
        vals.push(type === 3 ? u16(e + 8 + j * 2) : u32(e + 8 + j * 4));
      }
    } else {
      const dataOff = u32(e + 8);
      for (let j = 0; j < cnt; j++) {
        vals.push(type === 3 ? u16(dataOff + j * 2) : u32(dataOff + j * 4));
      }
    }

    if (tag === 324) offsets.push(...vals);
    else             bytecounts.push(...vals);
  }

  // Return offsets as BigInt to match decryptLevelEntry output format
  return { offsets: offsets.map(BigInt), bytecounts };
}

// ─── SCOG v3: 원본 IFD 체인 파서 ──────────────────────────────────────────

function parseTiffIFDs(buf, firstIfdOffset) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const le   = buf[0] === 0x49; // 'I' = little-endian
  const u16  = o => view.getUint16(o, le);
  const u32  = o => view.getUint32(o, le);

  const ifds = [];
  let curr = firstIfdOffset;

  while (curr && curr < buf.length) {
    const ec = u16(curr);
    const entries = {};

    for (let i = 0; i < ec; i++) {
      const e   = curr + 2 + i * 12;
      const tag = u16(e);
      if (![256, 257, 322, 323, 324, 325].includes(tag)) continue;

      const type    = u16(e + 2);
      const cnt     = u32(e + 4);
      const sz      = type === 3 ? 2 : 4;
      const totalSz = sz * cnt;
      const vals    = [];
      const readVal = (off) => type === 3 ? u16(off) : u32(off);

      if (totalSz <= 4) {
        for (let j = 0; j < cnt; j++) vals.push(readVal(e + 8 + j * sz));
      } else {
        const dataOff = u32(e + 8);
        for (let j = 0; j < cnt; j++) vals.push(readVal(dataOff + j * sz));
      }

      entries[tag] = vals;
    }

    ifds.push(entries);
    curr = u32(curr + 2 + ec * 12);
  }

  return ifds;
}


// ─── SCOG 클라이언트 ─────────────────────────────────────────────────────────

export class SCOGClient {
  constructor(url, credential, { onRequest } = {}) {
    this.url        = url;
    this.cred       = credential;
    this.onRequest  = onRequest || null;
    this._scogBlock = null;
    this._offsets   = {};
    this._fileSize  = null;
    this._v3Ifds    = null;
    this._v4Ifds    = null;
    this.stats          = { requests: 0, bytesTotal: 0, timeMs: 0 };
    this.lastTileDecrypt = null;
    this.v4DecryptLog    = [];    // v4: 타일별 복호화 로그 누적
    this._v4Keys         = {};   // v4: levelId → CryptoKey 캐시
    this._v4FileIdBytes  = null; // v4: file_id UTF-8 캐시
  }

  _isV4() {
    return this.cred.format === 'v4';
  }

  _isV3() {
    return 'scog_block_offset' in this.cred && !this._isV4();
  }

  _isV2() {
    return 'public_level' in this.cred && !this._isV3() && !this._isV4();
  }

  async loadScogBlock() {
    if (this._scogBlock) return;
    if (this._isV4()) {
      await this._loadV4();
      return;
    }
    if (this._isV3()) {
      await this._loadScogBlockV3();
    } else if (this._isV2()) {
      await this._loadScogBlockV2();
    } else {
      const n   = this.cred.scog_block_size;
      const raw = await this._fetch(0, n, 'SCOG 블록');
      this._scogBlock = parseScogBlock(raw);
    }
  }

  async _loadV4() {
    // v4: 16KB fetch → TIFF IFD 파싱 (SCOG 블록 없음)
    if (this._v4Ifds) return;
    const raw = await this._fetch(0, 16384, 'SCOG v4 TIFF 헤더 (16KB)');
    // IFD 체인 파싱 — 첫 IFD offset은 TIFF 헤더에서 읽기
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const le = raw[0] === 0x49;
    const firstIfd = le ? view.getUint32(4, true) : view.getUint32(4, false);
    this._v4Ifds = parseTiffIFDs(raw, firstIfd);
    this._scogBlock = { entries: {} };  // 빈 블록 (v4는 SCOG 블록 없음)
  }

  async _loadScogBlockV3() {
    // v3: 첫 16KB에 TIFF 헤더 + IFDs + SCOG 블록이 모두 포함
    const raw = await this._fetch(0, 16384, 'SCOG v3 헤더+블록 (16KB)');
    const offset = this.cred.scog_block_offset;
    this._scogBlock = parseScogBlock(raw.slice(offset));
    // 원본 IFD 체인 파싱 (공개 레벨 발견 + 메타데이터)
    this._v3Ifds = parseTiffIFDs(raw, this.cred.first_ifd_offset);
  }

  async _loadScogBlockV2() {
    // 파일 끝 8바이트 읽어 SCOG 블록 크기 + 파일 크기 파악
    const t0         = performance.now();
    const footerResp = await fetch(this.url, { headers: { Range: 'bytes=-8' } });
    const ms         = performance.now() - t0;

    if (footerResp.status !== 206 && footerResp.status !== 200)
      throw new Error(`SCOG v2 footer 읽기 실패: HTTP ${footerResp.status}`);

    const cr = footerResp.headers.get('Content-Range');
    if (!cr) throw new Error('Content-Range 헤더 없음. nginx CORS 설정 확인 필요.');
    this._fileSize = parseInt(cr.split('/')[1]);

    const footerBuf = new Uint8Array(await footerResp.arrayBuffer());
    const fv        = new DataView(footerBuf.buffer);
    const scogSize  = fv.getUint32(0, false) * 0x100000000 + fv.getUint32(4, false);

    this.stats.requests++;
    this.stats.bytesTotal += 8;
    this.stats.timeMs     += ms;
    if (this.onRequest) {
      this.onRequest({ label: 'SCOG v2 푸터', start: this._fileSize - 8, length: 8, ms: ms.toFixed(1) });
    }

    const blockStart = this._fileSize - 8 - scogSize;
    const raw        = await this._fetch(blockStart, scogSize, 'SCOG v2 블록');
    this._scogBlock  = parseScogBlock(raw);
  }

  async decryptLevel(levelId) {
    if (this._offsets[levelId]) return this._offsets[levelId];

    // v4: IFD에서 TileOffsets/TileByteCounts 직접 사용
    if (this._isV4()) {
      await this.loadScogBlock();
      if (!this.cred.levels[String(levelId)]) {
        throw new SCOGPermissionError(levelId, Object.keys(this.cred.levels).map(Number));
      }
      const ifd = this._v4Ifds?.[levelId];
      if (!ifd) throw new Error(`IFD ${levelId} 없음`);
      const result = {
        offsets:    (ifd[324] || []).map(BigInt),
        bytecounts: ifd[325] || new Array((ifd[324] || []).length).fill(0),
      };
      this._offsets[levelId] = result;
      return result;
    }

    // v3: IFD에서 공개/암호화 판단 (public_level 불필요)
    if (this._isV3()) {
      await this.loadScogBlock();
      const ifd = this._v3Ifds?.[levelId];
      if (ifd) {
        const offsets = ifd[324]; // TileOffsets
        if (offsets && offsets.some(v => v !== 0)) {
          // 공개 레벨: TileOffsets ≠ 0
          const result = {
            offsets:    offsets.map(BigInt),
            bytecounts: ifd[325] || new Array(offsets.length).fill(0),
          };
          this._offsets[levelId] = result;
          return result;
        }
      }
      // 암호화 레벨
      if (!this.cred.levels[String(levelId)]) {
        throw new SCOGPermissionError(levelId, Object.keys(this.cred.levels).map(Number));
      }
      const cekHex = this.cred.levels[String(levelId)];
      const cek    = hexToBytes(cekHex);
      const entry  = this._scogBlock.entries[levelId];
      if (!entry) throw new Error(`SCOG 블록에 레벨 ${levelId} 없음`);
      const result = await decryptLevelEntry(entry, cek, this.cred.file_id, levelId);
      this._offsets[levelId] = result;
      return result;
    }

    // v2 공개 레벨: levelId >= public_level
    if (this._isV2() && levelId >= this.cred.public_level) {
      const result = await this._readPublicLevelOffsets(levelId);
      this._offsets[levelId] = result;
      return result;
    }

    // v1 / v2 암호화 레벨
    await this.loadScogBlock();

    if (!this.cred.levels[String(levelId)]) {
      throw new SCOGPermissionError(levelId, Object.keys(this.cred.levels).map(Number));
    }

    const cekHex = this.cred.levels[String(levelId)];
    const cek    = hexToBytes(cekHex);
    const entry  = this._scogBlock.entries[levelId];
    if (!entry) throw new Error(`SCOG 블록에 레벨 ${levelId} 없음`);

    const result = await decryptLevelEntry(entry, cek, this.cred.file_id, levelId);
    this._offsets[levelId] = result;
    return result;
  }

  async _readPublicLevelOffsets(levelId) {
    // 자격증명 level_meta에 tile_offsets가 있으면 직접 사용 (추가 HTTP 요청 불필요)
    const meta = this.cred.level_meta?.[String(levelId)];
    if (meta?.tile_offsets) {
      return {
        offsets:    meta.tile_offsets.map(BigInt),
        bytecounts: meta.tile_bytecounts ?? new Array(meta.tile_offsets.length).fill(0),
      };
    }
    // Fallback: TIFF IFD에서 파싱 (구형 자격증명 호환)
    const buf    = await this._fetch(0, 16384, 'TIFF 헤더 (공개 레벨)');
    const result = parseTiffPublicLevel(buf, levelId);
    if (!result) throw new Error(`공개 레벨 ${levelId} TIFF IFD 파싱 실패`);
    return result;
  }

  async fetchTile(levelId, col, row) {
    const { offsets, bytecounts } = await this.decryptLevel(levelId);
    const meta   = this.levelMeta(levelId);
    const tilesX = Math.ceil(meta.image_width / meta.tile_width);
    const idx    = row * tilesX + col;

    const tiffOffset = Number(offsets[idx]);
    const bytecount  = bytecounts[idx];

    // v4/v2/v3: TIFF가 byte 0에서 시작 → fileOffset = tiffOffset
    // v1: [SCOG block][TIFF] → fileOffset = scog_block_size + tiffOffset
    const fileOffset = (this._isV4() || this._isV2() || this._isV3()) ? tiffOffset : (this.cred.scog_block_size + tiffOffset);

    const raw = await this._fetch(fileOffset, bytecount, `L${levelId} 타일(${col},${row})`);

    // v4: 타일 복호화
    if (this._isV4()) {
      const { decrypted, decryptMs } = await this._decryptTilePartial(raw, levelId, idx);
      const entry = { levelId, tileIndex: idx, col, row, encBytes: raw.length, decBytes: decrypted.length, decryptMs };
      this.lastTileDecrypt = entry;
      this.v4DecryptLog.push(entry);
      return decrypted;
    }
    this.lastTileDecrypt = null;
    return raw;
  }

  async _ensureV4Key(levelId) {
    if (!this._v4Keys[levelId]) {
      const cek = hexToBytes(this.cred.levels[String(levelId)]);
      this._v4Keys[levelId] = await crypto.subtle.importKey(
        'raw', cek, { name: 'AES-GCM' }, false, ['decrypt']
      );
    }
    if (!this._v4FileIdBytes) {
      this._v4FileIdBytes = new TextEncoder().encode(this.cred.file_id);
    }
  }

  async _decryptTilePartial(encTile, levelId, tileIndex) {
    // 키/fileId 사전 준비 (캐시됨 — 여기서 await 소비)
    await this._ensureV4Key(levelId);
    const key         = this._v4Keys[levelId];
    const fileIdBytes = this._v4FileIdBytes;

    const encryptSize = this.cred.encrypt_size || 1024;
    const iv     = encTile.slice(0, 12);
    const actual = Math.min(encryptSize, encTile.length - 28);
    const ct     = encTile.slice(12, 12 + actual + 16);
    const tail   = encTile.slice(12 + actual + 16);

    // AAD: file_id + level_id(2B BE) + tile_index(4B BE)
    const aadBuf = new Uint8Array(fileIdBytes.length + 6);
    aadBuf.set(fileIdBytes, 0);
    new DataView(aadBuf.buffer).setUint16(fileIdBytes.length, levelId, false);
    new DataView(aadBuf.buffer).setUint32(fileIdBytes.length + 2, tileIndex, false);

    // ── 순수 crypto.subtle.decrypt 시간만 측정 ──
    let head;
    const t0 = performance.now();
    try {
      const plainBuf = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aadBuf, tagLength: 128 },
        key, ct
      );
      head = new Uint8Array(plainBuf);
    } catch (e) {
      throw new SCOGDecryptError(levelId, e.message);
    }
    const decryptMs = performance.now() - t0;

    // head + tail 결합
    const result = new Uint8Array(head.length + tail.length);
    result.set(head, 0);
    result.set(tail, head.length);
    return { decrypted: result, decryptMs };
  }

  async readTileAsImage(levelId, col, row) {
    const meta  = this.levelMeta(levelId);
    const bytes = await this.fetchTile(levelId, col, row);
    return tileToImageData(bytes, meta.tile_width, meta.tile_height);
  }

  async readFullLevel(levelId) {
    const meta   = this.levelMeta(levelId);
    const tilesX = Math.ceil(meta.image_width  / meta.tile_width);
    const tilesY = Math.ceil(meta.image_height / meta.tile_height);

    const canvas = new OffscreenCanvas(meta.image_width, meta.image_height);
    const ctx    = canvas.getContext('2d');

    for (let row = 0; row < tilesY; row++) {
      for (let col = 0; col < tilesX; col++) {
        const imgData = await this.readTileAsImage(levelId, col, row);
        ctx.putImageData(imgData, col * meta.tile_width, row * meta.tile_height);
      }
    }
    return canvas;
  }

  availableLevels() {
    const levels = new Set(Object.keys(this.cred.levels).map(Number));
    if (this._isV4()) {
      // v4: 자격증명의 levels만 (모두 암호화)
      return [...levels].sort((a, b) => a - b);
    }
    if (this._isV3()) {
      // v3: IFD에서 공개 레벨 발견 (TileOffsets ≠ 0)
      if (this._v3Ifds) {
        this._v3Ifds.forEach((ifd, i) => {
          const offsets = ifd[324];
          if (offsets && offsets.some(v => v !== 0)) levels.add(i);
        });
      }
    } else if (this._isV2()) {
      const pub = this.cred.public_level;
      for (const k of Object.keys(this.cred.level_meta || {})) {
        if (Number(k) >= pub) levels.add(Number(k));
      }
    }
    return [...levels].sort((a, b) => a - b);
  }

  levelMeta(levelId) {
    if (this._isV4()) {
      const ifd = this._v4Ifds?.[levelId];
      if (!ifd) return null;
      return {
        image_width:  ifd[256]?.[0],
        image_height: ifd[257]?.[0],
        tile_width:   ifd[322]?.[0],
        tile_height:  ifd[323]?.[0],
        tile_count:   ifd[324]?.length || 0,
      };
    }
    if (this._isV3()) {
      const ifd = this._v3Ifds?.[levelId];
      if (!ifd) return null;
      return {
        image_width:  ifd[256]?.[0],
        image_height: ifd[257]?.[0],
        tile_width:   ifd[322]?.[0],
        tile_height:  ifd[323]?.[0],
        tile_count:   ifd[324]?.length || 0,
      };
    }
    return this.cred.level_meta[String(levelId)];
  }

  async _fetch(start, length, label = '') {
    const end  = start + length - 1;
    const t0   = performance.now();
    const resp = await fetch(this.url, { headers: { Range: `bytes=${start}-${end}` } });
    const t1   = performance.now();
    const ms   = t1 - t0;

    if (resp.status !== 200 && resp.status !== 206) {
      throw new Error(`HTTP ${resp.status}: Range=${start}-${end}`);
    }

    const data = new Uint8Array(await resp.arrayBuffer());
    this.stats.requests++;
    this.stats.bytesTotal += data.length;
    this.stats.timeMs     += ms;

    if (this.onRequest) {
      this.onRequest({ label, start, length: data.length, ms: ms.toFixed(1) });
    }
    return data;
  }
}

// ─── 에러 클래스 ─────────────────────────────────────────────────────────────

export class SCOGPermissionError extends Error {
  constructor(levelId, available) {
    super(`레벨 ${levelId} 접근 권한 없음. 보유: [${available.join(', ')}]`);
    this.name      = 'SCOGPermissionError';
    this.levelId   = levelId;
    this.available = available;
  }
}

export class SCOGDecryptError extends Error {
  constructor(levelId, reason) {
    super(`레벨 ${levelId} 복호화 실패: ${reason}`);
    this.name    = 'SCOGDecryptError';
    this.levelId = levelId;
  }
}

// ─── 유틸 ────────────────────────────────────────────────────────────────────

export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

export function formatBytes(n) {
  if (n < 1024)       return `${n} B`;
  if (n < 1024*1024)  return `${(n/1024).toFixed(1)} KB`;
  return `${(n/(1024*1024)).toFixed(2)} MB`;
}
