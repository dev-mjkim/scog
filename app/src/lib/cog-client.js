/**
 * cog-client.js — COG TIFF 파서 + COGClient (ES Module)
 */
import { tileToImageData } from './scog-client.js';

// ─── TIFF IFD 파서 ───────────────────────────────────────────────────────────

export function parseTiffIfds(buf, ifdAbsStart, le) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16  = o => view.getUint16(o, le);
  const u32  = o => view.getUint32(o, le);

  const readVals = (type, absOff, cnt) => {
    const relOff = absOff - ifdAbsStart;
    const sz     = { 3: 2, 4: 4 }[type] || 1;
    const vals   = [];
    for (let i = 0; i < cnt; i++) {
      const o = relOff + i * sz;
      if (o < 0 || o + sz > buf.length) break;
      vals.push(type === 3 ? u16(o) : type === 4 ? u32(o) : view.getUint8(o));
    }
    return vals;
  };

  const ifds = [];
  let curr = ifdAbsStart;

  while (curr) {
    const rel = curr - ifdAbsStart;
    if (rel + 2 > buf.length) break;
    const ec  = u16(rel);
    const raw = {};

    for (let i = 0; i < ec; i++) {
      const e    = rel + 2 + i * 12;
      const tag  = u16(e);
      const type = u16(e + 2);
      const cnt  = u32(e + 4);
      const sz   = { 1:1, 2:1, 3:2, 4:4, 5:8 }[type] || 1;
      const valAbsOff = sz * cnt <= 4 ? (ifdAbsStart + e + 8) : u32(e + 8);
      raw[tag] = readVals(type, valAbsOff, cnt);
    }

    ifds.push({
      imageWidth:     raw[256]?.[0] ?? 0,
      imageHeight:    raw[257]?.[0] ?? 0,
      tileWidth:      raw[322]?.[0] ?? 256,
      tileHeight:     raw[323]?.[0] ?? 256,
      tileOffsets:    raw[324]  ?? [],
      tileByteCounts: raw[325]  ?? [],
    });

    curr = u32(rel + 2 + ec * 12);
  }
  return ifds;
}

// ─── COG 클라이언트 ──────────────────────────────────────────────────────────

export class COGClient {
  constructor(url, { onRequest } = {}) {
    this.url       = url;
    this.onRequest = onRequest || null;
    this._ifds     = null;
    this.stats     = { requests: 0, bytesTotal: 0, timeMs: 0 };
  }

  async loadHeader() {
    if (this._ifds) return;

    const hdr  = await this._fetch(0, 8, 'COG 헤더');
    const le   = hdr[0] === 0x49;
    const hv   = new DataView(hdr.buffer, hdr.byteOffset, hdr.byteLength);
    const ifdOffset = hv.getUint32(4, le);

    const ifdBuf = await this._fetch(ifdOffset, 8192, 'COG IFD 영역');
    this._ifds   = parseTiffIfds(ifdBuf, ifdOffset, le);
  }

  // 레벨별 자연 해상도 반환 (extent 폭 / 이미지 폭)
  levelResolutions(extentWidth) {
    return Object.fromEntries(
      this._ifds.map((ifd, i) => [i, extentWidth / ifd.imageWidth])
    );
  }

  levelMeta(ifdIndex) {
    const ifd = this._ifds?.[ifdIndex];
    if (!ifd) return null;
    return {
      image_width:  ifd.imageWidth,
      image_height: ifd.imageHeight,
      tile_width:   ifd.tileWidth,
      tile_height:  ifd.tileHeight,
    };
  }

  async readTileAsImage(ifdIndex, col, row) {
    const ifd    = this._ifds[ifdIndex];
    const tilesX = Math.ceil(ifd.imageWidth / ifd.tileWidth);
    const idx    = row * tilesX + col;
    const bytes  = await this._fetch(
      ifd.tileOffsets[idx], ifd.tileByteCounts[idx],
      `COG L${ifdIndex} 타일(${col},${row})`
    );
    return tileToImageData(bytes, ifd.tileWidth, ifd.tileHeight);
  }

  async renderLevel(ifdIndex) {
    const ifd    = this._ifds[ifdIndex];
    const tilesX = Math.ceil(ifd.imageWidth  / ifd.tileWidth);
    const tilesY = Math.ceil(ifd.imageHeight / ifd.tileHeight);
    const canvas = new OffscreenCanvas(ifd.imageWidth, ifd.imageHeight);
    const ctx    = canvas.getContext('2d');

    for (let row = 0; row < tilesY; row++) {
      for (let col = 0; col < tilesX; col++) {
        const imgData = await this.readTileAsImage(ifdIndex, col, row);
        ctx.putImageData(imgData, col * ifd.tileWidth, row * ifd.tileHeight);
      }
    }
    return canvas;
  }

  async _fetch(start, length, label = '') {
    const end  = start + length - 1;
    const t0   = performance.now();
    const resp = await fetch(this.url, { headers: { Range: `bytes=${start}-${end}` } });
    const ms   = performance.now() - t0;

    if (resp.status !== 200 && resp.status !== 206)
      throw new Error(`HTTP ${resp.status}`);

    const data = new Uint8Array(await resp.arrayBuffer());
    this.stats.requests++;
    this.stats.bytesTotal += data.length;
    this.stats.timeMs     += ms;

    if (this.onRequest) this.onRequest({ label, start, length: data.length, ms: ms.toFixed(1) });
    return data;
  }
}
