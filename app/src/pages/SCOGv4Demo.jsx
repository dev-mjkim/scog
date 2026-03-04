import { useEffect, useRef, useState, useCallback } from 'react';
import Map        from 'ol/Map.js';
import View       from 'ol/View.js';
import TileLayer  from 'ol/layer/Tile.js';
import OSM        from 'ol/source/OSM.js';
import ImageLayer from 'ol/layer/Image.js';
import ImageStatic from 'ol/source/ImageStatic.js';
import { fromLonLat } from 'ol/proj.js';

import { SCOGClient, formatBytes } from '../lib/scog-client.js';
import { COGClient } from '../lib/cog-client.js';
import { CREDENTIALS_V4, SCOG_V4_URL, COG_URL, EXTENT } from '../credentials.js';

// ─── 티어 정의 ───────────────────────────────────────────────────────────────
const TIER_META = {
  admin: { icon: '👑', name: 'Admin', label: 'L0+L1+L2 복호화 (전해상도)',           encLevels: [0, 1, 2] },
  user:  { icon: '👤', name: 'User',  label: 'L1+L2 복호화 (저해상도)',               encLevels: [1, 2] },
  guest: { icon: '🌐', name: 'Guest', label: 'L2만 복호화 (최저해상도)',              encLevels: [2] },
};

// ─── SCOGv4Demo 컴포넌트 ─────────────────────────────────────────────────────

export default function SCOGv4Demo() {
  const mapRef   = useRef(null);
  const mapInst  = useRef(null);
  const layerRef = useRef(null);

  const [tier,    setTier]    = useState('admin');
  const [loading, setLoading] = useState(false);
  const [status,  setStatus]  = useState({ msg: '준비 완료 — 자격증명을 선택하고 Load를 눌러주세요', type: '' });
  const [levelSt, setLevelSt] = useState({ 0: '—', 1: '—', 2: '—' });
  const [levelTypes, setLevelTypes] = useState({ 0: '', 1: '', 2: '' });
  const [reqLog,  setReqLog]  = useState([]);
  const [stats,   setStats]   = useState({ requests: 0, bytesTotal: 0, timeMs: 0 });
  const [legend,  setLegend]  = useState({ active: '대기 중', blocked: '—' });
  const [decryptTimes, setDecryptTimes] = useState([]);

  // ── 지도 초기화 ─────────────────────────────────────────────────────────────
  useEffect(() => {
    mapInst.current = new Map({
      target: mapRef.current,
      layers: [new TileLayer({ source: new OSM() })],
      view: new View({
        center: fromLonLat([126.7023, 37.6047]),
        zoom: 14,
        projection: 'EPSG:3857',
      }),
    });
    return () => mapInst.current.setTarget(null);
  }, []);

  // ── 레이어 교체 헬퍼 ─────────────────────────────────────────────────────────
  const swapLayer = useCallback((blobUrl) => {
    if (layerRef.current) mapInst.current.removeLayer(layerRef.current);
    const layer = new ImageLayer({
      source: new ImageStatic({
        url:         blobUrl,
        imageExtent: EXTENT,
        projection:  'EPSG:3857',
      }),
      opacity: 0.9,
    });
    mapInst.current.addLayer(layer);
    layerRef.current = layer;
  }, []);

  // ── 티어 선택 ────────────────────────────────────────────────────────────────
  const selectTier = useCallback((t) => {
    if (loading) return;
    setTier(t);
    if (layerRef.current) {
      mapInst.current.removeLayer(layerRef.current);
      layerRef.current = null;
    }
    setLevelSt({ 0: '—', 1: '—', 2: '—' });
    setLevelTypes({ 0: '', 1: '', 2: '' });
    setReqLog([]);
    setStats({ requests: 0, bytesTotal: 0, timeMs: 0 });
    setLegend({ active: '대기 중', blocked: '—' });
    setDecryptTimes([]);
    setStatus({ msg: '준비 완료 — Load 버튼을 눌러주세요', type: '' });
  }, [loading]);

  // ── SCOG v4 로드 ─────────────────────────────────────────────────────────────
  const loadSCOGv4 = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setReqLog([]);
    setStats({ requests: 0, bytesTotal: 0, timeMs: 0 });
    setLevelSt({ 0: '—', 1: '—', 2: '—' });
    setLevelTypes({ 0: '', 1: '', 2: '' });
    setDecryptTimes([]);
    if (layerRef.current) { mapInst.current.removeLayer(layerRef.current); layerRef.current = null; }

    const cred   = CREDENTIALS_V4[tier];
    const client = new SCOGClient(SCOG_V4_URL, cred, {
      onRequest: (info) => {
        setReqLog(prev => [...prev, info]);
        setStats({ ...client.stats });
      },
    });

    // v4: 16KB 1회 요청으로 IFD 파싱
    await client.loadScogBlock();

    const levels      = client.availableLevels();
    const allLevels   = [0, 1, 2];
    const blockedLvls = allLevels.filter(l => !levels.includes(l));

    try {
      const renderLevel = Math.min(...levels);
      const meta        = client.levelMeta(renderLevel);

      setStatus({ msg: `레벨 ${renderLevel} 타일 복호화 중...`, type: 'loading' });
      setLevelSt(prev => ({ ...prev, [renderLevel]: '복호화 중...' }));
      setLevelTypes(prev => ({ ...prev, [renderLevel]: 'loading' }));

      // 타일 렌더링
      const tilesX = Math.ceil(meta.image_width  / meta.tile_width);
      const tilesY = Math.ceil(meta.image_height / meta.tile_height);
      const total  = tilesX * tilesY;
      let done = 0;
      const tileDecryptMs = [];

      const canvas = new OffscreenCanvas(meta.image_width, meta.image_height);
      const ctx    = canvas.getContext('2d');

      for (let row = 0; row < tilesY; row++) {
        for (let col = 0; col < tilesX; col++) {
          const imgData = await client.readTileAsImage(renderLevel, col, row);
          const info = client.lastTileDecrypt;
          if (info) {
            tileDecryptMs.push({
              level: info.levelId, col: info.col, row: info.row,
              tileIndex: info.tileIndex,
              encBytes: info.encBytes, decBytes: info.decBytes,
              decryptMs: info.decryptMs,
            });
          }
          ctx.putImageData(imgData, col * meta.tile_width, row * meta.tile_height);
          done++;
          setStatus({ msg: `타일 복호화+렌더링 중 (${done} / ${total})...`, type: 'loading' });
          setStats({ ...client.stats });
        }
      }

      setDecryptTimes(tileDecryptMs);
      setLevelSt(prev => ({ ...prev, [renderLevel]: `복호화 완료 (${total}타일)` }));
      setLevelTypes(prev => ({ ...prev, [renderLevel]: 'ok' }));

      // 접근 가능한 다른 레벨 표시
      for (const lv of levels) {
        if (lv !== renderLevel) {
          setLevelSt(prev => ({ ...prev, [lv]: '🔐 접근 가능' }));
          setLevelTypes(prev => ({ ...prev, [lv]: 'ok' }));
        }
      }

      const blob   = await canvas.convertToBlob({ type: 'image/png' });
      const objUrl = URL.createObjectURL(blob);
      swapLayer(objUrl);

      // 차단된 레벨 시도
      for (const lid of blockedLvls) {
        try {
          await client.decryptLevel(lid);
        } catch (e) {
          if (e.name === 'SCOGPermissionError') {
            setLevelSt(prev => ({ ...prev, [lid]: '🚫 PermissionError' }));
            setLevelTypes(prev => ({ ...prev, [lid]: 'blocked' }));
          }
        }
      }

      const tierName   = `${TIER_META[tier].icon} ${TIER_META[tier].name}`;
      const blockedStr = blockedLvls.length ? `L${blockedLvls.join(', L')}` : '없음';
      const avgDecUs   = tileDecryptMs.length
        ? (tileDecryptMs.reduce((s, t) => s + t.decryptMs, 0) / tileDecryptMs.length * 1000).toFixed(1)
        : '—';
      setLegend({
        active:  `${tierName} — L${renderLevel} (${meta.image_width}×${meta.image_height})`,
        blocked: blockedStr,
      });
      setStats({ ...client.stats });
      setStatus({
        msg: `완료 ✓  L${renderLevel} · ${client.stats.requests}개 요청 · ` +
             `${formatBytes(client.stats.bytesTotal)} · ${client.stats.timeMs.toFixed(0)}ms · ` +
             `AES-GCM 복호화 평균 ${avgDecUs}μs/타일`,
        type: 'done',
      });

    } catch (e) {
      console.error(e);
      setStatus({ msg: `오류: ${e.message}`, type: 'error' });
    }

    setLoading(false);
  }, [loading, tier, swapLayer]);

  // ── COG 로드 ─────────────────────────────────────────────────────────────────
  const loadCOG = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setReqLog([]);
    setStats({ requests: 0, bytesTotal: 0, timeMs: 0 });
    setLevelSt({ 0: '—', 1: '—', 2: '—' });
    setLevelTypes({ 0: '', 1: '', 2: '' });
    setDecryptTimes([]);
    if (layerRef.current) { mapInst.current.removeLayer(layerRef.current); layerRef.current = null; }

    const client = new COGClient(COG_URL, {
      onRequest: (info) => {
        setReqLog(prev => [...prev, info]);
        setStats({ ...client.stats });
      },
    });

    try {
      setStatus({ msg: 'COG 헤더 로드 중...', type: 'loading' });
      await client.loadHeader();

      const ifdIdx = 0;
      const meta   = client.levelMeta(ifdIdx);
      const tilesX = Math.ceil(meta.image_width  / meta.tile_width);
      const tilesY = Math.ceil(meta.image_height / meta.tile_height);
      const total  = tilesX * tilesY;
      let done = 0;

      setStatus({ msg: `COG 타일 읽는 중 (0 / ${total})...`, type: 'loading' });
      setLevelSt(prev => ({ ...prev, 0: '읽는 중...' }));
      setLevelTypes(prev => ({ ...prev, 0: 'loading' }));

      const canvas = new OffscreenCanvas(meta.image_width, meta.image_height);
      const ctx    = canvas.getContext('2d');

      for (let row = 0; row < tilesY; row++) {
        for (let col = 0; col < tilesX; col++) {
          const imgData = await client.readTileAsImage(ifdIdx, col, row);
          ctx.putImageData(imgData, col * meta.tile_width, row * meta.tile_height);
          done++;
          setStatus({ msg: `COG 타일 읽는 중 (${done} / ${total})...`, type: 'loading' });
          setStats({ ...client.stats });
        }
      }

      setLevelSt(prev => ({ ...prev, 0: '완료' }));
      setLevelTypes(prev => ({ ...prev, 0: 'ok' }));

      const blob   = await canvas.convertToBlob({ type: 'image/png' });
      const objUrl = URL.createObjectURL(blob);
      swapLayer(objUrl);

      setStats({ ...client.stats });
      setLegend({
        active:  `🗺️ COG — L0 (${meta.image_width}×${meta.image_height})`,
        blocked: '없음 (접근 제어 없음)',
      });
      setStatus({
        msg: `COG 완료 ✓  L0 렌더링 · ${client.stats.requests}개 요청 · ` +
             `${formatBytes(client.stats.bytesTotal)} · ${client.stats.timeMs.toFixed(0)}ms`,
        type: 'done',
      });

    } catch (e) {
      console.error(e);
      setStatus({ msg: `COG 오류: ${e.message}`, type: 'error' });
    }

    setLoading(false);
  }, [loading, swapLayer]);

  // ── 렌더 ─────────────────────────────────────────────────────────────────────
  const tierEncLevels = TIER_META[tier].encLevels;

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>

      {/* 상태 바 */}
      <div className={`status-bar ${status.type}`}>{status.msg}</div>

      {/* 메인 */}
      <div className="main">

        {/* 사이드 패널 */}
        <div className="sidebar">

          {/* 포맷 설명 */}
          <div className="panel" style={{ background: '#1a2035', borderColor: '#2d4a7a' }}>
            <div className="panel-title" style={{ color: '#f6ad55' }}>🔒 SCOG v4 (부분 타일 암호화)</div>
            <div style={{ fontSize: '11px', color: '#718096', lineHeight: 1.6 }}>
              파일 구조: <code style={{ color: '#f6ad55' }}>[TIFF Header][IFDs][암호화된 타일 데이터...]</code><br/>
              • 각 타일 앞 <strong style={{ color: '#f6ad55' }}>1KB AES-256-GCM 암호화</strong><br/>
              • DEFLATE 스트림 시작 파괴 → 전체 복원 불가<br/>
              • 오버헤드: 타일당 <strong style={{ color: '#f6ad55' }}>28B</strong> (IV 12B + tag 16B)<br/>
              • SCOG 블록 없음 — IFD 구조 유지 (유효한 TIFF)
            </div>
          </div>

          {/* 자격증명 선택 */}
          <div className="panel">
            <div className="panel-title">🔑 자격증명 티어 선택</div>
            <div className="tier-grid">
              {Object.entries(TIER_META).map(([t, m]) => (
                <button
                  key={t}
                  className={`tier-btn ${tier === t ? 'active' : ''}`}
                  onClick={() => selectTier(t)}
                >
                  <span className="tier-icon">{m.icon}</span>
                  <span className="tier-name">{m.name}</span>
                  <span className="tier-levels">{m.label}</span>
                </button>
              ))}
            </div>
            <button className="load-btn scog" onClick={loadSCOGv4} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load SCOG v4 Image'}
            </button>
            <button className="load-btn cog" onClick={loadCOG} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load COG Image (비교)'}
            </button>
          </div>

          {/* 레벨 접근 상태 */}
          <div className="panel">
            <div className="panel-title">📊 레벨 접근 상태</div>
            {[
              { id: 0, title: 'Full Resolution', sub: '1305×1107 · 9 타일 · 🔐 타일 암호화' },
              { id: 1, title: 'Overview × ½',    sub: '652×553 · 4 타일 · 🔐 타일 암호화' },
              { id: 2, title: 'Overview × ¼',    sub: '326×276 · 1 타일 · 🔐 타일 암호화' },
            ].map(({ id, title, sub }) => {
              const isAccessible = tierEncLevels.includes(id);
              return (
                <div className="level-row" key={id}>
                  <span className={`level-badge ${isAccessible ? 'accessible' : 'blocked'}`}>
                    L{id}
                  </span>
                  <div className="level-info">
                    <div>{title}</div>
                    <div className="level-res">{sub}</div>
                  </div>
                  <span className={`level-status ${levelTypes[id]}`}>
                    {levelSt[id]}
                  </span>
                </div>
              );
            })}
          </div>

          {/* 복호화 성능 */}
          {decryptTimes.length > 0 && (
            <div className="panel">
              <div className="panel-title">⚡ 타일별 AES-GCM 복호화</div>
              <div style={{ fontSize: '11px', color: '#a0aec0', lineHeight: 1.4 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '50px 90px 80px 70px', gap: '2px 6px', marginBottom: '6px', fontWeight: 600, color: '#718096', borderBottom: '1px solid #2d3748', paddingBottom: '4px' }}>
                  <span>#</span><span>타일</span><span>크기</span><span>복호화</span>
                </div>
                {decryptTimes.map((t, i) => (
                  <div key={i} style={{ display: 'grid', gridTemplateColumns: '50px 90px 80px 70px', gap: '2px 6px' }}>
                    <span style={{ color: '#718096' }}>tile {t.tileIndex}</span>
                    <span>L{t.level} ({t.col},{t.row})</span>
                    <span style={{ color: '#90cdf4' }}>{formatBytes(t.encBytes)}</span>
                    <strong style={{ color: '#68d391' }}>{(t.decryptMs * 1000).toFixed(1)}μs</strong>
                  </div>
                ))}
                <div style={{ borderTop: '1px solid #2d3748', marginTop: '4px', paddingTop: '4px', display: 'grid', gridTemplateColumns: '50px 90px 80px 70px', gap: '2px 6px', color: '#f6ad55' }}>
                  <span></span>
                  <span>평균</span>
                  <span>{formatBytes(Math.round(decryptTimes.reduce((s, t) => s + t.encBytes, 0) / decryptTimes.length))}</span>
                  <strong>
                    {(decryptTimes.reduce((s, t) => s + t.decryptMs, 0) / decryptTimes.length * 1000).toFixed(1)}μs
                  </strong>
                </div>
              </div>
            </div>
          )}

          {/* 통계 */}
          <div className="panel">
            <div className="panel-title">📈 Range Request 통계</div>
            <div className="stats-grid">
              <div className="stat-box">
                <div className="stat-num">{stats.requests}</div>
                <div className="stat-label">요청 수</div>
              </div>
              <div className="stat-box">
                <div className="stat-num">{formatBytes(stats.bytesTotal)}</div>
                <div className="stat-label">전송량</div>
              </div>
              <div className="stat-box">
                <div className="stat-num">{stats.timeMs.toFixed(0)}ms</div>
                <div className="stat-label">총 시간</div>
              </div>
            </div>
          </div>

          {/* HTTP 요청 로그 */}
          <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div className="panel-title">🌐 HTTP Range Requests</div>
            <div className="req-log">
              {reqLog.length === 0
                ? <div style={{ color: '#4a5568', fontSize: '12px', padding: '8px 10px' }}>(아직 요청 없음)</div>
                : reqLog.map((info, i) => (
                    <div className="req-item" key={i}>
                      <span className="req-label">{info.label}</span><br />
                      <span className="req-range">bytes={info.start.toLocaleString()}-{(info.start + info.length - 1).toLocaleString()}</span>
                      <span className="req-size"> · {formatBytes(info.length)}</span>
                      <span className="req-ms"> · {info.ms}ms</span>
                    </div>
                  ))
              }
            </div>
          </div>

        </div>

        {/* 지도 */}
        <div className="map-wrapper">
          <div ref={mapRef} style={{ width: '100%', height: '100%' }} />

          <div className="map-legend">
            <div className="legend-title">표시 레이어</div>
            <div className="legend-row">
              <div className="legend-dot green" />
              <span>{legend.active}</span>
            </div>
            <div className="legend-row">
              <div className="legend-dot red" />
              <span>차단: {legend.blocked}</span>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
