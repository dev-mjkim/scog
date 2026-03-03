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
import { CREDENTIALS, SCOG_URL, COG_URL, EXTENT } from '../credentials.js';

// ─── 레벨 접근 범위 ──────────────────────────────────────────────────────────
const TIER_LEVELS = {
  admin: [0, 1, 2],
  user:  [1, 2],
  guest: [2],
};

const TIER_META = {
  admin: { icon: '👑', name: 'Admin', label: '레벨 0·1·2' },
  user:  { icon: '👤', name: 'User',  label: '레벨 1·2' },
  guest: { icon: '🌐', name: 'Guest', label: '레벨 2만' },
};

// ─── SCOGDemo 컴포넌트 ───────────────────────────────────────────────────────

export default function SCOGDemo() {
  const mapRef  = useRef(null);   // DOM container
  const mapInst = useRef(null);   // OL Map instance
  const layerRef = useRef(null);  // current image layer

  const [tier,    setTier]    = useState('admin');
  const [loading, setLoading] = useState(false);
  const [status,  setStatus]  = useState({ msg: '준비 완료 — 자격증명을 선택하고 Load를 눌러주세요', type: '' });
  const [levelSt, setLevelSt] = useState({ 0: '—', 1: '—', 2: '—' });
  const [levelTypes, setLevelTypes] = useState({ 0: '', 1: '', 2: '' });
  const [reqLog,  setReqLog]  = useState([]);
  const [stats,   setStats]   = useState({ requests: 0, bytesTotal: 0, timeMs: 0 });
  const [legend,  setLegend]  = useState({ active: '대기 중', blocked: '—' });

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
    setStatus({ msg: '준비 완료 — Load 버튼을 눌러주세요', type: '' });
  }, [loading]);

  // ── SCOG 로드 ────────────────────────────────────────────────────────────────
  const loadSCOG = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    setReqLog([]);
    setStats({ requests: 0, bytesTotal: 0, timeMs: 0 });
    setLevelSt({ 0: '—', 1: '—', 2: '—' });
    setLevelTypes({ 0: '', 1: '', 2: '' });
    if (layerRef.current) { mapInst.current.removeLayer(layerRef.current); layerRef.current = null; }

    const cred   = CREDENTIALS[tier];
    const client = new SCOGClient(SCOG_URL, cred, {
      onRequest: (info) => {
        setReqLog(prev => [...prev, info]);
        setStats({ ...client.stats });
      },
    });

    const levels  = client.availableLevels();
    const blocked = [0, 1, 2].filter(l => !levels.includes(l));

    try {
      setStatus({ msg: 'SCOG 블록 로드 중...', type: 'loading' });

      const renderLevel = Math.min(...levels);
      const meta        = client.levelMeta(renderLevel);

      setStatus({ msg: `레벨 ${renderLevel} 복호화 중...`, type: 'loading' });
      setLevelSt(prev => ({ ...prev, [renderLevel]: '복호화 중...' }));
      setLevelTypes(prev => ({ ...prev, [renderLevel]: 'loading' }));

      await client.decryptLevel(renderLevel);
      setLevelSt(prev => ({ ...prev, [renderLevel]: '복호화 완료' }));
      setLevelTypes(prev => ({ ...prev, [renderLevel]: 'ok' }));

      // 타일 렌더링
      const tilesX = Math.ceil(meta.image_width  / meta.tile_width);
      const tilesY = Math.ceil(meta.image_height / meta.tile_height);
      const total  = tilesX * tilesY;
      let done = 0;

      const canvas = new OffscreenCanvas(meta.image_width, meta.image_height);
      const ctx    = canvas.getContext('2d');

      for (let row = 0; row < tilesY; row++) {
        for (let col = 0; col < tilesX; col++) {
          const imgData = await client.readTileAsImage(renderLevel, col, row);
          ctx.putImageData(imgData, col * meta.tile_width, row * meta.tile_height);
          done++;
          setStatus({ msg: `타일 읽는 중 (${done} / ${total})...`, type: 'loading' });
          setStats({ ...client.stats });
        }
      }

      const blob   = await canvas.convertToBlob({ type: 'image/png' });
      const objUrl = URL.createObjectURL(blob);
      swapLayer(objUrl);

      // 차단된 레벨 시도 → PermissionError 시연
      for (const lid of blocked) {
        try {
          await client.decryptLevel(lid);
        } catch (e) {
          if (e.name === 'SCOGPermissionError') {
            setLevelSt(prev => ({ ...prev, [lid]: '🚫 PermissionError' }));
            setLevelTypes(prev => ({ ...prev, [lid]: 'blocked' }));
          }
        }
      }

      const tierName  = `${TIER_META[tier].icon} ${TIER_META[tier].name}`;
      const blockedStr = blocked.length ? `L${blocked.join(', L')}` : '없음';
      setLegend({
        active:  `${tierName} — L${renderLevel} (${meta.image_width}×${meta.image_height})`,
        blocked: blockedStr,
      });
      setStats({ ...client.stats });
      setStatus({
        msg: `완료 ✓  레벨 ${renderLevel} 렌더링 · ${client.stats.requests}개 요청 · ` +
             `${formatBytes(client.stats.bytesTotal)} · ${client.stats.timeMs.toFixed(0)}ms`,
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
  const accessible = TIER_LEVELS[tier];

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>

      {/* 상태 바 */}
      <div className={`status-bar ${status.type}`}>{status.msg}</div>

      {/* 메인 */}
      <div className="main">

        {/* 사이드 패널 */}
        <div className="sidebar">

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
            <button className="load-btn scog" onClick={loadSCOG} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load SCOG Image'}
            </button>
            <button className="load-btn cog" onClick={loadCOG} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load COG Image'}
            </button>
          </div>

          {/* 레벨 접근 상태 */}
          <div className="panel">
            <div className="panel-title">📊 레벨 접근 상태</div>
            {[
              { id: 0, title: 'Full Resolution',  sub: '1298×1093 · 9 타일' },
              { id: 1, title: 'Overview × ½',     sub: '649×546 · 4 타일' },
              { id: 2, title: 'Overview × ¼',     sub: '324×273 · 1 타일' },
            ].map(({ id, title, sub }) => (
              <div className="level-row" key={id}>
                <span className={`level-badge ${accessible.includes(id) ? 'accessible' : 'blocked'}`}>
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
            ))}
          </div>

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
