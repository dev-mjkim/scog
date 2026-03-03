import { useEffect, useRef, useState, useCallback } from 'react';
import Map          from 'ol/Map.js';
import View         from 'ol/View.js';
import TileLayer    from 'ol/layer/Tile.js';
import OSM          from 'ol/source/OSM.js';
import ImageLayer   from 'ol/layer/Image.js';
import ImageStatic  from 'ol/source/ImageStatic.js';
import { fromLonLat } from 'ol/proj.js';

import { SCOGClient } from '../lib/scog-client.js';
import { COGClient }  from '../lib/cog-client.js';
import { CREDENTIALS, CREDENTIALS_V2, CREDENTIALS_V3, SCOG_URL, SCOG_V2_URL, SCOG_V3_URL, COG_URL, EXTENT } from '../credentials.js';

// ─── 레벨 선택 로직 ──────────────────────────────────────────────────────────
function bestLevel(resolution, levelResMap) {
  const sorted = Object.entries(levelResMap).sort((a, b) => b[1] - a[1]); // coarse→fine
  for (const [lvl, natRes] of sorted) {
    if (natRes <= resolution * 1.5) return Number(lvl);
  }
  return Number(sorted.at(-1)[0]);
}

// ─── 티어 메타 ───────────────────────────────────────────────────────────────
const TIER_META_V1 = {
  admin: { icon: '👑', name: 'Admin', levels: [0, 1, 2] },
  user:  { icon: '👤', name: 'User',  levels: [1, 2] },
  guest: { icon: '🌐', name: 'Guest', levels: [2] },
};
const TIER_META_V2 = {
  admin: { icon: '👑', name: 'Admin', levels: [0, 1, 2] },
  user:  { icon: '👤', name: 'User',  levels: [1, 2] },
  guest: { icon: '🌐', name: 'Guest', levels: [2] },
};
const TIER_META_V3 = TIER_META_V2;

// ─── ZoomViewer 컴포넌트 ──────────────────────────────────────────────────────
export default function ZoomViewer({ version = 'v1' }) {
  const TIER_META  = version === 'v3' ? TIER_META_V3 : version === 'v2' ? TIER_META_V2 : TIER_META_V1;
  const SCOG_CREDS = version === 'v3' ? CREDENTIALS_V3 : version === 'v2' ? CREDENTIALS_V2 : CREDENTIALS;
  const SCOG_SRC   = version === 'v3' ? SCOG_V3_URL : version === 'v2' ? SCOG_V2_URL : SCOG_URL;
  const defaultTier = 'admin';

  const mapRef   = useRef(null);
  const mapInst  = useRef(null);

  // 뮤터블 상태 (리렌더 불필요)
  const state = useRef({
    activeLayer:  null,
    blobUrl:      null,
    activeMode:   null,   // 'cog' | 'scog'
    currentLvl:   null,
    levelLoading: false,
    cogClient:    null,
    cogCache:     {},
    cogLevelRes:  {},
    scogClient:   null,
    scogCache:    {},
    scogLevelRes: {},
    scogTier:     defaultTier,
  });

  // React 상태 (UI 업데이트용)
  const [status,    setStatus]    = useState({ msg: '준비 완료 — 아래 버튼으로 이미지를 불러오세요', type: '' });
  const [loading,   setLoading]   = useState(false);
  const [scogTier,  setScogTier]  = useState(defaultTier);
  const [zoomInfo,  setZoomInfo]  = useState({ zoom: null, res: null });
  const [activePill, setActivePill] = useState(null);
  const [pillRes,   setPillRes]   = useState({});   // { 0: '0.89 m/px', ... }
  const [accessibleLevels, setAccessibleLevels] = useState([0, 1, 2]);
  const [switchLog, setSwitchLog] = useState([]);
  const [legend,    setLegend]    = useState({ mode: '—', level: '' });

  // ── 지도 초기화 ──────────────────────────────────────────────────────────────
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

    const updateZoom = () => {
      const view = mapInst.current.getView();
      setZoomInfo({ zoom: view.getZoom(), res: view.getResolution() });
    };
    mapInst.current.on('moveend', updateZoom);
    updateZoom();

    return () => mapInst.current.setTarget(null);
  }, []);

  // ── 레이어 교체 ──────────────────────────────────────────────────────────────
  const swapLayer = useCallback(async (canvas) => {
    const s = state.current;
    const blob = await canvas.convertToBlob({ type: 'image/png' });
    if (s.blobUrl) URL.revokeObjectURL(s.blobUrl);
    s.blobUrl = URL.createObjectURL(blob);

    if (s.activeLayer) mapInst.current.removeLayer(s.activeLayer);
    s.activeLayer = new ImageLayer({
      source: new ImageStatic({
        url: s.blobUrl, imageExtent: EXTENT, projection: 'EPSG:3857',
      }),
      opacity: 0.9,
    });
    mapInst.current.addLayer(s.activeLayer);
  }, []);

  // ── 로그 추가 ────────────────────────────────────────────────────────────────
  const addLog = useCallback((lvl, res, cached) => {
    const now = new Date().toLocaleTimeString('ko-KR', { hour12: false });
    setSwitchLog(prev => [...prev, { lvl, res, cached, time: now }]);
  }, []);

  // ── COG 레벨 표시 ────────────────────────────────────────────────────────────
  const showCOGLevel = useCallback(async (lvl) => {
    const s = state.current;
    const cached = !!s.cogCache[lvl];
    setStatus({ msg: `COG L${lvl} ${cached ? '(캐시) ' : ''}렌더링 중...`, type: 'loading' });
    setActivePill(lvl);

    if (!s.cogCache[lvl]) {
      s.cogCache[lvl] = await s.cogClient.renderLevel(lvl);
    }
    await swapLayer(s.cogCache[lvl]);

    const ifd = s.cogClient._ifds[lvl];
    addLog(lvl, mapInst.current.getView().getResolution(), cached);
    setLegend({
      mode:  '🗺️ COG (Zoom-Aware)',
      level: `L${lvl} — ${ifd.imageWidth}×${ifd.imageHeight} px`,
    });
    s.currentLvl = lvl;
  }, [swapLayer, addLog]);

  // ── SCOG 레벨 표시 ───────────────────────────────────────────────────────────
  const showSCOGLevel = useCallback(async (lvl) => {
    const s = state.current;
    const cached = !!s.scogCache[lvl];
    setStatus({ msg: `SCOG L${lvl} ${cached ? '(캐시) ' : ''}복호화/렌더링 중...`, type: 'loading' });
    setActivePill(lvl);

    if (!s.scogCache[lvl]) {
      await s.scogClient.decryptLevel(lvl);
      s.scogCache[lvl] = await s.scogClient.readFullLevel(lvl);
    }
    await swapLayer(s.scogCache[lvl]);

    const meta     = s.scogClient.levelMeta(lvl);
    const tierMeta = TIER_META[s.scogTier] ?? Object.values(TIER_META)[0];
    addLog(lvl, mapInst.current.getView().getResolution(), cached);
    setLegend({
      mode:  `🔐 SCOG — ${tierMeta.icon} ${tierMeta.name}`,
      level: `L${lvl} — ${meta.image_width}×${meta.image_height} px`,
    });
    s.currentLvl = lvl;
  }, [swapLayer, addLog]);

  // ── moveend 핸들러 ────────────────────────────────────────────────────────────
  const onMoveEnd = useCallback(async () => {
    const s = state.current;
    if (s.levelLoading) return;
    const res  = mapInst.current.getView().getResolution();
    const best = s.activeMode === 'cog'
      ? bestLevel(res, s.cogLevelRes)
      : bestLevel(res, s.scogLevelRes);
    if (best !== s.currentLvl) {
      s.levelLoading = true;
      try {
        if (s.activeMode === 'cog') await showCOGLevel(best);
        else                        await showSCOGLevel(best);
        setStatus({ msg: `${s.activeMode === 'cog' ? 'COG' : 'SCOG'} 완료 ✓  줌 인/아웃하면 overview가 자동 전환됩니다`, type: 'done' });
      } finally {
        s.levelLoading = false;
      }
    }
  }, [showCOGLevel, showSCOGLevel]);

  // ── 전체 리셋 ────────────────────────────────────────────────────────────────
  const resetAll = useCallback(() => {
    const s = state.current;
    mapInst.current.un('moveend', onMoveEnd);
    if (s.activeLayer) { mapInst.current.removeLayer(s.activeLayer); s.activeLayer = null; }
    if (s.blobUrl)     { URL.revokeObjectURL(s.blobUrl);              s.blobUrl = null; }
    s.cogClient = null; s.scogClient = null;
    s.cogCache = {};    s.scogCache = {};
    s.cogLevelRes = {}; s.scogLevelRes = {};
    s.currentLvl = null; s.activeMode = null; s.levelLoading = false;
    setSwitchLog([]);
    setLegend({ mode: '—', level: '' });
    setActivePill(null);
    setPillRes({});
    setAccessibleLevels([0, 1, 2]);
  }, [onMoveEnd]);

  // ── COG Zoom-Aware ────────────────────────────────────────────────────────────
  const loadCOGZoomAware = useCallback(async () => {
    resetAll();
    setLoading(true);
    setStatus({ msg: 'COG 헤더 로드 중...', type: 'loading' });

    const s = state.current;
    s.cogClient = new COGClient(COG_URL);

    try {
      await s.cogClient.loadHeader();
      const extentWidth = EXTENT[2] - EXTENT[0];
      s.cogLevelRes = s.cogClient.levelResolutions(extentWidth);

      const newPillRes = {};
      Object.entries(s.cogLevelRes).forEach(([i, res]) => {
        newPillRes[i] = `${res.toFixed(2)} m/px`;
      });
      setPillRes(newPillRes);

      s.activeMode = 'cog';
      mapInst.current.on('moveend', onMoveEnd);
      await showCOGLevel(bestLevel(mapInst.current.getView().getResolution(), s.cogLevelRes));
      setStatus({ msg: 'COG 완료 ✓  줌 인/아웃하면 overview가 자동 전환됩니다', type: 'done' });
    } catch (e) {
      console.error(e);
      setStatus({ msg: `COG 오류: ${e.message}`, type: 'error' });
    }
    setLoading(false);
  }, [resetAll, onMoveEnd, showCOGLevel]);

  // ── SCOG Zoom-Aware ───────────────────────────────────────────────────────────
  const loadSCOGZoomAware = useCallback(async () => {
    resetAll();
    setLoading(true);
    setStatus({ msg: 'SCOG 초기화 중...', type: 'loading' });

    const s = state.current;
    s.scogTier   = scogTier;
    s.scogClient = new SCOGClient(SCOG_SRC, SCOG_CREDS[scogTier], {});

    // v3: loadScogBlock으로 IFD 파싱 후 availableLevels/levelMeta 사용 가능
    await s.scogClient.loadScogBlock();

    const levels      = s.scogClient.availableLevels();
    const extentWidth = EXTENT[2] - EXTENT[0];
    s.scogLevelRes = Object.fromEntries(
      levels.map(lvl => {
        const meta = s.scogClient.levelMeta(lvl);
        return [lvl, extentWidth / meta.image_width];
      })
    );

    const newPillRes = {};
    Object.entries(s.scogLevelRes).forEach(([i, res]) => {
      newPillRes[i] = `${res.toFixed(2)} m/px`;
    });
    setPillRes(newPillRes);
    setAccessibleLevels(levels);

    try {
      s.activeMode = 'scog';
      mapInst.current.on('moveend', onMoveEnd);
      await showSCOGLevel(bestLevel(mapInst.current.getView().getResolution(), s.scogLevelRes));
      const tierMeta = TIER_META[scogTier];
      setStatus({ msg: `SCOG (${tierMeta.name}) 완료 ✓  줌 인/아웃하면 overview가 자동 전환됩니다`, type: 'done' });
    } catch (e) {
      console.error(e);
      setStatus({ msg: `SCOG 오류: ${e.message}`, type: 'error' });
    }
    setLoading(false);
  }, [resetAll, onMoveEnd, showSCOGLevel, scogTier]);

  // ── 렌더 ──────────────────────────────────────────────────────────────────────
  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>

      {/* 상태 바 */}
      <div className={`status-bar ${status.type}`}>{status.msg}</div>

      {/* 메인 */}
      <div className="main">

        {/* 사이드 패널 */}
        <div className="sidebar">

          {/* 로드 버튼 */}
          <div className="panel">
            <div className="panel-title">📂 이미지 로드</div>
            <button className="load-btn cog" onClick={loadCOGZoomAware} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load COG (Zoom-Aware)'}
            </button>

            {/* SCOG 자격증명 티어 선택 */}
            <div className="panel-title" style={{ marginTop: '12px' }}>🔑 SCOG 자격증명</div>
            <div className="tier-grid">
              {Object.entries(TIER_META).map(([t, m]) => (
                <button
                  key={t}
                  className={`tier-btn ${scogTier === t ? 'active' : ''}`}
                  onClick={() => setScogTier(t)}
                  disabled={loading}
                >
                  <span className="tier-icon">{m.icon}</span>
                  <span className="tier-name">{m.name}</span>
                  <span className="tier-levels">L{m.levels.join('·')}</span>
                </button>
              ))}
            </div>
            <button className="load-btn scog" onClick={loadSCOGZoomAware} disabled={loading}>
              {loading ? '로드 중...' : '▶ Load SCOG (Zoom-Aware)'}
            </button>
          </div>

          {/* 줌 정보 */}
          <div className="panel">
            <div className="panel-title">🔭 현재 뷰</div>
            <div className="info-grid">
              <div className="info-box">
                <div className="info-num">{zoomInfo.zoom ? zoomInfo.zoom.toFixed(1) : '—'}</div>
                <div className="info-sub">Zoom</div>
              </div>
              <div className="info-box">
                <div className="info-num">{zoomInfo.res ? zoomInfo.res.toFixed(2) : '—'}</div>
                <div className="info-sub">m/px</div>
              </div>
            </div>
            <div className="level-indicator">
              {[0, 1, 2].map(i => {
                const accessible = accessibleLevels.includes(i);
                return (
                  <div
                    key={i}
                    className={`level-pill ${activePill === i ? 'active' : ''}`}
                    style={!accessible ? { opacity: 0.35 } : {}}
                    title={!accessible ? '접근 불가 (자격증명 없음)' : undefined}
                  >
                    {accessible ? `L${i}` : `🚫L${i}`}
                    <span className="pill-res">{pillRes[i] || '—'}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 전환 로그 */}
          <div className="panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div className="panel-title">🔄 Overview 전환 로그</div>
            <div className="switch-log">
              {switchLog.length === 0
                ? <div style={{ color: '#4a5568', fontSize: '12px', padding: '6px 10px' }}>(아직 없음)</div>
                : switchLog.map((entry, i) => (
                    <div className="switch-item" key={i}>
                      <span className="si-time">{entry.time}</span><br />
                      <span className="si-level">Level {entry.lvl}</span>{' '}
                      <span className="si-res">(map: {entry.res.toFixed(2)} m/px)</span>
                      {entry.cached && <span style={{ color: '#718096' }}> [캐시]</span>}
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
            <div className="legend-title">현재 레이어</div>
            <div className="legend-mode">{legend.mode}</div>
            <div className="legend-level">{legend.level}</div>
          </div>
        </div>

      </div>
    </div>
  );
}
