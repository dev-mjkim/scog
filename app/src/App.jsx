import { useState } from "react";
import SCOGDemo from "./pages/SCOGDemo.jsx";
import SCOGv2Demo from "./pages/SCOGv2Demo.jsx";
import SCOGv3Demo from "./pages/SCOGv3Demo.jsx";
import SCOGv4Demo from "./pages/SCOGv4Demo.jsx";
import ZoomViewer from "./pages/ZoomViewer.jsx";

export default function App() {
  const [version, setVersion] = useState("v1");
  const [subPage, setSubPage] = useState("tiles");

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column" }}>
      {/* 메인 네비게이션 — v1 / v2 / v3 */}
      <nav className="app-nav">
        <span className="app-nav-title">
          🔐 <strong>SCOG</strong> Demo
        </span>
        <span className="badge">SCOG 2026</span>
        <div className="app-nav-tabs">
          <button
            className={`nav-tab ${version === "v1" ? "active" : ""}`}
            onClick={() => setVersion("v1")}
          >
            SCOG v1
          </button>
          <button
            className={`nav-tab ${version === "v2" ? "active" : ""}`}
            onClick={() => setVersion("v2")}
          >
            SCOG v2 (QGIS 호환)
          </button>
          <button
            className={`nav-tab ${version === "v3" ? "active" : ""}`}
            onClick={() => setVersion("v3")}
          >
            SCOG v3 (1-Request)
          </button>
          <button
            className={`nav-tab ${version === "v4" ? "active" : ""}`}
            onClick={() => setVersion("v4")}
          >
            SCOG v4 (타일 암호화)
          </button>
        </div>
      </nav>

      {/* 서브 네비게이션 — 전체 타일 / Zoom-Aware */}
      <div className="sub-nav">
        <button
          className={`sub-tab ${subPage === "tiles" ? "active" : ""}`}
          onClick={() => setSubPage("tiles")}
        >
          전체 타일 가져오기
        </button>
        <button
          className={`sub-tab ${subPage === "zoom" ? "active" : ""}`}
          onClick={() => setSubPage("zoom")}
        >
          Zoom-Aware Viewer
        </button>
      </div>

      <div style={{ flex: 1, overflow: "hidden" }}>
        {version === "v1" && subPage === "tiles" && <SCOGDemo />}
        {version === "v1" && subPage === "zoom" && (
          <ZoomViewer key="v1-zoom" version="v1" />
        )}
        {version === "v2" && subPage === "tiles" && <SCOGv2Demo />}
        {version === "v2" && subPage === "zoom" && (
          <ZoomViewer key="v2-zoom" version="v2" />
        )}
        {version === "v3" && subPage === "tiles" && <SCOGv3Demo />}
        {version === "v3" && subPage === "zoom" && (
          <ZoomViewer key="v3-zoom" version="v3" />
        )}
        {version === "v4" && subPage === "tiles" && <SCOGv4Demo />}
        {version === "v4" && subPage === "zoom" && (
          <ZoomViewer key="v4-zoom" version="v4" />
        )}
      </div>
    </div>
  );
}
