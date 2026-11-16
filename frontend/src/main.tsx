import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App as AntApp, ConfigProvider, theme } from "antd";
import "antd/dist/reset.css";
import "./styles.css";
import App from "./App";
import { LiveProvider } from "./hooks/useLive";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: "#22d3ee",
          colorInfo: "#22d3ee",
          colorBgBase: "#0b1220",
          colorBgContainer: "#111a2e",
          colorBorderSecondary: "rgba(148,163,184,0.14)",
          borderRadius: 8,
          fontFamily: 'Inter, "Segoe UI", system-ui, sans-serif',
        },
        components: {
          Layout: { headerBg: "#0b1220", bodyBg: "#0b1220", siderBg: "#0a1020" },
          Menu: { darkItemBg: "transparent", darkItemSelectedBg: "rgba(34,211,238,0.14)", darkItemSelectedColor: "#22d3ee" },
          Table: { headerBg: "#0f172a" },
        },
      }}
    >
      <AntApp>
        <BrowserRouter>
          <LiveProvider>
            <App />
          </LiveProvider>
        </BrowserRouter>
      </AntApp>
    </ConfigProvider>
  </StrictMode>,
);
