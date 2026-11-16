import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import Overview from "./pages/Overview";
import Monitoring from "./pages/Monitoring";
import Incidents from "./pages/Incidents";
import IncidentDetail from "./pages/IncidentDetail";
import Approvals from "./pages/Approvals";
import Agents from "./pages/Agents";
import CouncilPage from "./pages/Council";
import GraphPage from "./pages/Graph";
import TwinPage from "./pages/Twin";
import Intel from "./pages/Intel";
import Risk from "./pages/Risk";
import Assets from "./pages/Assets";
import Audit from "./pages/Audit";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/monitoring" element={<Monitoring />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/incidents/:id" element={<IncidentDetail />} />
        <Route path="/approvals" element={<Approvals />} />
        <Route path="/agents" element={<Agents />} />
        <Route path="/council" element={<CouncilPage />} />
        <Route path="/graph" element={<GraphPage />} />
        <Route path="/twin" element={<TwinPage />} />
        <Route path="/intel" element={<Intel />} />
        <Route path="/risk" element={<Risk />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/audit" element={<Audit />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AppLayout>
  );
}
