import { useState, type ReactNode } from "react";
import { Badge, Layout, Menu, Space, Tag, Tooltip, Typography } from "antd";
import {
  ApartmentOutlined,
  AlertOutlined,
  AuditOutlined,
  BarChartOutlined,
  CheckSquareOutlined,
  CloudServerOutlined,
  ClusterOutlined,
  DashboardOutlined,
  DeploymentUnitOutlined,
  ExperimentOutlined,
  RadarChartOutlined,
  ReadOutlined,
  RobotOutlined,
  SettingOutlined,
  TeamOutlined,
} from "@ant-design/icons";
import { useLocation, useNavigate } from "react-router-dom";
import { Logo } from "./Logo";
import { useLive } from "../hooks/useLive";
import { session } from "../api/client";

const NAV = [
  { type: "group" as const, label: "Operations", children: [
    { key: "/", icon: <DashboardOutlined />, label: "Security Overview" },
    { key: "/monitoring", icon: <RadarChartOutlined />, label: "Threat Monitoring" },
    { key: "/incidents", icon: <AlertOutlined />, label: "Incidents" },
    { key: "/approvals", icon: <CheckSquareOutlined />, label: "Response Approvals" },
  ] },
  { type: "group" as const, label: "AI Intelligence", children: [
    { key: "/agents", icon: <RobotOutlined />, label: "AI Agents" },
    { key: "/council", icon: <TeamOutlined />, label: "AI Council" },
    { key: "/graph", icon: <ApartmentOutlined />, label: "Attack Graph" },
    { key: "/twin", icon: <ExperimentOutlined />, label: "Digital Twin" },
    { key: "/intel", icon: <ReadOutlined />, label: "Threat Intel (RAG)" },
  ] },
  { type: "group" as const, label: "Governance", children: [
    { key: "/risk", icon: <BarChartOutlined />, label: "Risk Analytics" },
    { key: "/assets", icon: <CloudServerOutlined />, label: "Assets" },
    { key: "/audit", icon: <AuditOutlined />, label: "Reports & Audit" },
    { key: "/settings", icon: <SettingOutlined />, label: "System & Demo" },
  ] },
];

export function AppLayout({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  const nav = useNavigate();
  const loc = useLocation();
  const { connected } = useLive();
  const selected = "/" + (loc.pathname.split("/")[1] ?? "");

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Layout.Sider collapsible collapsed={collapsed} onCollapse={setCollapsed} width={236} className="sider">
        <Logo collapsed={collapsed} />
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[selected]}
          items={NAV}
          onClick={(e) => nav(e.key)}
          style={{ background: "transparent", borderInlineEnd: 0 }}
        />
      </Layout.Sider>
      <Layout>
        <Layout.Header className="topbar">
          <Space size={12}>
            <ClusterOutlined style={{ color: "#22d3ee" }} />
            <Typography.Text strong>SENTRIX AI</Typography.Text>
            <Typography.Text type="secondary" className="hide-sm">
              Autonomous Multi-Agent AI Cybersecurity and Threat Intelligence Platform
            </Typography.Text>
          </Space>
          <Space size={16}>
            <Tooltip title={connected ? "Live updates connected (WebSocket)" : "Live updates disconnected - retrying"}>
              <Badge status={connected ? "processing" : "error"} text={connected ? "Live" : "Offline"} />
            </Tooltip>
            <Tooltip title="Analyst identity recorded in the audit log (change in System & Demo)">
              <Tag icon={<DeploymentUnitOutlined />} color="geekblue">{session.actor}</Tag>
            </Tooltip>
          </Space>
        </Layout.Header>
        <Layout.Content className="content">{children}</Layout.Content>
      </Layout>
    </Layout>
  );
}
