import { Button, Card, Col, Empty, List, Progress, Row, Space, Table, Tag, Typography } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useNavigate } from "react-router-dom";
import { get } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useLive, useLiveRefresh } from "../hooks/useLive";
import { Kpi, Loadable, PageHeader, RiskBar, SEVERITY_COLOR, SeverityTag, StatusTag, fromNow, pct } from "../components/ui";

interface Summary {
  enterprise_risk: { score: number; level: string };
  top_risky_assets: { hostname: string; risk_score: number; level: string; criticality: string; active_incidents: string[] }[];
  open_incidents: number;
  open_by_severity: Record<string, number>;
  incidents_by_status: Record<string, number>;
  events_24h: number;
  events_by_severity_24h: Record<string, number>;
  events_hourly: { hour: string; count: number; max_threat: number }[];
  tactics: { tactic: string; count: number }[];
  pending_approvals: number;
  mean_time_to_resolve_hours: number | null;
  recent_incidents: { id: number; ref: string; title: string; severity: string; status: string; risk_score: number; last_seen: string }[];
  recent_decisions: { id: number; incident_id: number; playbook: string; consensus: number; agreement: number; created_at: string }[];
}

const SEVS = ["critical", "high", "medium", "low", "info"];

export default function Overview() {
  const nav = useNavigate();
  const { data, loading, error, reload } = useApi(() => get<Summary>("/dashboard/summary"));
  const { feed } = useLive();
  useLiveRefresh(["events_ingested", "analysis_completed", "action_reviewed", "incident_updated"], () => reload(true));

  const risk = data?.enterprise_risk;
  const riskColor = risk ? SEVERITY_COLOR[risk.level] : undefined;
  const sevData = SEVS.map((s) => ({ name: s, value: data?.open_by_severity[s] ?? 0 })).filter((d) => d.value);

  return (
    <>
      <PageHeader
        title="Security Overview"
        subtitle="Enterprise security posture computed from live telemetry, incidents and AI analysis"
        extra={<Button icon={<ReloadOutlined />} onClick={() => reload()}>Refresh</Button>}
      />
      <Loadable loading={loading && !data} error={error}>
        {data && (
          <div className="section-gap">
            <Row gutter={[16, 16]}>
              <Col xs={24} md={12} xl={6}>
                <Card size="small" className="kpi">
                  <div className="kpi-label">Enterprise risk</div>
                  <Space align="center" size={16}>
                    <Progress type="dashboard" size={86} percent={risk!.score} strokeColor={riskColor} format={(p) => `${p?.toFixed(0)}`} />
                    <div>
                      <Tag color={riskColor} style={{ color: "#0b1220", fontWeight: 700 }}>{risk!.level.toUpperCase()}</Tag>
                      <div className="kpi-hint">deterministic risk model</div>
                    </div>
                  </Space>
                </Card>
              </Col>
              <Col xs={12} md={6} xl={4}><Kpi label="Open incidents" value={data.open_incidents} color={data.open_incidents ? SEVERITY_COLOR.high : undefined} hint={`${data.open_by_severity.critical ?? 0} critical`} /></Col>
              <Col xs={12} md={6} xl={4}><Kpi label="Events (24h)" value={data.events_24h.toLocaleString()} hint={`${(data.events_by_severity_24h.high ?? 0) + (data.events_by_severity_24h.critical ?? 0)} high/critical`} /></Col>
              <Col xs={12} md={6} xl={5}>
                <Card size="small" className="kpi clickable" onClick={() => nav("/approvals")}>
                  <div className="kpi-label">Pending approvals</div>
                  <div className="kpi-value" style={{ color: data.pending_approvals ? SEVERITY_COLOR.medium : undefined }}>{data.pending_approvals}</div>
                  <div className="kpi-hint">human-in-the-loop response actions</div>
                </Card>
              </Col>
              <Col xs={12} md={6} xl={5}><Kpi label="Mean time to resolve" value={data.mean_time_to_resolve_hours != null ? `${data.mean_time_to_resolve_hours}h` : "—"} hint="resolved/closed incidents" /></Col>
            </Row>

            <Row gutter={[16, 16]}>
              <Col xs={24} xl={16}>
                <Card size="small" title="Event volume & peak threat score (last 24h, hourly)">
                  {data.events_hourly.length ? (
                    <ResponsiveContainer width="100%" height={240}>
                      <AreaChart data={data.events_hourly.map((h) => ({ ...h, hour: h.hour.slice(11, 16) }))}>
                        <CartesianGrid stroke="rgba(148,163,184,.1)" />
                        <XAxis dataKey="hour" stroke="#64748b" fontSize={11} />
                        <YAxis yAxisId="l" stroke="#64748b" fontSize={11} />
                        <YAxis yAxisId="r" orientation="right" domain={[0, 100]} stroke="#64748b" fontSize={11} />
                        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                        <Area yAxisId="l" dataKey="count" name="events" stroke="#22d3ee" fill="rgba(34,211,238,.2)" />
                        <Area yAxisId="r" dataKey="max_threat" name="peak threat" stroke="#ef4444" fill="rgba(239,68,68,.08)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : <Empty description="No events in the last 24 hours" />}
                </Card>
              </Col>
              <Col xs={24} xl={8}>
                <Card size="small" title="Open incidents by severity">
                  {sevData.length ? (
                    <ResponsiveContainer width="100%" height={240}>
                      <PieChart>
                        <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2}
                          onClick={(d: any) => nav(`/incidents?severity=${d.name}`)} className="clickable">
                          {sevData.map((d) => <Cell key={d.name} fill={SEVERITY_COLOR[d.name]} />)}
                        </Pie>
                        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : <Empty description="No open incidents" />}
                </Card>
              </Col>
            </Row>

            <Row gutter={[16, 16]}>
              <Col xs={24} xl={14}>
                <Card size="small" title="Recent incidents" extra={<a onClick={() => nav("/incidents")}>All incidents</a>}>
                  <Table
                    size="small"
                    rowKey="id"
                    pagination={false}
                    dataSource={data.recent_incidents}
                    onRow={(r) => ({ onClick: () => nav(`/incidents/${r.id}`), className: "clickable" })}
                    columns={[
                      { title: "Ref", dataIndex: "ref", width: 100 },
                      { title: "Title", dataIndex: "title", ellipsis: true },
                      { title: "Severity", dataIndex: "severity", width: 100, render: (v) => <SeverityTag value={v} /> },
                      { title: "Status", dataIndex: "status", width: 120, render: (v) => <StatusTag value={v} /> },
                      { title: "Risk", dataIndex: "risk_score", width: 110, render: (v) => <RiskBar value={v} /> },
                      { title: "Last seen", dataIndex: "last_seen", width: 120, render: fromNow },
                    ]}
                  />
                </Card>
              </Col>
              <Col xs={24} xl={10}>
                <Card size="small" title="Highest-risk assets" extra={<a onClick={() => nav("/risk")}>Risk analytics</a>}>
                  <List
                    size="small"
                    dataSource={data.top_risky_assets}
                    locale={{ emptyText: "No assets in inventory" }}
                    renderItem={(a) => (
                      <List.Item extra={<RiskBar value={a.risk_score} />}>
                        <List.Item.Meta
                          title={<Space>{a.hostname}<SeverityTag value={a.criticality} /></Space>}
                          description={a.active_incidents.length ? `Active: ${a.active_incidents.join(", ")}` : "No active incidents"}
                        />
                      </List.Item>
                    )}
                  />
                </Card>
              </Col>
            </Row>

            <Row gutter={[16, 16]}>
              <Col xs={24} lg={10}>
                <Card size="small" title="MITRE ATT&CK tactics observed">
                  {data.tactics.length ? (
                    <ResponsiveContainer width="100%" height={260}>
                      <BarChart data={[...data.tactics].sort((a, b) => b.count - a.count)} layout="vertical" margin={{ left: 40 }}>
                        <XAxis type="number" stroke="#64748b" fontSize={11} />
                        <YAxis type="category" dataKey="tactic" width={130} stroke="#94a3b8" fontSize={11} />
                        <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                        <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : <Empty description="No classified events yet" />}
                </Card>
              </Col>
              <Col xs={24} lg={7}>
                <Card size="small" title="Latest AI Council decisions" extra={<a onClick={() => nav("/council")}>Council</a>}>
                  <List
                    size="small"
                    dataSource={data.recent_decisions}
                    locale={{ emptyText: "No decisions yet" }}
                    renderItem={(d) => (
                      <List.Item className="clickable" onClick={() => nav(`/incidents/${d.incident_id}`)}>
                        <List.Item.Meta title={d.playbook} description={`consensus ${d.consensus.toFixed(2)} · agreement ${pct(d.agreement)} · ${fromNow(d.created_at)}`} />
                      </List.Item>
                    )}
                  />
                </Card>
              </Col>
              <Col xs={24} lg={7}>
                <Card size="small" title="Live activity (WebSocket)">
                  {feed.length ? feed.slice(0, 12).map((m, i) => (
                    <div key={i} className="feed-item">
                      <Tag color="cyan">{m.type.replace(/_/g, " ")}</Tag>
                      <Typography.Text type="secondary">
                        {m.data.ref ?? m.data.agent ?? (m.data.count != null ? `${m.data.count} events` : "")}
                        {m.data.decision ? ` → ${m.data.decision}` : ""}
                      </Typography.Text>
                    </div>
                  )) : <Empty description="Waiting for live activity" />}
                </Card>
              </Col>
            </Row>
          </div>
        )}
      </Loadable>
    </>
  );
}
