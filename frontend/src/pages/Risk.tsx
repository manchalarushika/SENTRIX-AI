import { Card, Col, Progress, Row, Table, Tag } from "antd";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { get } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { Loadable, PageHeader, RiskBar, SEVERITY_COLOR, SeverityTag } from "../components/ui";

export default function Risk() {
  const overview = useApi(() => get<any>("/risk/overview"));
  const trends = useApi(() => get<any>("/risk/trends", { days: 14 }));
  useLiveRefresh(["analysis_completed", "events_ingested"], () => { overview.reload(true); trends.reload(true); });

  const o = overview.data;
  return (
    <>
      <PageHeader title="Risk Analytics" subtitle="Enterprise and per-asset risk, attack trends and highest-risk users" />
      <Loadable loading={overview.loading && !o} error={overview.error}>
        {o && (
          <div className="section-gap">
            <Row gutter={[16, 16]}>
              <Col xs={24} md={8}>
                <Card size="small" title="Enterprise risk" extra={<span className="muted">{o.method}</span>}>
                  <div style={{ textAlign: "center" }}>
                    <Progress type="dashboard" percent={o.score} strokeColor={SEVERITY_COLOR[o.level]} format={(p) => `${p?.toFixed(0)}`} />
                    <div><Tag color={SEVERITY_COLOR[o.level]} style={{ color: "#0b1220", fontWeight: 700 }}>{o.level.toUpperCase()}</Tag></div>
                  </div>
                </Card>
              </Col>
              <Col xs={24} md={16}>
                <Card size="small" title="Top risk drivers">
                  <Table size="small" rowKey="hostname" pagination={false} dataSource={o.drivers ?? []}
                    locale={{ emptyText: "No elevated-risk assets" }}
                    columns={[
                      { title: "Host", dataIndex: "hostname" },
                      { title: "Criticality", dataIndex: "criticality", width: 110, render: (v) => <SeverityTag value={v} /> },
                      { title: "Risk", dataIndex: "risk_score", width: 120, render: (v) => <RiskBar value={v} /> },
                      { title: "Threat", width: 90, render: (_, r: any) => (r.factors.threat * 100).toFixed(0) },
                      { title: "Exposure", width: 90, render: (_, r: any) => (r.factors.exposure * 100).toFixed(0) },
                      { title: "Behaviour", width: 100, render: (_, r: any) => (r.factors.behaviour * 100).toFixed(0) },
                      { title: "Incidents", dataIndex: "active_incidents", render: (v: string[]) => v.join(", ") || "—" },
                    ]} />
                </Card>
              </Col>
            </Row>
            <Loadable loading={trends.loading} error={trends.error}>
              {trends.data && (
                <Row gutter={[16, 16]}>
                  <Col xs={24} lg={14}>
                    <Card size="small" title="Events by day & severity (14 days)">
                      <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={trends.data.events_by_day}>
                          <CartesianGrid stroke="rgba(148,163,184,.1)" />
                          <XAxis dataKey="date" stroke="#64748b" fontSize={10} />
                          <YAxis stroke="#64748b" fontSize={11} />
                          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                          <Legend />
                          {["critical", "high", "medium", "low"].map((s) => (
                            <Bar key={s} dataKey={s} stackId="a" fill={SEVERITY_COLOR[s]} />
                          ))}
                        </BarChart>
                      </ResponsiveContainer>
                    </Card>
                  </Col>
                  <Col xs={24} lg={10}>
                    <Card size="small" title="Top MITRE techniques">
                      <ResponsiveContainer width="100%" height={280}>
                        <BarChart data={trends.data.top_techniques} layout="vertical" margin={{ left: 20 }}>
                          <XAxis type="number" stroke="#64748b" fontSize={11} />
                          <YAxis type="category" dataKey="technique" width={80} stroke="#94a3b8" fontSize={10} />
                          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                          <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
                        </BarChart>
                      </ResponsiveContainer>
                    </Card>
                  </Col>
                  <Col xs={24}>
                    <Card size="small" title="Highest-risk users (UEBA)">
                      <Table size="small" rowKey="user" pagination={false} dataSource={trends.data.risky_users}
                        locale={{ emptyText: "No user activity" }}
                        columns={[
                          { title: "User", dataIndex: "user" },
                          { title: "Max threat", dataIndex: "max_threat", width: 120, render: (v) => <RiskBar value={v} /> },
                          { title: "Avg anomaly", dataIndex: "avg_anomaly", width: 120, render: (v: number) => v.toFixed(3) },
                          { title: "Events", dataIndex: "events", width: 100 },
                        ]} />
                    </Card>
                  </Col>
                </Row>
              )}
            </Loadable>
          </div>
        )}
      </Loadable>
    </>
  );
}
