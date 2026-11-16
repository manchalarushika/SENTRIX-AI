import { useState } from "react";
import { App, Button, Card, Col, Form, InputNumber, Row, Select, Space, Table, Tag } from "antd";
import { ThunderboltOutlined } from "@ant-design/icons";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { errorMessage, get, post } from "../api/client";
import type { Asset, TwinSimulation } from "../api/types";
import { useApi } from "../hooks/useApi";
import { Loadable, PageHeader, money, pct } from "../components/ui";

export default function TwinPage() {
  const { message } = App.useApp();
  const assets = useApi(() => get<Asset[]>("/assets"));
  const [result, setResult] = useState<TwinSimulation | null>(null);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();

  const run = async (v: any) => {
    setBusy(true);
    try {
      const res = await post<TwinSimulation>("/twin/simulate", {
        entry_hostnames: v.entry, runs: v.runs ?? 300, seed: v.seed ?? 7,
      });
      if (res.status !== "completed") message.warning(res.reason);
      setResult(res);
    } catch (e) { message.error(errorMessage(e)); } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="Cyber Digital Twin"
        subtitle="Seeded Monte Carlo simulation of attack propagation under each response playbook" />
      <Loadable loading={assets.loading} error={assets.error} empty={!assets.data?.length}>
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={7}>
            <Card size="small" title="Simulation parameters">
              <Form form={form} layout="vertical" onFinish={run} initialValues={{ runs: 300, seed: 7 }}>
                <Form.Item name="entry" label="Compromised entry host(s)" rules={[{ required: true, message: "Pick at least one host" }]}>
                  <Select mode="multiple" placeholder="Select hosts" showSearch
                    options={(assets.data ?? []).map((a) => ({ value: a.hostname, label: `${a.hostname} (${a.criticality})` }))} />
                </Form.Item>
                <Space.Compact block>
                  <Form.Item name="runs" label="Runs" style={{ width: "50%" }}><InputNumber min={50} max={5000} step={50} style={{ width: "100%" }} /></Form.Item>
                  <Form.Item name="seed" label="Seed" style={{ width: "50%" }}><InputNumber min={0} style={{ width: "100%" }} /></Form.Item>
                </Space.Compact>
                <Button type="primary" htmlType="submit" icon={<ThunderboltOutlined />} loading={busy} block>Run simulation</Button>
              </Form>
            </Card>
          </Col>
          <Col xs={24} lg={17}>
            {result?.status === "completed" ? (
              <div className="section-gap">
                <Card size="small" title={`Expected total cost per response (${result.runs} runs, seed ${result.seed})`}>
                  <ResponsiveContainer width="100%" height={260}>
                    <BarChart data={result.results} margin={{ bottom: 20 }}>
                      <CartesianGrid stroke="rgba(148,163,184,.1)" />
                      <XAxis dataKey="name" stroke="#64748b" fontSize={10} angle={-12} textAnchor="end" height={70} interval={0} />
                      <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => `$${(v / 1000).toFixed(0)}k`} />
                      <RTooltip formatter={(v) => money(Number(v))} contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                      <Bar dataKey="expected_total_cost" radius={[4, 4, 0, 0]}>
                        {result.results.map((r) => <Cell key={r.playbook} fill={r.playbook === result.best_playbook ? "#22d3ee" : "#475569"} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </Card>
                <Card size="small" title="Detailed outcomes">
                  <Table size="small" rowKey="playbook" pagination={false} dataSource={result.results} columns={[
                    { title: "Playbook", dataIndex: "name", render: (v, r) => <Space>{v}{r.playbook === result.best_playbook && <Tag color="cyan">best</Tag>}</Space> },
                    { title: "Exp. compromised", dataIndex: "expected_compromised", width: 130 },
                    { title: "Crit. compromise p", dataIndex: "critical_asset_compromise_probability", width: 140, render: pct },
                    { title: "Breach loss", dataIndex: "expected_breach_loss", width: 120, render: money },
                    { title: "Disruption", dataIndex: "response_disruption_cost", width: 120, render: money },
                    { title: "Total cost", dataIndex: "expected_total_cost", width: 120, render: (v) => <b>{money(v)}</b> },
                  ]} />
                </Card>
              </div>
            ) : (
              <Card size="small"><div className="muted" style={{ padding: 40, textAlign: "center" }}>
                {result?.reason ?? "Select one or more compromised hosts and run the simulation. Results are deterministic for a given seed."}
              </div></Card>
            )}
          </Col>
        </Row>
      </Loadable>
    </>
  );
}
