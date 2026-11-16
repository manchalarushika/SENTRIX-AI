import { useState } from "react";
import {
  Alert, App, Button, Card, Col, Descriptions, Empty, Input, List, Progress, Row,
  Select, Space, Table, Tabs, Tag, Timeline, Tooltip, Typography,
} from "antd";
import { DownloadOutlined, ReloadOutlined, RobotOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from "recharts";
import { useNavigate, useParams } from "react-router-dom";
import { download, errorMessage, get, patch, post } from "../api/client";
import type { AgentResult, IncidentDetail as Detail, ResponseAction } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { AttackGraphView } from "../components/AttackGraphView";
import { ActionsTable } from "../components/ActionsTable";
import {
  Loadable, MethodTag, PageHeader, RiskBar, SeverityTag, StatusTag, fmtTime, money, pct,
} from "../components/ui";

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive", "closed"];

export default function IncidentDetail() {
  const { id } = useParams();
  const { message } = App.useApp();
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState("");
  const inc = useApi(() => get<Detail>(`/incidents/${id}`), [id]);
  const acts = useApi(() => get<ResponseAction[]>(`/incidents/${id}/actions`), [id]);
  useLiveRefresh(["analysis_completed", "action_reviewed", "incident_updated"], () => { inc.reload(true); acts.reload(true); });

  const d = inc.data;
  const a = d?.analysis;

  const reanalyze = async () => {
    setBusy(true);
    try { await post(`/incidents/${id}/analyze`, { use_llm: true }); message.success("Re-analysis complete"); inc.reload(); acts.reload(); }
    catch (e) { message.error(errorMessage(e)); } finally { setBusy(false); }
  };
  const setStatus = async (status: string) => {
    try { await patch(`/incidents/${id}`, { status }); message.success(`Status → ${status}`); inc.reload(); }
    catch (e) { message.error(errorMessage(e)); }
  };
  const addNote = async () => {
    if (!note.trim()) return;
    try { await post(`/incidents/${id}/notes`, { body: note }); setNote(""); message.success("Note added"); inc.reload(); }
    catch (e) { message.error(errorMessage(e)); }
  };

  return (
    <Loadable loading={inc.loading && !d} error={inc.error}>
      {d && (
        <>
          <PageHeader
            title={`${d.ref} · ${d.title}`}
            subtitle={d.summary}
            extra={[
              <Select key="s" value={d.status} style={{ width: 160 }} onChange={setStatus}
                options={STATUSES.map((s) => ({ value: s, label: s.replace("_", " ") }))} />,
              <Button key="dl" icon={<DownloadOutlined />} onClick={() => download(`/incidents/${id}/report`, { format: "markdown" }, `${d.ref}.md`)}>Report</Button>,
              <Button key="re" icon={<RobotOutlined />} loading={busy} onClick={reanalyze}>Re-run AI analysis</Button>,
              <Button key="r" icon={<ReloadOutlined />} onClick={() => { inc.reload(); acts.reload(); }} />,
            ]}
          />

          {a?.council?.human_review_recommended && (
            <Alert style={{ marginBottom: 16 }} type="warning" showIcon
              message="Human review recommended"
              description="The council's agreement was contested, the decision margin was narrow, or validation flagged a likely false positive. Review the evidence before approving any response action." />
          )}

          <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
            <Col xs={12} md={6}><Card size="small" className="kpi"><div className="kpi-label">Severity</div><div style={{ marginTop: 6 }}><SeverityTag value={d.severity} /> <StatusTag value={d.status} /></div></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="kpi"><div className="kpi-label">Risk score</div><div className="kpi-value">{d.risk_score.toFixed(0)}</div><RiskBar value={d.risk_score} /></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="kpi"><div className="kpi-label">AI confidence</div><div className="kpi-value">{d.confidence.toFixed(2)}</div><div className="kpi-hint">verdict: {a?.verdict ?? "—"}</div></Card></Col>
            <Col xs={12} md={6}><Card size="small" className="kpi"><div className="kpi-label">Events / analysis</div><div className="kpi-value">{d.event_count}</div><div className="kpi-hint">v{d.analysis_version} · {fmtTime(d.analyzed_at)}</div></Card></Col>
          </Row>

          <Tabs
            defaultActiveKey="overview"
            items={[
              { key: "overview", label: "Overview", children: <OverviewTab d={d} /> },
              { key: "agents", label: `AI Agents (${a ? Object.keys(a.agents).length : 0})`, children: a ? <AgentsTab a={a} /> : <Empty /> },
              { key: "council", label: "AI Council", children: a ? <CouncilTab a={a} /> : <Empty /> },
              { key: "xai", label: "Explainable AI", children: a ? <XaiTab a={a} /> : <Empty /> },
              { key: "graph", label: "Attack Graph", children: <GraphTab id={id!} /> },
              { key: "twin", label: "Digital Twin", children: a ? <TwinTab a={a} /> : <Empty /> },
              { key: "actions", label: `Response (${acts.data?.length ?? 0})`,
                children: <ActionsTable actions={acts.data ?? []} onChange={() => { acts.reload(); inc.reload(); }} /> },
              { key: "llm", label: "LLM Analysis", children: a ? <LlmTab a={a} /> : <Empty /> },
            ]}
          />

          <Card size="small" title="Analyst notes" style={{ marginTop: 16 }}>
            <List
              size="small"
              dataSource={d.notes}
              locale={{ emptyText: "No notes yet" }}
              renderItem={(n) => <List.Item><List.Item.Meta title={`${n.author} · ${fmtTime(n.created_at)}`} description={n.body} /></List.Item>}
            />
            <Space.Compact style={{ width: "100%", marginTop: 8 }}>
              <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an investigation note" onPressEnter={addNote} />
              <Button type="primary" onClick={addNote}>Add</Button>
            </Space.Compact>
          </Card>
        </>
      )}
    </Loadable>
  );
}

function OverviewTab({ d }: { d: Detail }) {
  const nav = useNavigate();
  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={10}>
        <Card size="small" title="Incident facts">
          <Descriptions size="small" column={1} items={[
            { label: "Category", children: d.category },
            { label: "Hosts", children: d.hostnames.join(", ") || "—" },
            { label: "Users", children: d.users.join(", ") || "—" },
            { label: "MITRE tactics", children: <Space wrap>{d.tactics.map((t) => <Tag key={t} color="purple">{t}</Tag>)}</Space> },
            { label: "Techniques", children: <Space wrap>{d.techniques.map((t) => <Tag key={t}>{t}</Tag>)}</Space> },
            { label: "First seen", children: fmtTime(d.first_seen) },
            { label: "Last seen", children: fmtTime(d.last_seen) },
            { label: "Assignee", children: d.assignee ?? "—" },
          ]} />
        </Card>
      </Col>
      <Col xs={24} lg={14}>
        <Card size="small" title="Event timeline" extra={<a onClick={() => nav(`/monitoring`)}>Monitoring</a>}>
          <Timeline
            mode="left"
            items={(d.analysis?.agents.Observer?.findings.timeline ?? []).slice(0, 20).map((e: any) => ({
              color: e.threat_score >= 65 ? "red" : e.threat_score >= 40 ? "orange" : "blue",
              label: <span className="mono" style={{ fontSize: 11 }}>{fmtTime(e.timestamp)}</span>,
              children: <div><b>{e.event_type}</b> {e.technique && <Tag color="purple">{e.technique}</Tag>}<div className="muted" style={{ fontSize: 12 }}>{e.hostname} {e.user ? `· ${e.user}` : ""} · threat {e.threat_score}</div></div>,
            }))}
          />
          {!d.analysis && <Empty description="Run AI analysis to build the timeline" />}
        </Card>
      </Col>
    </Row>
  );
}

function AgentsTab({ a }: { a: NonNullable<Detail["analysis"]> }) {
  const order = ["Observer", "Behavior", "Oracle", "Sentinel", "Intel", "GraphAI", "DigitalTwin", "Risk", "Business"];
  const agents = order.filter((n) => a.agents[n]).map((n) => a.agents[n]);
  return (
    <Row gutter={[16, 16]}>
      {agents.map((ag: AgentResult) => (
        <Col xs={24} md={12} xl={8} key={ag.agent}>
          <Card size="small" title={<Space>{ag.agent}<MethodTag method={ag.method} /></Space>}
            extra={<Tooltip title="Agent confidence"><Progress type="circle" size={34} percent={Math.round(ag.confidence * 100)} /></Tooltip>}>
            <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>{ag.role}</div>
            <Typography.Paragraph style={{ marginBottom: 8 }}>{ag.summary}</Typography.Paragraph>
            {ag.votes && (
              <div className="muted mono" style={{ fontSize: 11 }}>
                top vote: {Object.entries(ag.votes).sort((x, y) => y[1].score - x[1].score)[0]?.[0]}
              </div>
            )}
          </Card>
        </Col>
      ))}
      <Col span={24}>
        <Card size="small" title="Agent pipeline execution">
          <Table size="small" rowKey="agent" pagination={false} dataSource={a.pipeline} columns={[
            { title: "Agent", dataIndex: "agent" },
            { title: "Method", dataIndex: "method", render: (m) => <MethodTag method={m} /> },
            { title: "Status", dataIndex: "status", render: (s) => <StatusTag value={s} /> },
            { title: "Duration", dataIndex: "duration_ms", render: (v: number) => `${v} ms` },
          ]} />
        </Card>
      </Col>
    </Row>
  );
}

function CouncilTab({ a }: { a: NonNullable<Detail["analysis"]> }) {
  const c = a.council;
  return (
    <div className="section-gap">
      <Alert type={c.strength === "strong" ? "success" : c.strength === "moderate" ? "info" : "warning"} showIcon
        icon={<SafetyCertificateOutlined />}
        message={<span>Council decision: <b>{c.decision_name}</b> · consensus {c.consensus_score.toFixed(2)} · {c.strength} agreement {pct(c.agreement)}</span>}
        description={c.rationale} />
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card size="small" title="Weighted votes by agent" extra={<span className="muted">{c.method}</span>}>
            <Table size="small" rowKey="agent" pagination={false} dataSource={c.votes}
              columns={[
                { title: "Agent", dataIndex: "agent" },
                { title: "Weight", dataIndex: "weight", width: 80 },
                { title: "Conf.", dataIndex: "confidence", width: 70 },
                { title: "Effective", dataIndex: "effective_weight", width: 90, render: pct },
                { title: "Prefers", dataIndex: "preferred_name" },
                { title: "Reason", dataIndex: "reason", ellipsis: true, render: (v) => <Tooltip title={v}>{v}</Tooltip> },
              ]} />
          </Card>
        </Col>
        <Col xs={24} lg={10}>
          <Card size="small" title="Consensus ranking">
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={c.ranking} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" domain={[0, 1]} stroke="#64748b" fontSize={11} />
                <YAxis type="category" dataKey="name" width={150} stroke="#94a3b8" fontSize={10} />
                <RTooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
                <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                  {c.ranking.map((r, i) => <Cell key={r.playbook} fill={i === 0 ? "#22d3ee" : "#475569"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </Card>
          <Card size="small" title="Dissent & counterfactuals" style={{ marginTop: 16 }}>
            {c.dissent.length ? c.dissent.map((x) => <div key={x.agent} className="feed-item"><Tag color="orange">{x.agent}</Tag> preferred <b>{x.preferred_name}</b>: {x.reason}</div>)
              : <span className="muted">No dissent — all agents preferred the decision.</span>}
            <div style={{ marginTop: 10 }}>
              {c.ablation.filter((x) => x.pivotal).length
                ? c.ablation.filter((x) => x.pivotal).map((x) => <Tag key={x.without} color="red">without {x.without} → {x.decision_name}</Tag>)
                : <span className="muted">No single agent changes the outcome (robust decision).</span>}
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
}

function XaiTab({ a }: { a: NonNullable<Detail["analysis"]> }) {
  const x = a.xai;
  return (
    <div className="section-gap">
      <Card size="small" title="Why SENTRIX reached this decision" extra={<span className="muted">{x.method}</span>}>
        <Timeline items={x.narrative.map((n) => ({ children: n }))} />
      </Card>
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card size="small" title="Decision factor attribution">
            {x.factor_attribution.map((f) => (
              <div key={f.factor} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}><span>{f.factor}</span><b>{pct(f.share)}</b></div>
                <Progress percent={Math.round(f.share * 100)} showInfo={false} strokeColor="#6366f1" />
              </div>
            ))}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card size="small" title="Agent contribution to the decision margin">
            <Table size="small" rowKey="agent" pagination={false}
              dataSource={[...x.decision_attribution].sort((p, q) => q.contribution_to_margin - p.contribution_to_margin)}
              columns={[
                { title: "Agent", dataIndex: "agent" },
                { title: "Contribution", dataIndex: "contribution_to_margin", width: 120, render: (v: number) => <Tag color={v > 0 ? "green" : v < 0 ? "red" : "default"}>{v >= 0 ? "+" : ""}{v.toFixed(3)}</Tag> },
                { title: "Reason", dataIndex: "reason", ellipsis: true },
              ]} />
          </Card>
        </Col>
      </Row>
      <Card size="small" title="Top evidence">
        {x.evidence.map((e) => (
          <div key={e.event_id} className="feed-item">
            <Space wrap>
              <Tag>{fmtTime(e.timestamp)}</Tag><b>{e.event_type}</b>{e.hostname && <Tag>{e.hostname}</Tag>}<Tag color="red">threat {e.threat_score}</Tag>
            </Space>
            {e.rule_evidence.map((r) => <div key={r.rule} className="muted" style={{ fontSize: 12 }}>↳ <Tag color="purple">{r.technique}</Tag>{r.name}: {r.evidence}</div>)}
            {e.behaviour_evidence.map((b) => <div key={b.indicator} className="muted" style={{ fontSize: 12 }}>↳ <Tag>{b.indicator}</Tag>+{b.contribution.toFixed(2)} {b.detail}</div>)}
          </div>
        ))}
      </Card>
    </div>
  );
}

function GraphTab({ id }: { id: string }) {
  const { data, loading, error } = useApi(() => get<any>(`/graph/incident/${id}`), [id]);
  return (
    <Loadable loading={loading} error={error}>
      {data && (
        <div className="section-gap">
          {data.note && <Alert type="info" showIcon message={data.note} />}
          <Card size="small" title="Predicted attack paths to high-value assets"
            extra={<span className="muted">networkx · most-probable paths (deterministic)</span>}>
            {data.graph?.nodes?.length ? <AttackGraphView nodes={data.graph.nodes} edges={data.graph.edges} /> : <Empty />}
          </Card>
          {data.paths?.length > 0 && (
            <Card size="small" title="Attack paths">
              <Table size="small" rowKey={(r: any) => r.target} pagination={false} dataSource={data.paths} columns={[
                { title: "Target", dataIndex: "target" },
                { title: "Criticality", dataIndex: "target_criticality", render: (v) => <SeverityTag value={v} /> },
                { title: "Path", dataIndex: "path", render: (p: string[]) => <span className="mono">{p.join(" → ")}</span> },
                { title: "Hops", dataIndex: "hops", width: 70 },
                { title: "Probability", dataIndex: "probability", width: 110, render: pct },
              ]} />
            </Card>
          )}
        </div>
      )}
    </Loadable>
  );
}

function TwinTab({ a }: { a: NonNullable<Detail["analysis"]> }) {
  const twin = a.agents.DigitalTwin?.findings;
  if (!twin || twin.status !== "completed") return <Empty description={twin?.reason ?? "No simulation"} />;
  const best = a.council.decision;
  return (
    <div className="section-gap">
      <Alert type="info" showIcon message={`${twin.runs} Monte Carlo runs per response option, seeded for reproducibility (${twin.method})`} />
      <Card size="small" title="Simulated outcome per response playbook">
        <Table size="small" rowKey="playbook" pagination={false}
          dataSource={twin.results}
          rowClassName={(r: any) => (r.playbook === best ? "" : "")}
          columns={[
            { title: "Playbook", dataIndex: "name", render: (v, r: any) => <Space>{v}{r.playbook === best && <Tag color="cyan">chosen</Tag>}</Space> },
            { title: "Exp. hosts compromised", dataIndex: "expected_compromised", width: 150 },
            { title: "Critical compromise p", dataIndex: "critical_asset_compromise_probability", width: 150, render: pct },
            { title: "Exp. breach loss", dataIndex: "expected_breach_loss", width: 140, render: money },
            { title: "Response disruption", dataIndex: "response_disruption_cost", width: 150, render: money },
            { title: "Exp. total cost", dataIndex: "expected_total_cost", width: 140, render: (v) => <b>{money(v)}</b> },
            { title: "Avoided vs monitoring", dataIndex: "cost_avoided_vs_monitoring", width: 160, render: (v: number) => <Tag color={v > 0 ? "green" : "default"}>{money(v)}</Tag> },
          ]} />
      </Card>
      <Card size="small" title="Expected total cost by response option">
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={twin.results} margin={{ bottom: 10 }}>
            <CartesianGrid stroke="rgba(148,163,184,.1)" />
            <XAxis dataKey="name" stroke="#64748b" fontSize={10} angle={-12} textAnchor="end" height={60} interval={0} />
            <YAxis stroke="#64748b" fontSize={11} tickFormatter={(v) => `$${(v / 1000).toFixed(0)}k`} />
            <RTooltip formatter={(v) => money(Number(v))} contentStyle={{ background: "#0f172a", border: "1px solid #334155" }} />
            <Bar dataKey="expected_total_cost" radius={[4, 4, 0, 0]}>
              {twin.results.map((r: any) => <Cell key={r.playbook} fill={r.playbook === best ? "#22d3ee" : "#475569"} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
}

function LlmTab({ a }: { a: NonNullable<Detail["analysis"]> }) {
  const l = a.llm;
  if (l.status !== "ok" || !l.content) {
    return <Alert type="info" showIcon message="LLM narrative not available"
      description={l.status === "disabled" ? "No LLM provider configured. Set LLM_PROVIDER and an API key in backend/.env to enable optional narrative analysis — all detection, scoring and council decisions work without it." : l.reason} />;
  }
  const c = l.content;
  return (
    <div className="section-gap">
      <Alert type="warning" showIcon message={l.label} description={`Generated by ${l.provider}/${l.model} in ${l.latency_ms} ms. The LLM does not influence scores, votes or response actions.`} />
      <Card size="small" title="Executive summary"><Typography.Paragraph>{c.executive_summary}</Typography.Paragraph></Card>
      <Card size="small" title="Attack narrative"><Typography.Paragraph style={{ whiteSpace: "pre-wrap" }}>{c.attack_narrative}</Typography.Paragraph>
        <Typography.Text type="secondary">Assessed objective: {c.attacker_objective}</Typography.Text></Card>
      <Row gutter={16}>
        <Col xs={24} md={12}><Card size="small" title="Recommended next steps"><List size="small" dataSource={c.recommended_next_steps} renderItem={(s) => <List.Item>{s}</List.Item>} /></Card></Col>
        <Col xs={24} md={12}><Card size="small" title="Open questions"><List size="small" dataSource={c.open_questions} renderItem={(s) => <List.Item>{s}</List.Item>} /></Card></Col>
      </Row>
    </div>
  );
}
