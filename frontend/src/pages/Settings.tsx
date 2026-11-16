import { useState } from "react";
import { App, Button, Card, Col, Descriptions, Input, Popconfirm, Row, Select, Space, Tag, Typography } from "antd";
import { get, errorMessage, post, session } from "../api/client";
import { useApi } from "../hooks/useApi";
import { Loadable, MethodTag, PageHeader } from "../components/ui";

export default function Settings() {
  const { message } = App.useApp();
  const status = useApi(() => get<any>("/system/status"));
  const scenarios = useApi(() => get<any[]>("/demo/scenarios"));
  const [actor, setActor] = useState(session.actor);
  const [apiKey, setApiKey] = useState(session.apiKey);
  const [scenario, setScenario] = useState<string>();
  const [busy, setBusy] = useState("");

  const saveIdentity = () => { session.actor = actor; session.apiKey = apiKey; message.success("Saved — reload to apply everywhere"); };
  const act = async (label: string, fn: () => Promise<any>) => {
    setBusy(label);
    try { const r = await fn(); message.success(typeof r === "string" ? r : "Done"); status.reload(); }
    catch (e) { message.error(errorMessage(e)); } finally { setBusy(""); }
  };

  const s = status.data;
  return (
    <>
      <PageHeader title="System & Demo" subtitle="Platform status, analyst identity and synthetic demo data" />
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Loadable loading={status.loading && !s} error={status.error}>
            {s && (
              <Card size="small" title="System status" className="section-gap">
                <Descriptions size="small" column={2} bordered items={[
                  { label: "Application", children: `${s.application} v${s.version}` },
                  { label: "Environment", children: s.environment },
                  { label: "Database", children: s.database },
                  { label: "API key for writes", children: s.api_key_required_for_writes ? <Tag color="green">required</Tag> : <Tag>open (dev)</Tag> },
                  { label: "LLM provider", children: <Space><Tag>{s.llm.provider}</Tag>{s.llm.configured ? <Tag color="green">configured</Tag> : <Tag>disabled</Tag>}</Space> },
                  { label: "LLM model", children: s.llm.model ?? "—" },
                  { label: "SOAR webhook", children: s.soar_webhook_configured ? <Tag color="green">configured</Tag> : <Tag>manual tasks</Tag> },
                  { label: "Isolation Forest", children: `${s.ml_model.isolation_forest} (${s.ml_model.trained_on_events} events)` },
                ]} />
                <Descriptions size="small" column={4} style={{ marginTop: 12 }} title="Record counts"
                  items={Object.entries(s.counts).map(([k, v]) => ({ label: k, children: String(v) }))} />
                <div style={{ marginTop: 12 }}>
                  <Typography.Text type="secondary">Capabilities: </Typography.Text>
                  {["deterministic", "machine_learning", "simulation", "llm_optional"].map((k) => (
                    <div key={k} style={{ marginTop: 6 }}>
                      <MethodTag method={k === "machine_learning" ? "machine-learning" : k === "llm_optional" ? "llm" : k} />
                      <span className="muted" style={{ fontSize: 12 }}> {s.capabilities[k].join(", ")}</span>
                    </div>
                  ))}
                </div>
              </Card>
            )}
          </Loadable>
        </Col>
        <Col xs={24} lg={10}>
          <Card size="small" title="Analyst identity" className="section-gap" style={{ marginBottom: 16 }}>
            <Typography.Paragraph type="secondary">Recorded in the audit log (X-Actor) and sent with each request. The API key (X-API-Key) is only needed if the backend sets API_KEY. Both are stored in this browser only.</Typography.Paragraph>
            <Space direction="vertical" style={{ width: "100%" }}>
              <Input addonBefore="Actor" value={actor} onChange={(e) => setActor(e.target.value)} />
              <Input.Password addonBefore="API key" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="(optional)" />
              <Button type="primary" onClick={saveIdentity}>Save identity</Button>
            </Space>
          </Card>
          <Card size="small" title="Demo data (synthetic)">
            <Typography.Paragraph type="secondary">Load the fictional &quot;Meridian Energy&quot; environment and replay attack scenarios through the real ingestion pipeline.</Typography.Paragraph>
            <Space direction="vertical" style={{ width: "100%" }}>
              <Button block loading={busy === "setup"} onClick={() => act("setup", () => post("/demo/setup").then((r: any) => `${r.assets_added} assets, ${r.baseline_events_added} baseline events`))}>
                1. Load assets & baseline telemetry
              </Button>
              <Space.Compact style={{ width: "100%" }}>
                <Select style={{ width: "100%" }} placeholder="Choose a scenario" value={scenario} onChange={setScenario}
                  options={(scenarios.data ?? []).map((sc) => ({ value: sc.name, label: `${sc.title} (${sc.events} events)` }))} />
                <Button type="primary" loading={busy === "run"} disabled={!scenario}
                  onClick={() => act("run", () => post("/demo/run", { scenario }).then((r: any) => `Ingested ${r.events_ingested} events → incidents ${r.incidents.join(", ")}`))}>
                  2. Run
                </Button>
              </Space.Compact>
              <Popconfirm title="Delete all events, incidents, decisions and actions?" description="Assets, intel and audit log are kept." okType="danger"
                onConfirm={() => act("reset", () => post("/demo/reset", undefined, { confirm: "RESET" }).then(() => "Operational data cleared"))}>
                <Button block danger loading={busy === "reset"}>Reset operational data</Button>
              </Popconfirm>
            </Space>
          </Card>
        </Col>
      </Row>
    </>
  );
}
