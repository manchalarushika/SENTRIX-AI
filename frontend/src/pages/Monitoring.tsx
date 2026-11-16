import { useState } from "react";
import { App, Button, Card, Descriptions, Drawer, Form, Input, InputNumber, Modal, Select, Space, Switch, Table, Tag, Upload } from "antd";
import { PlusOutlined, ReloadOutlined, UploadOutlined } from "@ant-design/icons";
import { useNavigate } from "react-router-dom";
import { errorMessage, get, post, upload } from "../api/client";
import type { Page, SecurityEvent } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { PageHeader, RiskBar, SeverityTag, fmtTime } from "../components/ui";

const FORMATS = ["generic", "windows", "sysmon", "syslog", "firewall", "edr", "cloud"];

export default function Monitoring() {
  const { message } = App.useApp();
  const nav = useNavigate();
  const [filters, setFilters] = useState<Record<string, any>>({ exclude_baseline: true });
  const [page, setPage] = useState({ current: 1, pageSize: 25 });
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [ingestOpen, setIngestOpen] = useState(false);
  const [uploadFormat, setUploadFormat] = useState("generic");
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm();

  const { data, loading, error, reload } = useApi(
    () => get<Page<SecurityEvent>>("/events", { ...filters, limit: page.pageSize, offset: (page.current - 1) * page.pageSize }),
    [JSON.stringify(filters), page.current, page.pageSize],
  );
  useLiveRefresh(["events_ingested"], () => live && reload(true));

  const submit = async () => {
    const v = await form.validateFields();
    setBusy(true);
    try {
      let raw: Record<string, unknown> | undefined;
      if (v.raw) {
        try { raw = JSON.parse(v.raw); } catch { throw new Error("Raw payload must be valid JSON"); }
      }
      const body = { ...v, raw };
      Object.keys(body).forEach((k) => (body[k] === "" || body[k] === undefined) && delete body[k]);
      const res = await post<any>("/events", body);
      message.success(res.duplicates ? "Duplicate event ignored" : `Event ingested${res.incidents_touched.length ? ` → incident ${res.incidents_touched.join(", ")}` : ""}`);
      setIngestOpen(false);
      form.resetFields();
      reload();
    } catch (e: any) {
      message.error(e?.message && !e.response ? e.message : errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader
        title="Threat Monitoring"
        subtitle="Normalized security events with MITRE classification, behavioural anomaly and threat scores"
        extra={[
          <Space key="live"><Switch checked={live} onChange={setLive} size="small" /> Live refresh</Space>,
          <Upload key="up" accept=".json,.jsonl,.ndjson,.csv" showUploadList={false}
            beforeUpload={async (f) => {
              setBusy(true);
              try {
                const r = await upload<any>("/events/upload", f, { format: uploadFormat });
                message.success(`${r.accepted} accepted, ${r.duplicates} duplicates, ${r.rejected} rejected`);
                reload();
              } catch (e) { message.error(errorMessage(e)); } finally { setBusy(false); }
              return false;
            }}>
            <Space.Compact>
              <Select value={uploadFormat} onChange={setUploadFormat} style={{ width: 110 }} options={FORMATS.map((f) => ({ value: f, label: f }))} />
              <Button icon={<UploadOutlined />} loading={busy}>Upload file</Button>
            </Space.Compact>
          </Upload>,
          <Button key="add" type="primary" icon={<PlusOutlined />} onClick={() => setIngestOpen(true)}>Ingest event</Button>,
          <Button key="r" icon={<ReloadOutlined />} onClick={() => reload()} />,
        ]}
      />
      <Card size="small" style={{ marginBottom: 16 }}>
        <Form layout="inline" onFinish={(v) => { setPage((p) => ({ ...p, current: 1 })); setFilters({ ...v, exclude_baseline: filters.exclude_baseline }); }}>
          <Form.Item name="q"><Input allowClear placeholder="Search text / technique" style={{ width: 200 }} /></Form.Item>
          <Form.Item name="severity"><Select allowClear placeholder="Severity" style={{ width: 130 }} options={["critical", "high", "medium", "low", "info"].map((s) => ({ value: s, label: s }))} /></Form.Item>
          <Form.Item name="hostname"><Input allowClear placeholder="Host" style={{ width: 140 }} /></Form.Item>
          <Form.Item name="user"><Input allowClear placeholder="User" style={{ width: 120 }} /></Form.Item>
          <Form.Item name="min_threat"><InputNumber min={0} max={100} placeholder="Min threat" style={{ width: 110 }} /></Form.Item>
          <Form.Item><Button htmlType="submit" type="primary">Apply</Button></Form.Item>
          <Form.Item><Space><Switch size="small" checked={filters.exclude_baseline} onChange={(c) => setFilters((f) => ({ ...f, exclude_baseline: c }))} />Hide synthetic baseline</Space></Form.Item>
        </Form>
      </Card>
      <Card size="small">
        <Table
          size="small"
          rowKey="id"
          loading={loading}
          dataSource={data?.items ?? []}
          locale={{ emptyText: error ?? "No events" }}
          pagination={{ ...page, total: data?.total ?? 0, showSizeChanger: true, onChange: (current, pageSize) => setPage({ current, pageSize }) }}
          onRow={(r) => ({ onClick: () => setSelected(r), className: "clickable" })}
          columns={[
            { title: "Time", dataIndex: "timestamp", width: 165, render: fmtTime },
            { title: "Severity", dataIndex: "severity", width: 100, render: (v) => <SeverityTag value={v} /> },
            { title: "Event", dataIndex: "event_type", ellipsis: true },
            { title: "Host", dataIndex: "hostname", width: 140 },
            { title: "User", dataIndex: "user", width: 110 },
            { title: "MITRE", dataIndex: "mitre_technique", width: 100, render: (v) => v && <Tag color="purple">{v}</Tag> },
            { title: "Anomaly", dataIndex: "anomaly_score", width: 85, render: (v: number) => v.toFixed(2) },
            { title: "Threat", dataIndex: "threat_score", width: 110, render: (v) => <RiskBar value={v} /> },
            { title: "Incident", dataIndex: "incident_id", width: 90, render: (v) => v && <a onClick={(e) => { e.stopPropagation(); nav(`/incidents/${v}`); }}>#{v}</a> },
          ]}
        />
      </Card>

      <Drawer width={640} open={!!selected} onClose={() => setSelected(null)} title={selected ? `Event #${selected.id} · ${selected.event_type}` : ""}>
        {selected && (
          <div className="section-gap">
            <Descriptions size="small" column={2} bordered items={[
              { label: "Time", children: fmtTime(selected.timestamp) },
              { label: "Source", children: `${selected.source} (${selected.source_format})` },
              { label: "Host", children: selected.hostname ?? "-" },
              { label: "User", children: selected.user ?? "-" },
              { label: "Src IP", children: selected.src_ip ?? "-" },
              { label: "Dst", children: selected.dst_ip ? `${selected.dst_ip}:${selected.dst_port ?? ""}` : "-" },
              { label: "Category", children: selected.category },
              { label: "MITRE", children: selected.mitre_technique ? `${selected.mitre_technique} ${selected.classification?.technique_name ?? ""} (${selected.mitre_tactic})` : "-" },
              { label: "Threat score", children: selected.threat_score },
              { label: "Anomaly score", children: selected.anomaly_score },
              { label: "Process", span: 2, children: <span className="mono">{selected.process ?? "-"}</span> },
              { label: "Command line", span: 2, children: <span className="mono">{selected.command_line ?? "-"}</span> },
              { label: "Description", span: 2, children: selected.description },
            ]} />
            <Card size="small" title="Rule evidence (deterministic)">
              {selected.classification?.indicators?.length ? selected.classification.indicators.map((i) => (
                <div key={i.rule} className="feed-item"><Tag color="purple">{i.technique}</Tag><b>{i.name}</b> — {i.evidence}</div>
              )) : <span className="muted">No detection rule matched.</span>}
              {selected.classification?.recommendation && <p className="muted" style={{ marginTop: 8 }}>Recommendation: {selected.classification.recommendation}</p>}
            </Card>
            <Card size="small" title="Behavioural indicators (UEBA + Isolation Forest)">
              {selected.anomaly_details?.indicators?.length ? selected.anomaly_details.indicators.map((i) => (
                <div key={i.indicator} className="feed-item"><Tag>{i.indicator}</Tag>+{i.contribution.toFixed(2)} — {i.detail}</div>
              )) : <span className="muted">No behavioural deviation.</span>}
              <pre className="mono muted" style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>{JSON.stringify(selected.anomaly_details?.baseline ?? {}, null, 2)}</pre>
            </Card>
          </div>
        )}
      </Drawer>

      <Modal title="Ingest security event" open={ingestOpen} onCancel={() => setIngestOpen(false)} onOk={submit} confirmLoading={busy} okText="Ingest" width={640}>
        <Form form={form} layout="vertical" initialValues={{ format: "generic", source: "manual" }}>
          <Space.Compact block>
            <Form.Item name="format" label="Format" style={{ width: "30%" }}><Select options={FORMATS.map((f) => ({ value: f, label: f }))} /></Form.Item>
            <Form.Item name="source" label="Source" style={{ width: "30%" }} rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="severity" label="Severity hint" style={{ width: "40%" }}><Select allowClear options={["info", "low", "medium", "high", "critical"].map((s) => ({ value: s, label: s }))} /></Form.Item>
          </Space.Compact>
          <Form.Item name="event_type" label="Event type" tooltip="e.g. Failed Logon, Process Creation, Malware Detected"><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="hostname" label="Host" style={{ width: "50%" }}><Input /></Form.Item>
            <Form.Item name="user" label="User" style={{ width: "50%" }}><Input /></Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="src_ip" label="Source IP" style={{ width: "35%" }}><Input /></Form.Item>
            <Form.Item name="dst_ip" label="Destination IP" style={{ width: "35%" }}><Input /></Form.Item>
            <Form.Item name="dst_port" label="Dst port" style={{ width: "30%" }}><InputNumber min={0} max={65535} style={{ width: "100%" }} /></Form.Item>
          </Space.Compact>
          <Form.Item name="description" label="Description"><Input.TextArea rows={2} /></Form.Item>
          <Form.Item name="raw" label="Raw vendor payload (JSON, optional)" tooltip='e.g. {"EventID":4625,"Computer":"DC-01","EventData":{"TargetUserName":"bob"}} with format=windows'>
            <Input.TextArea rows={3} className="mono" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
}
