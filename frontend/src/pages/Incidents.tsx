import { useState } from "react";
import { Button, Card, Form, Input, Select, Space, Table, Tag } from "antd";
import { ReloadOutlined } from "@ant-design/icons";
import { useNavigate, useSearchParams } from "react-router-dom";
import { get } from "../api/client";
import type { Incident, Page } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { PageHeader, RiskBar, SeverityTag, StatusTag, fmtTime, fromNow } from "../components/ui";

const STATUSES = ["open", "investigating", "contained", "resolved", "false_positive", "closed"];

export default function Incidents() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [filters, setFilters] = useState<Record<string, any>>({ severity: params.get("severity") ?? undefined, sort: "last_seen" });
  const [page, setPage] = useState({ current: 1, pageSize: 20 });
  const { data, loading, error, reload } = useApi(
    () => get<Page<Incident>>("/incidents", { ...filters, limit: page.pageSize, offset: (page.current - 1) * page.pageSize }),
    [JSON.stringify(filters), page.current, page.pageSize],
  );
  useLiveRefresh(["analysis_completed", "incident_updated", "events_ingested"], () => reload(true));

  return (
    <>
      <PageHeader title="Incidents" subtitle="Correlated incidents with AI analysis — current and historical"
        extra={<Button icon={<ReloadOutlined />} onClick={() => reload()}>Refresh</Button>} />
      <Card size="small" style={{ marginBottom: 16 }}>
        <Form layout="inline" initialValues={filters} onFinish={(v) => { setPage((p) => ({ ...p, current: 1 })); setFilters(v); }}>
          <Form.Item name="q"><Input allowClear placeholder="Search ref / title / summary" style={{ width: 240 }} /></Form.Item>
          <Form.Item name="status"><Select allowClear mode="multiple" placeholder="Status" style={{ minWidth: 180 }}
            options={STATUSES.map((s) => ({ value: s, label: s.replace("_", " ") }))} /></Form.Item>
          <Form.Item name="severity"><Select allowClear placeholder="Severity" style={{ width: 130 }}
            options={["critical", "high", "medium", "low", "info"].map((s) => ({ value: s, label: s }))} /></Form.Item>
          <Form.Item name="hostname"><Input allowClear placeholder="Host" style={{ width: 140 }} /></Form.Item>
          <Form.Item name="sort"><Select style={{ width: 160 }} options={[
            { value: "last_seen", label: "Sort: last activity" }, { value: "risk_score", label: "Sort: risk" }, { value: "first_seen", label: "Sort: first seen" }]} /></Form.Item>
          <Form.Item><Button type="primary" htmlType="submit">Apply</Button></Form.Item>
        </Form>
      </Card>
      <Card size="small">
        <Table
          size="middle"
          rowKey="id"
          loading={loading}
          dataSource={data?.items ?? []}
          locale={{ emptyText: error ?? "No incidents" }}
          pagination={{ ...page, total: data?.total ?? 0, showSizeChanger: true, onChange: (current, pageSize) => setPage({ current, pageSize }) }}
          onRow={(r) => ({ onClick: () => nav(`/incidents/${r.id}`), className: "clickable" })}
          columns={[
            { title: "Ref", dataIndex: "ref", width: 105 },
            { title: "Title", dataIndex: "title", render: (v, r) => <div><div>{v}</div><Space size={4} wrap>{r.tactics.slice(0, 4).map((t) => <Tag key={t} color="purple" style={{ fontSize: 10 }}>{t}</Tag>)}</Space></div> },
            { title: "Severity", dataIndex: "severity", width: 100, render: (v) => <SeverityTag value={v} /> },
            { title: "Status", dataIndex: "status", width: 125, render: (v) => <StatusTag value={v} /> },
            { title: "Risk", dataIndex: "risk_score", width: 110, render: (v) => <RiskBar value={v} /> },
            { title: "Conf.", dataIndex: "confidence", width: 70, render: (v: number) => v.toFixed(2) },
            { title: "Events", dataIndex: "event_count", width: 75 },
            { title: "Hosts", dataIndex: "hostnames", width: 180, ellipsis: true, render: (v: string[]) => v.join(", ") },
            { title: "Assignee", dataIndex: "assignee", width: 110, render: (v) => v ?? <span className="muted">—</span> },
            { title: "First seen", dataIndex: "first_seen", width: 160, render: fmtTime },
            { title: "Last activity", dataIndex: "last_seen", width: 120, render: fromNow },
          ]}
        />
      </Card>
    </>
  );
}
