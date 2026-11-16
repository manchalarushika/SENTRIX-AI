import { useState } from "react";
import { Button, Card, Form, Input, Select, Table, Tag } from "antd";
import { DownloadOutlined } from "@ant-design/icons";
import { download, get } from "../api/client";
import type { AuditEntry, Page } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { Loadable, PageHeader, fmtTime } from "../components/ui";

export default function Audit() {
  const [filters, setFilters] = useState<Record<string, any>>({});
  const [page, setPage] = useState({ current: 1, pageSize: 25 });
  const { data, loading, error, reload } = useApi(
    () => get<Page<AuditEntry>>("/audit", { ...filters, limit: page.pageSize, offset: (page.current - 1) * page.pageSize }),
    [JSON.stringify(filters), page.current, page.pageSize],
  );
  useLiveRefresh(["action_reviewed", "incident_updated", "events_ingested", "analysis_completed"], () => reload(true));

  return (
    <>
      <PageHeader title="Reports & Audit Log"
        subtitle="Immutable record of every state-changing action — ingestion, analysis, approvals, configuration"
        extra={<Button icon={<DownloadOutlined />} onClick={() => download("/audit/export.csv", filters, "sentrix_audit_log.csv")}>Export CSV</Button>} />
      <Card size="small" style={{ marginBottom: 16 }}>
        <Form layout="inline" onFinish={(v) => { setPage((p) => ({ ...p, current: 1 })); setFilters(v); }}>
          <Form.Item name="actor"><Input allowClear placeholder="Actor" style={{ width: 160 }} /></Form.Item>
          <Form.Item name="action"><Input allowClear placeholder="Action (e.g. action.approve)" style={{ width: 220 }} /></Form.Item>
          <Form.Item name="entity_type"><Select allowClear placeholder="Entity" style={{ width: 160 }}
            options={["incident", "response_action", "asset", "user", "event", "intel_document", "demo"].map((e) => ({ value: e, label: e }))} /></Form.Item>
          <Form.Item><Button type="primary" htmlType="submit">Filter</Button></Form.Item>
        </Form>
      </Card>
      <Card size="small">
        <Loadable loading={loading} error={error}>
          <Table size="small" rowKey="id" dataSource={data?.items ?? []}
            pagination={{ ...page, total: data?.total ?? 0, showSizeChanger: true, onChange: (current, pageSize) => setPage({ current, pageSize }) }}
            expandable={{ expandedRowRender: (r) => <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap" }}>{JSON.stringify(r.details, null, 2)}</pre> }}
            columns={[
              { title: "Time", dataIndex: "timestamp", width: 170, render: fmtTime },
              { title: "Actor", dataIndex: "actor", width: 150 },
              { title: "Action", dataIndex: "action", width: 170, render: (v) => <Tag>{v}</Tag> },
              { title: "Entity", dataIndex: "entity_type", width: 130 },
              { title: "ID", dataIndex: "entity_id", width: 80 },
              { title: "Outcome", dataIndex: "outcome", width: 100, render: (v) => <Tag color={v === "success" ? "green" : v === "denied" ? "red" : "default"}>{v}</Tag> },
              { title: "IP", dataIndex: "ip", width: 120 },
            ]} />
        </Loadable>
      </Card>
    </>
  );
}
