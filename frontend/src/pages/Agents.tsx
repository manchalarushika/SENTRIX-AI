import { Card, Col, Row, Space, Table, Tag, Typography } from "antd";
import { get } from "../api/client";
import { useApi } from "../hooks/useApi";
import { Loadable, MethodTag, PageHeader } from "../components/ui";

interface AgentInfo {
  name: string; role: string; method: string; votes_in_council: boolean;
  council_weight: number | null; runs: number; avg_ms?: number; avg_confidence?: number; errors?: number;
}

export default function Agents() {
  const { data, loading, error } = useApi(() => get<AgentInfo[]>("/agents"));
  return (
    <>
      <PageHeader title="AI Agents"
        subtitle="The multi-agent pipeline: each agent analyses an incident from one angle; voting agents feed the AI Council" />
      <Loadable loading={loading} error={error}>
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          {(data ?? []).map((a) => (
            <Col xs={24} md={12} xl={8} key={a.name}>
              <Card size="small" title={<Space>{a.name}<MethodTag method={a.method} /></Space>}
                extra={a.votes_in_council ? <Tag color="cyan">council weight {a.council_weight}</Tag> : <Tag>advisory</Tag>}>
                <Typography.Paragraph type="secondary" style={{ minHeight: 44 }}>{a.role}</Typography.Paragraph>
                <Space split="·" className="muted" style={{ fontSize: 12 }}>
                  <span>{a.runs} runs</span>
                  {a.avg_ms != null && <span>{a.avg_ms} ms avg</span>}
                  {a.avg_confidence != null && <span>conf {a.avg_confidence.toFixed(2)}</span>}
                  {a.errors ? <span style={{ color: "#ef4444" }}>{a.errors} errors</span> : null}
                </Space>
              </Card>
            </Col>
          ))}
        </Row>
        <Card size="small" title="Pipeline order & method">
          <Table size="small" rowKey="name" pagination={false} dataSource={data ?? []} columns={[
            { title: "Agent", dataIndex: "name" },
            { title: "Role", dataIndex: "role" },
            { title: "Method", dataIndex: "method", width: 130, render: (m) => <MethodTag method={m} /> },
            { title: "Council", dataIndex: "votes_in_council", width: 130, render: (v, r) => v ? <Tag color="cyan">weight {r.council_weight}</Tag> : <span className="muted">advisory</span> },
            { title: "Runs", dataIndex: "runs", width: 80 },
          ]} />
        </Card>
      </Loadable>
    </>
  );
}
