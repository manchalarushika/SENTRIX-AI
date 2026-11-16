import { Card, Col, Empty, Row, Table } from "antd";
import { get } from "../api/client";
import { useApi } from "../hooks/useApi";
import { AttackGraphView } from "../components/AttackGraphView";
import { Loadable, PageHeader, SeverityTag, pct } from "../components/ui";

export default function GraphPage() {
  const { data, loading, error } = useApi(() => get<any>("/graph/enterprise"));
  return (
    <>
      <PageHeader title="Enterprise Attack Graph"
        subtitle="Most-probable attack paths from the Internet to high-value assets (networkx, deterministic)" />
      <Loadable loading={loading} error={error}>
        {data && (
          <div className="section-gap">
            {data.note && <Empty description={data.note} />}
            <Card size="small" title="Attack surface — paths highlighted in red">
              {data.graph?.nodes?.length ? <AttackGraphView nodes={data.graph.nodes} edges={data.graph.edges} height={560} /> : <Empty />}
            </Card>
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={14}>
                <Card size="small" title="Most-probable attack paths from the Internet">
                  <Table size="small" rowKey={(r: any) => r.target} pagination={false} dataSource={data.paths ?? []}
                    locale={{ emptyText: "No internet-facing paths" }}
                    columns={[
                      { title: "Target", dataIndex: "target" },
                      { title: "Criticality", dataIndex: "target_criticality", width: 110, render: (v) => <SeverityTag value={v} /> },
                      { title: "Path", dataIndex: "path", render: (p) => <span className="mono">{(p as string[]).join(" → ")}</span> },
                      { title: "Prob.", dataIndex: "probability", width: 90, render: (v) => pct(v as number) },
                    ]} />
                </Card>
              </Col>
              <Col xs={24} lg={10}>
                <Card size="small" title="Choke points (betweenness centrality)">
                  <Table size="small" rowKey="hostname" pagination={false} dataSource={data.centrality ?? []}
                    locale={{ emptyText: "No data" }}
                    columns={[
                      { title: "Host", dataIndex: "hostname" },
                      { title: "Centrality", dataIndex: "betweenness", render: (v: number) => v.toFixed(3) },
                    ]} />
                </Card>
              </Col>
            </Row>
          </div>
        )}
      </Loadable>
    </>
  );
}
