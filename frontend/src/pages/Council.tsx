import { useState } from "react";
import { Card, Drawer, Space, Table, Tag, Tooltip } from "antd";
import { useNavigate } from "react-router-dom";
import { get } from "../api/client";
import type { CouncilDecision, Page } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { Loadable, PageHeader, fmtTime, pct } from "../components/ui";

export default function CouncilPage() {
  const nav = useNavigate();
  const [sel, setSel] = useState<CouncilDecision | null>(null);
  const { data, loading, error, reload } = useApi(() => get<Page<CouncilDecision>>("/council/decisions", { limit: 100 }));
  useLiveRefresh(["analysis_completed"], () => reload(true));

  return (
    <>
      <PageHeader title="AI Council Decisions"
        subtitle="Confidence-weighted consensus of the voting agents over candidate response playbooks" />
      <Card size="small">
        <Loadable loading={loading} error={error}>
          <Table
            size="small"
            rowKey="id"
            dataSource={data?.items ?? []}
            pagination={{ pageSize: 20 }}
            onRow={(r) => ({ onClick: () => setSel(r), className: "clickable" })}
            columns={[
              { title: "When", dataIndex: "created_at", width: 170, render: fmtTime },
              { title: "Incident", dataIndex: "incident_id", width: 100, render: (v) => <a onClick={(e) => { e.stopPropagation(); nav(`/incidents/${v}`); }}>#{v}</a> },
              { title: "Decision", dataIndex: "decided_playbook_name" },
              { title: "Consensus", dataIndex: "consensus_score", width: 110, render: (v: number) => v.toFixed(2) },
              { title: "Agreement", dataIndex: "agreement", width: 110, render: pct },
              { title: "Voters", dataIndex: "votes", width: 90, render: (v: any[]) => v.length },
              { title: "Dissent", dataIndex: "dissent", width: 160, render: (v: any[]) => v.length ? <Space wrap>{v.map((d) => <Tag key={d.agent} color="orange">{d.agent}</Tag>)}</Space> : <span className="muted">none</span> },
            ]}
          />
        </Loadable>
      </Card>
      <Drawer width={620} open={!!sel} onClose={() => setSel(null)} title={sel ? `Decision #${sel.id} · ${sel.decided_playbook_name}` : ""}>
        {sel && (
          <div className="section-gap">
            <p>{sel.rationale}</p>
            <Card size="small" title="Votes">
              <Table size="small" rowKey="agent" pagination={false} dataSource={sel.votes} columns={[
                { title: "Agent", dataIndex: "agent" },
                { title: "Eff. weight", dataIndex: "effective_weight", render: pct },
                { title: "Prefers", dataIndex: "preferred_name" },
                { title: "Reason", dataIndex: "reason", ellipsis: true, render: (v) => <Tooltip title={v}>{v}</Tooltip> },
              ]} />
            </Card>
            <Card size="small" title="Ranking">
              {sel.ranking.map((r, i) => <div key={r.playbook} className="feed-item"><Tag color={i === 0 ? "cyan" : "default"}>{r.score.toFixed(2)}</Tag>{r.name}</div>)}
            </Card>
          </div>
        )}
      </Drawer>
    </>
  );
}
