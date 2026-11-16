import { useState } from "react";
import { App, Button, Card, Input, Space, Switch, Table, Tag, Typography } from "antd";
import { SearchOutlined } from "@ant-design/icons";
import { errorMessage, get, post } from "../api/client";
import type { IntelDoc, Page } from "../api/types";
import { useApi } from "../hooks/useApi";
import { Loadable, PageHeader } from "../components/ui";

const TYPE_COLOR: Record<string, string> = { mitre_technique: "purple", cve: "red", playbook: "cyan", advisory: "gold", custom: "blue" };

export default function Intel() {
  const { message } = App.useApp();
  const [query, setQuery] = useState("");
  const [synth, setSynth] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const docs = useApi(() => get<Page<IntelDoc>>("/intel/documents", { limit: 500 }));

  const search = async () => {
    if (!query.trim()) return;
    setBusy(true);
    try { setResult(await post<any>("/intel/search", { query, top_k: 6, synthesize: synth })); }
    catch (e) { message.error(errorMessage(e)); } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader title="Threat Intelligence (RAG)"
        subtitle="TF-IDF retrieval over MITRE ATT&CK, CISA KEV and playbook knowledge; optional LLM synthesis grounded in retrieved docs" />
      <Card size="small" style={{ marginBottom: 16 }}>
        <Space.Compact style={{ width: "100%" }}>
          <Input size="large" value={query} onChange={(e) => setQuery(e.target.value)} onPressEnter={search}
            placeholder="e.g. lateral movement with admin shares, or CVE-2021-44228, or T1486" />
          <Button size="large" type="primary" icon={<SearchOutlined />} loading={busy} onClick={search}>Search</Button>
        </Space.Compact>
        <Space style={{ marginTop: 10 }}>
          <Switch checked={synth} onChange={setSynth} size="small" />
          <span className="muted">Synthesize an answer with the configured LLM (grounded in retrieved documents)</span>
        </Space>
      </Card>

      {result && (
        <Card size="small" title="Answer" style={{ marginBottom: 16 }}
          extra={<Tag color={result.answer_method?.includes("llm") ? "magenta" : "blue"}>{result.answer_method}</Tag>}>
          <Typography.Paragraph style={{ whiteSpace: "pre-wrap" }}>{result.answer}</Typography.Paragraph>
          {result.llm?.status === "disabled" && <Tag>LLM disabled — set LLM_PROVIDER in backend/.env to enable synthesis</Tag>}
          {result.llm?.status === "error" && <Tag color="red">LLM error: {result.llm.reason}</Tag>}
          <div style={{ marginTop: 12 }}>
            {result.documents.map((d: IntelDoc) => (
              <div key={d.doc_id} className="feed-item">
                <Space><Tag color={TYPE_COLOR[d.doc_type]}>{d.doc_id}</Tag><b>{d.title}</b><span className="muted">score {d.score?.toFixed(3)}</span></Space>
                {d.url && <a href={d.url} target="_blank" rel="noreferrer" style={{ marginLeft: 8 }}>source ↗</a>}
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card size="small" title="Knowledge base">
        <Loadable loading={docs.loading} error={docs.error}>
          <Table size="small" rowKey="doc_id" dataSource={docs.data?.items ?? []} pagination={{ pageSize: 15 }}
            expandable={{ expandedRowRender: (d) => <Typography.Paragraph style={{ whiteSpace: "pre-wrap", margin: 0 }}>{d.body}</Typography.Paragraph> }}
            columns={[
              { title: "ID", dataIndex: "doc_id", width: 160 },
              { title: "Type", dataIndex: "doc_type", width: 150, render: (v) => <Tag color={TYPE_COLOR[v]}>{v}</Tag> },
              { title: "Title", dataIndex: "title" },
              { title: "Source", dataIndex: "source", width: 200, render: (v) => <span className="muted">{v}</span> },
            ]} />
        </Loadable>
      </Card>
    </>
  );
}
