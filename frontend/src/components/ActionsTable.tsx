import { useState } from "react";
import { App, Button, Input, Modal, Space, Table, Tag, Tooltip } from "antd";
import { CheckOutlined, CloseOutlined } from "@ant-design/icons";
import { errorMessage, post } from "../api/client";
import type { ResponseAction } from "../api/types";
import { StatusTag, fmtTime } from "./ui";

const RISK_COLOR: Record<string, string> = { low: "green", medium: "gold", high: "red" };

/** Response-action table with the human-in-the-loop approval workflow. */
export function ActionsTable({ actions, onChange, showIncident = false }: {
  actions: ResponseAction[];
  onChange: () => void;
  showIncident?: boolean;
}) {
  const { message, modal } = App.useApp();
  const [note, setNote] = useState("");
  const [target, setTarget] = useState<ResponseAction | null>(null);
  const [busy, setBusy] = useState(false);

  const review = async (a: ResponseAction, decision: "approve" | "reject", n?: string) => {
    setBusy(true);
    try {
      await post(`/actions/${a.id}/review`, { decision, note: n });
      message.success(`Action ${decision === "approve" ? "approved" : "rejected"}`);
      onChange();
    } catch (e) { message.error(errorMessage(e)); } finally { setBusy(false); setTarget(null); setNote(""); }
  };
  const complete = async (a: ResponseAction) => {
    try { await post(`/actions/${a.id}/complete`, {}); message.success("Marked completed"); onChange(); }
    catch (e) { message.error(errorMessage(e)); }
  };

  const approve = (a: ResponseAction) => {
    if (a.risk_level === "high") { setTarget(a); return; }
    modal.confirm({
      title: "Approve response action?",
      content: <div>{a.description}<br /><b>Target:</b> {a.target}</div>,
      okText: "Approve", onOk: () => review(a, "approve"),
    });
  };

  return (
    <>
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={actions}
        locale={{ emptyText: "No response actions" }}
        columns={[
          ...(showIncident ? [{ title: "Incident", dataIndex: "incident_id", width: 90, render: (v: number) => <a href={`/incidents/${v}`}>#{v}</a> }] : []),
          { title: "Action", dataIndex: "description", render: (v, r) => <div>{v}<div className="muted mono" style={{ fontSize: 11 }}>{r.action_type} · {r.playbook}</div></div> },
          { title: "Target", dataIndex: "target", width: 160, ellipsis: true, render: (v) => <span className="mono">{v}</span> },
          { title: "Risk", dataIndex: "risk_level", width: 90, render: (v) => <Tag color={RISK_COLOR[v]}>{v}</Tag> },
          { title: "Status", dataIndex: "status", width: 130, render: (v) => <StatusTag value={v} /> },
          { title: "Reviewed by", dataIndex: "reviewed_by", width: 130, render: (v, r) => v ? <Tooltip title={`${fmtTime(r.reviewed_at)}${r.review_note ? ` · ${r.review_note}` : ""}`}>{v}</Tooltip> : <span className="muted">—</span> },
          {
            title: "Decision", width: 200, render: (_, a) => {
              if (a.status === "proposed") return (
                <Space>
                  <Button size="small" type="primary" icon={<CheckOutlined />} onClick={() => approve(a)}>Approve</Button>
                  <Button size="small" danger icon={<CloseOutlined />} onClick={() => review(a, "reject")}>Reject</Button>
                </Space>
              );
              if (a.status === "pending_manual" || a.status === "dispatched" || a.status === "failed")
                return <Button size="small" onClick={() => complete(a)}>Mark done</Button>;
              return <span className="muted">—</span>;
            },
          },
        ]}
        expandable={{
          expandedRowRender: (a) => (
            <div className="muted" style={{ fontSize: 12 }}>
              {a.dispatch_result?.instructions && <div><b>Manual step:</b> {a.dispatch_result.instructions}</div>}
              {a.dispatch_result?.mode && <div>Dispatch mode: {a.dispatch_result.mode}</div>}
              <div>Requested by {a.requested_by} · {fmtTime(a.created_at)}</div>
            </div>
          ),
        }}
      />
      <Modal
        title="Approve high-risk action"
        open={!!target}
        onCancel={() => { setTarget(null); setNote(""); }}
        confirmLoading={busy}
        okText="Approve"
        okButtonProps={{ disabled: !note.trim() }}
        onOk={() => target && review(target, "approve", note)}
      >
        {target && (
          <>
            <p><b>{target.description}</b><br />Target: <span className="mono">{target.target}</span></p>
            <p className="muted">High-risk actions (host isolation, account disablement, network segmentation) require a justification recorded in the audit log.</p>
            <Input.TextArea rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Justification (required)" />
          </>
        )}
      </Modal>
    </>
  );
}
