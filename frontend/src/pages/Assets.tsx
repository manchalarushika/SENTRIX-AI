import { useState } from "react";
import { App, Button, Card, Drawer, Form, Input, InputNumber, Select, Space, Switch, Table, Tag } from "antd";
import { PlusOutlined } from "@ant-design/icons";
import { del, errorMessage, get, post, put } from "../api/client";
import type { Asset } from "../api/types";
import { useApi } from "../hooks/useApi";
import { Loadable, PageHeader, RiskBar, SeverityTag, fmtTime } from "../components/ui";

const CRIT = ["low", "medium", "high", "critical"];

export default function Assets() {
  const { message, modal } = App.useApp();
  const { data, loading, error, reload } = useApi(() => get<Asset[]>("/assets"));
  const [editing, setEditing] = useState<Asset | null>(null);
  const [creating, setCreating] = useState(false);
  const [form] = Form.useForm();

  const open = (a: Asset | null) => {
    setEditing(a);
    setCreating(!a);
    form.setFieldsValue(a ? { ...a, software: a.software, connects_to: a.connects_to } : { criticality: "medium", business_value_per_hour: 1000, internet_facing: false });
  };
  const save = async () => {
    const v = await form.validateFields();
    try {
      if (creating) await post("/assets", v);
      else await put(`/assets/${editing!.id}`, v);
      message.success("Saved");
      setEditing(null); setCreating(false);
      reload();
    } catch (e) { message.error(errorMessage(e)); }
  };
  const remove = (a: Asset) => modal.confirm({
    title: `Delete ${a.hostname}?`, okType: "danger",
    onOk: async () => { try { await del(`/assets/${a.id}`); message.success("Deleted"); reload(); } catch (e) { message.error(errorMessage(e)); } },
  });

  return (
    <>
      <PageHeader title="Assets" subtitle="Enterprise asset inventory — drives the attack graph, digital twin and risk model"
        extra={<Button type="primary" icon={<PlusOutlined />} onClick={() => open(null)}>Add asset</Button>} />
      <Card size="small">
        <Loadable loading={loading} error={error} empty={!data?.length}>
          <Table size="small" rowKey="id" dataSource={data ?? []} pagination={{ pageSize: 20 }}
            onRow={(r) => ({ onClick: () => open(r), className: "clickable" })}
            columns={[
              { title: "Hostname", dataIndex: "hostname" },
              { title: "IP", dataIndex: "ip_address", width: 130 },
              { title: "Type", dataIndex: "asset_type", width: 130 },
              { title: "Zone", dataIndex: "network_zone", width: 120 },
              { title: "Dept", dataIndex: "department", width: 120 },
              { title: "Criticality", dataIndex: "criticality", width: 110, render: (v) => <SeverityTag value={v} /> },
              { title: "Internet", dataIndex: "internet_facing", width: 90, render: (v) => v ? <Tag color="red">exposed</Tag> : <Tag>internal</Tag> },
              { title: "Risk", dataIndex: "risk_score", width: 120, render: (v) => <RiskBar value={v} /> },
              { title: "Last seen", dataIndex: "last_seen", width: 160, render: fmtTime },
              { title: "", width: 70, render: (_, r) => <Button size="small" danger onClick={(e) => { e.stopPropagation(); remove(r); }}>Del</Button> },
            ]} />
        </Loadable>
      </Card>

      <Drawer width={520} open={!!editing || creating} onClose={() => { setEditing(null); setCreating(false); }}
        title={creating ? "Add asset" : `Edit ${editing?.hostname}`}
        extra={<Button type="primary" onClick={save}>Save</Button>}>
        <Form form={form} layout="vertical">
          <Form.Item name="hostname" label="Hostname" rules={[{ required: true }]}><Input disabled={!creating} /></Form.Item>
          <Space.Compact block>
            <Form.Item name="ip_address" label="IP address" style={{ width: "50%" }}><Input /></Form.Item>
            <Form.Item name="asset_type" label="Type" style={{ width: "50%" }}><Input placeholder="workstation, server, database..." /></Form.Item>
          </Space.Compact>
          <Form.Item name="operating_system" label="Operating system"><Input /></Form.Item>
          <Space.Compact block>
            <Form.Item name="department" label="Department" style={{ width: "50%" }}><Input /></Form.Item>
            <Form.Item name="network_zone" label="Network zone" style={{ width: "50%" }}>
              <Select options={["external", "dmz", "corporate", "management", "server", "ot"].map((z) => ({ value: z, label: z }))} />
            </Form.Item>
          </Space.Compact>
          <Space.Compact block>
            <Form.Item name="criticality" label="Criticality" style={{ width: "50%" }}>
              <Select options={CRIT.map((c) => ({ value: c, label: c }))} />
            </Form.Item>
            <Form.Item name="business_value_per_hour" label="Business value / hour ($)" style={{ width: "50%" }}>
              <InputNumber min={0} style={{ width: "100%" }} />
            </Form.Item>
          </Space.Compact>
          <Form.Item name="owner" label="Owner"><Input /></Form.Item>
          <Form.Item name="internet_facing" label="Internet-facing" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="software" label="Software (for vulnerability matching)">
            <Select mode="tags" tokenSeparators={[","]} placeholder="e.g. Log4j2 2.14.1, Exchange Server 2019" />
          </Form.Item>
          <Form.Item name="connects_to" label="Connects to (hostnames)">
            <Select mode="tags" tokenSeparators={[","]} placeholder="downstream hosts for the attack graph" />
          </Form.Item>
        </Form>
      </Drawer>
    </>
  );
}
