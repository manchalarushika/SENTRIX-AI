import { Card, Segmented } from "antd";
import { useState } from "react";
import { get } from "../api/client";
import type { Page, ResponseAction } from "../api/types";
import { useApi } from "../hooks/useApi";
import { useLiveRefresh } from "../hooks/useLive";
import { ActionsTable } from "../components/ActionsTable";
import { Loadable, PageHeader } from "../components/ui";

const VIEWS = {
  "Pending approval": "proposed",
  "Awaiting action": "pending_manual,dispatched,failed",
  "Resolved": "approved,completed,rejected,superseded",
};

export default function Approvals() {
  const [view, setView] = useState<keyof typeof VIEWS>("Pending approval");
  const { data, loading, error, reload } = useApi(
    () => get<Page<ResponseAction>>("/actions", { status: VIEWS[view], limit: 200 }),
    [view],
  );
  useLiveRefresh(["analysis_completed", "action_reviewed"], () => reload(true));

  return (
    <>
      <PageHeader
        title="Response Approvals"
        subtitle="SENTRIX never executes containment automatically — every response action requires analyst approval"
        extra={<Segmented options={Object.keys(VIEWS)} value={view} onChange={(v) => setView(v as keyof typeof VIEWS)} />}
      />
      <Card size="small">
        <Loadable loading={loading} error={error}>
          <ActionsTable actions={data?.items ?? []} onChange={() => reload()} showIncident />
        </Loadable>
      </Card>
    </>
  );
}
