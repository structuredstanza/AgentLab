"use client";

import * as React from "react";

import { CopyIcon, KeyRoundIcon, PlusIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { APIToken, MCPAuditRow, Task } from "@/lib/types";

// A token is the only credential an external harness gets: read-only, scoped to
// one task, expiring, revocable. The plaintext is shown once, at mint time.
export default function TokensPage() {
  const t = useTranslations("tokensPage");
  const [tokens, setTokens] = React.useState<APIToken[]>([]);
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [name, setName] = React.useState("");
  const [taskId, setTaskId] = React.useState("");
  const [ttlHours, setTtlHours] = React.useState(24);
  const [busy, setBusy] = React.useState(false);
  const [minted, setMinted] = React.useState<string>("");
  const [audit, setAudit] = React.useState<MCPAuditRow[]>([]);

  const load = React.useCallback(() => {
    api
      .apiTokens()
      .then(setTokens)
      .catch(() => setTokens([]));
  }, []);

  React.useEffect(() => {
    load();
    api
      .mcpAudit()
      .then(setAudit)
      .catch(() => setAudit([]));
    api
      .tasks()
      .then((resp) => {
        setTasks(resp.tasks);
        if (resp.tasks.length > 0) setTaskId(resp.tasks[0].id);
      })
      .catch(() => setTasks([]));
  }, [load]);

  const mint = async () => {
    if (!name.trim() || !taskId) return;
    setBusy(true);
    try {
      const created = await api.createAPIToken(name.trim(), taskId, ttlHours);
      setMinted(created.token);
      setName("");
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("mintFailed"));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (id: number) => {
    try {
      await api.revokeAPIToken(id);
      load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : t("revokeFailed"));
    }
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 p-4">
      <div>
        <h1 className="font-semibold text-lg">{t("title")}</h1>
        <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
      </div>

      <div className="flex flex-wrap items-end gap-2 rounded-md border p-3">
        <div className="flex flex-col gap-1 text-xs">
          <span>{t("name")}</span>
          <Input
            aria-label={t("name")}
            className="h-8 w-48"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("namePlaceholder")}
          />
        </div>
        <div className="flex flex-col gap-1 text-xs">
          <span>{t("task")}</span>
          <select
            aria-label={t("task")}
            className="h-8 rounded-md border bg-transparent px-2 text-sm"
            value={taskId}
            onChange={(e) => setTaskId(e.target.value)}
          >
            {tasks.map((task) => (
              <option key={task.id} value={task.id}>
                #{task.id} {task.name || task.description}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1 text-xs">
          <span>{t("ttl")}</span>
          <Input
            aria-label={t("ttl")}
            className="h-8 w-24"
            type="number"
            min={1}
            max={720}
            value={ttlHours}
            onChange={(e) => setTtlHours(Number(e.target.value) || 24)}
          />
        </div>
        <Button size="sm" disabled={busy || !name.trim() || !taskId} onClick={() => void mint()}>
          <PlusIcon className="size-3.5" /> {t("mint")}
        </Button>
      </div>

      {minted && (
        <div className="rounded-md border border-warning/50 bg-warning/10 p-3">
          <div className="mb-1 text-xs">{t("mintedOnce")}</div>
          <div className="flex items-center gap-2">
            <code className="min-w-0 flex-1 truncate font-mono text-xs">{minted}</code>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                void navigator.clipboard.writeText(minted);
                toast.success(t("copied"));
              }}
            >
              <CopyIcon className="size-3.5" />
            </Button>
          </div>
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col divide-y rounded-md border">
        {tokens.length === 0 && <p className="p-3 text-muted-foreground text-sm">{t("empty")}</p>}
        {tokens.map((token) => {
          const revoked = !!token.revoked_at;
          const expired = new Date(token.expires_at).getTime() < Date.now();
          return (
            <div key={token.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <KeyRoundIcon className="size-3.5 text-muted-foreground" />
              <span className="font-medium">{token.name}</span>
              <span className="text-muted-foreground text-xs">#{token.task_id}</span>
              {revoked ? (
                <Badge variant="outline" className="text-[10px] text-destructive">
                  {t("revoked")}
                </Badge>
              ) : expired ? (
                <Badge variant="outline" className="text-[10px]">
                  {t("expired")}
                </Badge>
              ) : (
                <Badge variant="secondary" className="text-[10px]">
                  {t("active")}
                </Badge>
              )}
              <span className="text-muted-foreground text-xs">
                {t("expires", { when: new Date(token.expires_at).toLocaleString() })}
              </span>
              {token.last_used_at && (
                <span className="text-muted-foreground text-xs">
                  {t("lastUsed", { when: new Date(token.last_used_at).toLocaleString() })}
                </span>
              )}
              {!revoked && (
                <Button size="sm" variant="ghost" className="ml-auto h-6 px-1.5" onClick={() => void revoke(token.id)}>
                  <Trash2Icon className="size-3.5 text-destructive" />
                </Button>
              )}
            </div>
          );
        })}
      </div>

      <div className="flex min-h-0 flex-col gap-2">
        <h2 className="font-medium text-sm">{t("auditTitle")}</h2>
        <p className="text-muted-foreground text-xs">{t("auditHint")}</p>
        <div className="flex flex-col divide-y rounded-md border">
          {audit.length === 0 && <p className="p-3 text-muted-foreground text-sm">{t("auditEmpty")}</p>}
          {audit.map((row) => (
            <div key={row.id} className="flex flex-wrap items-center gap-2 px-3 py-1.5 text-xs">
              <code className="font-mono">{row.tool}</code>
              <span className="text-muted-foreground">{row.token_name || `#${row.token_id}`}</span>
              <span className="text-muted-foreground">task #{row.task_id}</span>
              <span className="ml-auto text-muted-foreground">{new Date(row.created_at).toLocaleString()}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
