"use client";

import * as React from "react";

import { CopyIcon, EyeIcon, EyeOffIcon, PlusIcon, TrashIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { TaskCredential } from "@/lib/types";

export function CredentialsTab({ taskId }: { taskId: string }) {
  const t = useTranslations("taskDetail.credentials");
  const [items, setItems] = React.useState<TaskCredential[] | null>(null);
  const [error, setError] = React.useState("");
  const [revealed, setRevealed] = React.useState<Set<number>>(new Set());
  const [domain, setDomain] = React.useState("");
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [note, setNote] = React.useState("");
  const [adding, setAdding] = React.useState(false);

  const load = React.useCallback(() => {
    api
      .taskCredentials(taskId)
      .then((r) => {
        setItems(r);
        setError("");
      })
      .catch((e) => setError((e as Error).message));
  }, [taskId]);
  React.useEffect(() => {
    let alive = true;
    api
      .taskCredentials(taskId)
      .then((r) => {
        if (alive) {
          setItems(r);
          setError("");
        }
      })
      .catch((e) => {
        if (alive) setError((e as Error).message);
      });
    const timer = setInterval(() => {
      if (alive) load();
    }, 15000);
    return () => {
      alive = false;
      clearInterval(timer);
      setRevealed(new Set());
    };
  }, [load, taskId]);

  async function add() {
    if (!domain.trim() || !username.trim()) return;
    setAdding(true);
    try {
      await api.addTaskCredential(taskId, {
        domain: domain.trim(),
        username: username.trim(),
        password,
        note: note.trim(),
      });
      setDomain("");
      setUsername("");
      setPassword("");
      setNote("");
      load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setAdding(false);
    }
  }
  async function remove(id: number) {
    try {
      await api.deleteTaskCredential(taskId, id);
      setRevealed((current) => {
        const next = new Set(current);
        next.delete(id);
        return next;
      });
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  function toggle(id: number) {
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("title")}</CardTitle>
        <CardDescription>{t("description")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {error ? (
          <p role="alert" className="text-destructive text-sm">
            {error}
          </p>
        ) : null}
        {items === null ? (
          <Skeleton className="h-24 w-full" />
        ) : items.length === 0 ? (
          <Empty>
            <EmptyHeader>
              <EmptyTitle>{t("emptyTitle")}</EmptyTitle>
              <EmptyDescription>{t("emptyDescription")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <div className="flex flex-col divide-y">
            {items.map((c) => (
              <div key={c.id} className="flex flex-wrap items-center gap-2 py-2.5">
                <code className="font-medium text-sm">{c.domain}</code>
                <span className="text-muted-foreground text-sm">{c.username}</span>
                <Badge variant={c.source === "agent" ? "secondary" : "outline"}>
                  {t(c.source === "agent" ? "agentRecorded" : "declared")}
                </Badge>
                <div className="ml-auto flex items-center gap-1">
                  <code className="max-w-40 truncate rounded bg-muted px-2 py-0.5 text-sm">
                    {c.password === ""
                      ? t("agentGenerates")
                      : revealed.has(c.id)
                        ? c.password
                        : "•".repeat(Math.min(c.password.length, 12))}
                  </code>
                  {c.password !== "" ? (
                    <>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="size-7"
                        aria-label={t(revealed.has(c.id) ? "hidePassword" : "revealPassword")}
                        onClick={() => toggle(c.id)}
                      >
                        {revealed.has(c.id) ? <EyeOffIcon /> : <EyeIcon />}
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="size-7"
                        aria-label={t("copyPassword")}
                        onClick={() => void navigator.clipboard?.writeText(c.password).catch(() => undefined)}
                      >
                        <CopyIcon />
                      </Button>
                    </>
                  ) : null}
                  <Button
                    size="icon"
                    variant="ghost"
                    className="size-7"
                    aria-label={t("deleteCredential")}
                    onClick={() => remove(c.id)}
                  >
                    <TrashIcon />
                  </Button>
                </div>
                {c.note ? <p className="w-full text-muted-foreground text-xs">{c.note}</p> : null}
              </div>
            ))}
          </div>
        )}
        <div className="grid gap-2 sm:grid-cols-[1fr_1fr_1fr_auto]">
          <Input
            aria-label={t("domainLabel")}
            placeholder={t("domainPlaceholder")}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
          <Input
            aria-label={t("usernameLabel")}
            placeholder={t("usernamePlaceholder")}
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            aria-label={t("passwordLabel")}
            placeholder={t("passwordPlaceholder")}
            type="password"
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <Button variant="outline" disabled={adding || !domain.trim() || !username.trim()} onClick={add}>
            <PlusIcon />
            {t("add")}
          </Button>
          <Input
            className="sm:col-span-4"
            aria-label={t("noteLabel")}
            placeholder={t("notePlaceholder")}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
        </div>
      </CardContent>
    </Card>
  );
}
