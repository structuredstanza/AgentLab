"use client";

import * as React from "react";

import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { api } from "@/lib/api";
import type { PlanDraft, PlanProposal } from "@/lib/types";

// hasInclude mirrors plan.HasInclude on the backend. An inclusion widens what
// the guard will allow, so Apply stays disabled until the operator says so.
export function hasInclude(proposal: PlanProposal): boolean {
  return proposal.scope.some((rule) => rule.effect === "include");
}

function Section({ title, children, testId }: { title: string; children: React.ReactNode; testId: string }) {
  return (
    <section className="flex flex-col gap-1.5" data-testid={testId}>
      <h4 className="font-medium text-xs">{title}</h4>
      {children}
    </section>
  );
}

export function PlanProposalPreview({
  taskId,
  draft,
  onApplied,
  onDiscarded,
}: {
  taskId: string;
  draft: PlanDraft;
  onApplied?: (draft: PlanDraft) => void;
  onDiscarded?: (draft: PlanDraft) => void;
}) {
  const t = useTranslations("taskDetail.plan");
  const [includeAck, setIncludeAck] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const proposal = draft.proposal;
  const needsAck = hasInclude(proposal);
  const pending = draft.status === "draft";
  const nodeCount = (draft.created_node_ids ?? []).length;

  async function apply() {
    if (busy || (needsAck && !includeAck)) return;
    setBusy(true);
    try {
      const updated = await api.applyPlanDraft(taskId, draft.id, needsAck);
      toast.success(t("preview.applied", { count: updated.created_node_ids?.length ?? 0 }));
      onApplied?.(updated);
    } catch (e) {
      toast.error(t("preview.applyFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function discard() {
    if (busy) return;
    setBusy(true);
    try {
      await api.discardPlanDraft(taskId, draft.id);
      toast.success(t("preview.discarded"));
      onDiscarded?.(draft);
    } catch (e) {
      toast.error(t("preview.discardFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-3" data-testid="plan-preview">
      <div className="flex items-center gap-2">
        <h3 className="min-w-0 flex-1 truncate font-medium text-sm">{t("preview.title")}</h3>
        <Badge variant={pending ? "outline" : "secondary"}>
          {pending ? t("preview.statusDraft") : t("preview.statusApplied")}
        </Badge>
      </div>

      <p className="text-muted-foreground text-xs" data-testid="plan-summary">
        {proposal.summary || draft.summary}
      </p>

      <Separator />

      <Section title={t("preview.goals")} testId="plan-goals">
        {proposal.goals.length === 0 ? (
          <p className="text-muted-foreground text-xs">{t("preview.none")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {proposal.goals.map((goal) => (
              <li key={goal.ref} className="flex flex-wrap items-baseline gap-1.5 text-xs">
                <Badge variant="outline">{goal.ref}</Badge>
                <span className="min-w-0 flex-1">{goal.text}</span>
                {goal.vulnclass ? <Badge variant="secondary">{goal.vulnclass}</Badge> : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t("preview.intents")} testId="plan-intents">
        {proposal.intents.length === 0 ? (
          <p className="text-muted-foreground text-xs">{t("preview.none")}</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {proposal.intents.map((intent) => (
              <li key={intent.ref} className="flex flex-col gap-0.5 text-xs">
                <div className="flex flex-wrap items-baseline gap-1.5">
                  <Badge variant="outline">{intent.ref}</Badge>
                  <span className="min-w-0 flex-1">{intent.summary}</span>
                </div>
                <div className="flex flex-wrap gap-1.5 text-[11px] text-muted-foreground">
                  {intent.goal ? <span>{t("preview.goalRef", { ref: intent.goal })}</span> : null}
                  {intent.depends_on?.length ? (
                    <span>{t("preview.dependsOn", { refs: intent.depends_on.join(", ") })}</span>
                  ) : null}
                  {intent.asset_ids?.length ? (
                    <span>{t("preview.assets", { count: intent.asset_ids.length })}</span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t("preview.hints")} testId="plan-hints">
        {proposal.hints.length === 0 ? (
          <p className="text-muted-foreground text-xs">{t("preview.none")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {proposal.hints.map((hint, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: hints carry no id and the list is read-only.
              <li key={index} className="flex flex-wrap items-baseline gap-1.5 text-xs">
                {hint.rule ? <Badge variant="destructive">{t("preview.rule")}</Badge> : null}
                <span className="min-w-0 flex-1">{hint.text}</span>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t("preview.scope")} testId="plan-scope">
        {proposal.scope.length === 0 ? (
          <p className="text-muted-foreground text-xs">{t("preview.none")}</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {proposal.scope.map((rule) => (
              <li
                key={`${rule.effect}:${rule.kind}:${rule.value}`}
                className="flex flex-wrap items-baseline gap-1.5 text-xs"
              >
                <Badge variant={rule.effect === "include" ? "destructive" : "secondary"}>
                  {rule.effect === "include" ? t("preview.include") : t("preview.exclude")}
                </Badge>
                <span className="font-mono text-[11px]">{rule.kind}</span>
                <span className="min-w-0 flex-1">{rule.value}</span>
                {rule.note ? <span className="text-[11px] text-muted-foreground">{rule.note}</span> : null}
              </li>
            ))}
          </ul>
        )}
      </Section>

      {draft.status === "applied" ? (
        <p className="text-xs" data-testid="plan-created-nodes">
          {t("preview.appliedNodes", { count: nodeCount })}
        </p>
      ) : null}

      {pending ? (
        <div className="flex flex-col gap-2 border-t pt-3">
          {needsAck ? (
            <div className="flex items-start gap-2">
              <Checkbox
                id="plan-include-ack"
                checked={includeAck}
                onCheckedChange={(value) => setIncludeAck(value === true)}
                data-testid="plan-include-checkbox"
              />
              <Label htmlFor="plan-include-ack" className="text-xs leading-snug">
                {t("preview.includeWarning")}
              </Label>
            </div>
          ) : null}
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void apply()} disabled={busy || (needsAck && !includeAck)}>
              {t("preview.apply")}
            </Button>
            <Button size="sm" variant="outline" onClick={() => void discard()} disabled={busy}>
              {t("preview.discard")}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
