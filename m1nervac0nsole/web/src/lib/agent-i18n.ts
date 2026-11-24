import { useCallback, useEffect, useMemo, useState } from "react";

import { useTranslations } from "next-intl";

import { api } from "@/lib/api";
import type { Agent } from "@/lib/types";

// Seed inserts use ON CONFLICT DO NOTHING, so existing installations may retain
// older default labels. Look up system-seeded labels by key in the builtinAgents
// catalog and fall back to DB values. User-created agents always use their DB values.

// The retester is seeded in the DB with builtin=false (server FindingRetestAgentKey), but the system
// Since the key is fixed, it is included in the translation targets. Agents with builtin=true (goals/planner/
// mainagent/worker/auto/pentest) is filtered out by agent.builtin, so there is no need to put it here.
const SYSTEM_SEEDED_AGENT_KEYS = new Set(["retester"]);

function isSystemSeeded(agent: { key: string; builtin?: boolean }): boolean {
  return !!agent.builtin || SYSTEM_SEEDED_AGENT_KEYS.has(agent.key);
}

// useAgentLabels returns a set of helpers that give the name, description, and prompt variable labels of the default agents in the current language.
// It is a helper bundle that returns labels in the current language. Every display point obtains labels through these helpers.
export function useAgentLabels() {
  const t = useTranslations("builtinAgents");

  // Since the caller uses these functions as useMemo and useCallback dependencies (for conversation groups and filter computation),
  // a new bundle is created only when the language (t) changes. If a new object were created on every render, those computations would rerun each time.
  return useMemo(() => {
    // name returns the translated name if it is a default agent; otherwise it returns the DB name (agent.name).
    const name = (agent: { key: string; name: string; builtin?: boolean }): string => {
      if (isSystemSeeded(agent) && t.has(`${agent.key}.name`)) return t(`${agent.key}.name`);
      return agent.name;
    };

    // description returns the translated description for a default agent; otherwise it returns the DB description (or an empty string if there is none)
    // The empty-description fallback text is still appended by the caller as before.
    const description = (agent: { key: string; description?: string; builtin?: boolean }): string => {
      if (isSystemSeeded(agent) && t.has(`${agent.key}.description`)) return t(`${agent.key}.description`);
      return agent.description ?? "";
    };

    // nameByKey is a variant used when only the key is available without an Agent object (e.g., for grouping conversations).
    // Takes a lookup function (one that returns the agent); if it exists, translate, otherwise return the key 'key'.
    const nameByKey = (
      key: string,
      lookup: (key: string) => { key: string; name: string; builtin?: boolean } | undefined,
    ): string => {
      const agent = lookup(key);
      // biome-ignore lint/nursery/useNullishCoalescing: The || operator is intentional here, because agents with an empty ("") name must still be displayed with their key as before.
      return (agent && name(agent)) || key;
    };

    // varLabel translates built-in agents' prompt variable labels (e.g. "Overall task goal" for goals)
    // If there is none, it uses the DB label (fallback) as is.
    const varLabel = (agentKey: string, builtin: boolean, varName: string, fallback: string): string => {
      if ((builtin || SYSTEM_SEEDED_AGENT_KEYS.has(agentKey)) && t.has(`${agentKey}.vars.${varName}`)) {
        return t(`${agentKey}.vars.${varName}`);
      }
      return fallback;
    };

    return { name, description, nameByKey, varLabel };
  }, [t]);
}

// The agent list is only used for key → display name conversion in several places on screen (such as approval records),
// It is fetched once and shared at module level. If the fetch fails, it is retried on the next call.
let agentListPromise: Promise<Agent[]> | null = null;
function loadAgentList(): Promise<Agent[]> {
  if (!agentListPromise) {
    agentListPromise = api.agents().catch((err) => {
      agentListPromise = null;
      throw err;
    });
  }
  return agentListPromise;
}

// useAgentNameByKey returns a converter for screens that have only a key and no agent object (such as conv_agent_key
// conv_agent_key etc.) returns a converter used in ... For default agents, it returns the current language name,
// user agents show their DB name, and if the key is not in the list or the list has not been fetched yet, the key is shown as-is.
export function useAgentNameByKey(): (key: string) => string {
  const labels = useAgentLabels();
  const [agents, setAgents] = useState<Map<string, Agent>>(() => new Map());
  useEffect(() => {
    let alive = true;
    loadAgentList()
      .then((list) => {
        if (alive) setAgents(new Map(list.map((a) => [a.key, a])));
      })
      .catch(() => {
        // If the list cannot be fetched, the key is shown as-is (retried on the next mount).
      });
    return () => {
      alive = false;
    };
  }, []);
  return useCallback((key: string) => labels.nameByKey(key, (k) => agents.get(k)), [labels, agents]);
}
