import {
  Activity,
  Ban,
  BellRing,
  BookOpen,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

export interface NavItem {
  // Stable id: it keys the translation and is part of the navigation contract.
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
}

export interface NavGroup {
  id: number;
  // Translation key relative to the "nav" namespace; `label` is the authored
  // fallback so the shell renders before a locale supplies the key.
  labelKey: string;
  label: string;
  items: NavItem[];
}

// Grouping is presentation only: every url and item id below is the stable
// contract used by routing, active-state matching and the command palette.
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    labelKey: "group.operations",
    label: "Operations",
    items: [
      { id: "dashboard", title: "Overview", url: "/dashboard", icon: LayoutDashboard },
      { id: "tasks", title: "Tasks", url: "/function/tasks", icon: Target },
      { id: "chat", title: "Chat", url: "/chat", icon: MessageSquare },
    ],
  },
  {
    id: 2,
    labelKey: "group.evidence",
    label: "Evidence",
    items: [
      { id: "findings", title: "Findings", url: "/function/findings", icon: Bug },
      { id: "assets", title: "Assets", url: "/function/assets", icon: Network },
      { id: "traffic", title: "Traffic", url: "/function/traffic", icon: Activity },
      { id: "commands", title: "Tool Runs", url: "/function/commands", icon: Terminal },
      { id: "llm-records", title: "LLM Records", url: "/function/llm-records", icon: Radio },
    ],
  },
  {
    id: 3,
    labelKey: "group.intelligence",
    label: "Intelligence",
    items: [
      { id: "memory", title: "Memory", url: "/system/memory", icon: BookOpen },
      { id: "skills", title: "Skills", url: "/system/skills", icon: Sparkles },
    ],
  },
  {
    id: 4,
    labelKey: "group.configuration",
    label: "Configuration",
    items: [
      { id: "workspace", title: "Workspace", url: "/function/workspace", icon: FolderOpen },
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agents", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug },
      { id: "tools", title: "Tools", url: "/system/tools", icon: Wrench },
      { id: "toolbox", title: "Toolbox", url: "/system/toolbox", icon: Terminal },
      { id: "notify", title: "Notifications", url: "/system/notify", icon: BellRing },
      { id: "intercept", title: "Intercept Rules", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", title: "Asset Intercept", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", title: "Approval Records", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", title: "Logs", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "System Settings", url: "/system/settings", icon: Settings2 },
    ],
  },
];
