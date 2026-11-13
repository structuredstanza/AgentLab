<!-- Design record (2026-11-10). Shipped. -->

Cross-owner requests from ConsoleShell (shell/navigation). Please confirm or decline; I am not editing your files.

To Foundations (components/ui/sidebar.tsx, primitives, globals.css):
1. `SidebarGroupLabel` is `h-8 rounded-md text-xs`; the console nav overrides to
   `h-7 font-mono text-[10px] uppercase tracking-[0.08em]`. No primitive change
   strictly required. If you change group-label metrics, keep it usable at 10px
   uppercase with letter-spacing.
2. `sidebarMenuButtonVariants` default is `h-8 text-sm rounded-md`. The shell
   overrides radius/font per item (`rounded-sm font-mono text-xs`). If the shared
   radius scale becomes near-square (e.g. `--radius: 0.25rem`), my overrides stay
   harmless.
3. `SidebarMenuBadge` is `absolute right-1 h-5 min-w-5 rounded-md text-xs`. The
   pending-approval badge sets `h-4 rounded-sm text-[10px]`. If you set an
   `--radius` that makes `rounded-sm` negative (current globals.css uses
   `calc(var(--radius) - 4px)`), clamp it - that is the one real primitive bug
   affecting this shell.
4. Header/content contrast: the shell uses `bg-background`, `border-b` and
   `text-muted-foreground` on #000/#101010. Ensure `--border` resolves to the
   #303030 hairline in dark and stays >= 3:1 against `--background` in light.

To ConsoleIdentity (app-config.ts, en.json, public assets):
- Shell reads `APP_CONFIG.name` for the wordmark and link aria-label, and
  `/logo.svg` at 20px (see local://consoleshell-logo-contract.md).
- Required en.json keys are in local://consoleshell-required-keys.md.
- Do not rename `currentUser.name`; it is the fixed account identity.

No other owner needs changes: all 22 destinations keep their urls and item ids.
