import { APP_CONFIG } from "@/config/app-config";

// Monogram + wordmark. The mark itself is drawn in muted accent, so it needs no CSS filter.
function Wordmark() {
  return (
    <div className="flex items-center gap-2.5">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src={APP_CONFIG.logo.src} alt="" width={28} height={28} className="size-7" />
      <span className="font-medium text-lg tracking-tight">{APP_CONFIG.name}</span>
    </div>
  );
}

// Flat identity panel shared by the login and setup screens. It states the product name, the
// authorized-use boundary and the licence.
export function AuthBrandPanel() {
  return (
    <div className="hidden flex-col justify-between border-r bg-card p-10 lg:flex lg:w-1/3">
      <Wordmark />

      <div className="space-y-3">
        <p className="text-xl leading-snug">{APP_CONFIG.meta.description}</p>
        <p className="font-mono text-primary text-xs uppercase tracking-wider">Authorized engagements only</p>
      </div>

      <p className="font-mono text-muted-foreground text-xs">AGPL-3.0</p>
    </div>
  );
}

// The brand panel is hidden on narrow screens, so the same identity repeats above the form.
export function AuthMobileBrand() {
  return (
    <div className="flex justify-center lg:hidden">
      <Wordmark />
    </div>
  );
}
