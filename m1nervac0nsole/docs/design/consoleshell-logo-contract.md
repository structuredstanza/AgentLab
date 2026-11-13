<!-- Design record (2026-11-10). Shipped. -->

Shell wordmark contract (ConsoleShell -> ConsoleIdentity).

- The sidebar renders `/logo.svg` at 20x20 CSS px (`className="size-5"`) with `alt=""`
  because the visible wordmark already names the product; the link carries
  `aria-label={APP_CONFIG.name}`.
- Requirements for `web/public/logo.svg`: square viewBox, transparent background,
  readable at 20px on both #000 (dark) and #fff (light) surfaces. The current
  monogram (single stroke colour #6f7f8d) satisfies this; do not switch to a
  two-tone or gradient mark without telling me.
- The wordmark text is `APP_CONFIG.name` rendered in `font-mono` at 13px, truncated
  with ellipsis. Keep `APP_CONFIG.name` the exact display string `m1nervac0nsole`
  (no surrounding marketing copy) so the sidebar and browser metadata stay aligned.
- `/logo.png` is no longer referenced by the shell; keep or drop it, but the shell
  will not regress if it disappears.
- If the monogram needs a light/dark variant, ship `logo.svg` with
  `currentColor` strokes and tell me; I will apply the colour class.
