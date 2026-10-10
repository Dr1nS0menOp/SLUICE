# ADR 0011: A read-only web console served by the control plane

- Status: Accepted (amends ADR 0010: the console's static files need no token)
- Date: 2026-10-10

## Context

Operators asked to see the autopilot without the CLI: which templates are cut, why fields were
kept, whether the proof holds, and what the archive holds. The data already exists in `/status`;
the archive had no HTTP route.

A web UI is also an attack surface. Archived events are attacker-influenced text (a command line,
a user name, a URL), so a console that renders them as HTML is a stored-XSS channel into the
security team's browser. The control plane may listen beyond loopback with a token (ADR 0010).

## Decision

1. **Served by the control plane, built into the binary.** Three static files (`index.html`,
   `app.js`, `app.css`, in `crates/sluice-server/ui/`) are included with `include_str!` and
   served at `/` and `/ui/…`. No framework, no build step, no dependencies, no third-party
   fonts or scripts: the console works offline and adds nothing to the supply chain.
2. **Static files without a token; data with one.** The files contain no data, so they are served
   without the bearer token. The page asks for the token, keeps it in `sessionStorage` (this tab
   only), and sends it with every call to `/status`, `/rules` and `/archive/search`, which stay
   protected like before.
3. **Text only.** The script builds the page from DOM nodes and writes every value with
   `textContent`. A test fails the build if `app.js` uses `innerHTML`, `insertAdjacentHTML` or
   `eval`. The files are served with `Content-Security-Policy: default-src 'none';
   script-src 'self'; style-src 'self'; connect-src 'self'; …; frame-ancestors 'none'`,
   `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, so even a missed sink
   cannot run inline script or send data elsewhere.
4. **Read-only.** `GET /archive/search` takes `source` (comma-separated), `from`, `to`, `where`
   (one condition per line) and `limit` (at most 100), and reads at most 2,000,000 archive lines
   per request (`Scan::with_line_budget`), saying when it stopped early. Replay changes what a
   SIEM holds, so it stays with `sluice replay` and the gated MCP tool, where the destination is
   named explicitly.

## Consequences

- `sluice up` (and the container) has a console at `http://<listen>/` with no extra setup.
- Anyone who can reach the control plane can load the empty page, which reveals that Sluice runs
  there; it reveals nothing else without the token.
- `/status` now carries one example event per template, before and after its proven recipe
  (at most 64 KB each), so the console can show what a recipe does. That is raw event content
  behind the same token as the archive; the MCP `explain` tool does not pass it on.
- The console cannot shape decisions: it reads status and the archive and changes nothing.
  Actions such as pausing a recipe would need write routes and their own review.
- Archive search runs on a blocking thread and is bounded by the line budget, but a narrow time
  range is still the way to keep searches fast on large archives.
