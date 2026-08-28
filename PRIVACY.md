# Privacy

Last updated 2026-08-17. Covers the LucidPilot Chrome extension (overlay, audit log and control engine), the Hermes plugin, and the Claude Code plugin.

## What stays on your device

Everything LucidPilot records lives in `chrome.storage.local`, on your machine, and is never sent to us or anyone else:

- **The session audit log**: timestamp, action type (click/type/scroll/navigate), coordinates, page hostname, which agent (Claude, Hermes, etc.), and a short description of the element acted on (its tag and visible label). Capped at 500 entries; oldest entries drop off first.
- **Typed text and form values are never captured**, only the fact that typing happened. This holds for `contenteditable` elements (Gmail/Notion/Slack-style editors) too, not just plain form fields.
- **Page snapshots** (accessibility-tree/DOM snapshots the control engine requests on your behalf) and any screenshots produced by your own actions or an agent's navigation both stay local to the browser session and are not uploaded anywhere by the extension.
- **Network and console records**, only if you use the control engine and the driving agent (Claude Code, Hermes) requests them, are read from the page you're already on and returned to that agent's own tool. LucidPilot itself doesn't collect or store them separately.

## What we don't do

- No analytics or telemetry service. None of your usage, browsing, or extension activity is sent to any analytics or telemetry provider.
- No cloud storage of your audit log, snapshots, or session data.
- No sale or sharing of any captured data. Page content, screenshots and what you type never leave your machine. The calls listed below cover checkout, licensing, pricing and version checks, nothing else. None of them carries analytics, page content or what you type.

## What leaves your device

### Buying or managing a licence

When you check out or manage your licence on [pilot.lucidfabrics.com](https://pilot.lucidfabrics.com), your email and the plan you picked are sent to that checkout service to start a Stripe Checkout session. Stripe handles payment. This only happens if you choose to buy or manage a licence. Your licence key is emailed to you.

### Checking that licence

About once a day, the extension sends your licence key and a device identifier to the licensing service (`api.lucidfabrics.com`) to confirm it's still valid. The identifier is generated on your machine and used only to count device seats (3 per licence); the request also carries the label `chrome-extension`. It carries nothing about your browsing: no URLs, no page content, no history. If the network is down the licence keeps working for 7 days offline. Each successful check returns a short-lived signed token, which the extension passes to the local bridge (see below) and the bridge verifies on your machine, so between checks the licence works without waiting on the network.

### Loading the pricing

Each time you open the extension popup, it fetches current pricing from `api.lucidfabrics.com` to draw the paywall. This is a plain GET request and carries no personal data.

### Checking for a new version

About once a day, LucidPilot checks GitHub's public releases API (`api.github.com`) for the latest release, and caches the result for 24 hours. This reveals only your IP address to GitHub, nothing else.

None of these calls goes to any analytics or telemetry service.

## Marking sensitive domains

Sensitive domains (e.g. your bank) are configured in the extension popup panel. Flagging a domain blocks the agent from acting on it entirely and turns the overlay border red. The list is stored locally and never transmitted.

## LucidPilot for Mac (native app control)

On macOS, the optional LucidPilot for Mac helper lets an agent control the apps you allow, through the system accessibility API. What it reads (the accessibility tree of the app you targeted, its window titles, the text you asked it to read) and the allowlist of apps you granted all stay on your machine; none of it is sent to us.

The helper asks for two macOS permissions. Accessibility lets it read the target app's controls and send input into it. Screen Recording is requested only for `my_app_screenshot` and session replay; you can deny it and every other tool still works. A window screenshot or a session replay is written to a file on your disk, not uploaded by LucidPilot; if the agent then reads that file, its contents go to whichever model you're running, exactly like a browser screenshot today.

The helper authenticates to the local bridge with a token file (`~/.hermes/lucidpilot/helper-token`, readable only by you) that the bridge writes on your machine. The token never leaves your machine; it only lets the helper receive `app.*` commands over the loopback bridge.

## Local bridge

The control engine runs a loopback-only HTTP bridge (`127.0.0.1`, not reachable from the network) between the extension and your Hermes/Claude Code session. It only accepts commands from local, non-browser processes and only serves results back to this specific extension's origin (or, for the macOS helper, to a local process holding the token file above). Nothing it handles is sent anywhere beyond your own machine and, when you invoke a control action, the app or page you're already looking at.

## Who is responsible for your data

The data controller is Lucid Fabrics, a trade name of 9412-6364 Québec inc. (NEQ 1175191080), Québec, Canada.

## Questions

Open an issue on the project repository, or reach out via the email used at checkout.
