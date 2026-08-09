# Privacy

Last updated 2026-07-30. Covers the LucidPilot Chrome extension (overlay, audit log and control engine), the Hermes plugin, and the Claude Code plugin.

## What stays on your device

Everything LucidPilot records lives in `chrome.storage.local`, on your machine, and is never sent to us or anyone else:

- **The session audit log**: timestamp, action type (click/type/scroll/navigate), coordinates, page hostname, which agent (Claude, Hermes, etc.), and a short description of the element acted on (its tag and visible label). Capped at 500 entries; oldest entries drop off first.
- **Typed text and form values are never captured**, only the fact that typing happened. This holds for `contenteditable` elements (Gmail/Notion/Slack-style editors) too, not just plain form fields.
- **Page snapshots** (accessibility-tree/DOM snapshots the control engine requests on your behalf) and any screenshots produced by your own actions or an agent's navigation both stay local to the browser session and are not uploaded anywhere by the extension.
- **Network and console records**, only if you use the Pro control engine and the driving agent (Claude Code, Hermes) requests them, are read from the page you're already on and returned to that agent's own tool. LucidPilot itself doesn't collect or store them separately.

## What we don't do

- No telemetry or analytics. LucidPilot doesn't phone home about your usage, browsing, or extension activity.
- No cloud storage of your audit log, snapshots, or session data.
- No sale or sharing of any captured data. There's nothing to sell, it never leaves your machine.

## The two things that leave your device

### Buying a licence

When you check out on [pilot.lucidfabrics.com](https://pilot.lucidfabrics.com), your email and the plan you picked are sent to the licensing service (`api.lucidfabrics.com`) to start a Stripe Checkout session, and Stripe handles payment. This only happens if you choose to buy. Your licence key is emailed to you.

### Verifying that licence

The extension contacts the same licensing service (`api.lucidfabrics.com`) to activate and periodically re-check your key. Each request carries the key, a random identifier generated on your machine to count device seats (3 per licence), and the label `chrome-extension`. It carries nothing about your browsing: no URLs, no page content, no history. Re-checks happen about once a day; if the network is down the licence keeps working for 7 days offline. Each successful check returns a short-lived signed token, which the extension passes to the local bridge (see below) and the bridge verifies on your machine - so between checks the licence works without waiting on the network, and nothing extra leaves your computer.

## Marking sensitive domains

If you configure a sensitive-domain list (e.g. your bank) in the extension source, that list is stored locally and used only to decide when to show a red warning border. It is not transmitted anywhere.

## Local bridge

The Pro control engine runs a loopback-only HTTP bridge (`127.0.0.1`, not reachable from the network) between the extension and your Hermes/Claude Code session. It only accepts commands from local, non-browser processes and only serves results back to this specific extension's origin. Nothing it handles is sent anywhere beyond your own machine and, when you invoke a control action, the page you're already looking at.

## Questions

Open an issue on the project repository, or reach out via the email used at checkout.
