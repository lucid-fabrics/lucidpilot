"""End-to-end tests for mcp_server.py: spawn the real server as a subprocess,
speak newline-delimited JSON-RPC over its stdio, and assert on the responses.
Subprocess (not import) on purpose - it proves the exact invocation Claude Code
performs (`python3 mcp_server.py`) works, including the path-based package
loader and stdout cleanliness.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

import ed25519_sign

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "mcp_server.py"

EXPECTED_BROWSER = 21
EXPECTED_INDICATOR = 6
EXPECTED_WRAPPERS = 2  # lucidpilot_command + my_browser_authorize


class McpClient:
    """One server subprocess with a line-oriented JSON-RPC client around it."""

    def __init__(self, env_overrides: dict[str, str], tmp_path: Path):
        import os

        env = os.environ.copy()
        # Isolated license state and a non-default bridge port so tests never
        # touch a real session's bridge or the user's real license file.
        env["LUCIDPILOT_LICENSE_DIR"] = str(tmp_path / "license")
        # A fresh ephemeral port per subprocess, never a fixed one: the CI
        # runner executes the push and pull_request jobs concurrently on the
        # same host, and two pytest suites sharing one fixed port had one
        # suite's server subprocess silently become the OTHER suite's client
        # - licensed by a foreign flip, so its own list_changed never fired.
        import socket
        with socket.socket() as _s:
            _s.bind(("127.0.0.1", 0))
            self.bridge_port = _s.getsockname()[1]
        env["LUCIDPILOT_BRIDGE_PORT"] = str(self.bridge_port)
        env.update(env_overrides)
        self.notifications: list[str] = []
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            cwd=str(REPO_ROOT),
        )
        self._next_id = 0

    def request(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        self._next_id += 1
        req = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            req["params"] = params
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        # The server also emits notifications (no "id"), e.g.
        # notifications/tools/list_changed after a call that changes tool
        # visibility. Collect those and keep reading until the real answer.
        while True:
            line = self.proc.stdout.readline()
            assert line, f"server produced no response to {method} (stderr: {self.proc.stderr.read() if self.proc.stderr else ''})"
            resp = json.loads(line)
            if "id" not in resp:
                self.notifications.append(resp.get("method", ""))
                continue
            assert resp.get("id") == self._next_id
            return resp

    def call_tool(self, name: str, arguments: dict) -> str:
        resp = self.request("tools/call", {"name": name, "arguments": arguments})
        assert "result" in resp, f"tools/call {name} errored: {resp.get('error')}"
        return resp["result"]["content"][0]["text"]

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


# bridge.py's _DEV_EXTENSION_ID - the pinned origin /assert-license accepts.
DEV_EXT_ORIGIN = "chrome-extension://bjgfoabbfphcjlklnonbladkdoljcgel"


def license_via_assertion(port: int, timeout: float = 10.0) -> None:
    """Make the subprocess's bridge genuinely licensed the way the real
    extension does it: a pinned-Origin POST /assert-license. No
    monkeypatching (impossible anyway: the server under test is a subprocess)
    and no state file - keys no longer exist on this side."""
    import time
    import urllib.request

    def status() -> dict | None:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/status", timeout=0.5) as resp:
                return json.loads(resp.read().decode() or "{}")
        except OSError:
            return None

    deadline = time.monotonic() + timeout
    while status() is None:
        assert time.monotonic() < deadline, "subprocess bridge never came up on /status"
        time.sleep(0.05)

    # valid_assert() carries a session token signed by the suite's test key;
    # the subprocess verifies it because McpClient's env copy inherits
    # conftest's LUCIDPILOT_LICENSE_PUBKEY.
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/assert-license",
        data=ed25519_sign.valid_assert().encode(),
        headers={"Origin": DEV_EXT_ORIGIN},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        assert json.loads(resp.read().decode())["ok"] is True
    while time.monotonic() < deadline:
        s = status()
        if s and s.get("licensed") is True:
            return
        time.sleep(0.05)
    raise AssertionError("bridge never became licensed from the assertion")


@pytest.fixture
def licensed_client(tmp_path):
    c = McpClient({"LUCIDPILOT_CONTROL_TOOLS": "always"}, tmp_path)
    license_via_assertion(c.bridge_port)
    yield c
    c.close()


@pytest.fixture
def client(tmp_path):
    c = McpClient({"LUCIDPILOT_CONTROL_TOOLS": "always"}, tmp_path)
    yield c
    c.close()


@pytest.fixture
def indicator_only_client(tmp_path):
    c = McpClient({"LUCIDPILOT_CONTROL_TOOLS": "never"}, tmp_path)
    yield c
    c.close()


def test_initialize_handshake(client):
    resp = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}})
    result = resp["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["serverInfo"]["name"] == "lucidpilot"
    assert result["serverInfo"]["version"]
    assert "tools" in result["capabilities"]


def test_initialize_sends_tool_selection_instructions(client):
    """MCP's `instructions` is this server's only shot at the guidance Hermes
    replays every turn through its pre_llm_call primer: which browser the user
    meant, when a session also has chrome-devtools-mcp or Playwright loaded.
    Pinned because dropping it is invisible - nothing errors, the model just
    quietly starts picking the wrong browser."""
    instructions = client.request("initialize", {})["result"]["instructions"]
    assert "my_browser_*" in instructions
    # The claim must stay scoped. A blanket "always use my_browser_*" reads as a win
    # and costs one: the model follows it into a sandboxed-scrape or
    # fetch-an-article task that another tool does better.
    assert "signed-in" in instructions
    assert "not for every link" in instructions
    assert "research question" in instructions
    assert "/lp authorize" in instructions


def test_unlicensed_exposes_only_the_lucidpilot_command_wrappers(client):
    """No free tier: an unlicensed session advertises no my_browser_*/indicator_*
    tools at all. The two /lp wrappers stay visible on purpose - they are how
    a user runs `/lp doctor` and learns where to activate (the popup)."""
    names = {t["name"] for t in client.request("tools/list")["result"]["tools"]}
    assert names == {"lucidpilot_command", "my_browser_authorize"}


def test_license_flip_pushes_list_changed_without_a_tools_call(client):
    """Activation now happens in the extension popup - no tools/call is in
    flight, so the per-call visibility diff never runs. The bridge's
    licence-change callback must push notifications/tools/list_changed on its
    own, or the new tools stay invisible until the next call."""
    assert client.request("initialize", {})["result"]["capabilities"]["tools"]["listChanged"] is True
    names = {t["name"] for t in client.request("tools/list")["result"]["tools"]}
    assert names == {"lucidpilot_command", "my_browser_authorize"}

    client.notifications.clear()
    license_via_assertion(client.bridge_port)  # the flip - and NOT via any tools/call
    names = {t["name"] for t in client.request("tools/list")["result"]["tools"]}
    assert "notifications/tools/list_changed" in client.notifications
    assert "indicator_click" in names  # licence-only gate opens with no authorize


def test_licensed_and_authorized_tools_list_full_surface(licensed_client):
    # Both gates open: licensed (fixture) AND Chrome control granted, which is
    # what my_browser_*'s check_fn additionally requires.
    licensed_client.call_tool("my_browser_authorize", {"args": "15m"})
    tools = licensed_client.request("tools/list")["result"]["tools"]
    names = [t["name"] for t in tools]
    assert len(names) == len(set(names)), "duplicate tool names"
    assert len(names) == EXPECTED_BROWSER + EXPECTED_INDICATOR + EXPECTED_WRAPPERS
    assert sum(1 for n in names if n.startswith("my_browser_")) == EXPECTED_BROWSER + 1  # +my_browser_authorize
    assert sum(1 for n in names if n.startswith("indicator_")) == EXPECTED_INDICATOR
    for tool in tools:
        assert tool["description"], f"{tool['name']} has no description"
        assert tool["inputSchema"]["type"] == "object", f"{tool['name']} schema is not an object"


def test_licensed_indicator_tools_visible_while_chrome_control_is_locked(licensed_client):
    """The overlay is licence-gated but NOT auth-gated: with a licence and no
    /lp authorize, indicator_* must be listed while my_browser_* stays hidden."""
    names = {t["name"] for t in licensed_client.request("tools/list")["result"]["tools"]}
    assert "indicator_click" in names
    assert "my_browser_click" not in names, "control tools must still need the Chrome-control grant"


def test_this_host_identifies_as_claude_not_hermes(licensed_client):
    """The overlay's toast/log label, its accent colour, and the Chrome tab
    group all follow bridge.AGENT. It was hardcoded "hermes" everywhere, so a
    Claude Code user saw "Hermes" in violet and a tab group named "Hermes" -
    caught by a user looking at their own popup. The MCP server must declare
    itself; this asserts that from outside the process, through a real tool
    call, rather than trusting the constant.
    """
    out = licensed_client.call_tool("indicator_show", {})
    # No bridge/extension answers in this harness, so the guard returns the
    # fallback JS - which embeds the very agent value that would have been
    # wrong. Cheapest honest observation point for a subprocess.
    assert '"agent": "claude"' in out or "'agent': 'claude'" in out, out
    assert "hermes" not in out.lower(), out


def test_lp_command_help_uses_this_host_command_name(client):
    """Claude Code namespaces plugin commands, so the help must say
    /lucidpilot:lp - printing the bare /lp sent users to a command that
    answers "Unknown command"."""
    text = client.call_tool("lucidpilot_command", {"args": "help"})
    assert "/lucidpilot:lp authorize" in text
    assert "/lucidpilot:lp license" in text


def test_lp_command_refuses_authorize(client):
    text = client.call_tool("lucidpilot_command", {"args": "authorize 15m"})
    assert "my_browser_authorize" in text
    # and it must NOT have actually authorized
    status = client.call_tool("lucidpilot_command", {"args": "status"})
    assert "locked" in status.lower() or "authorize" in status.lower()


def test_lp_tool_gated_when_locked(client):
    text = client.call_tool("my_browser_click", {"x": 1, "y": 1})
    # Gating error arrives in-band as a string, not as a crash or JSON-RPC error.
    assert text.startswith("[lucidpilot]")
    assert "authoriz" in text.lower() or "locked" in text.lower()


def test_authorize_then_status_reflects_it(client):
    out = client.call_tool("my_browser_authorize", {"args": "15m"})
    assert "authoriz" in out.lower()
    status = client.call_tool("lucidpilot_command", {"args": "status"})
    assert "auth:" in status
    assert "locked" not in status.split("auth:")[1].split("·")[0].lower()


def test_control_tools_never_serves_no_browser_tools(indicator_only_client):
    """LUCIDPILOT_CONTROL_TOOLS=never skips my_browser_* registration entirely. This
    fixture is also unlicensed, so indicator_* is hidden by its licence gate
    too - leaving nothing but the wrappers."""
    names = {t["name"] for t in indicator_only_client.request("tools/list")["result"]["tools"]}
    assert not any(n.startswith("indicator_") for n in names)
    assert not any(n.startswith("my_browser_") and n != "my_browser_authorize" for n in names)


def test_unknown_method_and_unknown_tool(client):
    resp = client.request("no/such/method")
    assert resp["error"]["code"] == -32601
    resp = client.request("tools/call", {"name": "lp_nope", "arguments": {}})
    assert resp["error"]["code"] == -32602


def test_authorize_announces_the_new_tool_list(licensed_client):
    """A client caches the startup tool list. Without this notification,
    `/lp authorize` reported success while every my_browser_* tool stayed invisible
    until the session restarted - the bug that made the plugin unusable for
    its own author mid-session."""
    assert licensed_client.request("initialize", {})["result"]["capabilities"]["tools"]["listChanged"] is True

    # The licence flip that licensed this fixture pushes ONE list_changed from
    # the bridge's HTTP thread, at a schedule-dependent point in the stdout
    # stream. Drain it before asserting any quiet window - on a slow runner it
    # otherwise lands inside the "must stay quiet" check below (seen on CI).
    import time as _time
    deadline = _time.monotonic() + 5
    while "notifications/tools/list_changed" not in licensed_client.notifications:
        assert _time.monotonic() < deadline, "licence-flip list_changed never arrived"
        licensed_client.request("ping")

    licensed_client.notifications.clear()
    licensed_client.call_tool("my_browser_authorize", {"args": "15m"})
    # Piggy-backed on the next response's read loop.
    names = {t["name"] for t in licensed_client.request("tools/list")["result"]["tools"]}
    assert "notifications/tools/list_changed" in licensed_client.notifications
    assert "my_browser_click" in names

    # A call that changes nothing must stay quiet - a notification per call
    # would have every client re-listing constantly.
    licensed_client.notifications.clear()
    licensed_client.call_tool("lucidpilot_command", {"args": "status"})
    licensed_client.request("ping")
    assert licensed_client.notifications == []
