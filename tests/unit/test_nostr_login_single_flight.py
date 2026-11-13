"""Execute the browser's Nostr login with synthetic ports; no app or network."""

import json
import subprocess
from pathlib import Path

import pytest

STAGES = ("publicKey", "challenge", "challengeJson", "sign", "verify", "verifyJson")

HARNESS = r"""
const assert = require("node:assert/strict");
const vm = require("node:vm");
const {source, blockedStage, failure} = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const calls = {};
const redirects = [];
const alerts = [];
let fail = failure;
let release;
const gate = new Promise(resolve => { release = resolve; });
async function step(name, result) {
  calls[name] = (calls[name] || 0) + 1;
  if (name === blockedStage) await gate;
  if (name === fail) throw new Error("synthetic failure");
  return result;
}
const location = {
  origin: "https://ubid.example",
  set href(value) {
    if (fail === "redirect") throw new Error("synthetic navigation failure");
    redirects.push(value);
  }
};
const nostr = {
  getPublicKey: () => step("publicKey", "a".repeat(64)),
  signEvent: event => {
    assert.equal(event.kind, 22242);
    assert.deepEqual(Array.from(event.tags, tag => Array.from(tag)), [
      ["challenge", "synthetic-challenge"], ["url", "https://ubid.example/api/verify"]
    ]);
    assert.equal(event.content, "");
    return step("sign", {syntheticSignedEvent: true});
  }
};
const context = vm.createContext({
  window: {nostr: fail === "extension" ? null : nostr, location},
  alert: message => alerts.push(message),
  console: {error() {}},
  getRedirectUrl: () => "/oauth/authorize?state=synthetic&code_challenge=synthetic",
  fetch: (url, options) => {
    assert.equal(options.method, "POST");
    assert.equal(options.headers["Content-Type"], "application/json");
    const body = JSON.parse(options.body);
    assert.equal(body.pubkey, "02" + "a".repeat(64));
    if (url === "/api/challenge") {
      assert.equal(body.method, "nostr");
      return step("challenge", {
        ok: fail !== "challengeRejected",
        json: () => step("challengeJson", {
          challenge: "synthetic-challenge", challenge_id: "synthetic-id"
        })
      });
    }
    assert.equal(url, "/api/verify");
    assert.equal(body.challenge_id, "synthetic-id");
    assert.deepEqual(body.nostr_event, {syntheticSignedEvent: true});
    return step("verify", {
      ok: fail !== "verifyRejected",
      json: () => step("verifyJson", {verified: fail !== "unverified"})
    });
  }
});
vm.runInContext(source, context);
(async () => {
  const first = context.loginWithNostr();
  if (blockedStage) {
    assert.equal(calls.publicKey, 1);
    const immediateDuplicate = context.loginWithNostr();
    assert.equal(calls.publicKey, 1, "guard must be acquired before the first await");
    await immediateDuplicate;
    await new Promise(setImmediate);
    assert.equal(calls[blockedStage], 1);
    const snapshot = {...calls};
    await context.loginWithNostr();
    assert.deepEqual(calls, snapshot, "duplicate must do nothing while an await is pending");
    release();
  }
  await first;
  if (failure) {
    assert.equal(redirects.length, 0);
    assert.equal(alerts.length, 1);
    fail = null;
    context.window.nostr = nostr;
    await context.loginWithNostr();
    assert.equal(redirects.length, 1, "failure must allow a fresh attempt");
  } else {
    assert.deepEqual(calls, {
      publicKey: 1, challenge: 1, challengeJson: 1, sign: 1, verify: 1, verifyJson: 1
    });
    assert.equal(alerts.length, 0);
  }
  const completed = {...calls};
  await context.loginWithNostr();
  assert.deepEqual(calls, completed, "guard must remain held after redirect starts");
  assert.deepEqual(redirects, ["/oauth/authorize?state=synthetic&code_challenge=synthetic"]);
  console.log("PASS");
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def _run_login(*, blocked_stage=None, failure=None):
    source = Path("app/browser_routes.py").read_text(encoding="utf-8")
    start = source.index("    let nostrLoginInFlight = false;")
    end = source.index("    // --- Bind pill buttons (mobile-safe) ---", start)
    result = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps({"source": source[start:end], "blockedStage": blocked_stage, "failure": failure}),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS", "login or duplicate invocation did not complete"


@pytest.mark.parametrize("blocked_stage", STAGES)
def test_duplicate_nostr_login_is_single_flight_through_redirect(blocked_stage):
    _run_login(blocked_stage=blocked_stage)


@pytest.mark.parametrize(
    "failure",
    (
        "extension",
        "publicKey",
        "challenge",
        "challengeRejected",
        "sign",
        "verify",
        "verifyJson",
        "verifyRejected",
        "unverified",
        "redirect",
    ),
)
def test_failed_nostr_login_allows_retry_without_redirect(failure):
    _run_login(failure=failure)
