# IAC-01 isolated Invite & Call preview

Use only dedicated synthetic NIP-07 signers and disposable, trusted local
infrastructure. The ordinary application has no IAC runtime entrypoint.
The standalone composition accepts only a dedicated `iac-*.test` HTTPS origin
on an unprivileged port, loopback UDP TURN, and explicit in-memory synthetic
accounts. Provide a certificate trusted by the isolated client and a dedicated
TURN REST secret out of band. Never use production or staging configuration.

The store runs in one process and holds at most 128 preauth contexts, 128
sessions, and 128 invite records. It drops terminal signal payloads immediately
and reclaims terminal invite records after five minutes as requests arrive.
Session and invite credentials are independent and opaque. The server keeps
only their digests. Restarting invalidates all grants. The browser keeps its
CSRF value in memory, strips the invitation fragment before startup requests,
and reloads status for the exact session. Reload during negotiation ends the
call and requires a fresh invitation. No participant private key enters the app.

The server verifies the exact NIP-07 event with the existing BIP340 verifier.
Synthetic Current Full is checked at issuance, claim and mutual approval.
The recipient must be an active verified subject and may be Limited. Both
participants have to approve. Treat the comparison code as an out-of-band
consent aid. A stolen invite can still be claimed before the intended person.
Do not confirm when the comparison fails.

The signaling mailbox limits individual SDP and ICE payloads to 64 KiB and
4 KiB respectively, queued messages to 128 per recipient, total queued bodies
to 256 KiB per call, and deduplication history to 256 IDs per sender. Polling
uses a 1.4-second client interval with a 60-second disconnect grace. Signaling
uses relay-only trickle ICE for the configured IPv4 address. TURN credentials
are unique opaque usernames and expire after five minutes. The coturn instance
must use per-user and total allocation quotas, have a scratch database and
PID file, and bind only to loopback in the isolated namespace.

Signaling or credential revocation does not guarantee termination of existing
media allocations. The cooperating clients stop tracks and close their peer
connections. A peer's reported connection state is UX only. The relay and
signaling operator can observe metadata. The engineering preview makes no
production lineage, verified-human communication, or family rollout claim.

## Local verification

Use the repository's existing Python dependencies and Node. Run the `pytest`
command below from a clean environment with disposable fixture storage.

```sh
python -m pytest -q -ra -p no:cacheprovider \
  tests/unit/test_invite_call_v0.py tests/integration/test_invite_call_preview.py \
  tests/unit/test_nostr_auth_verify_helper.py tests/unit/test_nostr_login_single_flight.py \
  tests/unit/test_webrtc_signaling_regression.py tests/unit/test_canonical_login_persistence.py \
  tests/unit/test_oauth_session_lifecycle.py tests/test_oauth_flows.py
node --check app/static/iac/client.js
```

The opt-in HTTPS test requires existing OpenSSL, coturn and Linux namespace
tooling. The test checks that the namespace has only the loopback interface
before binding anything. It checks default certificate rejection, verifies the
preview hostname against the scratch trust anchor, signs real synthetic
authentication events, and uses the issued credentials for relay packet probes.
It exercises HTTPS and TURN without launching a browser or handling real media.
Use a fresh scratch home and directory and do not inherit application secrets.

```sh
unshare --net --fork --kill-child sh -c '
  ip link set lo up &&
  IAC_RUN_TLS_SMOKE=1 python -m pytest -q -ra -p no:cacheprovider \
    tests/integration/test_invite_call_preview.py \
    -k verified_isolated_https_and_authorized_turn_probe
'
```

Record the candidate SHA and actual runtime SHA separately. The next acceptance
gate needs two independent trusted browser profiles and external synthetic
signers or an explicitly labeled external test harness. Confirm the selected
candidate pair on both peers with `getStats()`, confirm real audio exchange and
optional video with two people, and verify track teardown and third-browser
denial. Keep certificates and signer material inside the disposable environment.
