"""Opt-in paired check using the real public UBID handler and the Social reader."""

import json
import os
import socket
import subprocess
from threading import Thread

import pytest
from sqlalchemy.orm import Session, sessionmaker
from werkzeug.serving import make_server

from tests.integration.test_automatic_sponsored_admission_postgres_v1 import (
    ALICE,
    BOB,
    EARLY,
    LATE,
    User,
    auto_db,
    automatic_engine,
    coordinate_automatic_pair,
    core,
    imported,
)

HOST = "ubid-preview.hodlxxi.test"
READ_SOCIAL = """
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createSocialAuthorityReader } from "./src/server/social-authority-reader.mjs";
import { createSocialOAuthBff } from "./src/server/social-oauth-bff.mjs";
import { createBoundedStore } from "./src/server/social-oauth-memory.mjs";
import { SESSION_COOKIE_NAME } from "./src/server/social-oauth-cookie.mjs";
import { buildAuthenticatedProductView } from "./web/auth-entry.mjs";

const [origin, subject] = process.argv.slice(1);
const config = {authorityOrigin: origin, outboundTimeoutMs: 5000};
const store = () => createBoundedStore({ttlSeconds: 60, capacity: 4});
const sessions = store();
const handle = randomUUID();
assert.ok(sessions.create(handle, {subject}));
const bff = createSocialOAuthBff({
  config, sessions, pendingTransactions: store(), authorityReader: createSocialAuthorityReader(config),
  oauthClient: {authenticate() { throw Error("unexpected login"); }}
});
const result = await bff({method: "GET", url: "/auth/authority", headers: {cookie: SESSION_COOKIE_NAME+"="+handle}});
assert.equal(result.status, 200);
const authority = JSON.parse(result.body);
const ui = buildAuthenticatedProductView({authenticated: true, subject}, authority, "#/full-network");
assert.equal(ui.route.page, authority.valid && authority.status === "full" ? "full-network" : "not-found");
console.log(JSON.stringify(authority));
"""


def test_full_refresh_and_social_read_same_live_publication(auto_db, core, app, tmp_path):
    social = os.getenv("SOCIAL_AUTHORITY_TEST_CHECKOUT")
    if not social:
        pytest.skip("requires paired Social checkout and isolated Preview DNS")
    assert {row[4][0] for row in socket.getaddrinfo(HOST, None)} == {"127.0.0.1"}
    bundles = [tmp_path / name for name in ("trusted", "unrelated")]
    for bundle in bundles:
        subprocess.run(["sh", "scripts/prepare_browser_preview_tls.sh", bundle], check=True)
    trusted, unrelated = bundles
    context = (str(trusted / "https.pem"), str(trusted / "https.key"))
    server = make_server("127.0.0.1", 0, app, threaded=True, ssl_context=context)
    port = server.server_port
    origin = f"https://{HOST}:{port}"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def fetch(subject, host, ca):
        return subprocess.run(
            [
                "curl",
                "-q",
                "--noproxy",
                "*",
                "--proto",
                "=https",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "5",
                "--cacert",
                ca / "preview-ca.pem",
                "--resolve",
                f"{host}:{port}:127.0.0.1",
                f"https://{host}:{port}/agent/authority/current/{subject}.json",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )

    def observe(subject, expected):
        response = fetch(subject, HOST, trusted)
        response.check_returncode()
        raw = json.loads(response.stdout)
        assert raw["subject"] == subject and raw["valid"] is True
        assert raw["identity_class"] == expected
        assert raw["current_full_relation_satisfied"] is (expected == "full")
        output = subprocess.check_output(
            ["node", "--input-type=module", "-e", READ_SOCIAL, origin, subject],
            cwd=social,
            timeout=10,
            env={**os.environ, "NODE_EXTRA_CA_CERTS": str(trusted / "preview-ca.pem")},
        )
        assert json.loads(output) == {"subject": subject, "status": expected, "valid": True}

    try:
        with Session(auto_db) as db, db.begin():
            db.add(User(pubkey=BOB[2:], is_active=True, metadata_json={}))
        observe(ALICE[2:], "full")
        observe(BOB[2:], "limited")
        core.fund(EARLY, LATE)
        pair = imported(auto_db)
        coordinate_automatic_pair(sessionmaker(auto_db), pair)
        observe(BOB[2:], "full")
        for host, ca in (("wrong.test", trusted), (HOST, unrelated)):
            refused = fetch(BOB[2:], host, ca)
            assert refused.returncode == 60, refused.stderr
        core.spent.add(next(iter(core.coins)))
        assert not coordinate_automatic_pair(sessionmaker(auto_db), pair).eligible
        observe(BOB[2:], "limited")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()
