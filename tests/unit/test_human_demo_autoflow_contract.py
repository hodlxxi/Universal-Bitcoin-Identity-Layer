from app.factory import create_app


def test_human_demo_requires_a_key_and_auto_advances_after_payment():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo", base_url="https://hodlxxi.com")
    text = response.get_data(as_text=True)

    assert response.status_code == 200

    for marker in [
        'name="requester_pubkey"',
        "required",
        "isValidRequesterPubkey",
        'demo: "human_proof_v2"',
        "demo_nonce",
        "newDemoNonce",
        "startPolling",
        "POLL_INTERVAL_MS",
        "checkJob({ fromPolling: true })",
        "await verifyJob()",
        "What the signed receipt remembers",
        "requester_pubkey_proof",
        "proofPaymentHash",
        "proofResultHash",
        "proofAgentPubkey",
        "verified agent signature",
    ]:
        assert marker in text


def test_human_demo_keeps_the_identity_boundary_explicit():
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    response = client.get("/demo")
    text = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "proven by a compatible Nostr signer" in text
    assert "This proves control of the signing key for this request" in text
    assert "Requester key proof means key control for this request only." in text
    assert "signature_verified" in text
    assert "No private key is requested" in text


def test_human_demo_v2_bound_proof_contract_markers():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    assert "human_proof_v2" in text
    assert "window.nostr.getPublicKey" in text
    assert (
        text.index('fetch("/api/challenge"') < text.index('fetch("/api/verify"') < text.index('fetch("/agent/request"')
    )
    assert "demo_nonce: newDemoNonce()" in text
    assert "preparedRequestBody" in text
    assert "private" not in text.lower() or "No private key is requested" in text
    assert "It does not prove a legal name, government identity, or that one human controls only one key." in text
    for marker in [
        "HODLXXI is a Bitcoin-native proof runtime: pay for an action, get a result, and verify the signed receipt later.",
        "I paid, I requested, I received, I can verify.",
        "What this proves",
        "What this does not prove",
        "not a token sale",
        "not an investment",
        "not KYC",
        "not legal identity",
        "not custody",
        "not a promise of profit",
        "not proof of moral trustworthiness",
        "not a guarantee of future performance",
        "not ownership of a network",
    ]:
        assert marker in text


def test_human_demo_marks_pay_card_paid_when_job_completes():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    done_marker = 'const done = data.status === "done" || Boolean(data.receipt);'
    paid_marker = 'setBadge("requestStatus", "paid", "ok");'
    result_marker = 'setBadge("jobStatus", "result received", "ok");'
    verify_marker = "await verifyJob();"
    reset_marker = 'setBadge("requestStatus", "not requested", "warn");'

    assert done_marker in text
    assert paid_marker in text
    assert result_marker in text
    assert verify_marker in text
    assert reset_marker in text
    assert text.index(done_marker) < text.index(paid_marker) < text.index(result_marker) < text.index(verify_marker)


def test_human_demo_does_not_request_invoice_before_verify_success():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    assert 'fetch("/api/verify"' in text
    assert 'fetch("/agent/request"' in text
    assert text.index("if (!verifyResponse.ok) throw new Error") < text.index(
        "await submitVerifiedPreparedRequest(stored.pubkey)"
    )
    assert text.index("await provePreparedRequest(signerPubkey, preparedRequestBody)") < text.index(
        "await submitVerifiedPreparedRequest(signerPubkey)"
    )


def test_human_demo_android_callback_failure_reenables_create_button():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    resume_marker = "async function resumeAndroidProofFromCallback()"
    catch_marker = """showRequesterError(String(error).replace(/^Error: /, ""));
        setText("requestResponse", compactJson({ error: String(error) }));
        document.getElementById("createButton").disabled = false;"""
    assert text.index(resume_marker) < text.index(catch_marker)


def test_human_demo_android_callback_success_clears_mobile_query_after_verify():
    from pathlib import Path

    text = Path("app/templates/agent/demo.html").read_text()
    verify_ok_marker = 'if (!verifyResponse.ok) throw new Error(verifyData.error || "Proof verification failed");'
    hash_match_marker = 'if (verifyData.request_hash !== stored.request_hash) throw new Error("Verified proof did not match the prepared request.");'
    clear_history_marker = "window.history.replaceState({}, document.title, window.location.pathname);"
    submit_marker = "await submitVerifiedPreparedRequest(stored.pubkey);"

    assert clear_history_marker in text
    assert (
        text.index(verify_ok_marker)
        < text.index(hash_match_marker)
        < text.index(clear_history_marker)
        < text.index(submit_marker)
    )
