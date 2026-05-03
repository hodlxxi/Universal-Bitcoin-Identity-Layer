def test_verify_nostr_page_has_status_block_not_placeholder(client):
    res = client.get('/verify/nostr/sample-event')
    assert res.status_code == 200
    text = res.get_data(as_text=True)
    assert 'Nostr Event Verification' in text
    assert 'PENDING' in text
    assert 'relay_transport_not_implemented' in text
    assert 'placeholder' not in text.lower()
