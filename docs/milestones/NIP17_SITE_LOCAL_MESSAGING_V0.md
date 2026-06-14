# HODLXXI NIP-17 Site-Local Messaging v0

Status: milestone complete / production dogfood ready.

## What works

HODLXXI supports a site-local encrypted private messaging loop:

1. A logged-in sender opens `/home#messages`.
2. The browser normalizes a receiver `npub`, 64-hex x-only pubkey, or 66-hex compressed pubkey.
3. The browser encrypts the message locally with `window.nostr.nip44.encrypt(...)`.
4. The browser signs a kind `1059` envelope with `window.nostr.signEvent(...)`.
5. The server accepts and stores only the opaque encrypted envelope.
6. A logged-in receiver opens `/home#messages`.
7. The browser loads `/api/messages/nip17/inbox/envelopes?include_envelope=1`.
8. The receiver decrypts locally with `window.nostr.nip44.decrypt(...)`.

## Production dogfood mode

Production intake may be enabled with:

    NIP17_MESSAGES_ENABLED=1

This enables local HTTP intake for authenticated users. It does not enable relay publishing.

The intended production-dogfood mode is:

- authenticated users may submit encrypted envelopes;
- relay publication remains disabled;
- the server stores only opaque encrypted envelopes;
- private messages are sent and decrypted through `/home#messages`;
- `/app` remains the Global Chat surface.

## Security invariants

The messaging v0 milestone preserves these invariants:

- Server does not receive plaintext.
- Server does not decrypt.
- Server does not store plaintext.
- Server does not custody private keys.
- Server does not publish to Nostr relays.
- Envelope intake requires an authenticated session.
- Envelope intake accepts only encrypted kind `1059` shaped envelopes.
- Envelope intake has a configurable max envelope size.
- Envelope bodies are returned only through explicit `include_envelope=1` for the authenticated receiver.
- Duplicate event IDs are not stored twice.
- Retention tooling exists for opaque envelope cleanup.

## HTTP surfaces

### Public policy

    GET /.well-known/nostr-dm-policy.json

This exposes the current messaging policy, including:

- `enabled`
- `intake_enabled`
- `relay_publishing`
- `key_custody`
- `server_plaintext_storage`
- `accepted_transport_kind`
- `auth_required`
- `max_envelope_bytes`

### Envelope intake

    POST /api/messages/nip17/envelopes

This endpoint accepts only an encrypted envelope object:

    {"envelope": {...}}

It does not accept plaintext messages as server transport.

### Inbox status

    GET /api/messages/nip17/inbox/status

Returns authenticated receiver inbox metadata only.

### Inbox envelopes

    GET /api/messages/nip17/inbox/envelopes
    GET /api/messages/nip17/inbox/envelopes?include_envelope=1

By default, the inbox list is metadata-only.

`include_envelope=1` explicitly returns the opaque encrypted envelope body to the authenticated receiver so the browser can decrypt locally.

## UI surfaces

### `/home#messages`

This is the private encrypted message surface.

It supports:

- recipient pubkey / npub input;
- browser-side encryption;
- signed kind `1059` envelope upload;
- encrypted inbox loading;
- browser-local decrypt.

### `/app`

This remains the Global Chat surface.

It supports:

- live Socket.IO chat;
- online presence;
- calls;
- public/global room behavior.

`/app` may show read-only encrypted inbox status, but private send/decrypt belongs in `/home#messages`.

## What this is not yet

This milestone is not full external Nostr relay messaging.

Deferred work:

- Real relay publication.
- Full NIP-17/NIP-59 external-client compatibility.
- Multi-relay delivery and retry logic.
- Contact list / address book.
- Conversation threading.
- Read receipts.
- Push notifications.
- Mobile notification integration.

## Why relay publication is deferred

The current milestone proves the private messaging safety loop first:

    browser encrypts
    browser signs
    server stores opaque envelope
    receiver loads opaque envelope
    browser decrypts

Relay publication is a separate phase because it requires additional delivery, compatibility, retry, relay-list, and external-client semantics.

## Rollback

Disable intake by removing or overriding:

    NIP17_MESSAGES_ENABLED=1

Then restart the service.

Stored opaque envelopes remain in the database until retention cleanup is applied.

## Milestone summary

HODLXXI now has a working site-local encrypted messaging v0:

    Key A sends encrypted message to Key B
    Key B loads inbox
    Key B decrypts locally
    Server never sees plaintext
    Server never decrypts
    Server never custodies keys
    Server does not publish to relays

This completes the private messaging v0 dogfood milestone.
