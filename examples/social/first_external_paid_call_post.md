HODLXXI / Volya.ID is looking for **one** external builder to run the first live paid-call test.

Endpoints:
- https://hodlxxi.com/.well-known/agent.json
- https://hodlxxi.com/agent/discovery
- https://hodlxxi.com/agent/capabilities
- https://hodlxxi.com/agent/request
- https://hodlxxi.com/agent/jobs/<job_id>
- https://hodlxxi.com/agent/verify/<job_id>

Flow: discover -> inspect -> request (`job_type=ping`) -> receive invoice -> manual Lightning payment -> poll -> verify receipt/trust event.

Can your DVM/MCP/Lightning client call this end-to-end?

Rules: no custody, no auto-payments, no outbound spending, verify don't trust.

Post this invite from the founder/operator human npub, never from the server agent private key.
