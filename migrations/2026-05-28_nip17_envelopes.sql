-- 2026-05-28: Opaque NIP-17/NIP-59 gift-wrap envelope storage
--
-- Stores encrypted relay-visible kind-1059 envelopes only.
-- Must never contain plaintext kind-14/kind-15 message bodies or user private keys.

CREATE TABLE IF NOT EXISTS nip17_envelopes (
  id VARCHAR(36) PRIMARY KEY,
  event_id VARCHAR(64) NOT NULL UNIQUE,
  envelope_hash VARCHAR(64) NOT NULL UNIQUE,
  wrapper_pubkey VARCHAR(64) NOT NULL,
  receiver_pubkey VARCHAR(64) NOT NULL,
  kind INTEGER NOT NULL DEFAULT 1059,
  event_created_at BIGINT NOT NULL,
  envelope_json JSONB NOT NULL,
  source VARCHAR(64) NOT NULL DEFAULT 'api',
  status VARCHAR(32) NOT NULL DEFAULT 'received',
  received_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  metadata JSONB
);

CREATE INDEX IF NOT EXISTS idx_nip17_envelopes_event_id ON nip17_envelopes (event_id);
CREATE INDEX IF NOT EXISTS idx_nip17_envelopes_envelope_hash ON nip17_envelopes (envelope_hash);
CREATE INDEX IF NOT EXISTS idx_nip17_receiver_received ON nip17_envelopes (receiver_pubkey, received_at);
CREATE INDEX IF NOT EXISTS idx_nip17_wrapper_received ON nip17_envelopes (wrapper_pubkey, received_at);
CREATE INDEX IF NOT EXISTS idx_nip17_status_received ON nip17_envelopes (status, received_at);
