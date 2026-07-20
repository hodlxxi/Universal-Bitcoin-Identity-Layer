-- 2026-07-20: Durable one-time action step-up challenge state.
-- Apply with the repository's direct SQL migration process (psql -f).

CREATE TABLE IF NOT EXISTS action_step_up_challenges (
  challenge_id VARCHAR(64) PRIMARY KEY,
  contract_version VARCHAR(64) NOT NULL,
  signature_domain VARCHAR(64) NOT NULL,
  actor_pubkey VARCHAR(64) NOT NULL,
  oauth_client_id VARCHAR(256) NOT NULL,
  token_jti VARCHAR(128) NOT NULL,
  action VARCHAR(64) NOT NULL,
  resource_id VARCHAR(256),
  request_sha256 VARCHAR(64) NOT NULL,
  nonce VARCHAR(64) NOT NULL UNIQUE,
  issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  consumed_at TIMESTAMP WITH TIME ZONE,
  CONSTRAINT ck_action_step_up_challenge_id_length CHECK (length(challenge_id) = 32),
  CONSTRAINT ck_action_step_up_actor_pubkey_length CHECK (length(actor_pubkey) = 64),
  CONSTRAINT ck_action_step_up_client_id_length CHECK (length(oauth_client_id) BETWEEN 1 AND 256),
  CONSTRAINT ck_action_step_up_token_jti_length CHECK (length(token_jti) BETWEEN 1 AND 128),
  CONSTRAINT ck_action_step_up_action_length CHECK (length(action) BETWEEN 1 AND 64),
  CONSTRAINT ck_action_step_up_resource_id_length CHECK (resource_id IS NULL OR length(resource_id) BETWEEN 1 AND 256),
  CONSTRAINT ck_action_step_up_request_hash_length CHECK (length(request_sha256) = 64),
  CONSTRAINT ck_action_step_up_nonce_length CHECK (length(nonce) = 64),
  CONSTRAINT ck_action_step_up_time_order CHECK (issued_at < expires_at),
  CONSTRAINT ck_action_step_up_consumed_time CHECK (consumed_at IS NULL OR (consumed_at >= issued_at AND consumed_at < expires_at))
);

CREATE INDEX IF NOT EXISTS ix_action_step_up_challenges_actor_pubkey ON action_step_up_challenges (actor_pubkey);
CREATE INDEX IF NOT EXISTS ix_action_step_up_challenges_oauth_client_id ON action_step_up_challenges (oauth_client_id);
CREATE INDEX IF NOT EXISTS ix_action_step_up_challenges_token_jti ON action_step_up_challenges (token_jti);
CREATE INDEX IF NOT EXISTS ix_action_step_up_challenges_expires_at ON action_step_up_challenges (expires_at);
CREATE INDEX IF NOT EXISTS ix_action_step_up_challenges_consumed_at ON action_step_up_challenges (consumed_at);
CREATE INDEX IF NOT EXISTS idx_action_step_up_actor_action ON action_step_up_challenges (actor_pubkey, action);
CREATE INDEX IF NOT EXISTS idx_action_step_up_unconsumed_expiry ON action_step_up_challenges (consumed_at, expires_at);
