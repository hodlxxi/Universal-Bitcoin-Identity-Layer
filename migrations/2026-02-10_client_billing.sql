-- 2026-02-10: OAuth client_id billing tables

CREATE TABLE IF NOT EXISTS ubid_clients (
  client_id VARCHAR(255) PRIMARY KEY,
  payg_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  sats_balance BIGINT NOT NULL DEFAULT 0,
  free_quota_remaining BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  last_quota_reset TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_ubid_clients_updated ON ubid_clients (updated_at);

CREATE TABLE IF NOT EXISTS payments_clients (
  invoice_id VARCHAR(255) PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL REFERENCES ubid_clients(client_id),
  payment_request TEXT,
  amount_sats BIGINT NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
  paid_at TIMESTAMP WITH TIME ZONE,
  credited BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_payments_clients_client ON payments_clients (client_id);
