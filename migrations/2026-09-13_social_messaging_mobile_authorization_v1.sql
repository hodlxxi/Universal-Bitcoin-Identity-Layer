-- Dormant mobile authorization storage. Apply in one separately authorized
-- transaction, after the device-binding authorization migration. No activation.
-- Rollback before commit is ordinary PostgreSQL DDL rollback. After accepted
-- data exists, retain these ledgers; dropping replay history is not a rollback.

CREATE TABLE social_messaging_device_authorization_requests (
  request_id VARCHAR(64) PRIMARY KEY CHECK (request_id ~ '^[0-9a-f]{64}$'),
  owner VARCHAR(6) NOT NULL CHECK (owner IN ('nostr','mobile')),
  digest VARCHAR(64) NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
  UNIQUE (request_id, owner, digest)
);
INSERT INTO social_messaging_device_authorization_requests (request_id, owner, digest)
SELECT request_id, 'nostr', digest FROM social_messaging_device_binding_authorization_replay;

CREATE FUNCTION claim_social_authorization_request_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO social_messaging_device_authorization_requests (request_id, owner, digest)
    VALUES (NEW.request_id, 'nostr', NEW.digest);
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_nostr_global_request
  BEFORE INSERT ON social_messaging_device_binding_authorization_replay
  FOR EACH ROW EXECUTE FUNCTION claim_social_authorization_request_v1();
CREATE TRIGGER trg_social_global_request_immutable
  BEFORE UPDATE OR DELETE ON social_messaging_device_authorization_requests
  FOR EACH ROW EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();

CREATE TABLE social_messaging_mobile_operations (
  operation_id VARCHAR(64) PRIMARY KEY,
  method VARCHAR(24) NOT NULL CHECK (method IN ('legacy_challenge_v1','qr_desktop_v1')),
  subject VARCHAR(64) NOT NULL CHECK (subject ~ '^[0-9a-f]{64}$'),
  context_id VARCHAR(64) NOT NULL CHECK (context_id ~ '^[0-9a-f]{64}$'),
  session_commitment VARCHAR(64) NOT NULL CHECK (session_commitment ~ '^[0-9a-f]{64}$'),
  created_at BIGINT NOT NULL CHECK (created_at >= 0),
  expires_at BIGINT NOT NULL,
  revision VARCHAR(64),
  secret_commitment VARCHAR(64),
  request_id VARCHAR(64) UNIQUE REFERENCES social_messaging_device_authorization_requests(request_id),
  authorization_digest VARCHAR(64) UNIQUE,
  source TEXT,
  status VARCHAR(24) NOT NULL CHECK (status IN (
    'created','reserved','awaiting-approval','approval-claimed',
    'accepted','expired','cancelled','abandoned','rejected')),
  UNIQUE (operation_id, request_id, authorization_digest),
  CHECK (created_at < expires_at AND expires_at <= created_at + 300),
  CHECK (
    (method = 'legacy_challenge_v1'
      AND operation_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND revision IS NULL AND secret_commitment IS NULL
      AND source IS NOT NULL AND status NOT IN ('created','awaiting-approval','approval-claimed'))
    OR (method = 'qr_desktop_v1' AND operation_id ~ '^[0-9a-f]{64}$'
      AND revision ~ '^[0-9a-f]{64}$' AND revision IS NOT NULL
      AND secret_commitment ~ '^[0-9a-f]{64}$' AND secret_commitment IS NOT NULL
      AND status <> 'reserved')),
  CHECK ((source IS NULL AND request_id IS NULL AND authorization_digest IS NULL
      AND status IN ('created','expired','cancelled','abandoned','rejected'))
    OR (source IS NOT NULL AND octet_length(source) BETWEEN 1 AND 16384
      AND request_id IS NOT NULL AND request_id ~ '^[0-9a-f]{64}$'
      AND authorization_digest IS NOT NULL AND authorization_digest ~ '^[0-9a-f]{64}$'
      AND status <> 'created'))
);
CREATE INDEX idx_social_mobile_expiry ON social_messaging_mobile_operations (status, expires_at);

CREATE FUNCTION guard_social_mobile_operation_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'mobile authorization unavailable';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT ((NEW.method = 'legacy_challenge_v1' AND NEW.status = 'reserved')
       OR (NEW.method = 'qr_desktop_v1' AND NEW.status = 'created')) THEN
      RAISE EXCEPTION 'mobile authorization unavailable';
    END IF;
  ELSE
    IF ROW(NEW.operation_id,NEW.method,NEW.subject,NEW.context_id,NEW.session_commitment,
       NEW.created_at,NEW.expires_at,NEW.revision,NEW.secret_commitment)
       IS DISTINCT FROM ROW(OLD.operation_id,OLD.method,OLD.subject,OLD.context_id,OLD.session_commitment,
       OLD.created_at,OLD.expires_at,OLD.revision,OLD.secret_commitment)
       OR (OLD.source IS NOT NULL AND ROW(NEW.source,NEW.request_id,NEW.authorization_digest)
          IS DISTINCT FROM ROW(OLD.source,OLD.request_id,OLD.authorization_digest))
       OR NOT (
          (OLD.status = 'created' AND NEW.status IN ('awaiting-approval','expired','cancelled','abandoned','rejected'))
          OR (OLD.status = 'awaiting-approval' AND NEW.status IN ('approval-claimed','expired','cancelled','abandoned','rejected'))
          OR (OLD.status IN ('reserved','approval-claimed') AND NEW.status IN ('accepted','expired','cancelled','abandoned','rejected'))
       ) THEN
      RAISE EXCEPTION 'mobile authorization unavailable';
    END IF;
  END IF;
  IF NEW.request_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM social_messaging_device_authorization_requests
      WHERE request_id = NEW.request_id AND owner = 'mobile' AND digest = NEW.authorization_digest
  ) THEN
    RAISE EXCEPTION 'mobile authorization unavailable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_mobile_operation_guard BEFORE INSERT OR UPDATE OR DELETE
  ON social_messaging_mobile_operations FOR EACH ROW EXECUTE FUNCTION guard_social_mobile_operation_v1();

CREATE TABLE social_messaging_mobile_acceptances (
  operation_id VARCHAR(64) PRIMARY KEY,
  request_id VARCHAR(64) NOT NULL UNIQUE,
  authorization_digest VARCHAR(64) NOT NULL UNIQUE,
  binding_id VARCHAR(64) NOT NULL UNIQUE REFERENCES social_messaging_device_bindings(binding_id) ON DELETE RESTRICT,
  proof_source TEXT NOT NULL CHECK (octet_length(proof_source) BETWEEN 1 AND 16384),
  result_source TEXT NOT NULL CHECK (octet_length(result_source) BETWEEN 1 AND 2048),
  accepted_at BIGINT NOT NULL CHECK (accepted_at >= 0),
  current_full_proof_id VARCHAR(112) NOT NULL
    CHECK (current_full_proof_id ~ '^hodlxxi-full-entitlement-v1-sha256:[0-9a-f]{64}$'),
  current_full_expires_at BIGINT NOT NULL CHECK (accepted_at < current_full_expires_at),
  FOREIGN KEY (operation_id, request_id, authorization_digest)
    REFERENCES social_messaging_mobile_operations(operation_id, request_id, authorization_digest)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
);

-- Shared binding ownership stops method-specific evidence tables from accepting
-- two independent authorizations for one canonical binding identity.
CREATE TABLE social_messaging_device_authorization_binding_owners (
  binding_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_device_bindings(binding_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED,
  request_id VARCHAR(64) NOT NULL UNIQUE REFERENCES social_messaging_device_authorization_requests(request_id)
    DEFERRABLE INITIALLY DEFERRED
);
INSERT INTO social_messaging_device_authorization_binding_owners (binding_id, request_id)
SELECT binding_id, request_id FROM social_messaging_device_binding_authorization_evidence;
CREATE FUNCTION claim_social_authorization_binding_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO social_messaging_device_authorization_binding_owners (binding_id, request_id)
    VALUES (NEW.binding_id, NEW.request_id);
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_nostr_binding_owner BEFORE INSERT
  ON social_messaging_device_binding_authorization_evidence
  FOR EACH ROW EXECUTE FUNCTION claim_social_authorization_binding_v1();
CREATE TRIGGER trg_social_mobile_binding_owner BEFORE INSERT
  ON social_messaging_mobile_acceptances
  FOR EACH ROW EXECUTE FUNCTION claim_social_authorization_binding_v1();
CREATE TRIGGER trg_social_binding_owner_immutable BEFORE UPDATE OR DELETE
  ON social_messaging_device_authorization_binding_owners
  FOR EACH ROW EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();

CREATE FUNCTION validate_social_mobile_acceptance_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE op social_messaging_mobile_operations; receipt social_messaging_mobile_acceptances;
BEGIN
  SELECT * INTO op FROM social_messaging_mobile_operations WHERE operation_id = NEW.operation_id;
  SELECT * INTO receipt FROM social_messaging_mobile_acceptances WHERE operation_id = NEW.operation_id;
  IF (op.status = 'accepted') IS DISTINCT FROM (receipt.operation_id IS NOT NULL)
    OR (receipt.operation_id IS NOT NULL AND NOT (op.created_at <= receipt.accepted_at AND receipt.accepted_at < op.expires_at)) THEN
    RAISE EXCEPTION 'mobile authorization unavailable';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER trg_social_mobile_operation_receipt AFTER INSERT OR UPDATE
  ON social_messaging_mobile_operations DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION validate_social_mobile_acceptance_v1();
CREATE CONSTRAINT TRIGGER trg_social_mobile_receipt_state AFTER INSERT
  ON social_messaging_mobile_acceptances DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION validate_social_mobile_acceptance_v1();
CREATE TRIGGER trg_social_mobile_receipt_immutable BEFORE UPDATE OR DELETE
  ON social_messaging_mobile_acceptances
  FOR EACH ROW EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();

CREATE TABLE social_messaging_mobile_exchanges (
  operation_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_mobile_acceptances(operation_id) ON DELETE RESTRICT,
  expires_at BIGINT NOT NULL CHECK (expires_at >= 0)
);
CREATE TABLE social_messaging_mobile_session_handoffs (
  operation_id VARCHAR(64) PRIMARY KEY REFERENCES social_messaging_mobile_exchanges(operation_id) ON DELETE RESTRICT,
  identity_source TEXT NOT NULL CHECK (octet_length(identity_source) BETWEEN 1 AND 2048),
  consumed_at BIGINT NOT NULL CHECK (consumed_at >= 0)
);
-- State/proof validation remains in the transaction owner; database guards below
-- independently enforce accepted QR-only, non-revoke and one-shot handoff.
CREATE FUNCTION validate_social_mobile_exchange_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE op social_messaging_mobile_operations; content JSONB; deadline BIGINT; accepted BIGINT;
BEGIN
  SELECT * INTO op FROM social_messaging_mobile_operations WHERE operation_id = NEW.operation_id;
  SELECT accepted_at INTO accepted FROM social_messaging_mobile_acceptances WHERE operation_id = NEW.operation_id;
  content := (op.source::jsonb ->> 'content')::jsonb;
  deadline := extract(epoch FROM ((coalesce(content -> 'authorization', content -> 'adoption') ->> 'expiresAt')::timestamptz))::bigint;
  IF op.method <> 'qr_desktop_v1' OR op.status <> 'accepted'
     OR content -> 'authorization' ->> 'operation' = 'revoke'
     OR NOT (accepted < NEW.expires_at AND NEW.expires_at = deadline) THEN
    RAISE EXCEPTION 'mobile authorization unavailable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_mobile_exchange_guard BEFORE INSERT ON social_messaging_mobile_exchanges
  FOR EACH ROW EXECUTE FUNCTION validate_social_mobile_exchange_v1();
CREATE TRIGGER trg_social_mobile_exchange_immutable BEFORE UPDATE OR DELETE ON social_messaging_mobile_exchanges
  FOR EACH ROW EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();
CREATE FUNCTION validate_social_mobile_handoff_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM social_messaging_mobile_exchanges e JOIN social_messaging_mobile_acceptances a USING(operation_id)
    WHERE e.operation_id = NEW.operation_id AND a.accepted_at <= NEW.consumed_at AND NEW.consumed_at < e.expires_at
  ) THEN
    RAISE EXCEPTION 'mobile authorization unavailable';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_mobile_handoff_guard BEFORE INSERT ON social_messaging_mobile_session_handoffs
  FOR EACH ROW EXECUTE FUNCTION validate_social_mobile_handoff_v1();
CREATE TRIGGER trg_social_mobile_handoff_immutable BEFORE UPDATE OR DELETE ON social_messaging_mobile_session_handoffs
  FOR EACH ROW EXECUTE FUNCTION reject_social_device_authorization_mutation_v1();
