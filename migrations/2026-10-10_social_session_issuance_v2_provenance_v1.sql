-- DORMANT SOURCE ONLY. PostgreSQL 16 source support; native execution unproven.
-- Apply atomically only through separately authorized DDL after native binding,
-- mobile request/binding ownership, OAuth lifecycle and V1 issuer registration.
-- No backfill, V1 mutation, role creation, issuer registration, signer provisioning.
-- DDL principal owns relations/functions and is trusted to preserve source.
-- Runtime: distinct direct non-owner login, no memberships/superuser/BYPASSRLS,
-- public schema USAGE but no CREATE; SELECT all new tables; INSERT ONLY offers,
-- parents, acceptances, issuances; existing owner SELECT/UPDATE for row locks and
-- OAuth token INSERT; no new table UPDATE/DELETE/TRUNCATE/REFERENCES/TRIGGER,
-- no column UPDATE grants or new function EXECUTE. Owner-fence/birth/invalidation
-- functions are SECURITY DEFINER, qualified, pg_catalog search_path, no dynamic SQL.
-- Invalidation alone needs pg_catalog, public, pg_temp (in that exact order):
-- its token UPDATE invokes unchanged legacy invoker guards with unqualified
-- public relations. public must be independently trusted, with no runtime
-- CREATE or schema-owner membership; pg_temp LAST prevents temporary shadows.
-- No grants to any runtime role here. Existing writers retain their privileges;
-- new triggers independently invalidate children and keep permanent history.
-- Rollback unused DDL normally. After use retain history; never drop as rollback.
-- Token births cover new tokens only, do not backfill or relabel old tokens.
-- No FK from token births to generic tokens: unrelated generic token cleanup is
-- not blocked, while V2 child FK and guards retain the exact child token.
SET LOCAL search_path = pg_catalog;
DO $v2$
BEGIN
  IF current_setting('server_version_num')::integer < 160000
     OR current_setting('server_version_num')::integer >= 170000
  THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
END;
$v2$;
LOCK TABLE public.users,public.oauth_clients,public.social_session_issuers,
 public.oauth_browser_generations,public.oauth_tokens,public.sessions,
 public.social_messaging_device_bindings IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE public.social_session_v2_offers (
  operation_id VARCHAR(64) NOT NULL,
  request_id VARCHAR(64) NOT NULL,
  authorization_digest VARCHAR(64) NOT NULL,
  wire TEXT NOT NULL,
  subject VARCHAR(64) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  backend_id VARCHAR(255) NOT NULL,
  service_principal VARCHAR(255) NOT NULL,
  issuer VARCHAR(255) NOT NULL,
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  birth_xid TEXT NOT NULL,
  CONSTRAINT social_session_v2_offers_pkey PRIMARY KEY (operation_id),
  CONSTRAINT social_session_v2_offers_u0 UNIQUE (request_id),
  CONSTRAINT social_session_v2_offers_u1 UNIQUE (authorization_digest),
  CONSTRAINT social_session_v2_offers_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_offers_c_request_id CHECK (request_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_offers_c_authorization_digest CHECK (authorization_digest ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_offers_c_wire CHECK (octet_length(wire) BETWEEN 1 AND 16384 AND wire !~ '[^ -~]'),
  CONSTRAINT social_session_v2_offers_c_subject CHECK (subject ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_offers_c_created_at CHECK (created_at >= 0 AND created_at <= 9007199254740991),
  CONSTRAINT social_session_v2_offers_c_expires_at CHECK (expires_at >= 0 AND expires_at <= 9007199254740991),
  CONSTRAINT social_session_v2_offers_c_interval CHECK (created_at < expires_at AND expires_at <= created_at + 300000)
);

CREATE TABLE public.social_session_v2_parents (
  operation_id VARCHAR(64) NOT NULL,
  token_id VARCHAR(36) NOT NULL,
  session_id VARCHAR(255) NOT NULL,
  browser_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(36) NOT NULL,
  continuity VARCHAR(64) NOT NULL,
  CONSTRAINT v2_parent_token_shape CHECK (token_id ~ '^[0-9a-f]{32}$'),
  CONSTRAINT social_session_v2_parents_pkey PRIMARY KEY (operation_id),
  CONSTRAINT social_session_v2_parents_f0 FOREIGN KEY (operation_id) REFERENCES public.social_session_v2_offers(operation_id),
  CONSTRAINT social_session_v2_parents_f1 FOREIGN KEY (token_id) REFERENCES public.oauth_session_generations(token_id),
  CONSTRAINT social_session_v2_parents_f2 FOREIGN KEY (session_id) REFERENCES public.sessions(session_id),
  CONSTRAINT social_session_v2_parents_f3 FOREIGN KEY (browser_id) REFERENCES public.oauth_browser_generations(generation_id),
  CONSTRAINT social_session_v2_parents_f4 FOREIGN KEY (user_id) REFERENCES public.users(id),
  CONSTRAINT social_session_v2_parents_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_parents_c_browser_id CHECK (browser_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_parents_c_continuity CHECK (continuity ~ '^[0-9a-f]{64}$')
);

CREATE TABLE public.social_session_v2_acceptances (
  operation_id VARCHAR(64) NOT NULL,
  acceptance_id VARCHAR(64) NOT NULL,
  approval_id VARCHAR(64) NOT NULL,
  approval_wire TEXT NOT NULL,
  wire TEXT NOT NULL,
  binding_id VARCHAR(64) NOT NULL,
  accepted_at BIGINT NOT NULL,
  possession_proof VARCHAR(64) NOT NULL,
  full_evidence_id VARCHAR(36) NOT NULL,
  full_evidence_version VARCHAR(128) NOT NULL,
  full_source_hash VARCHAR(64) NOT NULL,
  full_proof_id VARCHAR(112) NOT NULL,
  full_expires_at BIGINT NOT NULL,
  birth_xid TEXT NOT NULL,
  CONSTRAINT social_session_v2_acceptances_pkey PRIMARY KEY (operation_id),
  CONSTRAINT social_session_v2_acceptances_u0 UNIQUE (acceptance_id),
  CONSTRAINT social_session_v2_acceptances_u1 UNIQUE (approval_id),
  CONSTRAINT social_session_v2_acceptances_u2 UNIQUE (binding_id),
  CONSTRAINT social_session_v2_acceptances_u3 UNIQUE (operation_id, acceptance_id),
  CONSTRAINT social_session_v2_acceptances_f0 FOREIGN KEY (operation_id) REFERENCES public.social_session_v2_parents(operation_id),
  CONSTRAINT social_session_v2_acceptances_f1 FOREIGN KEY (binding_id) REFERENCES public.social_messaging_device_bindings(binding_id),
  CONSTRAINT social_session_v2_acceptances_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_acceptance_id CHECK (acceptance_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_approval_id CHECK (approval_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_approval_wire CHECK (octet_length(approval_wire) BETWEEN 1 AND 24576 AND approval_wire !~ '[^ -~]'),
  CONSTRAINT social_session_v2_acceptances_c_wire CHECK (octet_length(wire) BETWEEN 1 AND 4096 AND wire !~ '[^ -~]'),
  CONSTRAINT social_session_v2_acceptances_c_binding_id CHECK (binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_accepted_at CHECK (accepted_at >= 0 AND accepted_at <= 9007199254740991),
  CONSTRAINT social_session_v2_acceptances_c_possession_proof CHECK (possession_proof ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_full_source_hash CHECK (full_source_hash ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_acceptances_c_full_expires_at CHECK (full_expires_at >= 0 AND full_expires_at <= 9007199254740991)
);

CREATE TABLE public.social_session_v2_issuances (
  operation_id VARCHAR(64) NOT NULL,
  acceptance_id VARCHAR(64) NOT NULL,
  issuance_id VARCHAR(64) NOT NULL,
  token_id VARCHAR(36) NOT NULL,
  revision VARCHAR(64) NOT NULL,
  subject VARCHAR(64) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  backend_id VARCHAR(255) NOT NULL,
  service_principal VARCHAR(255) NOT NULL,
  issuer VARCHAR(255) NOT NULL,
  user_id VARCHAR(36) NOT NULL,
  delivery_commitment VARCHAR(64) NOT NULL,
  issued_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  kid VARCHAR(255) NOT NULL,
  birth_xid TEXT NOT NULL,
  CONSTRAINT v2_child_token_shape CHECK (token_id ~ '^[0-9a-f]{32}$'),
  CONSTRAINT social_session_v2_issuances_pkey PRIMARY KEY (operation_id),
  CONSTRAINT social_session_v2_issuances_u0 UNIQUE (issuance_id),
  CONSTRAINT social_session_v2_issuances_u1 UNIQUE (token_id),
  CONSTRAINT social_session_v2_issuances_f0 FOREIGN KEY (operation_id, acceptance_id) REFERENCES public.social_session_v2_acceptances(operation_id, acceptance_id),
  CONSTRAINT social_session_v2_issuances_f1 FOREIGN KEY (token_id, user_id, client_id) REFERENCES public.oauth_tokens(id, user_id, client_id),
  CONSTRAINT social_session_v2_issuances_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_acceptance_id CHECK (acceptance_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_issuance_id CHECK (issuance_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_revision CHECK (revision ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_subject CHECK (subject ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_delivery_commitment CHECK (delivery_commitment ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_issuances_c_issued_at CHECK (issued_at >= 0 AND issued_at <= 9007199254740991),
  CONSTRAINT social_session_v2_issuances_c_expires_at CHECK (expires_at >= 0 AND expires_at <= 9007199254740991),
  CONSTRAINT social_session_v2_issuances_c_interval CHECK (issued_at < expires_at AND expires_at <= issued_at + 300)
);

CREATE TABLE public.social_session_v2_invalidations (
  operation_id VARCHAR(64) NOT NULL,
  CONSTRAINT social_session_v2_invalidations_pkey PRIMARY KEY (operation_id),
  CONSTRAINT social_session_v2_invalidations_f0 FOREIGN KEY (operation_id) REFERENCES public.social_session_v2_offers(operation_id),
  CONSTRAINT social_session_v2_invalidations_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$')
);

CREATE TABLE public.social_session_v2_binding_births (
  binding_id VARCHAR(64) NOT NULL,
  operation_id VARCHAR(64) NOT NULL,
  birth_xid TEXT NOT NULL,
  CONSTRAINT social_session_v2_binding_births_pkey PRIMARY KEY (binding_id),
  CONSTRAINT social_session_v2_binding_births_u0 UNIQUE (operation_id),
  CONSTRAINT social_session_v2_binding_births_f0 FOREIGN KEY (operation_id) REFERENCES public.social_session_v2_offers(operation_id),
  CONSTRAINT social_session_v2_binding_births_f1 FOREIGN KEY (binding_id) REFERENCES public.social_messaging_device_bindings(binding_id),
  CONSTRAINT social_session_v2_binding_births_c_binding_id CHECK (binding_id ~ '^[0-9a-f]{64}$'),
  CONSTRAINT social_session_v2_binding_births_c_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$')
);

CREATE TABLE public.social_session_v2_token_births (
  token_id VARCHAR(36) NOT NULL,
  birth_xid TEXT NOT NULL,
  CONSTRAINT social_session_v2_token_births_pkey PRIMARY KEY (token_id)
);

CREATE FUNCTION public.social_session_v2_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $v2$
BEGIN
  IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  IF TG_TABLE_NAME = 'social_session_v2_offers' THEN
    IF NEW.birth_xid <> pg_catalog.pg_current_xact_id()::text
       OR EXISTS (SELECT 1 FROM public.social_messaging_mobile_operations WHERE operation_id = NEW.operation_id)
    THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    IF NOT COALESCE(
       NEW.wire::jsonb->>'method' = 'qr_desktop_pre_enrollment_v2'
       AND NEW.wire::jsonb->>'schema' = 'hodlxxi.social_messaging_device_authorization_method.v2'
       AND NEW.wire::jsonb->>'version' = '2'
       AND NEW.wire::jsonb->'context'->>'pairingId' = NEW.operation_id
       AND NEW.created_at = (extract(epoch FROM (NEW.wire::jsonb->'context'->>'createdAt')::timestamptz) * 1000)::bigint
       AND NEW.expires_at = (extract(epoch FROM (NEW.wire::jsonb->'context'->>'expiresAt')::timestamptz) * 1000)::bigint
       AND (NEW.wire::jsonb->>'content')::jsonb->'authorization'->>'operation' = 'register'
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'transitionKind' = 'initial'
       AND floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint < NEW.expires_at
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'subject' = NEW.subject
       AND (NEW.wire::jsonb->>'preEnrollment')::jsonb->>'requestId' = NEW.request_id
       AND NEW.authorization_digest = encode(sha256(convert_to(NEW.wire,'UTF8')),'hex'), FALSE)
    THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    INSERT INTO public.social_messaging_device_authorization_requests(request_id,owner,digest)
      VALUES (NEW.request_id,'mobile',NEW.authorization_digest);
  ELSIF TG_TABLE_NAME = 'social_session_v2_parents' THEN
    PERFORM 1 FROM public.users WHERE id = NEW.user_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_clients WHERE client_id IN (
      SELECT client_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.social_session_issuers WHERE client_id IN (
      SELECT client_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.oauth_browser_generations WHERE generation_id = NEW.browser_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_tokens WHERE id = NEW.token_id FOR UPDATE;
    PERFORM 1 FROM public.sessions WHERE session_id = NEW.session_id FOR UPDATE;
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.oauth_session_generations g ON g.token_id = NEW.token_id
      JOIN public.users u ON u.id = g.user_id
      JOIN public.oauth_clients c ON c.client_id = g.client_id
      JOIN public.social_session_issuers r ON r.client_id = c.client_id
      JOIN public.oauth_browser_generations b ON b.generation_id = g.browser_generation_id
      JOIN public.oauth_tokens t ON t.id = g.token_id
      JOIN public.sessions s ON s.session_id = g.session_id
      WHERE o.operation_id = NEW.operation_id AND o.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND g.session_id = NEW.session_id AND g.browser_generation_id = NEW.browser_id
        AND g.user_id = NEW.user_id AND g.subject = o.subject AND g.client_id = o.client_id
        AND r.backend_id = o.backend_id AND r.service_principal = o.service_principal
        AND u.is_active IS TRUE AND u.pubkey = o.subject AND c.is_active IS TRUE AND r.is_active IS TRUE
        AND b.is_active IS TRUE AND s.is_active IS TRUE AND t.is_revoked IS FALSE
        AND clock_timestamp() AT TIME ZONE 'UTC' < LEAST(b.expires_at,s.expires_at,t.access_token_expires_at)
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  ELSIF TG_TABLE_NAME = 'social_session_v2_acceptances' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.social_session_v2_parents p USING(operation_id)
      JOIN public.social_messaging_device_bindings b ON b.binding_id = NEW.binding_id
      WHERE o.operation_id = NEW.operation_id AND b.subject_pubkey = o.subject
        AND b.request_id = o.request_id AND b.operation = 'register' AND b.binding_version = 1
        AND b.active IS TRUE AND EXISTS (
          SELECT 1 FROM public.social_session_v2_binding_births bb WHERE bb.binding_id = b.binding_id
            AND bb.operation_id = o.operation_id AND bb.birth_xid = pg_catalog.pg_current_xact_id()::text)
        AND NEW.accepted_at >= o.created_at AND NEW.accepted_at < o.expires_at
        AND NEW.approval_wire::jsonb->>'content' = o.wire
        AND NEW.approval_wire::jsonb->>'id' = NEW.approval_id
        AND NEW.wire::jsonb->>'acceptanceId' = NEW.acceptance_id
        AND NEW.wire::jsonb->>'approvalEventId' = NEW.approval_id
        AND NEW.wire::jsonb->>'authorizationDigest' = o.authorization_digest
        AND NEW.wire::jsonb->>'bindingId' = NEW.binding_id
        AND NEW.wire::jsonb->>'subject' = o.subject
        AND NEW.wire::jsonb->>'requestId' = o.request_id
        AND (o.wire::jsonb->>'preEnrollment')::jsonb->>'x25519BindingId' = NEW.binding_id
        AND b.device_id = (o.wire::jsonb->>'preEnrollment')::jsonb->>'deviceId'
        AND b.public_key = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'publicKey')
        AND b.valid_from = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'bindingValidFrom')::timestamptz
        AND b.expires_at = ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'bindingExpiresAt')::timestamptz
        AND NEW.accepted_at < NEW.full_expires_at
        AND floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint < LEAST(o.expires_at,NEW.full_expires_at)
        AND NEW.accepted_at < ((o.wire::jsonb->>'preEnrollment')::jsonb->>'expiresAt')::bigint
        AND to_timestamp(NEW.accepted_at / 1000.0) < ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'expiresAt')::timestamptz
        AND NEW.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND NOT EXISTS (SELECT 1 FROM public.social_session_v2_invalidations WHERE operation_id = o.operation_id)
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
    INSERT INTO public.social_messaging_device_authorization_binding_owners(binding_id,request_id)
      SELECT NEW.binding_id,request_id FROM public.social_session_v2_offers WHERE operation_id = NEW.operation_id;
  ELSIF TG_TABLE_NAME = 'social_session_v2_issuances' THEN
    PERFORM 1 FROM public.users WHERE id = NEW.user_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_clients WHERE client_id = NEW.client_id FOR UPDATE;
    PERFORM 1 FROM public.social_session_issuers WHERE client_id = NEW.client_id FOR UPDATE;
    PERFORM 1 FROM public.oauth_browser_generations WHERE generation_id IN (
      SELECT browser_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.oauth_tokens WHERE id IN (
      SELECT token_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.sessions WHERE session_id IN (
      SELECT session_id FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id) FOR UPDATE;
    PERFORM 1 FROM public.social_messaging_device_bindings WHERE binding_id IN (
      SELECT binding_id FROM public.social_session_v2_acceptances WHERE operation_id = NEW.operation_id) FOR UPDATE;
    IF NOT EXISTS (
      SELECT 1 FROM public.social_session_v2_offers o
      JOIN public.social_session_v2_parents p USING(operation_id)
      JOIN public.social_session_v2_acceptances a USING(operation_id)
      JOIN public.oauth_session_generations g ON g.token_id = p.token_id
      JOIN public.users u ON u.id = p.user_id
      JOIN public.oauth_clients c ON c.client_id = o.client_id
      JOIN public.social_session_issuers r ON r.client_id = o.client_id
      JOIN public.oauth_tokens t ON t.id = NEW.token_id
      JOIN public.oauth_tokens pt ON pt.id = p.token_id
      JOIN public.sessions s ON s.session_id = p.session_id
      JOIN public.oauth_browser_generations bg ON bg.generation_id = p.browser_id
      JOIN public.social_messaging_device_bindings b ON b.binding_id = a.binding_id
      WHERE o.operation_id = NEW.operation_id AND a.acceptance_id = NEW.acceptance_id
        AND NEW.subject = o.subject AND NEW.user_id = p.user_id
        AND NEW.client_id = o.client_id AND NEW.backend_id = o.backend_id
        AND NEW.service_principal = o.service_principal AND NEW.issuer = o.issuer
        AND r.backend_id = NEW.backend_id AND r.service_principal = NEW.service_principal
        AND u.pubkey = NEW.subject AND u.is_active IS TRUE AND c.is_active IS TRUE AND r.is_active IS TRUE
        AND pt.is_revoked IS FALSE AND s.is_active IS TRUE AND bg.is_active IS TRUE AND b.active IS TRUE
        AND g.session_id = p.session_id AND g.browser_generation_id = p.browser_id AND g.subject = NEW.subject
        AND a.accepted_at < (NEW.issued_at + 1) * 1000 AND NEW.expires_at * 1000 <= o.expires_at
        AND NEW.issuance_id NOT IN (o.operation_id,o.request_id,o.authorization_digest,a.acceptance_id,a.approval_id)
        AND NEW.expires_at * 1000 <= ((o.wire::jsonb->>'preEnrollment')::jsonb->>'expiresAt')::bigint
        AND to_timestamp(NEW.expires_at) <= ((o.wire::jsonb->>'content')::jsonb->'authorization'->>'expiresAt')::timestamptz
        AND b.valid_from <= to_timestamp(NEW.issued_at) AND to_timestamp(NEW.expires_at) <= b.expires_at
        AND to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC' <= LEAST(pt.access_token_expires_at,s.expires_at,bg.expires_at)
        AND EXISTS (SELECT 1 FROM public.social_session_v2_token_births tb
          WHERE tb.token_id = t.id AND tb.birth_xid = pg_catalog.pg_current_xact_id()::text)
        AND a.birth_xid = pg_catalog.pg_current_xact_id()::text
        AND NEW.birth_xid = a.birth_xid
        AND t.user_id = NEW.user_id AND t.client_id = NEW.client_id AND t.is_revoked IS FALSE
        AND t.created_at = to_timestamp(NEW.issued_at) AT TIME ZONE 'UTC'
        AND t.access_token_expires_at = to_timestamp(NEW.expires_at) AT TIME ZONE 'UTC'
        AND t.scope = 'openid profile' AND t.token_type = 'Bearer'
        AND t.refresh_token IS NULL AND t.refresh_token_expires_at IS NULL
        AND t.access_token ~ '^[0-9a-f]{64}$'
        AND t.metadata->>'token_contract' = 'hodlxxi.oauth.access-token.v1'
        AND t.metadata->>'token_use' = 'access' AND t.metadata->>'issuer' = NEW.issuer
        AND t.metadata->>'audience' = NEW.client_id AND t.metadata->>'kid' = NEW.kid
        AND NOT EXISTS (SELECT 1 FROM public.oauth_session_generations WHERE token_id = NEW.token_id)
        AND NOT EXISTS (SELECT 1 FROM public.social_session_issuances WHERE token_id = NEW.token_id)
        AND NOT EXISTS (SELECT 1 FROM public.social_session_v2_invalidations WHERE operation_id = NEW.operation_id)
        AND clock_timestamp() AT TIME ZONE 'UTC' < t.access_token_expires_at
    ) THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  END IF;
  RETURN NEW;
END;
$v2$;
REVOKE ALL ON FUNCTION public.social_session_v2_guard() FROM PUBLIC;

CREATE FUNCTION public.social_session_v2_complete() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $v2$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.social_session_v2_parents WHERE operation_id = NEW.operation_id)
  THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
  RETURN NULL;
END;
$v2$;
REVOKE ALL ON FUNCTION public.social_session_v2_complete() FROM PUBLIC;

CREATE FUNCTION public.social_session_v2_immutable() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $v2$
BEGIN
  RAISE EXCEPTION 'social session issuance v2 unavailable';
END;
$v2$;
REVOKE ALL ON FUNCTION public.social_session_v2_immutable() FROM PUBLIC;

CREATE FUNCTION public.social_session_v2_invalidate() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $v2$
BEGIN
  IF TG_TABLE_NAME = 'oauth_tokens' THEN
    IF EXISTS (SELECT 1 FROM public.social_session_v2_issuances WHERE token_id = OLD.id) THEN
      IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
      IF ROW(NEW.id,NEW.user_id,NEW.client_id,NEW.access_token,NEW.created_at,NEW.scope,NEW.token_type,
             NEW.refresh_token,NEW.refresh_token_expires_at,NEW.metadata::text)
        IS DISTINCT FROM ROW(OLD.id,OLD.user_id,OLD.client_id,OLD.access_token,OLD.created_at,OLD.scope,OLD.token_type,
             OLD.refresh_token,OLD.refresh_token_expires_at,OLD.metadata::text)
        OR NEW.access_token_expires_at > OLD.access_token_expires_at OR NEW.is_revoked IS NULL
        OR (OLD.is_revoked IS TRUE AND NEW.is_revoked IS NOT TRUE)
      THEN RAISE EXCEPTION 'social session issuance v2 unavailable'; END IF;
      IF NEW.access_token_expires_at < OLD.access_token_expires_at THEN NEW.is_revoked := TRUE; END IF;
      -- Child tokens never own an OAuth browser generation or grandchildren.
      -- Returning here also prevents BEFORE-trigger invalidation recursion.
      RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.is_revoked IS FALSE AND NEW.access_token_expires_at = OLD.access_token_expires_at
    THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE token_id = OLD.id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'sessions' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.expires_at = OLD.expires_at
       AND ROW(NEW.session_id,NEW.user_id,NEW.created_at,NEW.session_type)
         IS NOT DISTINCT FROM ROW(OLD.session_id,OLD.user_id,OLD.created_at,OLD.session_type) THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE session_id = OLD.session_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'oauth_browser_generations' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.expires_at = OLD.expires_at THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE browser_id = OLD.generation_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'users' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE AND NEW.pubkey = OLD.pubkey THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_parents WHERE user_id = OLD.id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'oauth_clients' THEN
    IF TG_OP = 'UPDATE' AND NEW.is_active IS TRUE
       AND ROW(NEW.client_id,NEW.scope,NEW.metadata::text) IS NOT DISTINCT FROM ROW(OLD.client_id,OLD.scope,OLD.metadata::text)
    THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_offers WHERE client_id = OLD.client_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'social_session_issuers' THEN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_offers WHERE client_id = OLD.client_id ON CONFLICT DO NOTHING;
  ELSIF TG_TABLE_NAME = 'social_messaging_device_bindings' THEN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    INSERT INTO public.social_session_v2_invalidations(operation_id)
      SELECT operation_id FROM public.social_session_v2_acceptances WHERE binding_id = OLD.binding_id ON CONFLICT DO NOTHING;
  END IF;
  UPDATE public.oauth_tokens SET is_revoked = TRUE WHERE is_revoked IS FALSE AND id IN (
    SELECT i.token_id FROM public.social_session_v2_issuances i
    JOIN public.social_session_v2_invalidations v USING(operation_id));
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$v2$;
REVOKE ALL ON FUNCTION public.social_session_v2_invalidate() FROM PUBLIC;

CREATE FUNCTION public.social_session_v2_birth() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $v2$
BEGIN
  IF TG_TABLE_NAME = 'oauth_tokens' THEN
    INSERT INTO public.social_session_v2_token_births(token_id,birth_xid)
      VALUES (NEW.id,pg_catalog.pg_current_xact_id()::text);
  ELSE
    INSERT INTO public.social_session_v2_binding_births(binding_id,operation_id,birth_xid)
      SELECT NEW.binding_id,operation_id,pg_catalog.pg_current_xact_id()::text
      FROM public.social_session_v2_offers WHERE request_id = NEW.request_id;
  END IF;
  RETURN NEW;
END;
$v2$;
REVOKE ALL ON FUNCTION public.social_session_v2_birth() FROM PUBLIC;

CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_offers FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_offers FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_insert BEFORE INSERT ON public.social_session_v2_offers FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_guard();
CREATE CONSTRAINT TRIGGER v2_complete AFTER INSERT ON public.social_session_v2_offers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_complete();
REVOKE ALL ON public.social_session_v2_offers FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_parents FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_parents FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_insert BEFORE INSERT ON public.social_session_v2_parents FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_guard();
REVOKE ALL ON public.social_session_v2_parents FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_acceptances FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_acceptances FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_insert BEFORE INSERT ON public.social_session_v2_acceptances FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_guard();
REVOKE ALL ON public.social_session_v2_acceptances FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_issuances FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_issuances FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_insert BEFORE INSERT ON public.social_session_v2_issuances FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_guard();
REVOKE ALL ON public.social_session_v2_issuances FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_invalidations FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_invalidations FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
REVOKE ALL ON public.social_session_v2_invalidations FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_binding_births FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_binding_births FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
REVOKE ALL ON public.social_session_v2_binding_births FROM PUBLIC;
CREATE TRIGGER v2_immutable BEFORE DELETE OR UPDATE ON public.social_session_v2_token_births FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_immutable();
CREATE TRIGGER v2_no_truncate BEFORE TRUNCATE ON public.social_session_v2_token_births FOR EACH STATEMENT EXECUTE FUNCTION public.social_session_v2_immutable();
REVOKE ALL ON public.social_session_v2_token_births FROM PUBLIC;
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_tokens FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.sessions FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_browser_generations FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_clients FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.social_session_issuers FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_invalidate();
CREATE TRIGGER v2_birth AFTER INSERT ON public.oauth_tokens FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_birth();
CREATE TRIGGER v2_birth AFTER INSERT ON public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION public.social_session_v2_birth();
