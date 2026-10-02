-- Dormant additive V2 atomic-acceptance durability. Apply only in a separately
-- authorized transaction. The whole file is transaction-reversible before
-- commit; it performs no backfill, runtime activation or authority inference.
CREATE TABLE "public"."social_preaccepted_enrollment_v2_atomic_acceptances" (
    reservation_id VARCHAR(64) PRIMARY KEY,
    reservation_revision BIGINT NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    operation_id VARCHAR(64) NOT NULL,
    subject VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    acceptance_id VARCHAR(64) NOT NULL,
    challenge_id VARCHAR(64) NOT NULL,
    challenge_revision BIGINT NOT NULL,
    association_id VARCHAR(64) NOT NULL,
    input_digest VARCHAR(131) NOT NULL,
    input_payload_digest VARCHAR(146) NOT NULL,
    evidence_token_id VARCHAR(64) NOT NULL,
    evidence_digest VARCHAR(139) NOT NULL,
    evidence_payload_digest VARCHAR(138) NOT NULL,
    state VARCHAR(9) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    decided_at BIGINT,
    statement_digest VARCHAR(146),
    effect_id VARCHAR(64),
    effect_digest VARCHAR(129),
    receipt_id VARCHAR(64),
    finalization_request_digest VARCHAR(143),
    reservation_wire TEXT NOT NULL,
    input_wire TEXT NOT NULL,
    evidence_compact_jws TEXT NOT NULL,
    statement_compact_jws TEXT,
    finalization_observation_wire TEXT,
    effect_wire TEXT,
    receipt_wire TEXT,
    CONSTRAINT uq_social_preaccepted_v2_acceptance_request UNIQUE (request_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_operation UNIQUE (operation_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_device UNIQUE (device_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_acceptance UNIQUE (acceptance_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_challenge UNIQUE (challenge_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_association UNIQUE (association_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_input UNIQUE (input_digest),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_evidence_token UNIQUE (evidence_token_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_evidence UNIQUE (evidence_digest),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_effect UNIQUE (effect_id),
    CONSTRAINT uq_social_preaccepted_v2_acceptance_receipt UNIQUE (receipt_id),
    CONSTRAINT ck_social_preaccepted_v2_reservation_id CHECK (reservation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_request_id CHECK (request_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_operation_id CHECK (operation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_subject CHECK (subject ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_device_id CHECK (device_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_acceptance_id CHECK (acceptance_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_challenge_id CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_association_id CHECK (association_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_token_id CHECK (evidence_token_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_preaccepted_v2_revision CHECK (reservation_revision = 1),
    CONSTRAINT ck_social_preaccepted_v2_challenge_revision
        CHECK (challenge_revision BETWEEN 1 AND 9007199254740991),
    CONSTRAINT ck_social_preaccepted_v2_state
        CHECK (state IN ('pending','accepted','rejected','expired','cancelled')),
    CONSTRAINT ck_social_preaccepted_v2_times CHECK (
        created_at BETWEEN 0 AND 9007199254740991 AND
        expires_at BETWEEN 1 AND 9007199254740991 AND created_at < expires_at AND
        (decided_at IS NULL OR decided_at BETWEEN 0 AND 9007199254740991)),
    CONSTRAINT ck_social_preaccepted_v2_reservation_wire CHECK (
        octet_length(reservation_wire) BETWEEN 1 AND 8192 AND reservation_wire !~ '[^ -~]'),
    CONSTRAINT ck_social_preaccepted_v2_input_wire CHECK (
        octet_length(input_wire) BETWEEN 1 AND 24576 AND input_wire !~ '[^ -~]'),
    CONSTRAINT ck_social_preaccepted_v2_evidence_wire CHECK (
        octet_length(evidence_compact_jws) BETWEEN 1 AND 16384 AND
        evidence_compact_jws !~ '[^ -~]'),
    CONSTRAINT ck_social_preaccepted_v2_statement_wire CHECK (
        statement_compact_jws IS NULL OR
        (octet_length(statement_compact_jws) BETWEEN 1 AND 4096 AND
         statement_compact_jws !~ '[^ -~]')),
    CONSTRAINT ck_social_preaccepted_v2_observation_wire CHECK (
        finalization_observation_wire IS NULL OR
        (octet_length(finalization_observation_wire) BETWEEN 1 AND 16384 AND
         finalization_observation_wire !~ '[^ -~]')),
    CONSTRAINT ck_social_preaccepted_v2_effect_wire CHECK (
        effect_wire IS NULL OR
        (octet_length(effect_wire) BETWEEN 1 AND 8192 AND effect_wire !~ '[^ -~]')),
    CONSTRAINT ck_social_preaccepted_v2_receipt_wire CHECK (
        receipt_wire IS NULL OR
        (octet_length(receipt_wire) BETWEEN 1 AND 8192 AND receipt_wire !~ '[^ -~]'))
);

CREATE FUNCTION "public"."guard_social_preaccepted_v2_acceptance_v1"()
RETURNS trigger LANGUAGE plpgsql
COST 100
SET search_path = pg_catalog
AS $$
DECLARE
    reservation JSONB;
    evidence_payload JSONB;
    observation JSONB;
    effect JSONB;
    receipt JSONB;
    expected_reservation_wire TEXT;
    evidence_payload_segment TEXT;
    evidence_payload_wire TEXT;
    expected_authority_snapshot_wire TEXT;
    expected_authority_snapshot_digest TEXT;
    expected_observation_wire TEXT;
    expected_effect_wire TEXT;
    expected_receipt_wire TEXT;
    preimage TEXT;
    expected TEXT;
    field_count INTEGER;
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    reservation := NEW.reservation_wire::jsonb;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(reservation);
    IF jsonb_typeof(reservation) <> 'object' OR field_count <> 29 OR
       NOT reservation ?& ARRAY[
           'acceptanceId','associationExpectedState','associationExpectedVersion',
           'associationId','challengeId','challengeRevision','createdAt','decidedAt',
           'deviceId','effectDigest','effectId','evidenceDigest',
           'evidencePayloadDigest','evidenceTokenId','expiresAt','inputDigest',
           'inputPayloadDigest','operation','operationId','receiptId','requestId',
           'reservationId','reservationRevision','schema','state','statementDigest',
           'subject','terminalReason','version'] THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    expected_reservation_wire :=
        '{"acceptanceId":' || (reservation -> 'acceptanceId')::text ||
        ',"associationExpectedState":' || (reservation -> 'associationExpectedState')::text ||
        ',"associationExpectedVersion":' || (reservation -> 'associationExpectedVersion')::text ||
        ',"associationId":' || (reservation -> 'associationId')::text ||
        ',"challengeId":' || (reservation -> 'challengeId')::text ||
        ',"challengeRevision":' || (reservation -> 'challengeRevision')::text ||
        ',"createdAt":' || (reservation -> 'createdAt')::text ||
        ',"decidedAt":' || (reservation -> 'decidedAt')::text ||
        ',"deviceId":' || (reservation -> 'deviceId')::text ||
        ',"effectDigest":' || (reservation -> 'effectDigest')::text ||
        ',"effectId":' || (reservation -> 'effectId')::text ||
        ',"evidenceDigest":' || (reservation -> 'evidenceDigest')::text ||
        ',"evidencePayloadDigest":' || (reservation -> 'evidencePayloadDigest')::text ||
        ',"evidenceTokenId":' || (reservation -> 'evidenceTokenId')::text ||
        ',"expiresAt":' || (reservation -> 'expiresAt')::text ||
        ',"inputDigest":' || (reservation -> 'inputDigest')::text ||
        ',"inputPayloadDigest":' || (reservation -> 'inputPayloadDigest')::text ||
        ',"operation":' || (reservation -> 'operation')::text ||
        ',"operationId":' || (reservation -> 'operationId')::text ||
        ',"receiptId":' || (reservation -> 'receiptId')::text ||
        ',"requestId":' || (reservation -> 'requestId')::text ||
        ',"reservationId":' || (reservation -> 'reservationId')::text ||
        ',"reservationRevision":' || (reservation -> 'reservationRevision')::text ||
        ',"schema":' || (reservation -> 'schema')::text ||
        ',"state":' || (reservation -> 'state')::text ||
        ',"statementDigest":' || (reservation -> 'statementDigest')::text ||
        ',"subject":' || (reservation -> 'subject')::text ||
        ',"terminalReason":' || (reservation -> 'terminalReason')::text ||
        ',"version":' || (reservation -> 'version')::text || '}';

    IF NEW.reservation_wire <> expected_reservation_wire OR
       reservation ->> 'schema' <>
           'hodlxxi.social_preaccepted_enrollment_v2_acceptance_reservation.v1' OR
       reservation ->> 'version' <> '1' OR reservation ->> 'reservationRevision' <> '1' OR
       reservation ->> 'operation' <> 'register' OR
       reservation ->> 'associationExpectedState' <> 'absent' OR
       reservation ->> 'associationExpectedVersion' <> '0' OR
       reservation ->> 'reservationId' <> NEW.reservation_id OR
       reservation ->> 'requestId' <> NEW.request_id OR
       reservation ->> 'operationId' <> NEW.operation_id OR
       reservation ->> 'subject' <> NEW.subject OR
       reservation ->> 'deviceId' <> NEW.device_id OR
       reservation ->> 'acceptanceId' <> NEW.acceptance_id OR
       reservation ->> 'challengeId' <> NEW.challenge_id OR
       reservation ->> 'challengeRevision' <> NEW.challenge_revision::text OR
       reservation ->> 'associationId' <> NEW.association_id OR
       reservation ->> 'inputDigest' <> NEW.input_digest OR
       reservation ->> 'inputPayloadDigest' <> NEW.input_payload_digest OR
       reservation ->> 'evidenceTokenId' <> NEW.evidence_token_id OR
       reservation ->> 'evidenceDigest' <> NEW.evidence_digest OR
       reservation ->> 'evidencePayloadDigest' <> NEW.evidence_payload_digest OR
       reservation ->> 'state' <> NEW.state OR
       reservation ->> 'createdAt' <> NEW.created_at::text OR
       reservation ->> 'expiresAt' <> NEW.expires_at::text OR
       reservation -> 'decidedAt' IS DISTINCT FROM
           COALESCE(to_jsonb(NEW.decided_at), 'null'::jsonb) OR
       reservation -> 'statementDigest' IS DISTINCT FROM
           COALESCE(to_jsonb(NEW.statement_digest), 'null'::jsonb) OR
       reservation -> 'effectId' IS DISTINCT FROM
           COALESCE(to_jsonb(NEW.effect_id), 'null'::jsonb) OR
       reservation -> 'effectDigest' IS DISTINCT FROM
           COALESCE(to_jsonb(NEW.effect_digest), 'null'::jsonb) OR
       reservation -> 'receiptId' IS DISTINCT FROM
           COALESCE(to_jsonb(NEW.receipt_id), 'null'::jsonb) THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    expected := 'hodlxxi-social-preaccepted-enrollment-verification-input-v2-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_VERIFICATION_INPUT_V2', 'UTF8') ||
            decode('00', 'hex') || convert_to(NEW.input_wire, 'UTF8')), 'hex');
    IF NEW.input_digest <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    expected := 'hodlxxi-social-preaccepted-enrollment-v2-deadline-evidence-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_DEADLINE_EVIDENCE_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(NEW.evidence_compact_jws, 'UTF8')), 'hex');
    IF NEW.evidence_digest <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.decided_at IS NOT NULL OR
           NEW.statement_digest IS NOT NULL OR NEW.effect_id IS NOT NULL OR
           NEW.effect_digest IS NOT NULL OR NEW.receipt_id IS NOT NULL OR
           NEW.finalization_request_digest IS NOT NULL OR
           NEW.statement_compact_jws IS NOT NULL OR
           NEW.finalization_observation_wire IS NOT NULL OR NEW.effect_wire IS NOT NULL OR
           NEW.receipt_wire IS NOT NULL OR reservation -> 'terminalReason' <> 'null'::jsonb THEN
            RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state <> 'pending' OR NEW.state = 'pending' OR
       ROW(NEW.reservation_id, NEW.reservation_revision, NEW.request_id, NEW.operation_id,
           NEW.subject, NEW.device_id, NEW.acceptance_id, NEW.challenge_id,
           NEW.challenge_revision, NEW.association_id, NEW.input_digest,
           NEW.input_payload_digest, NEW.evidence_token_id, NEW.evidence_digest,
           NEW.evidence_payload_digest, NEW.created_at, NEW.expires_at, NEW.input_wire,
           NEW.evidence_compact_jws) IS DISTINCT FROM
       ROW(OLD.reservation_id, OLD.reservation_revision, OLD.request_id, OLD.operation_id,
           OLD.subject, OLD.device_id, OLD.acceptance_id, OLD.challenge_id,
           OLD.challenge_revision, OLD.association_id, OLD.input_digest,
           OLD.input_payload_digest, OLD.evidence_token_id, OLD.evidence_digest,
           OLD.evidence_payload_digest, OLD.created_at, OLD.expires_at, OLD.input_wire,
           OLD.evidence_compact_jws) THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    IF NEW.state IN ('rejected', 'expired', 'cancelled') THEN
        IF NEW.decided_at IS NULL OR NEW.statement_digest IS NOT NULL OR
           NEW.effect_id IS NOT NULL OR NEW.effect_digest IS NOT NULL OR
           NEW.receipt_id IS NOT NULL OR NEW.finalization_request_digest IS NOT NULL OR
           NEW.statement_compact_jws IS NOT NULL OR
           NEW.finalization_observation_wire IS NOT NULL OR NEW.effect_wire IS NOT NULL OR
           NEW.receipt_wire IS NOT NULL OR
           NEW.decided_at < NEW.created_at OR
           (NEW.state = 'expired' AND NEW.decided_at < NEW.expires_at) OR
           (NEW.state IN ('rejected', 'cancelled') AND NEW.decided_at >= NEW.expires_at) OR
           (NEW.state = 'rejected' AND reservation ->> 'terminalReason' <> 'verification_denied') OR
           (NEW.state = 'expired' AND reservation ->> 'terminalReason' <> 'evidence_expired') OR
           (NEW.state = 'cancelled' AND reservation ->> 'terminalReason' <> 'explicitly_cancelled') THEN
            RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.state <> 'accepted' OR NEW.decided_at IS NULL OR
       NEW.decided_at < NEW.created_at OR NEW.decided_at >= NEW.expires_at OR
       NEW.statement_digest IS NULL OR NEW.effect_id IS NULL OR NEW.effect_digest IS NULL OR
       NEW.receipt_id IS NULL OR NEW.finalization_request_digest IS NULL OR
       NEW.statement_compact_jws IS NULL OR NEW.finalization_observation_wire IS NULL OR
       NEW.effect_wire IS NULL OR NEW.receipt_wire IS NULL OR
       reservation -> 'terminalReason' <> 'null'::jsonb THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    expected := 'hodlxxi-social-preaccepted-enrollment-v2-verification-statement-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_VERIFICATION_STATEMENT_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(NEW.statement_compact_jws, 'UTF8')), 'hex');
    IF NEW.statement_digest <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    IF NEW.evidence_compact_jws !~ '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    evidence_payload_segment := split_part(NEW.evidence_compact_jws, '.', 2);
    evidence_payload_wire := convert_from(
        decode(
            translate(evidence_payload_segment, '-_', '+/') ||
            repeat('=', (4 - length(evidence_payload_segment) % 4) % 4),
            'base64'),
        'UTF8');
    IF translate(
           replace(rtrim(encode(convert_to(evidence_payload_wire, 'UTF8'), 'base64'), '='), E'\n', ''),
           '+/', '-_') <> evidence_payload_segment THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    expected := 'hodlxxi-social-preaccepted-enrollment-v2-deadline-payload-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_DEADLINE_PAYLOAD_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(evidence_payload_wire, 'UTF8')), 'hex');
    IF NEW.evidence_payload_digest <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    evidence_payload := evidence_payload_wire::jsonb;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(evidence_payload);
    IF jsonb_typeof(evidence_payload) <> 'object' OR field_count <> 46 OR
       NOT evidence_payload ?& ARRAY[
           'acceptanceId','approvalEventId','approverOAuthBrowserGenerationId',
           'approverOAuthSessionId','approverOAuthTokenId','approverSessionExpiresAt',
           'associationId','associationVersion','attemptId','aud','authorizationDigest',
           'clientId','deviceId','enrollmentChallengeId','expiresAt','fullEvidenceId',
           'fullEvidenceVersion','fullExpiresAt','fullProofId','fullSourceEvidenceSha256',
           'inputDigest','inputPayloadDigest','iss','jti','observedAt','operation',
           'operationId','parentOAuthBrowserGenerationId','parentOAuthSessionId',
           'parentOAuthTokenId','phoneSessionExpiresAt','purpose','requestId',
           'reservationId','reservationRevision','schema','servicePrincipal',
           'socialSessionIssuanceId','socialSessionIssuanceRevision','socialSessionTokenId',
           'subject','version','x25519BindingExpiresAt','x25519BindingId',
           'x25519BindingVersion','x25519PublicKeyCommitment'] OR
       evidence_payload ->> 'reservationId' <> NEW.reservation_id OR
       evidence_payload ->> 'reservationRevision' <> NEW.reservation_revision::text OR
       evidence_payload ->> 'requestId' <> NEW.request_id OR
       evidence_payload ->> 'operationId' <> NEW.operation_id OR
       evidence_payload ->> 'operation' <> 'register' OR
       evidence_payload ->> 'subject' <> NEW.subject OR
       evidence_payload ->> 'deviceId' <> NEW.device_id OR
       evidence_payload ->> 'acceptanceId' <> NEW.acceptance_id OR
       evidence_payload ->> 'enrollmentChallengeId' <> NEW.challenge_id OR
       evidence_payload ->> 'associationId' <> NEW.association_id OR
       evidence_payload ->> 'inputDigest' <> NEW.input_digest OR
       evidence_payload ->> 'inputPayloadDigest' <> NEW.input_payload_digest OR
       evidence_payload ->> 'jti' <> NEW.evidence_token_id OR
       evidence_payload ->> 'observedAt' <> NEW.created_at::text OR
       evidence_payload ->> 'expiresAt' <> NEW.expires_at::text THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    expected_authority_snapshot_wire :=
        '{"acceptanceId":' || (evidence_payload -> 'acceptanceId')::text ||
        ',"approvalEventId":' || (evidence_payload -> 'approvalEventId')::text ||
        ',"approverOAuthBrowserGenerationId":' ||
            (evidence_payload -> 'approverOAuthBrowserGenerationId')::text ||
        ',"approverOAuthSessionId":' || (evidence_payload -> 'approverOAuthSessionId')::text ||
        ',"approverOAuthTokenId":' || (evidence_payload -> 'approverOAuthTokenId')::text ||
        ',"approverSessionExpiresAt":' || (evidence_payload -> 'approverSessionExpiresAt')::text ||
        ',"associationId":' || (evidence_payload -> 'associationId')::text ||
        ',"associationVersion":' || (evidence_payload -> 'associationVersion')::text ||
        ',"attemptId":' || (evidence_payload -> 'attemptId')::text ||
        ',"authorizationDigest":' || (evidence_payload -> 'authorizationDigest')::text ||
        ',"deviceId":' || (evidence_payload -> 'deviceId')::text ||
        ',"enrollmentChallengeId":' || (evidence_payload -> 'enrollmentChallengeId')::text ||
        ',"fullEvidenceId":' || (evidence_payload -> 'fullEvidenceId')::text ||
        ',"fullEvidenceVersion":' || (evidence_payload -> 'fullEvidenceVersion')::text ||
        ',"fullExpiresAt":' || (evidence_payload -> 'fullExpiresAt')::text ||
        ',"fullProofId":' || (evidence_payload -> 'fullProofId')::text ||
        ',"fullSourceEvidenceSha256":' || (evidence_payload -> 'fullSourceEvidenceSha256')::text ||
        ',"inputDigest":' || (evidence_payload -> 'inputDigest')::text ||
        ',"inputPayloadDigest":' || (evidence_payload -> 'inputPayloadDigest')::text ||
        ',"observedAt":' || to_jsonb(NEW.decided_at)::text ||
        ',"operation":' || (evidence_payload -> 'operation')::text ||
        ',"operationId":' || (evidence_payload -> 'operationId')::text ||
        ',"parentOAuthBrowserGenerationId":' ||
            (evidence_payload -> 'parentOAuthBrowserGenerationId')::text ||
        ',"parentOAuthSessionId":' || (evidence_payload -> 'parentOAuthSessionId')::text ||
        ',"parentOAuthTokenId":' || (evidence_payload -> 'parentOAuthTokenId')::text ||
        ',"phoneSessionExpiresAt":' || (evidence_payload -> 'phoneSessionExpiresAt')::text ||
        ',"requestId":' || (evidence_payload -> 'requestId')::text ||
        ',"schema":"hodlxxi.social_preaccepted_enrollment_v2_current_authority_snapshot.v1"' ||
        ',"socialSessionIssuanceId":' || (evidence_payload -> 'socialSessionIssuanceId')::text ||
        ',"socialSessionIssuanceRevision":' ||
            (evidence_payload -> 'socialSessionIssuanceRevision')::text ||
        ',"socialSessionTokenId":' || (evidence_payload -> 'socialSessionTokenId')::text ||
        ',"subject":' || (evidence_payload -> 'subject')::text ||
        ',"version":1' ||
        ',"x25519BindingExpiresAt":' || (evidence_payload -> 'x25519BindingExpiresAt')::text ||
        ',"x25519BindingId":' || (evidence_payload -> 'x25519BindingId')::text ||
        ',"x25519BindingVersion":' || (evidence_payload -> 'x25519BindingVersion')::text ||
        ',"x25519PublicKeyCommitment":' ||
            (evidence_payload -> 'x25519PublicKeyCommitment')::text || '}';
    expected_authority_snapshot_digest :=
        'hodlxxi-social-preaccepted-enrollment-v2-authority-snapshot-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_AUTHORITY_SNAPSHOT_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(expected_authority_snapshot_wire, 'UTF8')), 'hex');

    observation := NEW.finalization_observation_wire::jsonb;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(observation);
    IF jsonb_typeof(observation) <> 'object' OR field_count <> 14 OR
       NOT observation ?& ARRAY[
           'associationAuthorityEpoch','associationCurrentId','associationState',
           'associationVersion','authoritySnapshot','authoritySnapshotDigest','challengeId',
           'challengeRevision','challengeState','observedAt','reservationId',
           'reservationRevision','schema','version'] OR
       observation ->> 'schema' <>
           'hodlxxi.social_preaccepted_enrollment_v2_finalization_observation.v1' OR
       observation ->> 'version' <> '1' OR observation ->> 'reservationId' <> NEW.reservation_id OR
       observation ->> 'reservationRevision' <> '1' OR
       observation ->> 'challengeId' <> NEW.challenge_id OR
       observation ->> 'challengeRevision' <> NEW.challenge_revision::text OR
       observation ->> 'challengeState' <> 'issued' OR
       observation ->> 'associationState' <> 'absent' OR
       observation -> 'associationCurrentId' <> 'null'::jsonb OR
       observation ->> 'associationVersion' <> '0' OR
       observation ->> 'associationAuthorityEpoch' <> '0' OR
       observation ->> 'observedAt' <> NEW.decided_at::text OR
       observation ->> 'authoritySnapshot' <> expected_authority_snapshot_wire OR
       observation ->> 'authoritySnapshotDigest' <> expected_authority_snapshot_digest THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    expected_observation_wire :=
        '{"associationAuthorityEpoch":' || (observation -> 'associationAuthorityEpoch')::text ||
        ',"associationCurrentId":' || (observation -> 'associationCurrentId')::text ||
        ',"associationState":' || (observation -> 'associationState')::text ||
        ',"associationVersion":' || (observation -> 'associationVersion')::text ||
        ',"authoritySnapshot":' || to_jsonb(expected_authority_snapshot_wire)::text ||
        ',"authoritySnapshotDigest":' || to_jsonb(expected_authority_snapshot_digest)::text ||
        ',"challengeId":' || (observation -> 'challengeId')::text ||
        ',"challengeRevision":' || (observation -> 'challengeRevision')::text ||
        ',"challengeState":' || (observation -> 'challengeState')::text ||
        ',"observedAt":' || (observation -> 'observedAt')::text ||
        ',"reservationId":' || (observation -> 'reservationId')::text ||
        ',"reservationRevision":' || (observation -> 'reservationRevision')::text ||
        ',"schema":' || (observation -> 'schema')::text ||
        ',"version":' || (observation -> 'version')::text || '}';
    IF NEW.finalization_observation_wire <> expected_observation_wire THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    preimage :=
        '{"evidenceDigest":' || to_jsonb(NEW.evidence_digest)::text ||
        ',"inputDigest":' || to_jsonb(NEW.input_digest)::text ||
        ',"inputPayloadDigest":' || to_jsonb(NEW.input_payload_digest)::text ||
        ',"reservationId":' || to_jsonb(NEW.reservation_id)::text ||
        ',"reservationRevision":1,"statementDigest":' || to_jsonb(NEW.statement_digest)::text || '}';
    expected := 'hodlxxi-social-preaccepted-enrollment-v2-finalization-request-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_FINALIZATION_REQUEST_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(preimage, 'UTF8')), 'hex');
    IF NEW.finalization_request_digest <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    effect := NEW.effect_wire::jsonb;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(effect);
    expected_effect_wire :=
        '{"acceptanceId":' || (effect -> 'acceptanceId')::text ||
        ',"associationId":' || (effect -> 'associationId')::text ||
        ',"associationVersion":' || (effect -> 'associationVersion')::text ||
        ',"authorityEpoch":' || (effect -> 'authorityEpoch')::text ||
        ',"challengeId":' || (effect -> 'challengeId')::text ||
        ',"effectId":' || (effect -> 'effectId')::text ||
        ',"finalizationRequestDigest":' || (effect -> 'finalizationRequestDigest')::text ||
        ',"operation":' || (effect -> 'operation')::text ||
        ',"reservationId":' || (effect -> 'reservationId')::text ||
        ',"reservationRevision":' || (effect -> 'reservationRevision')::text ||
        ',"schema":' || (effect -> 'schema')::text ||
        ',"version":' || (effect -> 'version')::text || '}';
    IF jsonb_typeof(effect) <> 'object' OR field_count <> 12 OR
       NEW.effect_wire <> expected_effect_wire OR
       effect ->> 'schema' <> 'hodlxxi.social_preaccepted_enrollment_v2_acceptance_effect.v1' OR
       effect ->> 'version' <> '1' OR effect ->> 'operation' <> 'preaccepted-enrollment-v2-accept' OR
       effect ->> 'reservationId' <> NEW.reservation_id OR
       effect ->> 'reservationRevision' <> '1' OR
       effect ->> 'acceptanceId' <> NEW.acceptance_id OR
       effect ->> 'associationId' <> NEW.association_id OR
       effect ->> 'associationVersion' <> '1' OR effect ->> 'authorityEpoch' <> '1' OR
       effect ->> 'challengeId' <> NEW.challenge_id OR
       effect ->> 'finalizationRequestDigest' <> NEW.finalization_request_digest OR
       effect ->> 'effectId' <> NEW.effect_id THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    preimage :=
        '{"acceptanceId":' || to_jsonb(NEW.acceptance_id)::text ||
        ',"associationId":' || to_jsonb(NEW.association_id)::text ||
        ',"authoritySnapshotDigest":' || to_jsonb(expected_authority_snapshot_digest)::text ||
        ',"challengeId":' || to_jsonb(NEW.challenge_id)::text ||
        ',"finalizationRequestDigest":' || to_jsonb(NEW.finalization_request_digest)::text ||
        ',"reservationId":' || to_jsonb(NEW.reservation_id)::text ||
        ',"reservationRevision":1,' ||
        '"schema":"hodlxxi.social_preaccepted_enrollment_v2_effect_id_preimage.v1","version":1}';
    expected := encode(sha256(
        convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_EFFECT_ID_V1', 'UTF8') ||
        decode('00', 'hex') || convert_to(preimage, 'UTF8')), 'hex');
    IF NEW.effect_id <> expected OR NEW.effect_digest <>
       'hodlxxi-social-preaccepted-enrollment-v2-effect-v1-sha256:' || encode(sha256(
           convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_EFFECT_DIGEST_V1', 'UTF8') ||
           decode('00', 'hex') || convert_to(NEW.effect_wire, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;

    receipt := NEW.receipt_wire::jsonb;
    SELECT count(*) INTO field_count FROM jsonb_object_keys(receipt);
    expected_receipt_wire :=
        '{"acceptanceId":' || (receipt -> 'acceptanceId')::text ||
        ',"associationId":' || (receipt -> 'associationId')::text ||
        ',"challengeId":' || (receipt -> 'challengeId')::text ||
        ',"decidedAt":' || (receipt -> 'decidedAt')::text ||
        ',"effectDigest":' || (receipt -> 'effectDigest')::text ||
        ',"effectId":' || (receipt -> 'effectId')::text ||
        ',"evidenceDigest":' || (receipt -> 'evidenceDigest')::text ||
        ',"finalizationRequestDigest":' || (receipt -> 'finalizationRequestDigest')::text ||
        ',"inputDigest":' || (receipt -> 'inputDigest')::text ||
        ',"receiptId":' || (receipt -> 'receiptId')::text ||
        ',"reservationId":' || (receipt -> 'reservationId')::text ||
        ',"reservationRevision":' || (receipt -> 'reservationRevision')::text ||
        ',"schema":' || (receipt -> 'schema')::text ||
        ',"statementDigest":' || (receipt -> 'statementDigest')::text ||
        ',"status":' || (receipt -> 'status')::text ||
        ',"version":' || (receipt -> 'version')::text || '}';
    IF jsonb_typeof(receipt) <> 'object' OR field_count <> 16 OR
       NEW.receipt_wire <> expected_receipt_wire OR
       receipt ->> 'schema' <> 'hodlxxi.social_preaccepted_enrollment_v2_acceptance_receipt.v1' OR
       receipt ->> 'version' <> '1' OR receipt ->> 'status' <> 'committed' OR
       receipt ->> 'reservationId' <> NEW.reservation_id OR
       receipt ->> 'reservationRevision' <> '1' OR
       receipt ->> 'acceptanceId' <> NEW.acceptance_id OR
       receipt ->> 'associationId' <> NEW.association_id OR
       receipt ->> 'challengeId' <> NEW.challenge_id OR
       receipt ->> 'decidedAt' <> NEW.decided_at::text OR
       receipt ->> 'effectId' <> NEW.effect_id OR receipt ->> 'effectDigest' <> NEW.effect_digest OR
       receipt ->> 'evidenceDigest' <> NEW.evidence_digest OR
       receipt ->> 'inputDigest' <> NEW.input_digest OR
       receipt ->> 'statementDigest' <> NEW.statement_digest OR
       receipt ->> 'finalizationRequestDigest' <> NEW.finalization_request_digest OR
       receipt ->> 'receiptId' <> NEW.receipt_id THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    preimage :=
        '{"effectDigest":' || to_jsonb(NEW.effect_digest)::text ||
        ',"effectId":' || to_jsonb(NEW.effect_id)::text ||
        ',"finalizationRequestDigest":' || to_jsonb(NEW.finalization_request_digest)::text ||
        ',"reservationId":' || to_jsonb(NEW.reservation_id)::text ||
        ',"reservationRevision":1,' ||
        '"schema":"hodlxxi.social_preaccepted_enrollment_v2_receipt_id_preimage.v1","version":1}';
    expected := encode(sha256(
        convert_to('HODLXXI_SOCIAL_PREACCEPTED_ENROLLMENT_V2_RECEIPT_ID_V1', 'UTF8') ||
        decode('00', 'hex') || convert_to(preimage, 'UTF8')), 'hex');
    IF NEW.receipt_id <> expected THEN
        RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
    END IF;
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'social preaccepted enrollment v2 atomic acceptance storage unavailable';
END $$;

CREATE TRIGGER "trg_social_preaccepted_v2_acceptance_guard"
    BEFORE INSERT OR UPDATE OR DELETE
    ON "public"."social_preaccepted_enrollment_v2_atomic_acceptances"
    FOR EACH ROW EXECUTE FUNCTION "public"."guard_social_preaccepted_v2_acceptance_v1"();
CREATE TRIGGER "trg_social_preaccepted_v2_acceptance_no_truncate"
    BEFORE TRUNCATE ON "public"."social_preaccepted_enrollment_v2_atomic_acceptances"
    FOR EACH STATEMENT EXECUTE FUNCTION "public"."guard_social_preaccepted_v2_acceptance_v1"();

-- Fail closed until a separately provisioned, non-owner runtime role receives
-- only schema USAGE and SELECT/INSERT/UPDATE on this exact table.  Trigger
-- execution does not require the runtime role to execute the trigger function.
REVOKE ALL PRIVILEGES ON TABLE
    "public"."social_preaccepted_enrollment_v2_atomic_acceptances" FROM PUBLIC;
REVOKE ALL PRIVILEGES ON FUNCTION
    "public"."guard_social_preaccepted_v2_acceptance_v1"() FROM PUBLIC;
