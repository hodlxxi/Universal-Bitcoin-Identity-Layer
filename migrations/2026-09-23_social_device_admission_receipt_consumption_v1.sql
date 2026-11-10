-- Dormant additive prerequisite for a future enrollment atomic owner.
-- Apply only after the 2026-09-21 challenge and 2026-09-22 Ed25519 migrations,
-- in one separately authorized migration transaction. No runtime activation.
CREATE TABLE social_device_enrollment_admission_receipts (
    receipt_id VARCHAR(64) PRIMARY KEY,
    challenge_id VARCHAR(64) NOT NULL,
    operation VARCHAR(19) NOT NULL,
    decided_at BIGINT NOT NULL,
    effect_id VARCHAR(64) NOT NULL,
    effect_digest VARCHAR(64) NOT NULL,
    proposed_association_id VARCHAR(64) NOT NULL,
    authority_wire TEXT NOT NULL,
    receipt_wire TEXT NOT NULL,
    CONSTRAINT fk_social_enrollment_receipt_challenge
        FOREIGN KEY (challenge_id)
        REFERENCES social_device_admission_challenges (challenge_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT uq_social_enrollment_receipt_challenge UNIQUE (challenge_id),
    CONSTRAINT uq_social_enrollment_receipt_effect UNIQUE (effect_id),
    CONSTRAINT ck_social_enrollment_receipt_id
        CHECK (receipt_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_enrollment_receipt_challenge
        CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_enrollment_receipt_effect_id
        CHECK (effect_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_enrollment_receipt_effect_digest
        CHECK (effect_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_enrollment_receipt_association
        CHECK (proposed_association_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_social_enrollment_receipt_operation
        CHECK (operation = 'enrollment-activate'),
    CONSTRAINT ck_social_enrollment_receipt_decided_at
        CHECK (decided_at BETWEEN 0 AND 9007199254740991),
    CONSTRAINT ck_social_enrollment_receipt_authority_wire CHECK (
        octet_length(authority_wire) BETWEEN 1 AND 8192 AND
        authority_wire !~ '[^ -~]'),
    CONSTRAINT ck_social_enrollment_receipt_wire CHECK (
        octet_length(receipt_wire) BETWEEN 1 AND 2048 AND
        receipt_wire !~ '[^ -~]')
);

CREATE FUNCTION guard_social_enrollment_receipt_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    authority JSONB;
    expected_authority_wire TEXT;
    effect_id_preimage TEXT;
    effect_transition_preimage TEXT;
    receipt_id_preimage TEXT;
    expected_receipt_wire TEXT;
    authority_field_count INTEGER;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    authority := NEW.authority_wire::jsonb;
    SELECT count(*) INTO authority_field_count FROM jsonb_object_keys(authority);
    IF jsonb_typeof(authority) <> 'object' OR
       authority_field_count <> 25 OR
       NOT authority ?& ARRAY[
           'approverFullProofId','challengeId','challengeKind','contextDigest',
           'deviceId','enrollmentDigest','fullProofId','inputDigest',
           'lockedDeadlineMs','observedAt','operation','preEffectAssociationId',
           'preEffectAssociationState','preEffectAssociationVersion',
           'preEffectAuthorityEpoch','proposedAssociationId',
           'proposedAssociationVersion','proposedAuthorityEpoch',
           'proposedEd25519PublicKey','proposedPredecessorAssociationId',
           'schema','statementTokenId','subject','transitionKind','version'] THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    expected_authority_wire :=
        '{"approverFullProofId":' || (authority -> 'approverFullProofId')::text ||
        ',"challengeId":' || (authority -> 'challengeId')::text ||
        ',"challengeKind":' || (authority -> 'challengeKind')::text ||
        ',"contextDigest":' || (authority -> 'contextDigest')::text ||
        ',"deviceId":' || (authority -> 'deviceId')::text ||
        ',"enrollmentDigest":' || (authority -> 'enrollmentDigest')::text ||
        ',"fullProofId":' || (authority -> 'fullProofId')::text ||
        ',"inputDigest":' || (authority -> 'inputDigest')::text ||
        ',"lockedDeadlineMs":' || (authority -> 'lockedDeadlineMs')::text ||
        ',"observedAt":' || (authority -> 'observedAt')::text ||
        ',"operation":' || (authority -> 'operation')::text ||
        ',"preEffectAssociationId":' || (authority -> 'preEffectAssociationId')::text ||
        ',"preEffectAssociationState":' || (authority -> 'preEffectAssociationState')::text ||
        ',"preEffectAssociationVersion":' || (authority -> 'preEffectAssociationVersion')::text ||
        ',"preEffectAuthorityEpoch":' || (authority -> 'preEffectAuthorityEpoch')::text ||
        ',"proposedAssociationId":' || (authority -> 'proposedAssociationId')::text ||
        ',"proposedAssociationVersion":' || (authority -> 'proposedAssociationVersion')::text ||
        ',"proposedAuthorityEpoch":' || (authority -> 'proposedAuthorityEpoch')::text ||
        ',"proposedEd25519PublicKey":' || (authority -> 'proposedEd25519PublicKey')::text ||
        ',"proposedPredecessorAssociationId":' ||
            (authority -> 'proposedPredecessorAssociationId')::text ||
        ',"schema":' || (authority -> 'schema')::text ||
        ',"statementTokenId":' || (authority -> 'statementTokenId')::text ||
        ',"subject":' || (authority -> 'subject')::text ||
        ',"transitionKind":' || (authority -> 'transitionKind')::text ||
        ',"version":' || (authority -> 'version')::text || '}';

    IF NEW.authority_wire <> expected_authority_wire OR
       authority ->> 'schema' <> 'hodlxxi.social_enrollment_transition_authority.v1' OR
       authority ->> 'version' <> '1' OR
       authority ->> 'operation' <> NEW.operation OR
       authority ->> 'challengeKind' <> 'enrollment-v2' OR
       authority ->> 'challengeId' <> NEW.challenge_id OR
       authority ->> 'proposedAssociationId' <> NEW.proposed_association_id OR
       authority ->> 'observedAt' !~ '^(0|[1-9][0-9]*)$' OR
       authority ->> 'lockedDeadlineMs' !~ '^[1-9][0-9]*$' OR
       (authority ->> 'observedAt')::bigint >=
           (authority ->> 'lockedDeadlineMs')::bigint THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    effect_id_preimage :=
        '{"challengeId":' || (authority -> 'challengeId')::text ||
        ',"challengeKind":' || (authority -> 'challengeKind')::text ||
        ',"contextDigest":' || (authority -> 'contextDigest')::text ||
        ',"deviceId":' || (authority -> 'deviceId')::text ||
        ',"inputDigest":' || (authority -> 'inputDigest')::text ||
        ',"operation":' || (authority -> 'operation')::text ||
        ',"schema":"hodlxxi.social_enrollment_effect_id_preimage.v1"' ||
        ',"statementTokenId":' || (authority -> 'statementTokenId')::text ||
        ',"subject":' || (authority -> 'subject')::text ||
        ',"version":1}';
    IF NEW.effect_id <> encode(sha256(
        convert_to('HODLXXI_SOCIAL_ENROLLMENT_EFFECT_ID_V1', 'UTF8') ||
        decode('00', 'hex') || convert_to(effect_id_preimage, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    effect_transition_preimage :=
        '{"challengeId":' || (authority -> 'challengeId')::text ||
        ',"challengeKind":' || (authority -> 'challengeKind')::text ||
        ',"deviceId":' || (authority -> 'deviceId')::text ||
        ',"enrollmentDigest":' || (authority -> 'enrollmentDigest')::text ||
        ',"operation":' || (authority -> 'operation')::text ||
        ',"preEffectAssociationId":' || (authority -> 'preEffectAssociationId')::text ||
        ',"preEffectAssociationState":' || (authority -> 'preEffectAssociationState')::text ||
        ',"preEffectAssociationVersion":' || (authority -> 'preEffectAssociationVersion')::text ||
        ',"preEffectAuthorityEpoch":' || (authority -> 'preEffectAuthorityEpoch')::text ||
        ',"proposedAssociationId":' || (authority -> 'proposedAssociationId')::text ||
        ',"proposedAssociationVersion":' || (authority -> 'proposedAssociationVersion')::text ||
        ',"proposedAuthorityEpoch":' || (authority -> 'proposedAuthorityEpoch')::text ||
        ',"proposedEd25519PublicKey":' || (authority -> 'proposedEd25519PublicKey')::text ||
        ',"proposedPredecessorAssociationId":' ||
            (authority -> 'proposedPredecessorAssociationId')::text ||
        ',"proposedState":"active"' ||
        ',"schema":"hodlxxi.social_enrollment_effect_transition.v1"' ||
        ',"subject":' || (authority -> 'subject')::text ||
        ',"transitionKind":' || (authority -> 'transitionKind')::text ||
        ',"version":1}';
    IF NEW.effect_digest <> encode(sha256(
        convert_to('HODLXXI_SOCIAL_ENROLLMENT_EFFECT_DIGEST_V1', 'UTF8') ||
        decode('00', 'hex') || convert_to(effect_transition_preimage, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    receipt_id_preimage :=
        '{"challengeId":' || to_jsonb(NEW.challenge_id)::text ||
        ',"effectDigest":' || to_jsonb(NEW.effect_digest)::text ||
        ',"effectId":' || to_jsonb(NEW.effect_id)::text ||
        ',"operation":' || to_jsonb(NEW.operation)::text ||
        ',"schema":"hodlxxi.social_enrollment_receipt_id_preimage.v1"' ||
        ',"version":1}';
    IF NEW.receipt_id <> encode(sha256(
        convert_to('HODLXXI_SOCIAL_ENROLLMENT_RECEIPT_ID_V1', 'UTF8') ||
        decode('00', 'hex') || convert_to(receipt_id_preimage, 'UTF8')), 'hex') THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;

    expected_receipt_wire :=
        '{"challengeId":' || to_jsonb(NEW.challenge_id)::text ||
        ',"decidedAt":' || NEW.decided_at::text ||
        ',"operation":' || to_jsonb(NEW.operation)::text ||
        ',"receiptId":' || to_jsonb(NEW.receipt_id)::text ||
        ',"schema":"hodlxxi.social_device_admission_receipt.v1"' ||
        ',"status":"committed","version":1}';
    IF NEW.receipt_wire <> expected_receipt_wire THEN
        RAISE EXCEPTION 'social enrollment receipt storage unavailable';
    END IF;
    RETURN NEW;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'social enrollment receipt storage unavailable';
END $$;

CREATE TRIGGER trg_social_enrollment_receipt_guard
    BEFORE INSERT OR UPDATE OR DELETE
    ON social_device_enrollment_admission_receipts
    FOR EACH ROW EXECUTE FUNCTION guard_social_enrollment_receipt_v1();
CREATE TRIGGER trg_social_enrollment_receipt_no_truncate
    BEFORE TRUNCATE ON social_device_enrollment_admission_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION guard_social_enrollment_receipt_v1();

-- Preserve the original immutable challenge evidence and terminal semantics,
-- adding only enrollment issued -> consumed. Cross-table completeness is
-- checked by deferred constraint triggers below at the caller's COMMIT.
CREATE OR REPLACE FUNCTION guard_social_device_challenge_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'issued' THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        IF ROW(NEW.challenge_id, NEW.context_wire, NEW.challenge_wire,
               NEW.routing_request_wire) IS DISTINCT FROM
           ROW(OLD.challenge_id, OLD.context_wire, OLD.challenge_wire,
               OLD.routing_request_wire) OR
           OLD.state <> 'issued' THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        IF NEW.state = 'consumed' THEN
            IF NEW.context_wire::jsonb ->> 'challengeKind' <> 'enrollment-v2' OR
               NEW.challenge_wire::jsonb ->> 'schema' <>
                   'hodlxxi.social_messaging_device_enrollment.v2' THEN
                RAISE EXCEPTION 'social device challenge storage unavailable';
            END IF;
        ELSIF NEW.state NOT IN ('expired','invalidated','cancelled') THEN
            RAISE EXCEPTION 'social device challenge storage unavailable';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'social device challenge storage unavailable';
END $$;

CREATE FUNCTION assert_social_enrollment_atomic_v1()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_challenge_id VARCHAR(64);
    challenge social_device_admission_challenges%ROWTYPE;
    receipt social_device_enrollment_admission_receipts%ROWTYPE;
    effect social_device_ed25519_association_events%ROWTYPE;
    prior social_device_ed25519_association_events%ROWTYPE;
    authority JSONB;
    context_document JSONB;
    enrollment_document JSONB;
    expected_context_digest TEXT;
    expected_enrollment_digest TEXT;
BEGIN
    IF TG_TABLE_NAME = 'social_device_ed25519_association_events' THEN
        IF NEW.kind NOT IN ('initial','rotate','reenroll') THEN
            RETURN NULL;
        END IF;
        target_challenge_id := NEW.enrollment_challenge_id;
    ELSE
        target_challenge_id := NEW.challenge_id;
    END IF;

    SELECT * INTO challenge FROM social_device_admission_challenges
        WHERE challenge_id = target_challenge_id;
    IF NOT FOUND OR challenge.state <> 'consumed' THEN
        RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
    END IF;
    SELECT * INTO receipt FROM social_device_enrollment_admission_receipts
        WHERE challenge_id = target_challenge_id;
    IF NOT FOUND OR receipt.operation <> 'enrollment-activate' THEN
        RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
    END IF;
    SELECT * INTO effect FROM social_device_ed25519_association_events
        WHERE enrollment_challenge_id = target_challenge_id
          AND kind IN ('initial','rotate','reenroll');
    IF NOT FOUND OR effect.association_id <> receipt.proposed_association_id THEN
        RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
    END IF;

    authority := receipt.authority_wire::jsonb;
    context_document := challenge.context_wire::jsonb;
    enrollment_document := challenge.challenge_wire::jsonb;
    expected_context_digest :=
        'hodlxxi-social-device-verification-context-v1-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_DEVICE_VERIFICATION_CONTEXT_V1', 'UTF8') ||
            decode('00', 'hex') || convert_to(challenge.context_wire, 'UTF8')), 'hex');
    expected_enrollment_digest :=
        'hodlxxi-social-messaging-device-enrollment-v2-sha256:' ||
        encode(sha256(
            convert_to('HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2', 'UTF8') ||
            decode('00', 'hex') || convert_to(challenge.challenge_wire, 'UTF8')), 'hex');

    IF authority ->> 'challengeId' <> target_challenge_id OR
       authority ->> 'contextDigest' <> expected_context_digest OR
       authority ->> 'enrollmentDigest' <> expected_enrollment_digest OR
       authority ->> 'subject' <> effect.subject OR
       authority ->> 'deviceId' <> effect.device_id OR
       authority ->> 'proposedAssociationId' <> effect.association_id OR
       (authority ->> 'proposedAssociationVersion')::bigint <>
           effect.association_version OR
       (authority ->> 'proposedAuthorityEpoch')::bigint <>
           effect.authority_epoch OR
       authority ->> 'proposedEd25519PublicKey' <> effect.ed25519_public_key OR
       authority ->> 'proposedPredecessorAssociationId'
           IS DISTINCT FROM effect.predecessor_association_id OR
       authority ->> 'transitionKind' <> effect.kind OR
       context_document ->> 'challengeKind' <> 'enrollment-v2' OR
       context_document ->> 'challengeId' <> target_challenge_id OR
       context_document ->> 'subject' <> effect.subject OR
       context_document ->> 'deviceId' <> effect.device_id OR
       context_document ->> 'associationId' <> effect.association_id OR
       (context_document ->> 'associationVersion')::bigint <>
           effect.association_version OR
       (context_document ->> 'authorityEpoch')::bigint <>
           effect.authority_epoch OR
       context_document ->> 'ed25519PublicKey' <> effect.ed25519_public_key OR
       context_document ->> 'predecessorAssociationId'
           IS DISTINCT FROM effect.predecessor_association_id OR
       enrollment_document ->> 'enrollmentChallengeId' <> target_challenge_id OR
       enrollment_document ->> 'subject' <> effect.subject OR
       enrollment_document ->> 'deviceId' <> effect.device_id OR
       enrollment_document ->> 'ed25519PublicKey' <> effect.ed25519_public_key THEN
        RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
    END IF;

    IF effect.kind = 'initial' THEN
        IF authority ->> 'preEffectAssociationState' <> 'absent' OR
           authority -> 'preEffectAssociationId' <> 'null'::jsonb OR
           authority -> 'preEffectAssociationVersion' <> 'null'::jsonb OR
           authority ->> 'preEffectAuthorityEpoch' <> '0' OR
           effect.authority_epoch <> 1 OR effect.association_version <> 1 OR
           effect.predecessor_association_id IS NOT NULL THEN
            RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
        END IF;
    ELSE
        SELECT * INTO prior FROM social_device_ed25519_association_events
            WHERE subject = effect.subject AND device_id = effect.device_id
              AND authority_epoch = effect.authority_epoch - 1;
        IF NOT FOUND OR
           authority ->> 'preEffectAssociationId' <> prior.association_id OR
           (authority ->> 'preEffectAssociationVersion')::bigint <>
               prior.association_version OR
           (authority ->> 'preEffectAuthorityEpoch')::bigint <>
               prior.authority_epoch OR
           authority ->> 'proposedPredecessorAssociationId' <>
               prior.association_id OR
           (effect.kind = 'rotate' AND
               (authority ->> 'preEffectAssociationState' <> 'active' OR
                prior.kind = 'revoke')) OR
           (effect.kind = 'reenroll' AND
               (authority ->> 'preEffectAssociationState' <> 'revoked' OR
                prior.kind <> 'revoke')) THEN
            RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
        END IF;
    END IF;
    RETURN NULL;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
END $$;

CREATE CONSTRAINT TRIGGER trg_social_enrollment_receipt_atomic
    AFTER INSERT ON social_device_enrollment_admission_receipts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION assert_social_enrollment_atomic_v1();
CREATE CONSTRAINT TRIGGER trg_social_enrollment_challenge_atomic
    AFTER UPDATE ON social_device_admission_challenges
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NEW.state = 'consumed')
    EXECUTE FUNCTION assert_social_enrollment_atomic_v1();
CREATE CONSTRAINT TRIGGER trg_social_enrollment_event_atomic
    AFTER INSERT ON social_device_ed25519_association_events
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN (NEW.kind IN ('initial','rotate','reenroll'))
    EXECUTE FUNCTION assert_social_enrollment_atomic_v1();
