-- Dormant separately activated V2-native path. SOURCE ONLY; never backfill.
-- Requires the pinned V1 receipt, V2 CAS, revision and native issuance sources.
-- Installation and role grants require a separate authorized DDL transaction.
-- No live role is named; PUBLIC receives no table or function privileges.
CREATE TABLE public.social_enrollment_v2_native_associations (
    reservation_id VARCHAR(64) PRIMARY KEY,
    challenge_id VARCHAR(64) NOT NULL UNIQUE CONSTRAINT na_challenge_fk REFERENCES public.social_device_admission_challenges(challenge_id),
    subject VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    authority_epoch BIGINT NOT NULL,
    event_wire TEXT NOT NULL,
    birth_xid TEXT NOT NULL,
    CONSTRAINT na_event_fk FOREIGN KEY(subject,device_id,authority_epoch) REFERENCES public.social_device_ed25519_association_events(subject,device_id,authority_epoch)
);
CREATE TABLE public.social_enrollment_v2_native_effects (
    reservation_id VARCHAR(64) PRIMARY KEY CONSTRAINT ne_reservation_fk REFERENCES public.social_enrollment_v2_native_associations(reservation_id),
    challenge_id VARCHAR(64) NOT NULL UNIQUE CONSTRAINT ne_challenge_fk REFERENCES public.social_device_admission_challenges(challenge_id),
    subject VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    authority_epoch BIGINT NOT NULL,
    effect_id VARCHAR(64) NOT NULL UNIQUE,
    receipt_id VARCHAR(64) NOT NULL UNIQUE,
    event_wire TEXT NOT NULL,
    effect_wire TEXT NOT NULL,
    receipt_wire TEXT NOT NULL,
    evidence_pin TEXT NOT NULL,
    statement_pin TEXT NOT NULL,
    birth_xid TEXT NOT NULL,
    CONSTRAINT ne_event_fk FOREIGN KEY(subject,device_id,authority_epoch) REFERENCES public.social_device_ed25519_association_events(subject,device_id,authority_epoch)
);
CREATE TABLE public.social_enrollment_v2_native_consumptions (
    reservation_id VARCHAR(64) PRIMARY KEY CONSTRAINT nc_reservation_fk REFERENCES public.social_enrollment_v2_native_effects(reservation_id),
    birth_xid TEXT NOT NULL
);
CREATE TABLE public.social_enrollment_v2_native_decisions (
    reservation_id VARCHAR(64) PRIMARY KEY CONSTRAINT nd_reservation_fk REFERENCES public.social_enrollment_v2_native_effects(reservation_id),
    birth_xid TEXT NOT NULL UNIQUE
);

CREATE FUNCTION public.deny_social_enrollment_v2_native_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    RAISE EXCEPTION 'social enrollment v2 finalization denied';
END
$$;

CREATE FUNCTION public.execute_social_enrollment_v2_native_effects(
    reservation TEXT, event_bytes TEXT, effect_bytes TEXT, receipt_bytes TEXT,
    evidence_registration TEXT, statement_registration TEXT, stage TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE
    r public.social_preaccepted_enrollment_v2_atomic_acceptances%ROWTYPE;
    ch public.social_device_admission_challenges%ROWTYPE;
    b public.social_enrollment_v2_native_associations%ROWTYPE;
    e public.social_enrollment_v2_native_effects%ROWTYPE;
    document JSONB;
    expected_event TEXT;
    enrollment_digest TEXT;
    association_preimage TEXT;
    expected_association TEXT;
    expected_input TEXT;
    native_root TEXT := pg_catalog.pg_current_xact_id()::text;
    changed INTEGER;
BEGIN
    LOCK TABLE public.social_preaccepted_enrollment_v2_atomic_acceptances IN SHARE ROW EXCLUSIVE MODE;
    SELECT * INTO STRICT r FROM public.social_preaccepted_enrollment_v2_atomic_acceptances
        WHERE reservation_id=reservation FOR UPDATE;
    IF r.state <> 'pending' OR r.reservation_revision <> 1 OR r.challenge_revision <> 1 OR
       stage IS NULL OR stage NOT IN ('association','receipt','consumption') OR
       event_bytes IS NULL OR effect_bytes IS NULL OR receipt_bytes IS NULL OR
       evidence_registration IS NULL OR statement_registration IS NULL THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    SELECT * INTO STRICT ch FROM public.social_device_admission_challenges
        WHERE challenge_id=r.challenge_id FOR UPDATE;
    IF ch.state <> 'issued' OR ch.routing_request_wire IS NOT NULL OR
       ch.context_wire <> (r.input_wire::jsonb ->> 'context') OR
       ch.challenge_wire <> (r.input_wire::jsonb ->> 'enrollment') OR
       NOT EXISTS (SELECT 1 FROM public.social_device_admission_challenge_revisions
           WHERE challenge_id=r.challenge_id AND revision=r.challenge_revision) OR
       EXISTS (SELECT 1 FROM public.social_device_enrollment_admission_receipts
           WHERE challenge_id=r.challenge_id OR proposed_association_id=r.association_id) THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    expected_input := '{"acceptanceId":' || to_jsonb(r.acceptance_id)::text ||
        ',"approvalEvent":' || (r.input_wire::jsonb -> 'approvalEvent')::text ||
        ',"context":' || to_jsonb(ch.context_wire)::text ||
        ',"enrollment":' || to_jsonb(ch.challenge_wire)::text ||
        ',"phoneProof":' || (r.input_wire::jsonb -> 'phoneProof')::text ||
        ',"schema":"hodlxxi.social_preaccepted_enrollment_verification_input.v2","version":2}';
    IF r.input_wire IS DISTINCT FROM expected_input THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    document := ch.challenge_wire::jsonb;
    enrollment_digest := 'hodlxxi-social-messaging-device-enrollment-v2-sha256:' ||
        encode(sha256(convert_to('HODLXXI_SOCIAL_MESSAGING_DEVICE_ENROLLMENT_DIGEST_V2','UTF8') ||
            decode('00','hex') || convert_to(ch.challenge_wire,'UTF8')),'hex');
    association_preimage := '{"associationVersion":1,"deviceId":' || (document -> 'deviceId')::text ||
        ',"ed25519PublicKey":' || (document -> 'ed25519PublicKey')::text ||
        ',"enrollmentDigest":' || to_jsonb(enrollment_digest)::text ||
        ',"predecessorAssociationId":null,' ||
        '"schema":"hodlxxi.social_messaging_device_ed25519_association_creation.v1","subject":' ||
        (document -> 'subject')::text || ',"version":1}';
    expected_association := encode(sha256(
        convert_to('HODLXXI_SOCIAL_MESSAGING_DEVICE_ED25519_ASSOCIATION_ID_V1','UTF8') ||
        decode('00','hex') || convert_to(association_preimage,'UTF8')),'hex');
    IF r.association_id IS DISTINCT FROM expected_association THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    expected_event := '{"associationId":' || to_jsonb(r.association_id)::text ||
        ',"associationVersion":1,"authorityEpoch":1,"enrollmentWire":' || to_jsonb(ch.challenge_wire)::text ||
        ',"kind":"initial","predecessorAssociationId":null,' ||
        '"schema":"hodlxxi.social_messaging_device_ed25519_association_event.v1","version":1}';
    IF event_bytes <> expected_event OR document ->> 'subject' <> r.subject OR
       document ->> 'deviceId' <> r.device_id OR document ->> 'enrollmentChallengeId' <> r.challenge_id OR
       effect_bytes::jsonb ->> 'reservationId' <> reservation OR
       receipt_bytes::jsonb ->> 'reservationId' <> reservation OR
       receipt_bytes::jsonb ->> 'effectId' <> effect_bytes::jsonb ->> 'effectId' THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    IF stage='association' THEN
        -- Real initial shared mutation. Plain INSERT, no adoption or upsert.
        INSERT INTO public.social_device_ed25519_association_chains
            (subject,device_id,authority_epoch,last_association_id,last_association_version,current_association_id,state)
            VALUES(r.subject,r.device_id,0,NULL,NULL,NULL,'empty');
        INSERT INTO public.social_device_ed25519_association_events
            (subject,device_id,authority_epoch,kind,association_id,association_version,
             predecessor_association_id,ed25519_public_key,enrollment_challenge_id,event_wire)
            VALUES(r.subject,r.device_id,1,'initial',r.association_id,1,NULL,
                document ->> 'ed25519PublicKey',r.challenge_id,event_bytes);
        INSERT INTO public.social_enrollment_v2_native_associations
            VALUES(reservation,r.challenge_id,r.subject,r.device_id,1,event_bytes,native_root);
    ELSE
        SELECT * INTO STRICT b FROM public.social_enrollment_v2_native_associations WHERE reservation_id=reservation;
        IF b.birth_xid <> native_root OR b.event_wire <> event_bytes THEN
            RAISE EXCEPTION 'social enrollment v2 finalization denied';
        END IF;
        IF stage='receipt' THEN
            INSERT INTO public.social_enrollment_v2_native_effects
                VALUES(reservation,r.challenge_id,r.subject,r.device_id,1,
                    effect_bytes::jsonb ->> 'effectId',receipt_bytes::jsonb ->> 'receiptId',
                    event_bytes,effect_bytes,receipt_bytes,evidence_registration,statement_registration,native_root);
        ELSE
            SELECT * INTO STRICT e FROM public.social_enrollment_v2_native_effects WHERE reservation_id=reservation;
            IF e.birth_xid <> native_root OR e.event_wire <> event_bytes OR e.effect_wire <> effect_bytes OR
               e.receipt_wire <> receipt_bytes OR e.evidence_pin <> evidence_registration OR
               e.statement_pin <> statement_registration THEN
                RAISE EXCEPTION 'social enrollment v2 finalization denied';
            END IF;
            UPDATE public.social_device_admission_challenges SET state='consumed'
                WHERE challenge_id=r.challenge_id AND state='issued' AND context_wire=ch.context_wire
                  AND challenge_wire=ch.challenge_wire;
            GET DIAGNOSTICS changed = ROW_COUNT;
            IF changed <> 1 THEN RAISE EXCEPTION 'social enrollment v2 finalization denied'; END IF;
            INSERT INTO public.social_enrollment_v2_native_consumptions VALUES(reservation,native_root);
        END IF;
    END IF;
    RETURN;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'social enrollment v2 finalization denied';
END
$$;

CREATE FUNCTION public.assert_social_enrollment_v2_native_complete(reservation TEXT, native_root TEXT)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
    r public.social_preaccepted_enrollment_v2_atomic_acceptances%ROWTYPE;
    b public.social_enrollment_v2_native_associations%ROWTYPE;
    e public.social_enrollment_v2_native_effects%ROWTYPE;
    ch public.social_device_admission_challenges%ROWTYPE;
    ev public.social_device_ed25519_association_events%ROWTYPE;
    head public.social_device_ed25519_association_chains%ROWTYPE;
    claims JSONB;
    payload_segment TEXT;
BEGIN
    SELECT * INTO STRICT r FROM public.social_preaccepted_enrollment_v2_atomic_acceptances WHERE reservation_id=reservation;
    SELECT * INTO STRICT b FROM public.social_enrollment_v2_native_associations WHERE reservation_id=reservation;
    SELECT * INTO STRICT e FROM public.social_enrollment_v2_native_effects WHERE reservation_id=reservation;
    SELECT * INTO STRICT ch FROM public.social_device_admission_challenges WHERE challenge_id=r.challenge_id;
    SELECT * INTO STRICT ev FROM public.social_device_ed25519_association_events
        WHERE subject=r.subject AND device_id=r.device_id AND authority_epoch=1;
    SELECT * INTO STRICT head FROM public.social_device_ed25519_association_chains
        WHERE subject=r.subject AND device_id=r.device_id;
    IF native_root IS NULL OR native_root <> pg_catalog.pg_current_xact_id()::text OR
       r.state <> 'accepted' OR b.birth_xid <> native_root OR e.birth_xid <> native_root OR
       b.challenge_id <> r.challenge_id OR b.subject <> r.subject OR b.device_id <> r.device_id OR
       b.authority_epoch <> 1 OR b.event_wire <> ev.event_wire OR e.event_wire <> ev.event_wire OR
       e.challenge_id <> r.challenge_id OR e.subject <> r.subject OR e.device_id <> r.device_id OR
       e.authority_epoch <> 1 OR e.effect_id <> r.effect_id OR e.receipt_id <> r.receipt_id OR
       e.effect_wire <> r.effect_wire OR e.receipt_wire <> r.receipt_wire OR
       ch.state <> 'consumed' OR ch.routing_request_wire IS NOT NULL OR
       ch.context_wire <> (r.input_wire::jsonb ->> 'context') OR
       ch.challenge_wire <> (r.input_wire::jsonb ->> 'enrollment') OR
       ch.context_wire::jsonb ->> 'challengeKind' IS DISTINCT FROM 'enrollment-v2' OR
       ch.context_wire::jsonb ->> 'challengeId' IS DISTINCT FROM r.challenge_id OR
       ch.context_wire::jsonb ->> 'subject' IS DISTINCT FROM r.subject OR
       ch.context_wire::jsonb ->> 'deviceId' IS DISTINCT FROM r.device_id OR
       ch.context_wire::jsonb ->> 'associationId' IS DISTINCT FROM r.association_id OR
       ch.context_wire::jsonb -> 'associationVersion' IS DISTINCT FROM '1'::jsonb OR
       ch.context_wire::jsonb -> 'authorityEpoch' IS DISTINCT FROM '1'::jsonb OR
       ch.context_wire::jsonb -> 'predecessorAssociationId' IS DISTINCT FROM 'null'::jsonb OR
       ch.context_wire::jsonb ->> 'ed25519PublicKey' IS DISTINCT FROM ev.ed25519_public_key OR
       ch.challenge_wire::jsonb ->> 'enrollmentChallengeId' IS DISTINCT FROM r.challenge_id OR
       ch.challenge_wire::jsonb ->> 'subject' IS DISTINCT FROM r.subject OR
       ch.challenge_wire::jsonb ->> 'deviceId' IS DISTINCT FROM r.device_id OR
       ev.kind <> 'initial' OR ev.association_id <> r.association_id OR ev.association_version <> 1 OR
       ev.predecessor_association_id IS NOT NULL OR ev.enrollment_challenge_id <> r.challenge_id OR
       ev.ed25519_public_key <> ch.challenge_wire::jsonb ->> 'ed25519PublicKey' OR
       head.authority_epoch <> 1 OR head.state <> 'active' OR head.current_association_id <> r.association_id OR
       head.last_association_id <> r.association_id OR head.last_association_version <> 1 OR
       (SELECT count(*) FROM public.social_device_ed25519_association_events
           WHERE subject=r.subject AND device_id=r.device_id) <> 1 OR
       NOT EXISTS(SELECT 1 FROM public.social_enrollment_v2_native_consumptions
           WHERE reservation_id=reservation AND birth_xid=native_root) OR
       NOT EXISTS(SELECT 1 FROM public.social_enrollment_v2_native_decisions
           WHERE reservation_id=reservation AND birth_xid=native_root) OR
       NOT EXISTS(SELECT 1 FROM public.social_device_admission_challenge_revisions
           WHERE challenge_id=r.challenge_id AND revision=r.challenge_revision) OR
       EXISTS(SELECT 1 FROM public.social_device_enrollment_admission_receipts
           WHERE challenge_id=r.challenge_id OR proposed_association_id=r.association_id) THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    payload_segment := split_part(r.evidence_compact_jws,'.',2);
    claims := convert_from(decode(translate(payload_segment,'-_','+/') ||
        repeat('=',(4-length(payload_segment)%4)%4),'base64'),'UTF8')::jsonb;
    IF NOT EXISTS(SELECT 1 FROM public.social_session_v2_acceptances a
        JOIN public.social_session_v2_issuances i USING(operation_id)
        WHERE a.operation_id=r.operation_id AND a.acceptance_id=r.acceptance_id AND
            a.approval_wire=r.input_wire::jsonb ->> 'approvalEvent' AND
            i.acceptance_id=r.acceptance_id AND i.issuance_id=claims ->> 'socialSessionIssuanceId' AND
            i.revision=claims ->> 'socialSessionIssuanceRevision' AND
            i.token_id=claims ->> 'socialSessionTokenId' AND a.birth_xid=i.birth_xid) THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    RETURN;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'social enrollment v2 finalization denied';
END
$$;

CREATE FUNCTION public.capture_social_enrollment_v2_native_decision()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    IF TG_OP <> 'UPDATE' OR TG_TABLE_SCHEMA <> 'public' OR
       TG_TABLE_NAME <> 'social_preaccepted_enrollment_v2_atomic_acceptances' THEN
        RAISE EXCEPTION 'social enrollment v2 finalization denied';
    END IF;
    IF NEW.state='accepted' THEN
        IF OLD.state <> 'pending' THEN RAISE EXCEPTION 'social enrollment v2 finalization denied'; END IF;
        INSERT INTO public.social_enrollment_v2_native_decisions
            VALUES(NEW.reservation_id,pg_catalog.pg_current_xact_id()::text);
        PERFORM public.assert_social_enrollment_v2_native_complete(NEW.reservation_id,pg_catalog.pg_current_xact_id()::text);
    END IF;
    RETURN NULL;
END
$$;
CREATE TRIGGER trg_social_preaccepted_v2_native_decision AFTER UPDATE
    ON public.social_preaccepted_enrollment_v2_atomic_acceptances FOR EACH ROW
    EXECUTE FUNCTION public.capture_social_enrollment_v2_native_decision();

CREATE FUNCTION public.assert_social_enrollment_v2_native_ledger()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM public.assert_social_enrollment_v2_native_complete(NEW.reservation_id,pg_catalog.pg_current_xact_id()::text);
    RETURN NULL;
END
$$;

-- Original V1 branch retained after the distinct V2 branch.
CREATE OR REPLACE FUNCTION public.assert_social_enrollment_atomic_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE
    target_challenge_id VARCHAR(64);
    v2_reservation VARCHAR(64);
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

    SELECT reservation_id INTO v2_reservation FROM public.social_enrollment_v2_native_associations
        WHERE challenge_id=target_challenge_id;
    IF FOUND THEN
        IF TG_TABLE_NAME='social_device_enrollment_admission_receipts' THEN
            RAISE EXCEPTION 'social enrollment atomic invariant unavailable';
        END IF;
        PERFORM public.assert_social_enrollment_v2_native_complete(v2_reservation,pg_catalog.pg_current_xact_id()::text);
        RETURN NULL;
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

CREATE TRIGGER v2_native_immutable BEFORE UPDATE OR DELETE ON public.social_enrollment_v2_native_associations
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE TRIGGER v2_native_no_truncate BEFORE TRUNCATE ON public.social_enrollment_v2_native_associations
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE CONSTRAINT TRIGGER v2_native_complete AFTER INSERT ON public.social_enrollment_v2_native_associations
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION public.assert_social_enrollment_v2_native_ledger();
REVOKE ALL ON public.social_enrollment_v2_native_associations FROM PUBLIC;

CREATE TRIGGER v2_native_immutable BEFORE UPDATE OR DELETE ON public.social_enrollment_v2_native_effects
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE TRIGGER v2_native_no_truncate BEFORE TRUNCATE ON public.social_enrollment_v2_native_effects
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE CONSTRAINT TRIGGER v2_native_complete AFTER INSERT ON public.social_enrollment_v2_native_effects
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION public.assert_social_enrollment_v2_native_ledger();
REVOKE ALL ON public.social_enrollment_v2_native_effects FROM PUBLIC;

CREATE TRIGGER v2_native_immutable BEFORE UPDATE OR DELETE ON public.social_enrollment_v2_native_consumptions
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE TRIGGER v2_native_no_truncate BEFORE TRUNCATE ON public.social_enrollment_v2_native_consumptions
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE CONSTRAINT TRIGGER v2_native_complete AFTER INSERT ON public.social_enrollment_v2_native_consumptions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION public.assert_social_enrollment_v2_native_ledger();
REVOKE ALL ON public.social_enrollment_v2_native_consumptions FROM PUBLIC;

CREATE TRIGGER v2_native_immutable BEFORE UPDATE OR DELETE ON public.social_enrollment_v2_native_decisions
    FOR EACH ROW EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE TRIGGER v2_native_no_truncate BEFORE TRUNCATE ON public.social_enrollment_v2_native_decisions
    FOR EACH STATEMENT EXECUTE FUNCTION public.deny_social_enrollment_v2_native_mutation();
CREATE CONSTRAINT TRIGGER v2_native_complete AFTER INSERT ON public.social_enrollment_v2_native_decisions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION public.assert_social_enrollment_v2_native_ledger();
REVOKE ALL ON public.social_enrollment_v2_native_decisions FROM PUBLIC;
REVOKE ALL ON FUNCTION public.deny_social_enrollment_v2_native_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.execute_social_enrollment_v2_native_effects(TEXT,TEXT,TEXT,TEXT,TEXT,TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_social_enrollment_v2_native_complete(TEXT,TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.capture_social_enrollment_v2_native_decision() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_social_enrollment_v2_native_ledger() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_social_enrollment_atomic_v1() FROM PUBLIC;
-- Trigger invocation needs no runtime direct EXECUTE grant. Preserve bodies.
REVOKE ALL ON FUNCTION public.guard_social_device_challenge_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_social_ed25519_chain_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.assert_social_ed25519_chain_initialized_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_social_ed25519_event_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.advance_social_ed25519_chain_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_social_enrollment_receipt_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_social_mobile_operation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.reject_social_device_authorization_mutation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.validate_social_mobile_acceptance_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_session_generation_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_mapped_session_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_token_session_invalidation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_owner_session_invalidation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.oauth_browser_generation_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.social_session_token_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.social_session_parent_invalidation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.social_session_binding_invalidation_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.social_session_issuer_guard_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.social_session_client_invalidation_v1() FROM PUBLIC;
