"""Distinct native V2 effects in the shared association/challenge database.

The native function is a narrow effects executor, not an authority reader. Its
immutable ledger is reachable only through that function. Native root evidence
comes from pg_current_xact_id inside the same function that inserts the real
chain/event and consumes the exact challenge; no xmin or caller birth claim.
"""

import hashlib
import json
import math
import re
import weakref
from types import MappingProxyType

from sqlalchemy import BigInteger, Column, ForeignKeyConstraint, MetaData, String, Table, Text, UniqueConstraint, text
from sqlalchemy.sql.elements import TextClause

from app.services import social_device_challenge_store as challenges
from app.services import social_messaging_device_ed25519_association_lifecycle as lifecycle
from app.services import social_messaging_mobile_pre_enrollment_v2 as v2
from app.services import social_preaccepted_enrollment_v2_atomic_acceptance_storage as durable
from app.services.social_device_challenge_revision_storage import _native_catalog_object
from app.services.social_enrollment_v2_finalization_contract import _deny, _sanitized

RUNTIME_ENABLED = False
EFFECT_TABLE = "social_enrollment_v2_native_effects"
DECISION_TABLE = "social_enrollment_v2_native_decisions"
WRITE_FUNCTION = "execute_social_enrollment_v2_native_effects"
DECISION_FUNCTION = "capture_social_enrollment_v2_native_decision"
DECISION_TRIGGER = "trg_social_preaccepted_v2_native_decision"
_WRITERS = weakref.WeakKeyDictionary()


def _wire(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


class NativeV2Effects:
    @_sanitized
    def __init__(self, authority):
        from app.services.social_enrollment_v2_finalization_authority import _OWNERS, NativeFinalizationAuthority

        if (
            type(self) is not NativeV2Effects
            or type(authority) is not NativeFinalizationAuthority
            or authority not in _OWNERS
        ):
            _deny()
        self.authority = authority
        self.guard = authority.guard
        self.failed = False
        self._identity = None
        _WRITERS[self] = (authority, self.guard)
        self.check()

    def _poison(self):
        self.failed = True
        if hasattr(self, "authority"):
            self.authority._poison()

    def check(self):
        if self.failed or _WRITERS.get(self) != (self.authority, self.guard) or self.guard is not self.authority.guard:
            _deny()
        self.authority._check()
        from app.services.social_device_challenge_revision_storage import (
            SqlAlchemyTransactionBoundIssuedChallengeRevisionReader,
        )
        from app.services.social_session_issuance_v2_authority import attest

        if not hasattr(self, "_revision_catalog"):
            self._revision_catalog = SqlAlchemyTransactionBoundIssuedChallengeRevisionReader(self.authority.port)
        else:
            self._revision_catalog._catalog()
            self._revision_catalog._marker()
            self._revision_catalog._store_identity()
        identity = (attest(self.guard), attest_native_schema(self.guard.connection))
        if self._identity is None:
            self._identity = identity
        elif identity != self._identity:
            _deny()
        self.authority._check()

    @_sanitized
    def execute(self, candidate):
        # Resolve the private immutable plan for pure event construction.
        # The loop below performs the complete fresh schema/authority checks
        # before the FIRST mutation, and on both sides of every later stage.
        # An additional pre-loop read/audit/read would duplicate that boundary.
        record = self.authority.resolve(candidate, expected_state="prepared")
        p = v2.parse_preaccepted_enrollment_verification_input_v2(record.input_wire)
        event = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(), p.enrollment_wire).events[0]
        event_wire = lifecycle.canonical_association_event_v1_bytes(event).decode("ascii")
        plan = record.canonical_plan
        phase = "prepared"
        for stage, following in (
            ("association", "association_written"),
            ("receipt", "receipt_written"),
            ("consumption", "effects_written"),
        ):
            self.check()
            self.authority.recheck(candidate, phase=phase)
            self.guard.sql(
                "SELECT public.execute_social_enrollment_v2_native_effects("
                ":reservation, :event, :effect, :receipt, :evidence_pin, :statement_pin, :stage)",
                dict(
                    reservation=record.stored.reservation.reservation_id,
                    event=event_wire,
                    effect=plan.effect_wire,
                    receipt=plan.receipt.wire,
                    evidence_pin=_wire(record.evidence_pin),
                    statement_pin=_wire(record.statement_pin),
                    stage=stage,
                ),
            )
            self.authority.move(candidate, phase, following)
            phase = following
            self.check()
            self.authority.recheck(candidate, phase=phase)
        return event_wire

    @_sanitized
    def verify_history(self, stored, *, evidence_pin, statement_pin, provisional=False):
        """Retained original mutation evidence; never renew current authority."""
        self.check()
        r = stored.reservation
        if r.state != "accepted" or stored.effect is None or stored.receipt is None:
            _deny()
        rows = (
            self.guard.sql(
                "SELECT * FROM public.social_enrollment_v2_native_effects WHERE reservation_id=:id",
                {"id": r.reservation_id},
            )
            .mappings()
            .all()
        )
        decisions = (
            self.guard.sql(
                "SELECT * FROM public.social_enrollment_v2_native_decisions WHERE reservation_id=:id",
                {"id": r.reservation_id},
            )
            .mappings()
            .all()
        )
        if len(rows) != 1 or len(decisions) != 1:
            _deny()
        ledger, decision = dict(rows[0]), dict(decisions[0])
        p = v2.parse_preaccepted_enrollment_verification_input_v2(stored.input_wire)
        event = lifecycle.initial_association_v1(lifecycle.AssociationLifecycleV1(), p.enrollment_wire).events[0]
        event_wire = lifecycle.canonical_association_event_v1_bytes(event).decode("ascii")
        xid = ledger["birth_xid"]
        if type(xid) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", xid) is None or int(xid) > 2**64 - 1:
            _deny()
        expected = dict(
            reservation_id=r.reservation_id,
            challenge_id=r.challenge_id,
            subject=r.subject,
            device_id=r.device_id,
            authority_epoch=1,
            effect_id=r.effect_id,
            receipt_id=r.receipt_id,
            event_wire=event_wire,
            effect_wire=stored.effect.wire,
            receipt_wire=stored.receipt.wire,
            evidence_pin=_wire(evidence_pin),
            statement_pin=_wire(statement_pin),
            birth_xid=xid,
        )
        if ledger != expected or decision != dict(reservation_id=r.reservation_id, birth_xid=xid):
            _deny()
        for name in ("associations", "consumptions"):
            retained = (
                self.guard.sql(
                    f"SELECT * FROM public.social_enrollment_v2_native_{name} WHERE reservation_id=:id",
                    {"id": r.reservation_id},
                )
                .mappings()
                .all()
            )
            wanted = dict(reservation_id=r.reservation_id, birth_xid=xid)
            if name == "associations":
                wanted.update(
                    challenge_id=r.challenge_id,
                    subject=r.subject,
                    device_id=r.device_id,
                    authority_epoch=1,
                    event_wire=event_wire,
                )
            if len(retained) != 1 or dict(retained[0]) != wanted:
                _deny()
        if provisional and xid != self.guard.xid or not provisional and xid == self.guard.xid:
            _deny()
        # Same guarded physical Connection, canonical explicit public relations.
        challenge_rows = (
            self.guard.sql(
                "SELECT * FROM public.social_device_admission_challenges WHERE challenge_id=:id FOR UPDATE",
                {"id": r.challenge_id},
            )
            .mappings()
            .all()
        )
        revision_rows = self.guard.sql(
            "SELECT revision FROM public.social_device_admission_challenge_revisions WHERE challenge_id=:id",
            {"id": r.challenge_id},
        ).all()
        if len(challenge_rows) != 1 or revision_rows != [(r.challenge_revision,)]:
            _deny()
        ch = challenges.parse_stored_device_challenge_v1(challenge_rows[0])
        if ch.state != "consumed" or ch.context.wire != p.context.wire or ch.challenge_wire != p.enrollment_wire:
            _deny()
        from app.services.social_device_ed25519_association_storage import SqlAlchemyEd25519AssociationStore

        history = SqlAlchemyEd25519AssociationStore(self.authority.port).lock_lifecycle(r.subject, r.device_id)
        lifecycle.association_snapshot_v1(history)
        if not history.events or history.events[0] != event or provisional and len(history.events) != 1:
            _deny()
        legacy = self.guard.sql(
            "SELECT receipt_id FROM public.social_device_enrollment_admission_receipts "
            "WHERE challenge_id=:challenge OR proposed_association_id=:association",
            dict(challenge=r.challenge_id, association=r.association_id),
        ).all()
        if legacy:
            _deny()
        self._original_native_history(stored)
        self.check()
        return stored.receipt.wire

    def _original_native_history(self, stored):
        from app.services import social_messaging_device_verification_deadline_evidence_v1 as evidence
        from app.services.social_session_issuance_v2_authority import _snapshot
        from app.services.social_session_issuance_v2_storage import (
            V2Acceptance,
            V2BindingBirth,
            V2Issuance,
            V2Offer,
            V2Parent,
            V2TokenBirth,
        )

        auth = evidence.verify_messaging_device_verification_deadline_evidence_v1(
            stored.evidence_compact_jws,
            config=self.authority.config.evidence_config,
            expected_input_wire=stored.input_wire,
            now=stored.reservation.decided_at,
        )
        claims = evidence.project_authenticated_messaging_device_verification_deadline_evidence_v1(auth)["claims"]
        r = stored.reservation
        p = v2.parse_preaccepted_enrollment_verification_input_v2(stored.input_wire)
        a = _snapshot(self.guard.row(V2Acceptance, V2Acceptance.operation_id, r.operation_id))
        i = _snapshot(self.guard.row(V2Issuance, V2Issuance.operation_id, r.operation_id))
        parent = _snapshot(self.guard.row(V2Parent, V2Parent.operation_id, r.operation_id))
        offer = _snapshot(self.guard.row(V2Offer, V2Offer.operation_id, r.operation_id))
        binding = _snapshot(self.guard.row(V2BindingBirth, V2BindingBirth.binding_id, claims.x25519_binding_id))
        token = _snapshot(self.guard.row(V2TokenBirth, V2TokenBirth.token_id, claims.social_session_token_id))
        accepted = v2.parse_acceptance_v2(a.wire, approval_event_wire=a.approval_wire)
        if (
            a.approval_wire != p.approval.wire
            or accepted.acceptance_id != r.acceptance_id
            or a.acceptance_id != r.acceptance_id
            or i.acceptance_id != r.acceptance_id
            or i.issuance_id != claims.social_session_issuance_id
            or i.revision != claims.social_session_issuance_revision
            or i.token_id != claims.social_session_token_id
            or i.subject != r.subject
            or a.birth_xid != i.birth_xid
            or binding.birth_xid != i.birth_xid
            or token.birth_xid != i.birth_xid
            or parent.token_id != claims.parent_oauth_token_id
            or parent.session_id != claims.parent_oauth_session_id
            or parent.browser_id != claims.parent_oauth_browser_generation_id
            or binding.operation_id != r.operation_id
            or offer.wire != p.approval.envelope.wire
        ):
            _deny()


# Complete static native function bodies; migration synchronization is tested.
NATIVE_FUNCTIONS = {
    "deny_social_enrollment_v2_native_mutation": (
        """
BEGIN
    RAISE EXCEPTION 'social enrollment v2 finalization denied';
END
""",
        None,
        "trigger",
        "search_path=pg_catalog",
    ),
    "execute_social_enrollment_v2_native_effects": (
        """
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
""",
        [
            "reservation",
            "event_bytes",
            "effect_bytes",
            "receipt_bytes",
            "evidence_registration",
            "statement_registration",
            "stage",
        ],
        "void",
        "search_path=pg_catalog, public, pg_temp",
    ),
    "assert_social_enrollment_v2_native_complete": (
        """
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
""",
        ["reservation", "native_root"],
        "void",
        "search_path=pg_catalog",
    ),
    "capture_social_enrollment_v2_native_decision": (
        """
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
""",
        None,
        "trigger",
        "search_path=pg_catalog",
    ),
    "assert_social_enrollment_v2_native_ledger": (
        """
BEGIN
    PERFORM public.assert_social_enrollment_v2_native_complete(NEW.reservation_id,pg_catalog.pg_current_xact_id()::text);
    RETURN NULL;
END
""",
        None,
        "trigger",
        "search_path=pg_catalog",
    ),
    "assert_social_enrollment_atomic_v1": (
        """
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
END """,
        None,
        "trigger",
        "search_path=pg_catalog, public, pg_temp",
    ),
}

ORIGINAL_FUNCTIONS = {
    "guard_social_ed25519_chain_v1": """
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- Raw SQL creation obeys the same absent-row lock as the adapter.
        PERFORM pg_advisory_xact_lock(hashtextextended(NEW.subject || ':' || NEW.device_id, 0));
        IF NEW.state <> 'empty' THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        RETURN NEW;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Only the event trigger may advance the materialized current row.
        IF pg_trigger_depth() <> 2 OR
           ROW(NEW.subject, NEW.device_id) IS DISTINCT FROM ROW(OLD.subject, OLD.device_id) OR
           NEW.authority_epoch <> OLD.authority_epoch + 1 THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'social device ed25519 association storage unavailable';
END """,
    "assert_social_ed25519_chain_initialized_v1": """
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM social_device_ed25519_association_chains
        WHERE subject = NEW.subject AND device_id = NEW.device_id
          AND state <> 'empty' AND authority_epoch >= 1
    ) THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    RETURN NULL;
END """,
    "guard_social_ed25519_event_v1": """
DECLARE
    head social_device_ed25519_association_chains%ROWTYPE;
    creation social_device_ed25519_association_events%ROWTYPE;
    document jsonb;
    enrollment jsonb;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    SELECT * INTO head FROM social_device_ed25519_association_chains
        WHERE subject = NEW.subject AND device_id = NEW.device_id FOR UPDATE;
    IF NOT FOUND OR NEW.authority_epoch <> head.authority_epoch + 1 THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    document := NEW.event_wire::jsonb;
    IF octet_length(NEW.event_wire) NOT BETWEEN 1 AND 4096 OR NEW.event_wire ~ '[^ -~]' OR
       document ->> 'schema' IS DISTINCT FROM 'hodlxxi.social_messaging_device_ed25519_association_event.v1' OR
       document ->> 'version' IS DISTINCT FROM '1' OR
       document ->> 'kind' IS DISTINCT FROM NEW.kind OR
       document ->> 'associationId' IS DISTINCT FROM NEW.association_id OR
       (document ->> 'associationVersion')::bigint IS DISTINCT FROM NEW.association_version OR
       (document ->> 'authorityEpoch')::bigint IS DISTINCT FROM NEW.authority_epoch OR
       document ->> 'predecessorAssociationId' IS DISTINCT FROM NEW.predecessor_association_id THEN
        RAISE EXCEPTION 'social device ed25519 association storage unavailable';
    END IF;
    IF NEW.kind IN ('initial','rotate','reenroll') THEN
        enrollment := (document ->> 'enrollmentWire')::jsonb;
        IF enrollment ->> 'subject' IS DISTINCT FROM NEW.subject OR
           enrollment ->> 'deviceId' IS DISTINCT FROM NEW.device_id OR
           enrollment ->> 'ed25519PublicKey' IS DISTINCT FROM NEW.ed25519_public_key OR
           enrollment ->> 'enrollmentChallengeId' IS DISTINCT FROM NEW.enrollment_challenge_id THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        IF NEW.kind = 'initial' THEN
            IF head.state <> 'empty' OR NEW.association_version <> 1 OR
               NEW.predecessor_association_id IS NOT NULL THEN
                RAISE EXCEPTION 'social device ed25519 association storage unavailable';
            END IF;
        ELSIF NEW.association_version <> head.last_association_version + 1 OR
              NEW.predecessor_association_id IS DISTINCT FROM head.last_association_id OR
              (NEW.kind = 'rotate' AND head.state <> 'active') OR
              (NEW.kind = 'reenroll' AND head.state <> 'revoked') THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
    ELSE
        IF document -> 'enrollmentWire' <> 'null'::jsonb OR head.state <> 'active' OR
           NEW.association_id <> head.current_association_id OR
           NEW.association_version <> head.last_association_version THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
        SELECT * INTO creation FROM social_device_ed25519_association_events
            WHERE subject = NEW.subject AND device_id = NEW.device_id
              AND association_id = NEW.association_id
              AND kind IN ('initial','rotate','reenroll');
        IF NOT FOUND OR NEW.predecessor_association_id IS DISTINCT FROM creation.predecessor_association_id THEN
            RAISE EXCEPTION 'social device ed25519 association storage unavailable';
        END IF;
    END IF;
    RETURN NEW;
END """,
    "advance_social_ed25519_chain_v1": """
BEGIN
    IF NEW.kind IN ('initial','rotate','reenroll') THEN
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch,
            last_association_id = NEW.association_id,
            last_association_version = NEW.association_version,
            current_association_id = NEW.association_id,
            state = 'active'
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    ELSIF NEW.kind = 'revoke' THEN
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch,
            current_association_id = NULL,
            state = 'revoked'
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    ELSE
        UPDATE social_device_ed25519_association_chains SET
            authority_epoch = NEW.authority_epoch
        WHERE subject = NEW.subject AND device_id = NEW.device_id;
    END IF;
    RETURN NULL;
END """,
    "guard_social_enrollment_receipt_v1": """
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
END """,
    "guard_social_device_challenge_v1": """
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
END """,
}


FUNCTION_SQL = """
SELECT pg_catalog.to_jsonb(p) AS function, l.lanname AS language,
       n.nspname AS namespace, pg_catalog.encode(pg_catalog.float4send(p.procost),'hex') AS cost,
       pg_catalog.encode(pg_catalog.float4send(p.prorows),'hex') AS rows,
       pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,
       pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER') AS owns
FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid=p.prolang
WHERE n.nspname='public' AND p.proname=:name
"""


def _attest_function(row, name):
    from app.services.social_session_issuance_v2_storage import FUNCTION_CONFIGS, FUNCTIONS, LEGACY_FUNCTION_HASHES

    if set(row) != {"function", "language", "namespace", "cost", "rows", "executable", "owns"}:
        _deny()
    p = _native_catalog_object(row["function"], "function")
    identity = tuple(p.pop(field) for field in ("oid", "proowner", "pronamespace", "prolang"))
    p.pop("proacl")
    p.pop("procost")
    p.pop("prorows")
    if name in NATIVE_FUNCTIONS:
        source, names, returns, config = NATIVE_FUNCTIONS[name]
        definer = True
    elif name in ORIGINAL_FUNCTIONS:
        source, names, returns, config, definer = ORIGINAL_FUNCTIONS[name], None, "trigger", None, False
    elif name in FUNCTIONS:
        source, names, returns, config, definer = FUNCTIONS[name], None, "trigger", FUNCTION_CONFIGS[name], True
    else:
        digest = CAS_FUNCTION_SOURCE_SHA256 if name == durable.GUARD_FUNCTION else LEGACY_FUNCTION_HASHES[name]
        source = p["prosrc"]
        if type(source) is not str:
            _deny()
        source_digest = hashlib.sha256(source.encode("ascii")).hexdigest()
        if name == durable.GUARD_FUNCTION and source_digest == durable.FRESHNESS_GUARD_SOURCE_SHA256:
            digest = durable.FRESHNESS_GUARD_SOURCE_SHA256
            # Same-OID switches between the two known definitions must change
            # the retained complete native identity. Legacy vectors stay exact.
            identity += (source_digest,)
        if source_digest != digest:
            _deny()
        names, returns, config, definer = (
            None,
            "trigger",
            "search_path=pg_catalog" if name == durable.GUARD_FUNCTION else None,
            False,
        )
    expected = dict(
        proname=name,
        prokind="f",
        prosecdef=definer,
        proleakproof=False,
        proisstrict=False,
        proretset=False,
        provolatile="v",
        proparallel="u",
        pronargs=len(names or ()),
        pronargdefaults=0,
        prorettype=2279 if returns == "trigger" else 2278,
        proargtypes=" ".join("25" for _ in names or ()),
        proallargtypes=None,
        proargmodes=None,
        proargnames=names,
        proargdefaults=None,
        protrftypes=None,
        prosrc=source,
        probin=None,
        prosqlbody=None,
        proconfig=list(config) if type(config) is tuple else [config] if config else None,
        provariadic=0,
        prosupport=0,
    )
    if (
        p != expected
        or row["language"] != "plpgsql"
        or row["namespace"] != "public"
        or row["cost"] != "42c80000"
        or row["rows"] != "00000000"
        or row["owns"] is not False
        or row["executable"] is not (name == WRITE_FUNCTION)
    ):
        _deny()
    return identity


NATIVE_COLUMNS = {
    "social_enrollment_v2_native_associations": (
        ("reservation_id", 1043, 68),
        ("challenge_id", 1043, 68),
        ("subject", 1043, 68),
        ("device_id", 1043, 68),
        ("authority_epoch", 20, -1),
        ("event_wire", 25, -1),
        ("birth_xid", 25, -1),
    ),
    EFFECT_TABLE: (
        ("reservation_id", 1043, 68),
        ("challenge_id", 1043, 68),
        ("subject", 1043, 68),
        ("device_id", 1043, 68),
        ("authority_epoch", 20, -1),
        ("effect_id", 1043, 68),
        ("receipt_id", 1043, 68),
        ("event_wire", 25, -1),
        ("effect_wire", 25, -1),
        ("receipt_wire", 25, -1),
        ("evidence_pin", 25, -1),
        ("statement_pin", 25, -1),
        ("birth_xid", 25, -1),
    ),
    "social_enrollment_v2_native_consumptions": (("reservation_id", 1043, 68), ("birth_xid", 25, -1)),
    DECISION_TABLE: (("reservation_id", 1043, 68), ("birth_xid", 25, -1)),
}


def _metadata():
    """Separate dormant mapping; copying FK targets never creates those tables."""
    from app.services.social_device_ed25519_association_storage import (
        SocialDeviceEd25519AssociationChain,
        SocialDeviceEd25519AssociationEvent,
    )

    metadata = MetaData()
    for model in (
        challenges.SocialDeviceAdmissionChallengeRow,
        SocialDeviceEd25519AssociationChain,
        SocialDeviceEd25519AssociationEvent,
    ):
        model.__table__.to_metadata(metadata, schema="public")
    for name, columns in NATIVE_COLUMNS.items():
        constraints = []
        if name.endswith("associations") or name == EFFECT_TABLE:
            prefix = "na" if name.endswith("associations") else "ne"
            constraints.extend(
                (
                    UniqueConstraint("challenge_id"),
                    ForeignKeyConstraint(
                        ("challenge_id",),
                        ("public.social_device_admission_challenges.challenge_id",),
                        name=prefix + "_challenge_fk",
                    ),
                    ForeignKeyConstraint(
                        ("subject", "device_id", "authority_epoch"),
                        tuple(
                            "public.social_device_ed25519_association_events." + c
                            for c in ("subject", "device_id", "authority_epoch")
                        ),
                        name=prefix + "_event_fk",
                    ),
                )
            )
            if prefix == "ne":
                constraints.extend(
                    (
                        UniqueConstraint("effect_id"),
                        UniqueConstraint("receipt_id"),
                        ForeignKeyConstraint(
                            ("reservation_id",),
                            ("public.social_enrollment_v2_native_associations.reservation_id",),
                            name="ne_reservation_fk",
                        ),
                    )
                )
        else:
            prefix = "nc" if name.endswith("consumptions") else "nd"
            constraints.append(
                ForeignKeyConstraint(
                    ("reservation_id",),
                    ("public.social_enrollment_v2_native_effects.reservation_id",),
                    name=prefix + "_reservation_fk",
                )
            )
            if name == DECISION_TABLE:
                constraints.append(UniqueConstraint("birth_xid"))
        Table(
            name,
            metadata,
            *(
                Column(
                    c,
                    String(64) if typ == 1043 else BigInteger() if typ == 20 else Text(),
                    primary_key=i == 0,
                    nullable=False,
                )
                for i, (c, typ, mod) in enumerate(columns)
            ),
            *constraints,
            schema="public",
        )
    return metadata


NATIVE_METADATA = _metadata()

VISIBLE_AUTHORITIES = (
    (
        "users",
        "current_entitlement_evidence",
        "oauth_tokens",
        "sessions",
        "oauth_clients",
        "oauth_session_generations",
        "oauth_browser_generations",
        "social_messaging_device_bindings",
        "social_session_issuers",
        "social_messaging_mobile_operations",
        "social_messaging_device_authorization_binding_owners",
        "social_device_admission_challenges",
        "social_device_admission_challenge_revisions",
        "social_device_ed25519_association_chains",
        "social_device_ed25519_association_events",
        "social_device_enrollment_admission_receipts",
        durable.TABLE,
    )
    + tuple(
        "social_session_v2_" + s
        for s in ("offers", "parents", "acceptances", "issuances", "invalidations", "binding_births", "token_births")
    )
    + tuple(NATIVE_COLUMNS)
)

VISIBILITY_SQL = """
SELECT c.relname, pg_catalog.to_jsonb(c) AS relation,
       pg_catalog.to_regclass(c.relname)::oid=c.oid AS resolves,
       pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER') AS owns,
       NOT EXISTS(SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid) AS standalone
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='public' AND c.relname=ANY(CAST(:names AS text[])) ORDER BY c.relname
"""


_FRESH_CATALOG_SELECTS = {
    "\nSELECT pg_catalog.to_jsonb(a) AS attribute FROM pg_catalog.pg_attribute a\nWHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum\n": (
        "oid",
        ("attribute",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(a))) AS row_values,a.attnum AS row_order_0 FROM pg_catalog.pg_attribute a\nWHERE a.attrelid=selected.catalog_selector AND a.attnum>0 ORDER BY a.attnum\n) AS catalog_rows",
    ),
    "\nSELECT pg_catalog.to_jsonb(k) AS constraint,\n       pg_catalog.pg_get_constraintdef(k.oid,false) AS definition\nFROM pg_catalog.pg_constraint k WHERE k.conrelid=:oid ORDER BY k.conname\n": (
        "oid",
        ("constraint", "definition"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(k),pg_catalog.pg_get_constraintdef(k.oid,false))) AS row_values,k.conname AS row_order_0 FROM pg_catalog.pg_constraint k WHERE k.conrelid=selected.catalog_selector ORDER BY k.conname\n) AS catalog_rows",
    ),
    "\nSELECT pg_catalog.to_jsonb(i) AS index, pg_catalog.to_jsonb(c) AS relation,\n       pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,\n       pg_catalog.pg_get_expr(i.indpred,i.indrelid,false) AS predicate\nFROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\nWHERE i.indrelid=:oid ORDER BY c.relname\n": (
        "oid",
        ("index", "relation", "definition", "predicate"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(i),pg_catalog.to_jsonb(c),pg_catalog.pg_get_indexdef(i.indexrelid),pg_catalog.pg_get_expr(i.indpred,i.indrelid,false))) AS row_values,c.relname AS row_order_0 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\nWHERE i.indrelid=selected.catalog_selector ORDER BY c.relname\n) AS catalog_rows",
    ),
    "\nSELECT x.grantor::bigint,x.grantee::bigint,x.privilege_type,x.is_grantable,\n       current_user::pg_catalog.regrole::oid::bigint\nFROM pg_catalog.pg_class c CROSS JOIN LATERAL\npg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) x\nWHERE c.oid=:oid ORDER BY x.grantor,x.grantee,x.privilege_type\n": (
        "oid",
        ("grantor", "grantee", "privilege_type", "is_grantable", "?column?"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0,catalog_rows.row_order_1,catalog_rows.row_order_2),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(x.grantor::bigint,x.grantee::bigint,x.privilege_type,x.is_grantable,current_user::pg_catalog.regrole::oid::bigint)) AS row_values,x.grantor AS row_order_0,x.grantee AS row_order_1,x.privilege_type AS row_order_2 FROM pg_catalog.pg_class c CROSS JOIN LATERAL\npg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) x\nWHERE c.oid=selected.catalog_selector ORDER BY x.grantor,x.grantee,x.privilege_type\n) AS catalog_rows",
    ),
    "\nSELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT'),\n pg_catalog.has_table_privilege(current_user,:oid,'INSERT'),\n pg_catalog.has_table_privilege(current_user,:oid,'UPDATE'),\n pg_catalog.has_table_privilege(current_user,:oid,'DELETE'),\n pg_catalog.has_table_privilege(current_user,:oid,'TRUNCATE'),\n pg_catalog.has_table_privilege(current_user,:oid,'REFERENCES'),\n pg_catalog.has_table_privilege(current_user,:oid,'TRIGGER'),\n pg_catalog.has_any_column_privilege(current_user,:oid,'SELECT'),\n pg_catalog.has_any_column_privilege(current_user,:oid,'INSERT'),\n pg_catalog.has_any_column_privilege(current_user,:oid,'UPDATE'),\n pg_catalog.has_any_column_privilege(current_user,:oid,'REFERENCES')\n": (
        "oid",
        (
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
            "?column?",
        ),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'SELECT'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'INSERT'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'UPDATE'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'DELETE'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'TRUNCATE'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'REFERENCES'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'TRIGGER'),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'SELECT'),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'INSERT'),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'UPDATE'),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'REFERENCES'))) AS row_values ) AS catalog_rows",
    ),
    "SELECT count(*) FROM pg_catalog.pg_attrdef WHERE adrelid=:oid": (
        "oid",
        ("?column?",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(count(*))) AS row_values FROM pg_catalog.pg_attrdef WHERE adrelid=selected.catalog_selector) AS catalog_rows",
    ),
    "SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND attacl IS NOT NULL": (
        "oid",
        ("?column?",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(count(*))) AS row_values FROM pg_catalog.pg_attribute WHERE attrelid=selected.catalog_selector AND attacl IS NOT NULL) AS catalog_rows",
    ),
    "SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=:oid": (
        "oid",
        ("?column?",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(count(*))) AS row_values FROM pg_catalog.pg_constraint WHERE conrelid=selected.catalog_selector) AS catalog_rows",
    ),
    "\n        SELECT has_table_privilege(current_user,:oid,'SELECT'),\n          EXISTS(SELECT 1 FROM unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p\n            WHERE has_table_privilege(current_user,:oid,p)),\n          EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0\n            AND (has_column_privilege(current_user,:oid,a.attnum,'INSERT')\n              OR has_column_privilege(current_user,:oid,a.attnum,'UPDATE')\n              OR has_column_privilege(current_user,:oid,a.attnum,'REFERENCES')))\n    ": (
        "oid",
        ("?column?", "?column?", "?column?"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(has_table_privilege(current_user,selected.catalog_selector,'SELECT'),EXISTS(SELECT 1 FROM unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p\n            WHERE has_table_privilege(current_user,selected.catalog_selector,p)),EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=selected.catalog_selector AND a.attnum>0\n            AND (has_column_privilege(current_user,selected.catalog_selector,a.attnum,'INSERT')\n              OR has_column_privilege(current_user,selected.catalog_selector,a.attnum,'UPDATE')\n              OR has_column_privilege(current_user,selected.catalog_selector,a.attnum,'REFERENCES'))))) AS row_values ) AS catalog_rows",
    ),
    "SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT'),\n            pg_catalog.has_table_privilege(current_user,:oid,'INSERT'),\n            pg_catalog.has_table_privilege(current_user,:oid,'UPDATE'),\n            EXISTS(SELECT 1 FROM unnest(ARRAY['DELETE','TRUNCATE','REFERENCES','TRIGGER']) p\n                WHERE pg_catalog.has_table_privilege(current_user,:oid,p)),\n            EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0\n                AND pg_catalog.has_column_privilege(current_user,:oid,a.attnum,'REFERENCES')),\n            pg_catalog.has_any_column_privilege(current_user,:oid,'INSERT'),\n            pg_catalog.has_any_column_privilege(current_user,:oid,'UPDATE')": (
        "oid",
        ("?column?", "?column?", "?column?", "?column?", "?column?", "?column?", "?column?"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'SELECT'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'INSERT'),pg_catalog.has_table_privilege(current_user,selected.catalog_selector,'UPDATE'),EXISTS(SELECT 1 FROM unnest(ARRAY['DELETE','TRUNCATE','REFERENCES','TRIGGER']) p\n                WHERE pg_catalog.has_table_privilege(current_user,selected.catalog_selector,p)),EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=selected.catalog_selector AND a.attnum>0\n                AND pg_catalog.has_column_privilege(current_user,selected.catalog_selector,a.attnum,'REFERENCES')),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'INSERT'),pg_catalog.has_any_column_privilege(current_user,selected.catalog_selector,'UPDATE'))) AS row_values ) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(t) AS trigger\n        FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname": (
        "oid",
        ("trigger",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(t))) AS row_values,t.tgname AS row_order_0 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=selected.catalog_selector AND NOT t.tgisinternal ORDER BY t.tgname) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(k) AS constraint,\n        pg_catalog.pg_get_constraintdef(k.oid,false) AS definition\n        FROM pg_catalog.pg_constraint k WHERE k.conrelid=:oid ORDER BY k.conname": (
        "oid",
        ("constraint", "definition"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(k),pg_catalog.pg_get_constraintdef(k.oid,false))) AS row_values,k.conname AS row_order_0 FROM pg_catalog.pg_constraint k WHERE k.conrelid=selected.catalog_selector ORDER BY k.conname) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(i) AS index,\n        pg_catalog.to_jsonb(c) AS relation, pg_catalog.pg_get_indexdef(i.indexrelid) AS definition\n        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\n        WHERE i.indrelid=:oid ORDER BY c.relname": (
        "oid",
        ("index", "relation", "definition"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(i),pg_catalog.to_jsonb(c),pg_catalog.pg_get_indexdef(i.indexrelid))) AS row_values,c.relname AS row_order_0 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid\n        WHERE i.indrelid=selected.catalog_selector ORDER BY c.relname) AS catalog_rows",
    ),
    "SELECT conindid::bigint FROM pg_catalog.pg_constraint\n                WHERE conrelid=:oid AND contype='p'": (
        "oid",
        ("conindid",),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(conindid::bigint)) AS row_values FROM pg_catalog.pg_constraint\n                WHERE conrelid=selected.catalog_selector AND contype='p') AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(t) AS trigger,\n        pg_catalog.pg_get_triggerdef(t.oid,false) AS definition\n        FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname": (
        "oid",
        ("trigger", "definition"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(t),pg_catalog.pg_get_triggerdef(t.oid,false))) AS row_values,t.tgname AS row_order_0 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=selected.catalog_selector AND NOT t.tgisinternal ORDER BY t.tgname) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(t) AS trigger,\n      pg_catalog.pg_get_triggerdef(t.oid,false) AS definition\n      FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname": (
        "oid",
        ("trigger", "definition"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(t),pg_catalog.pg_get_triggerdef(t.oid,false))) AS row_values,t.tgname AS row_order_0 FROM pg_catalog.pg_trigger t WHERE t.tgrelid=selected.catalog_selector AND NOT t.tgisinternal ORDER BY t.tgname) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(t) AS trigger,\n            pg_catalog.pg_get_triggerdef(t.oid,false) AS definition,\n            (SELECT conname FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint) AS constraint_name,\n            p.proname,n.nspname\n            FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid\n            JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname": (
        "oid",
        ("trigger", "definition", "constraint_name", "proname", "nspname"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values ORDER BY catalog_rows.row_order_0),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(t),pg_catalog.pg_get_triggerdef(t.oid,false),(SELECT conname FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint),p.proname,n.nspname)) AS row_values,t.tgname AS row_order_0 FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid\n            JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\n            WHERE t.tgrelid=selected.catalog_selector AND NOT t.tgisinternal ORDER BY t.tgname) AS catalog_rows",
    ),
    "SELECT pg_catalog.to_jsonb(c) AS relation,n.nspname\n            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=:oid": (
        "oid",
        ("relation", "nspname"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(c),n.nspname)) AS row_values FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=selected.catalog_selector) AS catalog_rows",
    ),
    "\nSELECT pg_catalog.to_jsonb(p) AS function, l.lanname AS language,\n       n.nspname AS namespace, pg_catalog.encode(pg_catalog.float4send(p.procost),'hex') AS cost,\n       pg_catalog.encode(pg_catalog.float4send(p.prorows),'hex') AS rows,\n       pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE') AS executable,\n       pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER') AS owns\nFROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\nJOIN pg_catalog.pg_language l ON l.oid=p.prolang\nWHERE n.nspname='public' AND p.proname=:name\n": (
        "name",
        ("function", "language", "namespace", "cost", "rows", "executable", "owns"),
        "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(p),l.lanname,n.nspname,pg_catalog.encode(pg_catalog.float4send(p.procost),'hex'),pg_catalog.encode(pg_catalog.float4send(p.prorows),'hex'),pg_catalog.has_function_privilege(current_user,p.oid,'EXECUTE'),pg_catalog.pg_has_role(current_user,p.proowner,'MEMBER'))) AS row_values FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace\nJOIN pg_catalog.pg_language l ON l.oid=p.prolang\nWHERE n.nspname='public' AND p.proname=selected.catalog_selector\n) AS catalog_rows",
    ),
}


def _fresh_catalog_chain(connection):
    """Object continuity only; caller's existing XID/role guards still run."""
    root = getattr(connection, "get_transaction", None)
    nested = getattr(connection, "get_nested_transaction", None)
    if not callable(root) or not callable(nested):
        return (connection,)
    if connection.closed or connection.invalidated:
        _deny()
    return (connection, root(), nested(), connection.connection.dbapi_connection)


class _FreshCatalogObject(tuple):
    __slots__ = ()


class _FreshCatalogArray(tuple):
    __slots__ = ()


_FRESH_SCALAR_TYPES = (type(None), bool, int, float, str)


def _fresh_freeze(value, depth=0):
    """Own every JSON container once; preserve scalar types without coercion."""
    if depth > 64:
        _deny()
    if type(value) in _FRESH_SCALAR_TYPES:
        return value
    # JSON used to strip scalar subclass attributes (for example a model's
    # quoted_name). Own the same base scalar, without invoking custom casts.
    if isinstance(value, str):
        return str.__str__(value)
    if isinstance(value, int):
        return int.__int__(value)
    if isinstance(value, float):
        return float.__float__(value)
    if type(value) is dict:
        if any(not isinstance(key, str) for key in value):
            _deny()
        # Even a scalar child at depth 65 must deny, as on the recursive path.
        if depth == 64 and value:
            _deny()
        cells = []
        for key in sorted(value):
            cell = value[key]
            cells.append(
                (str.__str__(key), cell if type(cell) in _FRESH_SCALAR_TYPES else _fresh_freeze(cell, depth + 1))
            )
        return _FreshCatalogObject(cells)
    if type(value) in (list, tuple):
        if depth == 64 and value:
            _deny()
        return _FreshCatalogArray(
            [cell if type(cell) in _FRESH_SCALAR_TYPES else _fresh_freeze(cell, depth + 1) for cell in value]
        )
    _deny()


def _fresh_thaw(value):
    if type(value) is _FreshCatalogObject:
        return {key: cell if type(cell) in _FRESH_SCALAR_TYPES else _fresh_thaw(cell) for key, cell in value}
    if type(value) is _FreshCatalogArray:
        return [cell if type(cell) in _FRESH_SCALAR_TYPES else _fresh_thaw(cell) for cell in value]
    return value


def _fresh_grouped_catalog_query(descriptor):
    """Lift only fixed row-producing catalog scans into one grouped scan.

    Projection and aggregate ordering come verbatim from the fixed carrier.
    Scalar privileges/counts and function-name families keep their own plans.
    This is not a parser for caller SQL: only closed descriptors reach here.
    """
    kind, columns, query = descriptor
    if kind != "oid" or columns[0] not in ("attribute", "constraint", "index", "grantor", "trigger", "relation"):
        return None
    match = re.search(
        r"WHERE (a\.attrelid|k\.conrelid|i\.indrelid|t\.tgrelid|c\.oid)=selected\.catalog_selector", query
    )
    if match is None:
        return None
    key = match[1]
    prefix, separator, inner = query.partition(" AS catalog_rows FROM (")
    if not separator or not inner.endswith(") AS catalog_rows") or query.count("selected.catalog_selector") != 1:
        _deny()
    aggregate = prefix.removeprefix("SELECT COALESCE(").removesuffix(",'[]'::json)")
    inner = inner.removesuffix(") AS catalog_rows").rstrip()
    if " ORDER BY " in inner:
        inner = inner.rsplit(" ORDER BY ", 1)[0]
    inner = "SELECT " + key + " AS catalog_selector," + inner.removeprefix("SELECT ")
    inner = inner.replace(key + "=selected.catalog_selector", key + "=ANY(CAST(:fresh_catalog_selectors AS oid[]))")
    return (
        "WITH captured AS MATERIALIZED (SELECT catalog_rows.catalog_selector,"
        + aggregate
        + " AS catalog_rows FROM ("
        + inner
        + ") AS catalog_rows GROUP BY catalog_rows.catalog_selector) "
        "SELECT selected.catalog_selector,COALESCE(captured.catalog_rows,'[]'::jsonb::json) "
        "FROM pg_catalog.unnest(CAST(:fresh_catalog_selectors AS oid[])) AS selected(catalog_selector) "
        "LEFT JOIN captured ON captured.catalog_selector=selected.catalog_selector ORDER BY selected.catalog_selector"
    )


def _fresh_catalog_statement_text(statement):
    # Exact TextClause only. Subclasses/custom statements may have different
    # compilation semantics and must use the live, unmodified fallback.
    return statement.text if type(statement) is TextClause else None


class _FreshCatalogRows:
    def __init__(self, rows, columns, *, mappings=False):
        fields = {"f" + str(i) for i in range(1, len(columns) + 1)}
        if type(rows) is not list or len(rows) > 4096:
            _deny()
        if any(type(row) is not dict or set(row) != fields for row in rows):
            _deny()
        self._values = tuple(
            tuple(_fresh_freeze(row["f" + str(i)]) for i in range(1, len(columns) + 1)) for row in rows
        )
        self._columns = tuple(columns)
        self._mappings = mappings

    def mappings(self):
        if len(set(self._columns)) != len(self._columns):
            _deny()
        result = object.__new__(_FreshCatalogRows)
        result._values = self._values
        result._columns = self._columns
        result._mappings = True
        return result

    def all(self):
        values = [tuple(_fresh_thaw(cell) for cell in row) for row in self._values]
        if self._mappings:
            return [dict(zip(self._columns, row)) for row in values]
        return values

    def one(self):
        rows = self.all()
        if len(rows) != 1:
            _deny()
        return rows[0]

    def scalar_one(self):
        row = self.one()
        if len(row) != 1 or self._mappings:
            _deny()
        return row[0]


def _completion_named_catalog_selects():
    """Closed compound-selector families; only their transport drops the name filter."""
    result = {}
    for source, descriptor in _FRESH_CATALOG_SELECTS.items():
        if descriptor[1] == ("constraint", "definition"):
            named = source.replace("WHERE k.conrelid=:oid", "WHERE k.conrelid=:oid AND k.conname=:name")
            result[named] = (descriptor, "oid", "constraint", "conname")
        elif descriptor[1] == ("index", "relation", "definition", "predicate"):
            named = source.replace("WHERE i.indrelid=:oid", "WHERE i.indrelid=:oid AND c.relname=:name")
            result[named] = (descriptor, "oid", "relation", "relname")
    source = "SELECT pg_catalog.to_jsonb(k) AS constraint\n            FROM pg_catalog.pg_constraint k WHERE k.conrelid=:child AND k.conname=:name AND k.contype='f'"
    query = "SELECT COALESCE(pg_catalog.json_agg(catalog_rows.row_values),'[]'::json) AS catalog_rows FROM (SELECT pg_catalog.row_to_json(ROW(pg_catalog.to_jsonb(k))) AS row_values FROM pg_catalog.pg_constraint k WHERE k.conrelid=selected.catalog_selector AND k.contype='f') AS catalog_rows"
    result[source] = (("oid", ("constraint",), query), "child", "constraint", "conname")
    return result


_completion_named_selects = _completion_named_catalog_selects()


class _FreshCatalogObservation:
    """One attestation only; identical later accesses execute a fresh SELECT."""

    def __init__(self, connection):
        from app.services.social_enrollment_v2_catalog_roles import attest_catalog_role, catalog_pin_for
        from app.services.social_session_issuance_v2_storage import FUNCTIONS, LEGACY_FUNCTION_HASHES

        self.connection = connection
        self._chain = _fresh_catalog_chain(connection)
        self._catalog_role_pin = catalog_pin_for(connection)
        self._catalog_role_identity = attest_catalog_role(connection, self._catalog_role_pin, sql=text)
        self._names = sorted(
            NATIVE_FUNCTIONS.keys()
            | ORIGINAL_FUNCTIONS.keys()
            | FUNCTIONS.keys()
            | LEGACY_FUNCTION_HASHES.keys()
            | {durable.GUARD_FUNCTION}
        )
        self._oids = ()
        self._fetched = set()
        self._rows = {}
        self._first = True
        self._completion_named_used = set()

    def _check(self):
        from app.services.social_enrollment_v2_catalog_roles import catalog_pin_for

        if catalog_pin_for(self.connection) != self._catalog_role_pin:
            _deny()
        if _fresh_catalog_chain(self.connection) != self._chain:
            _deny()

    def _live(self, statement, parameters):
        self._check()
        before = self._chain
        result = self.connection.execute(statement, parameters)
        after = _fresh_catalog_chain(self.connection)
        # A read-only standalone Connection may autobegin on its first SELECT.
        if self._first and len(before) == 4 and before[1] is None:
            if after[0] is not before[0] or after[1] is None or after[2:] != before[2:]:
                _deny()
            self._chain = after
        elif after != before:
            _deny()
        self._first = False
        return result

    def _fetch(self, source, descriptor, selectors):
        kind, columns, query = descriptor
        if not 1 <= len(selectors) <= 96 or len(set(selectors)) != len(selectors):
            _deny()
        sql = _fresh_grouped_catalog_query(descriptor)
        if sql is None:
            sql = (
                "SELECT selected.catalog_selector,captured.catalog_rows "
                "FROM pg_catalog.unnest(CAST(:fresh_catalog_selectors AS "
                + ("oid[]" if kind == "oid" else "text[]")
                + ")) AS selected(catalog_selector) CROSS JOIN LATERAL ("
                + query
                + ") AS captured ORDER BY selected.catalog_selector"
            )
        sql += (
            " /* UBID_FRESH_FINALIZATION_CATALOG */ /* UBID_FRESH_SELECTOR_"
            + hashlib.sha256(source.encode()).hexdigest()
            + " */"
        )
        observed = self._live(text(sql), {"fresh_catalog_selectors": list(selectors)}).all()
        if len(observed) != len(selectors):
            _deny()
        seen = set()
        for row in observed:
            if len(row) != 2 or type(row[0]) is not (int if kind == "oid" else str):
                _deny()
            selector, values = row
            if selector not in selectors or selector in seen:
                _deny()
            seen.add(selector)
            self._rows[(source, selector)] = _FreshCatalogRows(values, columns)
        if seen != set(selectors):
            _deny()
        self._fetched.add(source)

    def _completion_named(self, source, parameters):
        family = _completion_named_selects.get(source)
        if family is None:
            return None
        descriptor, bind, column, field = family
        if (
            set(parameters) != {bind, "name"}
            or type(parameters[bind]) is not int
            or type(parameters["name"]) is not str
        ):
            return None
        selector, name = parameters[bind], parameters["name"]
        key = (source, selector, name)
        if selector not in self._oids or key in self._completion_named_used:
            return None
        if source not in self._fetched:
            self._fetch(source, descriptor, self._oids)
        elif (source, selector) not in self._rows:
            self._fetch(source, descriptor, tuple(oid for oid in self._oids if (source, oid) not in self._rows))
        self._check()
        captured = self._rows[(source, selector)].mappings().all()
        selected = []
        for row in captured:
            value = row[column]
            if type(value) is not dict:
                _deny()
            if value.get(field) == name:
                selected.append({"f" + str(i): row[c] for i, c in enumerate(descriptor[1], 1)})
        self._completion_named_used.add(key)
        return _FreshCatalogRows(selected, descriptor[1])

    def execute(self, statement, parameters=None):
        self._check()
        source = _fresh_catalog_statement_text(statement)
        parameters = parameters or {}
        named = self._completion_named(source, parameters)
        if named is not None:
            self._check()
            return named
        descriptor = _FRESH_CATALOG_SELECTS.get(source)
        if descriptor is not None and set(parameters) == {descriptor[0]}:
            kind = descriptor[0]
            selector = parameters[kind]
            selectors = self._oids if kind == "oid" else self._names
            if type(selector) is (int if kind == "oid" else str) and selector in selectors:
                if source not in self._fetched:
                    self._fetch(source, descriptor, selectors)
                self._check()
                # Consume once. Repeated logical reads retain their original
                # fresh-query semantics, including later constraint comparisons.
                result = self._rows.pop((source, selector), None)
                if result is not None:
                    return result
        result = self._live(statement, parameters)
        if (source == VISIBILITY_SQL and parameters == {"names": list(VISIBLE_AUTHORITIES)}) or (
            source == VISIBILITY_SQL and parameters == {"names": sorted(EXTERNAL_BINDING_COLUMNS)}
        ):
            rows = result.mappings().all()
            oids = set()
            for row in rows:
                if set(row) != {"relname", "relation", "resolves", "owns", "standalone"}:
                    _deny()
                relation = _native_catalog_object(row["relation"], "relation")
                for oid in (relation["oid"], relation["reltoastrelid"]):
                    if type(oid) is not int or oid < 0:
                        _deny()
                    if oid:
                        oids.add(oid)
            self._oids = tuple(sorted(set(self._oids) | oids))
            # Retain only an immutable, separately owned copy for this one
            # consumed result; no catalog state survives the attestation.
            values = [
                {
                    "f" + str(i): row[c]
                    for i, c in enumerate(("relname", "relation", "resolves", "owns", "standalone"), 1)
                }
                for row in rows
            ]
            result = _FreshCatalogRows(values, ("relname", "relation", "resolves", "owns", "standalone"))
        self._check()
        return result


@_sanitized
def attest_native_schema(connection):
    """Fresh bounded transport; the original complete validator runs unchanged."""
    observation = _FreshCatalogObservation(connection)
    identity = _attest_native_schema(observation)
    observation._check()
    return identity


@_sanitized
@_sanitized
def _attest_native_schema(connection):
    """Reobserve definitions; cache only the returned immutable identity tuple."""
    from app.services.social_session_issuance_v2_storage import (
        FUNCTIONS,
        LEGACY_FUNCTION_HASHES,
        _runtime_role_identity,
    )

    schemas = connection.execute(text("SELECT pg_catalog.current_schemas(true)")).scalar_one()
    if type(schemas) not in (list, tuple) or tuple(schemas) != ("pg_catalog", "public"):
        _deny()

    class CatalogPort:
        def sql(self, sql, values=None):
            return connection.execute(text(sql), values or {})

    role = _runtime_role_identity(CatalogPort())
    if role[4] != ("pg_read_all_settings",):
        _deny()
    secure = connection.execute(text("""
        SELECT current_user=session_user AND current_setting('session_replication_role')='origin'
          AND current_setting('transaction_isolation')='read committed'
          AND current_setting('server_version_num')::integer BETWEEN 160000 AND 169999
          AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n
            WHERE n.nspname !~ '^pg_temp_' AND has_schema_privilege(current_user,n.oid,'CREATE')),
          n.oid,n.nspowner
        FROM pg_catalog.pg_namespace n WHERE n.nspname='public'
    """)).one()
    if len(secure) != 3 or secure[0] is not True or any(type(v) is not int or v <= 0 for v in secure[1:]):
        _deny()
    identities = [role, tuple(secure[1:]), _attest_pg16_system_definitions(connection)]
    peer_identity = getattr(connection, "_catalog_role_identity", None)
    if peer_identity is not None:
        identities.append(("challenge_writer_role", peer_identity))
    membership = connection.execute(text("""SELECT m.roleid::bigint,m.member::bigint,m.grantor::bigint,
        m.admin_option,m.inherit_option,m.set_option FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles r ON r.oid=m.member WHERE r.rolname=current_user""")).all()
    if (
        len(membership) != 1
        or len(membership[0]) != 6
        or any(type(v) is not int or v <= 0 for v in membership[0][:3])
        or any(type(v) is not bool for v in membership[0][3:])
        or tuple(membership[0][:2]) != (role[5][0], role[0])
        or tuple(membership[0][3:]) != (False, True, True)
    ):
        _deny()
    identities.append(tuple(membership[0]))
    functions = {}
    for name in sorted(
        NATIVE_FUNCTIONS.keys()
        | ORIGINAL_FUNCTIONS.keys()
        | FUNCTIONS.keys()
        | LEGACY_FUNCTION_HASHES.keys()
        | {durable.GUARD_FUNCTION}
    ):
        rows = connection.execute(text(FUNCTION_SQL), {"name": name}).mappings().all()
        if len(rows) != 1:
            _deny()
        identity = _attest_function(rows[0], name)
        if identity[0] in functions.values():
            _deny()
        functions[name] = identity[0]
        identities.append((name, identity))
    rows = connection.execute(text(VISIBILITY_SQL), {"names": list(VISIBLE_AUTHORITIES)}).mappings().all()
    if len(rows) != len(VISIBLE_AUTHORITIES):
        _deny()
    by_name = {}
    for row in rows:
        if set(row) != {"relname", "relation", "resolves", "owns", "standalone"}:
            _deny()
        r = _native_catalog_object(row["relation"], "relation")
        _attest_shared_physical_types(r)
        if (
            r["relname"] != row["relname"]
            or row["resolves"] is not True
            or row["owns"] is not False
            or row["standalone"] is not True
            or r["relkind"] != "r"
            or r["relpersistence"] != "p"
            or r["relrowsecurity"]
            or r["relforcerowsecurity"]
            or r["relhasrules"]
            or r["relhassubclass"]
            or r["relispartition"]
            or r["reloftype"] != 0
            or r["relpartbound"] is not None
            or r["reloptions"] is not None
            or r["relrewrite"] != "0"
        ):
            _deny()
        if (
            r["relname"] in by_name
            or r["relnamespace"] != secure[1]
            or r["reltype"] == 0
            or any(existing["oid"] == r["oid"] for existing in by_name.values())
            or any(existing["reltype"] == r["reltype"] for existing in by_name.values())
        ):
            _deny()
        identities.append((r["oid"], r["reltype"], r["relowner"], r["reltoastrelid"]))
        by_name[r["relname"]] = r
    if set(by_name) != set(VISIBLE_AUTHORITIES):
        _deny()
    dependency_pins, dependency_constraints = _attest_dependency_definitions(connection, by_name, functions)
    identities.extend(dependency_pins)
    revision_pins, revision_indexes, constraint_pins = _attest_original_revision_definitions(connection, by_name)
    identities.extend(revision_pins)
    shared_pins, shared_constraints = _attest_shared_relations(connection, by_name, revision_indexes)
    identities.extend(shared_pins)
    constraint_pins.update(shared_constraints)
    constraint_pins.update(dependency_constraints)
    key_bindings = {
        (name, tuple(c["conkey"])): (c["oid"], c["conindid"])
        for (name, _), c in constraint_pins.items()
        if c["contype"] in ("p", "u")
    }
    for name, columns in NATIVE_COLUMNS.items():
        r = by_name[name]
        identities.extend(
            _attest_native_table(connection, r, columns, functions, by_name, key_bindings, constraint_pins)
        )
    identities.extend(_attest_shared_triggers(connection, by_name, functions, constraint_pins))
    identities.extend(_attest_internal_triggers(connection, by_name, constraint_pins))
    identities.append(_attest_history_privileges(connection, by_name))
    return tuple(identities)


def _attest_native_table(connection, relation, columns, functions, relations, key_bindings, constraint_pins):
    """Closed new relations; native physical/maintenance fields are excluded."""
    oid = relation["oid"]
    if relation["relnatts"] != len(columns) or relation["relchecks"] != 0 or not relation["relhasindex"]:
        _deny()
    privileges = connection.execute(
        text("""
        SELECT has_table_privilege(current_user,:oid,'SELECT'),
          EXISTS(SELECT 1 FROM unnest(ARRAY['INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
            WHERE has_table_privilege(current_user,:oid,p)),
          EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0
            AND (has_column_privilege(current_user,:oid,a.attnum,'INSERT')
              OR has_column_privilege(current_user,:oid,a.attnum,'UPDATE')
              OR has_column_privilege(current_user,:oid,a.attnum,'REFERENCES')))
    """),
        {"oid": oid},
    ).one()
    if (
        len(privileges) != 3
        or any(type(v) is not bool for v in privileges)
        or tuple(privileges) != (True, False, False)
    ):
        _deny()
    acl_identity = _attest_shared_acl(connection, relation, profiles=(("SELECT",),))
    _attest_shared_attributes(connection, relation, tuple((*column, True) for column in columns))
    triggers = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(t) AS trigger
        FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname"""),
            {"oid": oid},
        )
        .mappings()
        .all()
    )
    constraints = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(k) AS constraint,
        pg_catalog.pg_get_constraintdef(k.oid,false) AS definition
        FROM pg_catalog.pg_constraint k WHERE k.conrelid=:oid ORDER BY k.conname"""),
            {"oid": oid},
        )
        .mappings()
        .all()
    )
    by_constraint = {row["constraint"]["conname"]: row for row in constraints}
    if len(triggers) != 3:
        _deny()
    identities = [acl_identity]
    _attest_shared_zero_count(connection, "SELECT count(*) FROM pg_catalog.pg_attrdef WHERE adrelid=:oid", oid)
    identities.extend(_attest_relation_definition(connection, relation, column_count=len(columns), checks=0))
    for row in triggers:
        if set(row) != {"trigger"}:
            _deny()
        t = _native_catalog_object(row["trigger"], "trigger")
        trigger_oid = t.pop("oid")
        name = t["tgname"]
        fn, kind, deferred = {
            "v2_native_immutable": ("deny_social_enrollment_v2_native_mutation", 27, False),
            "v2_native_no_truncate": ("deny_social_enrollment_v2_native_mutation", 34, False),
            "v2_native_complete": ("assert_social_enrollment_v2_native_ledger", 5, True),
        }[name]
        constraint = by_constraint[name]["constraint"]["oid"] if deferred else 0
        constraint = int(constraint)
        expected = dict(
            tgrelid=oid,
            tgparentid=0,
            tgname=name,
            tgfoid=functions[fn],
            tgtype=kind,
            tgenabled="O",
            tgisinternal=False,
            tgconstrrelid=0,
            tgconstrindid=0,
            tgconstraint=constraint,
            tgdeferrable=deferred,
            tginitdeferred=deferred,
            tgnargs=0,
            tgattr="",
            tgargs="\\x",
            tgqual=None,
            tgoldtable=None,
            tgnewtable=None,
        )
        if t != expected:
            _deny()
        identities.append((trigger_oid, t["tgfoid"], constraint))
    # Every PK/UNIQUE/FK/constraint-trigger must match its source specification.
    # Unknown fields, constraints or indexes fail before a native effect.
    identities.extend(
        _attest_native_constraints(connection, relation, constraints, columns, relations, key_bindings, constraint_pins)
    )
    return identities


def _attest_native_constraints(connection, relation, rows, columns, relations, key_bindings, constraint_pins):
    name, oid = relation["relname"], relation["oid"]
    primary = name + "_pkey"
    expected = {primary: ("p", [1], None, None), "v2_native_complete": ("t", None, None, None)}
    if name.endswith("associations") or name == EFFECT_TABLE:
        prefix = "na" if name.endswith("associations") else "ne"
        expected.update(
            {
                prefix + "_challenge_fk": ("f", [2], challenges.TABLE, [1]),
                prefix + "_event_fk": ("f", [3, 4, 5], "social_device_ed25519_association_events", [1, 2, 3]),
                name + "_challenge_id_key": ("u", [2], None, None),
            }
        )
        if prefix == "ne":
            expected["ne_reservation_fk"] = ("f", [1], "social_enrollment_v2_native_associations", [1])
            expected[name + "_effect_id_key"] = ("u", [6], None, None)
            expected[name + "_receipt_id_key"] = ("u", [7], None, None)
    else:
        prefix = "nc" if name.endswith("consumptions") else "nd"
        expected[prefix + "_reservation_fk"] = ("f", [1], EFFECT_TABLE, [1])
        if name == DECISION_TABLE:
            expected[name + "_birth_xid_key"] = ("u", [2], None, None)
    if len(rows) != len(expected) or {r["constraint"]["conname"] for r in rows} != set(expected):
        _deny()
    indexes = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(i) AS index,
        pg_catalog.to_jsonb(c) AS relation, pg_catalog.pg_get_indexdef(i.indexrelid) AS definition
        FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
        WHERE i.indrelid=:oid ORDER BY c.relname"""),
            {"oid": oid},
        )
        .mappings()
        .all()
    )
    indexed = {n: spec for n, spec in expected.items() if spec[0] in ("p", "u")}
    if len(indexes) != len(indexed):
        _deny()
    index_ids = {}
    identities = []
    for row in indexes:
        if set(row) != {"index", "relation", "definition"}:
            _deny()
        ir = _native_catalog_object(row["relation"], "relation")
        n = ir["relname"]
        if n not in indexed or n in index_ids or ir["oid"] in index_ids.values():
            _deny()
        kind, keys, _, _ = indexed[n]
        i = _native_catalog_object(row["index"], "index")
        if set(row) != {"index", "relation", "definition"}:
            _deny()
        i.pop("indisclustered")
        key = keys[0]
        wanted = dict(
            indexrelid=ir["oid"],
            indrelid=oid,
            indnatts=1,
            indnkeyatts=1,
            indisunique=kind != "n",
            indnullsnotdistinct=False,
            indisprimary=kind == "p" or relation["relkind"] == "t",
            indisexclusion=False,
            indimmediate=True,
            indisvalid=True,
            indcheckxmin=False,
            indisready=True,
            indislive=True,
            indisreplident=False,
            indkey=str(key),
            indcollation="100",
            indclass="3126",
            indoption="0",
            indexprs=None,
            indpred=None,
        )
        definition = f"CREATE UNIQUE INDEX {n} ON public.{name} USING btree ({columns[key-1][0]})"
        if (
            i != wanted
            or row["definition"] != definition
            or ir["relowner"] != relation["relowner"]
            or ir["relnamespace"] != relation["relnamespace"]
            or ir["relkind"] != "i"
            or ir["relam"] != 403
        ):
            _deny()
        index_ids[n] = ir["oid"]
        identities.append(_attest_shared_index_relation(ir, relation, n, len(keys)))
    for row in rows:
        if set(row) != {"constraint", "definition"}:
            _deny()
        c = _native_catalog_object(row["constraint"], "constraint")
        constraint_oid = c.pop("oid")
        n = c["conname"]
        kind, keys, target, target_keys = expected[n]
        target_oid = relations[target]["oid"] if target else 0
        target_index = 0
        if target:
            binding = key_bindings.get((target, tuple(target_keys)))
            if binding is None:
                _deny()
            target_index = connection.execute(
                text("""SELECT conindid::bigint FROM pg_catalog.pg_constraint
                WHERE conrelid=:oid AND contype='p'"""),
                {"oid": target_oid},
            ).scalar_one()
            if type(target_index) is not int or target_index != binding[1]:
                _deny()
        expected_catalog = dict(
            conname=n,
            connamespace=relation["relnamespace"],
            contype=kind,
            condeferrable=kind == "t",
            condeferred=kind == "t",
            convalidated=True,
            conrelid=oid,
            contypid=0,
            conindid=index_ids[n] if kind in ("p", "u") else target_index,
            conparentid=0,
            confrelid=target_oid,
            confupdtype="a" if target else " ",
            confdeltype="a" if target else " ",
            confmatchtype="s" if target else " ",
            conislocal=True,
            coninhcount=0,
            connoinherit=True,
            conkey=keys,
            confkey=target_keys,
            conpfeqop=[98, 98, 410] if target and len(keys) == 3 else [98] if target else None,
            conppeqop=[98, 98, 410] if target and len(keys) == 3 else [98] if target else None,
            conffeqop=[98, 98, 410] if target and len(keys) == 3 else [98] if target else None,
            confdelsetcols=None,
            conexclop=None,
            conbin=None,
        )
        if c != expected_catalog:
            _deny()
        if kind == "t":
            definition = "TRIGGER DEFERRABLE INITIALLY DEFERRED"
        elif kind in ("p", "u"):
            definition = ("PRIMARY KEY" if kind == "p" else "UNIQUE") + " (" + columns[keys[0] - 1][0] + ")"
        else:
            source_keys = ", ".join(columns[k - 1][0] for k in keys)
            target_columns = (
                "subject, device_id, authority_epoch"
                if len(keys) == 3
                else "challenge_id" if target == challenges.TABLE else "reservation_id"
            )
            definition = f"FOREIGN KEY ({source_keys}) REFERENCES {target}({target_columns})"
        if row["definition"] not in (definition, definition.replace("REFERENCES ", "REFERENCES public.")):
            _deny()
        identities.append((constraint_oid, target_oid, target_index))
    for row in rows:
        c = _native_catalog_object(row["constraint"], "constraint")
        if any(c["oid"] == pin["oid"] for pin in constraint_pins.values()):
            _deny()
        constraint_pins[(name, c["conname"])] = dict(c)
        if c["contype"] in ("p", "u"):
            key_bindings[(name, tuple(c["conkey"]))] = (c["oid"], c["conindid"])
    return identities


@_sanitized
def validate_cas_profile(connection, rows, *, full_schema=True):
    """Fresh CAS trigger profile; the full graph is required at acceptance."""
    if type(full_schema) is not bool:
        _deny()
    if (
        len(rows) != 3
        or any(set(row) != CAS_CATALOG_FIELDS for row in rows)
        or {row["trigger_name"] for row in rows}
        != {durable.GUARD_TRIGGER, durable.NO_TRUNCATE_TRIGGER, DECISION_TRIGGER}
    ):
        _deny()
    row = next(row for row in rows if row["trigger_name"] == DECISION_TRIGGER)
    fn = connection.execute(text(FUNCTION_SQL), {"name": DECISION_FUNCTION}).mappings().all()
    if len(fn) != 1:
        _deny()
    identity = _attest_function(fn[0], DECISION_FUNCTION)
    expected = dict(
        trigger_function_oid=identity[0],
        trigger_type=17,
        trigger_enabled="O",
        trigger_argument_count=0,
        trigger_arguments_hex="",
        trigger_attributes="",
        trigger_internal=False,
        trigger_constraint_oid=0,
        trigger_constraint_relation_oid=0,
        trigger_constraint_index_oid=0,
        trigger_deferrable=False,
        trigger_initially_deferred=False,
        trigger_qualification=None,
        trigger_old_table=None,
        trigger_new_table=None,
        trigger_parent_oid=0,
    )
    if any(row[key] != value for key, value in expected.items()):
        _deny()
    return (row["trigger_oid"], identity, attest_native_schema(connection) if full_schema else None)


SHARED_TRIGGERS = {
    "social_device_ed25519_association_chains": {
        "trg_social_ed25519_chain_guard": ("guard_social_ed25519_chain_v1", 31, False, None),
        "trg_social_ed25519_chain_truncate": ("guard_social_ed25519_chain_v1", 34, False, None),
        "trg_social_ed25519_chain_initialized": ("assert_social_ed25519_chain_initialized_v1", 5, True, None),
    },
    "social_device_ed25519_association_events": {
        "trg_social_ed25519_event_guard": ("guard_social_ed25519_event_v1", 31, False, None),
        "trg_social_ed25519_event_truncate": ("guard_social_ed25519_event_v1", 34, False, None),
        "trg_social_ed25519_event_advance": ("advance_social_ed25519_chain_v1", 5, False, None),
        "trg_social_enrollment_event_atomic": (
            "assert_social_enrollment_atomic_v1",
            5,
            True,
            "((new.kind)::text = ANY ((ARRAY['initial'::character varying, 'rotate'::character varying, 'reenroll'::character varying])::text[]))",
        ),
    },
    challenges.TABLE: {
        "trg_social_challenge_guard": ("guard_social_device_challenge_v1", 31, False, None),
        "trg_social_challenge_no_truncate": ("guard_social_device_challenge_v1", 34, False, None),
        "trg_social_challenge_revision_issue": ("issue_social_device_challenge_revision_v1", 5, False, None),
        "trg_social_enrollment_challenge_atomic": (
            "assert_social_enrollment_atomic_v1",
            17,
            True,
            "((new.state)::text = 'consumed'::text)",
        ),
    },
    "social_device_enrollment_admission_receipts": {
        "trg_social_enrollment_receipt_guard": ("guard_social_enrollment_receipt_v1", 31, False, None),
        "trg_social_enrollment_receipt_no_truncate": ("guard_social_enrollment_receipt_v1", 34, False, None),
        "trg_social_enrollment_receipt_atomic": ("assert_social_enrollment_atomic_v1", 5, True, None),
    },
    durable.TABLE: {
        durable.GUARD_TRIGGER: (durable.GUARD_FUNCTION, 31, False, None),
        durable.NO_TRUNCATE_TRIGGER: (durable.GUARD_FUNCTION, 34, False, None),
        DECISION_TRIGGER: (DECISION_FUNCTION, 17, False, None),
    },
}


def _attest_shared_triggers(connection, relations, functions, constraint_pins):
    identities = []
    for name, expected in SHARED_TRIGGERS.items():
        oid = relations[name]["oid"]
        rows = (
            connection.execute(
                text("""SELECT pg_catalog.to_jsonb(t) AS trigger,
            pg_catalog.pg_get_triggerdef(t.oid,false) AS definition,
            (SELECT conname FROM pg_catalog.pg_constraint k WHERE k.oid=t.tgconstraint) AS constraint_name,
            p.proname,n.nspname
            FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
            JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname"""),
                {"oid": oid},
            )
            .mappings()
            .all()
        )
        if len(rows) != len(expected) or {row["trigger"]["tgname"] for row in rows} != set(expected):
            _deny()
        for row in rows:
            t = _native_catalog_object(row["trigger"], "trigger")
            trigger_oid = t.pop("oid")
            fn, kind, deferred, predicate = expected[t["tgname"]]
            if row["proname"] != fn or row["nspname"] != "public":
                _deny()
            if fn in functions and t["tgfoid"] != functions[fn]:
                _deny()
            constraint = t["tgconstraint"]
            if deferred and constraint_pins.get((name, t["tgname"]), {}).get("oid") != constraint:
                _deny()
            if (deferred and (constraint <= 0 or row["constraint_name"] != t["tgname"])) or (
                not deferred and (constraint != 0 or row["constraint_name"] is not None)
            ):
                _deny()
            actual_predicate = t.pop("tgqual")
            wanted = dict(
                tgrelid=oid,
                tgparentid=0,
                tgname=t["tgname"],
                tgfoid=t["tgfoid"],
                tgtype=kind,
                tgenabled="O",
                tgisinternal=False,
                tgconstrrelid=0,
                tgconstrindid=0,
                tgconstraint=constraint,
                tgdeferrable=deferred,
                tginitdeferred=deferred,
                tgnargs=0,
                tgattr="",
                tgargs="\\x",
                tgoldtable=None,
                tgnewtable=None,
            )
            if t != wanted or (actual_predicate is None) != (predicate is None):
                _deny()
            if predicate is not None:
                # Closed canonical PG16 predicate deparsing, not a substring
                # test on an arbitrary trigger definition or a cached tgqual.
                declaration = f"CREATE CONSTRAINT TRIGGER {t['tgname']} AFTER " + ("UPDATE" if kind == 17 else "INSERT")
                declaration += (
                    f" ON public.{name} DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN ({predicate}) EXECUTE FUNCTION "
                )
                declarations = {declaration}
                if name == "social_device_ed25519_association_events":
                    declarations.add(
                        declaration.replace(
                            "((ARRAY['initial'::character varying, 'rotate'::character varying, 'reenroll'::character varying])::text[])",
                            "(ARRAY['initial'::text, 'rotate'::text, 'reenroll'::text])",
                        )
                    )
                allowed = {d + qualified + "()" for d in declarations for qualified in (fn, "public." + fn)}
                if row["definition"] not in allowed:
                    _deny()
            identities.append((trigger_oid, t["tgfoid"], constraint))
    return identities


CAS_FUNCTION_SOURCE_SHA256 = "38333f36156479f869ad45805e12c1e21aa4be527aaf4284c82c25fe25271a5b"


CAS_CATALOG_FIELDS = frozenset(
    (
        "function_all_argument_types",
        "function_argument_count",
        "function_argument_defaults",
        "function_argument_modes",
        "function_argument_names",
        "function_argument_type_oids",
        "function_binary",
        "function_config",
        "function_cost",
        "function_default_argument_count",
        "function_kind",
        "function_language",
        "function_leakproof",
        "function_name",
        "function_oid",
        "function_owner_oid",
        "function_parallel",
        "function_return_type",
        "function_returns_set",
        "function_rows",
        "function_security_definer",
        "function_source",
        "function_sql_body",
        "function_strict",
        "function_support_oid",
        "function_transform_types",
        "function_variadic_type_oid",
        "function_volatility",
        "relation_access_method",
        "relation_check_constraint_count",
        "relation_column_count",
        "relation_force_row_security",
        "relation_has_indexes",
        "relation_has_rules",
        "relation_has_subclasses",
        "relation_has_triggers",
        "relation_is_partition",
        "relation_is_populated",
        "relation_is_shared",
        "relation_kind",
        "relation_name",
        "relation_of_type_oid",
        "relation_oid",
        "relation_options",
        "relation_owner_oid",
        "relation_partition_bound",
        "relation_persistence",
        "relation_replica_identity",
        "relation_row_security",
        "relation_tablespace_oid",
        "relation_type_oid",
        "toast_access_method",
        "toast_check_constraint_count",
        "toast_column_count",
        "toast_force_row_security",
        "toast_has_indexes",
        "toast_has_rules",
        "toast_has_subclasses",
        "toast_has_triggers",
        "toast_is_partition",
        "toast_is_populated",
        "toast_is_shared",
        "toast_kind",
        "toast_name_matches_relation_oid",
        "toast_namespace",
        "toast_of_type_oid",
        "toast_options",
        "toast_partition_bound",
        "toast_persistence",
        "toast_relation_oid",
        "toast_relation_owner_oid",
        "toast_replica_identity",
        "toast_row_security",
        "toast_row_type_oid",
        "toast_tablespace_oid",
        "trigger_argument_count",
        "trigger_arguments_hex",
        "trigger_attributes",
        "trigger_constraint_index_oid",
        "trigger_constraint_oid",
        "trigger_constraint_relation_oid",
        "trigger_deferrable",
        "trigger_enabled",
        "trigger_function_oid",
        "trigger_initially_deferred",
        "trigger_internal",
        "trigger_name",
        "trigger_new_table",
        "trigger_oid",
        "trigger_old_table",
        "trigger_parent_oid",
        "trigger_qualification",
        "trigger_type",
    )
)


FK_BINDINGS = {
    "fk_social_ed25519_event_chain": (
        "social_device_ed25519_association_events",
        "social_device_ed25519_association_chains",
    ),
    "fk_social_enrollment_receipt_challenge": ("social_device_enrollment_admission_receipts", challenges.TABLE),
    "fk_social_challenge_revision_parent": ("social_device_admission_challenge_revisions", challenges.TABLE),
    "na_challenge_fk": ("social_enrollment_v2_native_associations", challenges.TABLE),
    "na_event_fk": ("social_enrollment_v2_native_associations", "social_device_ed25519_association_events"),
    "ne_reservation_fk": (EFFECT_TABLE, "social_enrollment_v2_native_associations"),
    "ne_challenge_fk": (EFFECT_TABLE, challenges.TABLE),
    "ne_event_fk": (EFFECT_TABLE, "social_device_ed25519_association_events"),
    "nc_reservation_fk": ("social_enrollment_v2_native_consumptions", EFFECT_TABLE),
    "nd_reservation_fk": (DECISION_TABLE, EFFECT_TABLE),
}


def _attest_internal_triggers(connection, relations, constraint_pins):
    relevant = (
        set(NATIVE_COLUMNS)
        | set(SHARED_TRIGGERS)
        | {"social_device_admission_challenge_revisions"}
        | set(V2_DEFINITION_PROFILES)
        | set(AUTHORITY_CONSTRAINTS)
    )
    bindings = dict(FK_BINDINGS)
    for child, profiles in V2_DEFINITION_PROFILES.items():
        bindings.update({name: (child, target[0]) for name, kind, _, _, target in profiles if kind == "f"})
    for (child, name), c in constraint_pins.items():
        if c["contype"] == "f":
            parent = next(n for n, r in relations.items() if r["oid"] == c["confrelid"])
            bindings[name] = (child, parent)
    expected = {}
    identities = []
    for name, (child, parent) in bindings.items():
        rows = (
            connection.execute(
                text("""SELECT pg_catalog.to_jsonb(k) AS constraint
            FROM pg_catalog.pg_constraint k WHERE k.conrelid=:child AND k.conname=:name AND k.contype='f'"""),
                dict(child=relations[child]["oid"], name=name),
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            _deny()
        c = _native_catalog_object(rows[0]["constraint"], "constraint")
        if (child, name) in constraint_pins and c != constraint_pins[(child, name)]:
            _deny()
        if c["confrelid"] != relations[parent]["oid"] or not c["convalidated"] or c["conparentid"] != 0:
            _deny()
        # Every descriptor was validated against its source profile above.
        if (child, name) not in constraint_pins:
            _deny()
        deferred = c["condeferrable"]
        actions = (c["confupdtype"], c["confdeltype"])
        for table, kind, fn, deferrable, is_child in (
            (child, 5, "RI_FKey_check_ins", deferred, True),
            (child, 17, "RI_FKey_check_upd", deferred, True),
            (
                parent,
                9,
                "RI_FKey_restrict_del" if actions[1] == "r" else "RI_FKey_noaction_del",
                deferred and actions[1] != "r",
                False,
            ),
            (
                parent,
                17,
                "RI_FKey_restrict_upd" if actions[0] == "r" else "RI_FKey_noaction_upd",
                deferred and actions[0] != "r",
                False,
            ),
        ):
            # Both halves of each required FK are part of that binding, even
            # when the other table's unrelated schema is outside the inventory.
            expected[(relations[table]["oid"], c["oid"], kind, is_child)] = (
                fn,
                deferrable,
                c["conindid"],
                relations[parent if is_child else child]["oid"],
            )
        identities.append((c["oid"], c["conrelid"], c["confrelid"], c["conindid"]))
    rows = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(t) AS trigger,p.oid::bigint AS function_oid,
        p.proname,p.prosrc,p.pronargs,p.prorettype::bigint,n.nspname,
        p.oid=pg_catalog.to_regprocedure('pg_catalog."' || p.proname || '"()') AS canonical,
        l.lanname
        FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid=t.tgfoid
        JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
        JOIN pg_catalog.pg_language l ON l.oid=p.prolang
        WHERE t.tgisinternal AND (t.tgrelid=ANY(CAST(:oids AS oid[]))
          OR t.tgconstraint=ANY(CAST(:constraints AS oid[]))) ORDER BY t.oid"""),
            {
                "oids": [relations[name]["oid"] for name in sorted(relevant)],
                "constraints": [identity[0] for identity in identities],
            },
        )
        .mappings()
        .all()
    )
    if len(rows) != len(expected):
        _deny()
    observed = set()
    for row in rows:
        if set(row) != {
            "trigger",
            "function_oid",
            "proname",
            "prosrc",
            "pronargs",
            "prorettype",
            "nspname",
            "canonical",
            "lanname",
        }:
            _deny()
        t = _native_catalog_object(row["trigger"], "trigger")
        trigger_oid = t.pop("oid")
        key = (t["tgrelid"], t["tgconstraint"], t["tgtype"], t["tgname"].startswith("RI_ConstraintTrigger_c_"))
        if key not in expected or key in observed:
            _deny()
        observed.add(key)
        fn, deferred, index, other = expected[key]
        prefix = "c" if key[3] else "a"
        wanted = dict(
            tgrelid=key[0],
            tgparentid=0,
            tgname=f"RI_ConstraintTrigger_{prefix}_{trigger_oid}",
            tgfoid=row["function_oid"],
            tgtype=key[2],
            tgenabled="O",
            tgisinternal=True,
            tgconstrrelid=other,
            tgconstrindid=index,
            tgconstraint=key[1],
            tgdeferrable=deferred,
            tginitdeferred=deferred,
            tgnargs=0,
            tgattr="",
            tgargs="\\x",
            tgqual=None,
            tgoldtable=None,
            tgnewtable=None,
        )
        if (
            t != wanted
            or row["proname"] != fn
            or row["prosrc"] != fn
            or row["pronargs"] != 0
            or row["prorettype"] != 2279
            or row["nspname"] != "pg_catalog"
            or row["canonical"] is not True
            or row["lanname"] != "internal"
            or type(row["function_oid"]) is not int
            or row["function_oid"] <= 0
            or type(row["pronargs"]) is not int
            or type(row["prorettype"]) is not int
        ):
            _deny()
        identities.append((trigger_oid, row["function_oid"], key[1]))
    return identities


def _attest_relation_definition(
    connection, relation, *, column_count, checks, toast=False, has_toast=True, has_triggers=True
):
    r = dict(relation)
    _attest_shared_physical_types(r)
    if r["relrewrite"] != "0":
        _deny()
    identity = tuple(r.pop(key) for key in ("oid", "relnamespace", "reltype", "relowner", "reltoastrelid"))
    r.pop("relacl")
    for field in ("relfilenode", "relpages", "reltuples", "relallvisible", "relrewrite", "relfrozenxid", "relminmxid"):
        r.pop(field)
    wanted = dict(
        relname=relation["relname"],
        reloftype=0,
        relam=2,
        reltablespace=0,
        relhasindex=True,
        relisshared=False,
        relpersistence="p",
        relkind="t" if toast else "r",
        relnatts=column_count,
        relchecks=checks,
        relhasrules=False,
        relhastriggers=not toast and has_triggers,
        relhassubclass=False,
        relrowsecurity=False,
        relforcerowsecurity=False,
        relispopulated=True,
        relreplident="n" if toast else "d",
        relispartition=False,
        reloptions=None,
        relpartbound=None,
    )
    if r != wanted:
        _deny()
    if not toast and relation["reltype"] == 0:
        _deny()
    identities = [identity]
    if not toast and not has_toast:
        if relation["reltoastrelid"] != 0:
            _deny()
    if not toast and has_toast:
        rows = (
            connection.execute(
                text("""SELECT pg_catalog.to_jsonb(c) AS relation,n.nspname
            FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=:oid"""),
                {"oid": relation["reltoastrelid"]},
            )
            .mappings()
            .all()
        )
        if len(rows) != 1 or set(rows[0]) != {"relation", "nspname"}:
            _deny()
        t = _native_catalog_object(rows[0]["relation"], "relation")
        if (
            rows[0]["nspname"] != "pg_toast"
            or t["relname"] != f"pg_toast_{relation['oid']}"
            or t["relowner"] != relation["relowner"]
            or t["reltype"] != 0
            or t["reltoastrelid"] != 0
            or t["oid"] != relation["reltoastrelid"]
            or t["relnamespace"] != 99
            or t["relacl"] is not None
        ):
            _deny()
        identities.extend(_attest_relation_definition(connection, t, column_count=3, checks=0, toast=True))
        tc = (("chunk_id", 26, -1, False), ("chunk_seq", 23, -1, False), ("chunk_data", 17, -1, False))
        _attest_shared_attributes(connection, t, tc)
        _, pins = _attest_shared_indexes(connection, t, tc, {t["relname"] + "_index": ("u", [1, 2], None)})
        identities.extend(pins)
        _attest_shared_zero_count(
            connection, "SELECT count(*) FROM pg_catalog.pg_constraint WHERE conrelid=:oid", t["oid"]
        )
    return identities


def _attest_history_privileges(connection, relations):
    actual = []
    names = (
        "social_device_ed25519_association_chains",
        "social_device_ed25519_association_events",
        "social_device_enrollment_admission_receipts",
        challenges.TABLE,
    )
    for name in names:
        row = connection.execute(
            text("""SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT'),
            pg_catalog.has_table_privilege(current_user,:oid,'INSERT'),
            pg_catalog.has_table_privilege(current_user,:oid,'UPDATE'),
            EXISTS(SELECT 1 FROM unnest(ARRAY['DELETE','TRUNCATE','REFERENCES','TRIGGER']) p
                WHERE pg_catalog.has_table_privilege(current_user,:oid,p)),
            EXISTS(SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=:oid AND a.attnum>0
                AND pg_catalog.has_column_privilege(current_user,:oid,a.attnum,'REFERENCES')),
            pg_catalog.has_any_column_privilege(current_user,:oid,'INSERT'),
            pg_catalog.has_any_column_privilege(current_user,:oid,'UPDATE')"""),
            {"oid": relations[name]["oid"]},
        ).one()
        if tuple(row[5:]) != (row[1], row[2]):
            _deny()
        actual.append(tuple(row[:5]))
    profiles = {
        (
            (True, False, True, False, False),
            (True, False, False, False, False),
            (True, False, True, False, False),
            (True, False, True, False, False),
        ),
        (
            (True, True, True, False, False),
            (True, True, False, False, False),
            (True, True, True, False, False),
            (True, False, True, False, False),
        ),
    }
    if tuple(actual) not in profiles:
        _deny()
    return tuple(actual)


# Fixed PG16 normal forms transcribed from the two pinned legacy migrations.
CHAIN = "social_device_ed25519_association_chains"
EVENT = "social_device_ed25519_association_events"
LEGACY_RECEIPT = "social_device_enrollment_admission_receipts"
SHARED_COLUMNS = {
    CHAIN: (
        ("subject", 1043, 68, True),
        ("device_id", 1043, 68, True),
        ("authority_epoch", 20, -1, True),
        ("last_association_id", 1043, 68, False),
        ("last_association_version", 20, -1, False),
        ("current_association_id", 1043, 68, False),
        ("state", 1043, 11, True),
    ),
    EVENT: (
        ("subject", 1043, 68, True),
        ("device_id", 1043, 68, True),
        ("authority_epoch", 20, -1, True),
        ("kind", 1043, 14, True),
        ("association_id", 1043, 68, True),
        ("association_version", 20, -1, True),
        ("predecessor_association_id", 1043, 68, False),
        ("ed25519_public_key", 1043, 68, False),
        ("enrollment_challenge_id", 1043, 68, False),
        ("event_wire", 25, -1, True),
    ),
    LEGACY_RECEIPT: (
        ("receipt_id", 1043, 68, True),
        ("challenge_id", 1043, 68, True),
        ("operation", 1043, 23, True),
        ("decided_at", 20, -1, True),
        ("effect_id", 1043, 68, True),
        ("effect_digest", 1043, 68, True),
        ("proposed_association_id", 1043, 68, True),
        ("authority_wire", 25, -1, True),
        ("receipt_wire", 25, -1, True),
    ),
}


def _hex_check(column):
    return f"CHECK ((({column})::text ~ '^[0-9a-f]{{64}}$'::text))"


def _kinds(values):
    return "((kind)::text = ANY ((ARRAY[" + ", ".join(f"'{v}'::character varying" for v in values) + "])::text[]))"


CREATION_PREDICATE = _kinds(("initial", "rotate", "reenroll"))
PREDECESSOR_PREDICATE = _kinds(("rotate", "reenroll"))
SHARED_CHECKS = {
    CHAIN: (
        ("ck_social_ed25519_chain_subject", _hex_check("subject"), [1]),
        ("ck_social_ed25519_chain_device", _hex_check("device_id"), [2]),
        (
            "ck_social_ed25519_chain_state",
            "CHECK (((((state)::text = 'empty'::text) AND (authority_epoch = 0) AND (last_association_id IS NULL) AND (last_association_version IS NULL) AND (current_association_id IS NULL)) OR (((state)::text = 'active'::text) AND (authority_epoch >= 1) AND (last_association_id IS NOT NULL) AND (last_association_version >= 1) AND ((current_association_id)::text = (last_association_id)::text)) OR (((state)::text = 'revoked'::text) AND (authority_epoch >= 2) AND (last_association_id IS NOT NULL) AND (last_association_version >= 1) AND (current_association_id IS NULL))))",
            [7, 3, 4, 5, 6],
        ),
    ),
    EVENT: (
        ("ck_social_ed25519_event_subject", _hex_check("subject"), [1]),
        ("ck_social_ed25519_event_device", _hex_check("device_id"), [2]),
        ("ck_social_ed25519_event_id", _hex_check("association_id"), [5]),
        (
            "ck_social_ed25519_event_predecessor",
            "CHECK (((predecessor_association_id IS NULL) OR ((predecessor_association_id)::text ~ '^[0-9a-f]{64}$'::text)))",
            [7],
        ),
        (
            "ck_social_ed25519_event_key",
            "CHECK (((ed25519_public_key IS NULL) OR ((ed25519_public_key)::text ~ '^[0-9a-f]{64}$'::text)))",
            [8],
        ),
        (
            "ck_social_ed25519_event_challenge",
            "CHECK (((enrollment_challenge_id IS NULL) OR ((enrollment_challenge_id)::text ~ '^[0-9a-f]{64}$'::text)))",
            [9],
        ),
        (
            "ck_social_ed25519_event_bounds",
            "CHECK ((((authority_epoch >= 1) AND (authority_epoch <= '9007199254740991'::bigint)) AND ((association_version >= 1) AND (association_version <= '9007199254740991'::bigint))))",
            [3, 6],
        ),
        (
            "ck_social_ed25519_event_kind",
            "CHECK (("
            + _kinds(("initial", "rotate", "invalidate", "revoke", "reenroll"))
            + " AND (("
            + CREATION_PREDICATE
            + " AND (ed25519_public_key IS NOT NULL) AND (enrollment_challenge_id IS NOT NULL)) OR ("
            + _kinds(("invalidate", "revoke"))
            + " AND (ed25519_public_key IS NULL) AND (enrollment_challenge_id IS NULL)))))",
            [4, 8, 9],
        ),
    ),
    LEGACY_RECEIPT: (
        ("ck_social_enrollment_receipt_id", _hex_check("receipt_id"), [1]),
        ("ck_social_enrollment_receipt_challenge", _hex_check("challenge_id"), [2]),
        ("ck_social_enrollment_receipt_effect_id", _hex_check("effect_id"), [5]),
        ("ck_social_enrollment_receipt_effect_digest", _hex_check("effect_digest"), [6]),
        ("ck_social_enrollment_receipt_association", _hex_check("proposed_association_id"), [7]),
        ("ck_social_enrollment_receipt_operation", "CHECK (((operation)::text = 'enrollment-activate'::text))", [3]),
        (
            "ck_social_enrollment_receipt_decided_at",
            "CHECK (((decided_at >= 0) AND (decided_at <= '9007199254740991'::bigint)))",
            [4],
        ),
        (
            "ck_social_enrollment_receipt_authority_wire",
            "CHECK ((((octet_length(authority_wire) >= 1) AND (octet_length(authority_wire) <= 8192)) AND (authority_wire !~ '[^ -~]'::text)))",
            [8],
        ),
        (
            "ck_social_enrollment_receipt_wire",
            "CHECK ((((octet_length(receipt_wire) >= 1) AND (octet_length(receipt_wire) <= 2048)) AND (receipt_wire !~ '[^ -~]'::text)))",
            [9],
        ),
    ),
}
SHARED_KEYS = {
    CHAIN: {
        "pk_social_ed25519_chain": ("p", [1, 2], None, None),
        "trg_social_ed25519_chain_initialized": ("t", None, None, None),
    },
    EVENT: {
        "pk_social_ed25519_event": ("p", [1, 2, 3], None, None),
        "fk_social_ed25519_event_chain": ("f", [1, 2], CHAIN, [1, 2]),
        "trg_social_enrollment_event_atomic": ("t", None, None, None),
    },
    LEGACY_RECEIPT: {
        LEGACY_RECEIPT + "_pkey": ("p", [1], None, None),
        "uq_social_enrollment_receipt_challenge": ("u", [2], None, None),
        "uq_social_enrollment_receipt_effect": ("u", [5], None, None),
        "fk_social_enrollment_receipt_challenge": ("f", [2], challenges.TABLE, [1]),
        "trg_social_enrollment_receipt_atomic": ("t", None, None, None),
    },
}
SHARED_PARTIAL_INDEXES = {
    "uq_social_ed25519_creation_id": ([5], CREATION_PREDICATE),
    "uq_social_ed25519_creation_version": ([1, 2, 6], CREATION_PREDICATE),
    "uq_social_ed25519_creation_predecessor": ([7], PREDECESSOR_PREDICATE),
    "uq_social_ed25519_creation_key": ([1, 2, 8], CREATION_PREDICATE),
    "uq_social_ed25519_creation_challenge": ([9], CREATION_PREDICATE),
}


# Ancillary CAS relation definitions absent from the original function/trigger guard.
# Its native API/canonical rules remain solely in the original guard.
SHARED_COLUMNS[durable.TABLE] = (
    ("reservation_id", 1043, 68, True),
    ("reservation_revision", 20, -1, True),
    ("request_id", 1043, 68, True),
    ("operation_id", 1043, 68, True),
    ("subject", 1043, 68, True),
    ("device_id", 1043, 68, True),
    ("acceptance_id", 1043, 68, True),
    ("challenge_id", 1043, 68, True),
    ("challenge_revision", 20, -1, True),
    ("association_id", 1043, 68, True),
    ("input_digest", 1043, 135, True),
    ("input_payload_digest", 1043, 150, True),
    ("evidence_token_id", 1043, 68, True),
    ("evidence_digest", 1043, 143, True),
    ("evidence_payload_digest", 1043, 142, True),
    ("state", 1043, 13, True),
    ("created_at", 20, -1, True),
    ("expires_at", 20, -1, True),
    ("decided_at", 20, -1, False),
    ("statement_digest", 1043, 150, False),
    ("effect_id", 1043, 68, False),
    ("effect_digest", 1043, 133, False),
    ("receipt_id", 1043, 68, False),
    ("finalization_request_digest", 1043, 147, False),
    ("reservation_wire", 25, -1, True),
    ("input_wire", 25, -1, True),
    ("evidence_compact_jws", 25, -1, True),
    ("statement_compact_jws", 25, -1, False),
    ("finalization_observation_wire", 25, -1, False),
    ("effect_wire", 25, -1, False),
    ("receipt_wire", 25, -1, False),
)
SHARED_CHECKS[durable.TABLE] = (
    ("ck_social_preaccepted_v2_reservation_id", "CHECK (((reservation_id)::text ~ '^[0-9a-f]{64}$'::text))", [1]),
    ("ck_social_preaccepted_v2_request_id", "CHECK (((request_id)::text ~ '^[0-9a-f]{64}$'::text))", [3]),
    ("ck_social_preaccepted_v2_operation_id", "CHECK (((operation_id)::text ~ '^[0-9a-f]{64}$'::text))", [4]),
    ("ck_social_preaccepted_v2_subject", "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))", [5]),
    ("ck_social_preaccepted_v2_device_id", "CHECK (((device_id)::text ~ '^[0-9a-f]{64}$'::text))", [6]),
    ("ck_social_preaccepted_v2_acceptance_id", "CHECK (((acceptance_id)::text ~ '^[0-9a-f]{64}$'::text))", [7]),
    ("ck_social_preaccepted_v2_challenge_id", "CHECK (((challenge_id)::text ~ '^[0-9a-f]{64}$'::text))", [8]),
    ("ck_social_preaccepted_v2_association_id", "CHECK (((association_id)::text ~ '^[0-9a-f]{64}$'::text))", [10]),
    ("ck_social_preaccepted_v2_token_id", "CHECK (((evidence_token_id)::text ~ '^[0-9a-f]{64}$'::text))", [13]),
    ("ck_social_preaccepted_v2_revision", "CHECK ((reservation_revision = 1))", [2]),
    (
        "ck_social_preaccepted_v2_challenge_revision",
        "CHECK (((challenge_revision >= 1) AND (challenge_revision <= '9007199254740991'::bigint)))",
        [9],
    ),
    (
        "ck_social_preaccepted_v2_state",
        "CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'accepted'::character varying, 'rejected'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))",
        [16],
    ),
    (
        "ck_social_preaccepted_v2_times",
        "CHECK ((((created_at >= 0) AND (created_at <= '9007199254740991'::bigint)) AND ((expires_at >= 1) AND (expires_at <= '9007199254740991'::bigint)) AND (created_at < expires_at) AND ((decided_at IS NULL) OR ((decided_at >= 0) AND (decided_at <= '9007199254740991'::bigint)))))",
        [17, 18, 19],
    ),
    (
        "ck_social_preaccepted_v2_reservation_wire",
        "CHECK ((((octet_length(reservation_wire) >= 1) AND (octet_length(reservation_wire) <= 8192)) AND (reservation_wire !~ '[^ -~]'::text)))",
        [25],
    ),
    (
        "ck_social_preaccepted_v2_input_wire",
        "CHECK ((((octet_length(input_wire) >= 1) AND (octet_length(input_wire) <= 24576)) AND (input_wire !~ '[^ -~]'::text)))",
        [26],
    ),
    (
        "ck_social_preaccepted_v2_evidence_wire",
        "CHECK ((((octet_length(evidence_compact_jws) >= 1) AND (octet_length(evidence_compact_jws) <= 16384)) AND (evidence_compact_jws !~ '[^ -~]'::text)))",
        [27],
    ),
    (
        "ck_social_preaccepted_v2_statement_wire",
        "CHECK (((statement_compact_jws IS NULL) OR (((octet_length(statement_compact_jws) >= 1) AND (octet_length(statement_compact_jws) <= 4096)) AND (statement_compact_jws !~ '[^ -~]'::text))))",
        [28],
    ),
    (
        "ck_social_preaccepted_v2_observation_wire",
        "CHECK (((finalization_observation_wire IS NULL) OR (((octet_length(finalization_observation_wire) >= 1) AND (octet_length(finalization_observation_wire) <= 16384)) AND (finalization_observation_wire !~ '[^ -~]'::text))))",
        [29],
    ),
    (
        "ck_social_preaccepted_v2_effect_wire",
        "CHECK (((effect_wire IS NULL) OR (((octet_length(effect_wire) >= 1) AND (octet_length(effect_wire) <= 8192)) AND (effect_wire !~ '[^ -~]'::text))))",
        [30],
    ),
    (
        "ck_social_preaccepted_v2_receipt_wire",
        "CHECK (((receipt_wire IS NULL) OR (((octet_length(receipt_wire) >= 1) AND (octet_length(receipt_wire) <= 8192)) AND (receipt_wire !~ '[^ -~]'::text))))",
        [31],
    ),
)
SHARED_KEYS[durable.TABLE] = {
    "social_preaccepted_enrollment_v2_atomic_acceptances_pkey": ("p", [1], None, None),
    "uq_social_preaccepted_v2_acceptance_request": ("u", [3], None, None),
    "uq_social_preaccepted_v2_acceptance_operation": ("u", [4], None, None),
    "uq_social_preaccepted_v2_acceptance_device": ("u", [6], None, None),
    "uq_social_preaccepted_v2_acceptance_acceptance": ("u", [7], None, None),
    "uq_social_preaccepted_v2_acceptance_challenge": ("u", [8], None, None),
    "uq_social_preaccepted_v2_acceptance_association": ("u", [10], None, None),
    "uq_social_preaccepted_v2_acceptance_input": ("u", [11], None, None),
    "uq_social_preaccepted_v2_acceptance_evidence_token": ("u", [13], None, None),
    "uq_social_preaccepted_v2_acceptance_evidence": ("u", [14], None, None),
    "uq_social_preaccepted_v2_acceptance_effect": ("u", [21], None, None),
    "uq_social_preaccepted_v2_acceptance_receipt": ("u", [23], None, None),
}

SHARED_ATTRIBUTES_SQL = """
SELECT pg_catalog.to_jsonb(a) AS attribute FROM pg_catalog.pg_attribute a
WHERE a.attrelid=:oid AND a.attnum>0 ORDER BY a.attnum
"""
SHARED_CONSTRAINTS_SQL = """
SELECT pg_catalog.to_jsonb(k) AS constraint,
       pg_catalog.pg_get_constraintdef(k.oid,false) AS definition
FROM pg_catalog.pg_constraint k WHERE k.conrelid=:oid ORDER BY k.conname
"""
SHARED_INDEXES_SQL = """
SELECT pg_catalog.to_jsonb(i) AS index, pg_catalog.to_jsonb(c) AS relation,
       pg_catalog.pg_get_indexdef(i.indexrelid) AS definition,
       pg_catalog.pg_get_expr(i.indpred,i.indrelid,false) AS predicate
FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid
WHERE i.indrelid=:oid ORDER BY c.relname
"""


def _attest_shared_attributes(connection, relation, columns, *, alternatives=(), positions=None):
    sql = SHARED_ATTRIBUTES_SQL
    params = {"oid": relation["oid"]}
    if positions is not None:
        sql = sql.replace("a.attnum>0", "a.attnum=ANY(CAST(:positions AS smallint[]))")
        params["positions"] = list(positions)
    rows = connection.execute(text(sql), params).mappings().all()
    if len(rows) != len(columns):
        _deny()
    observed = []
    accepted = (columns, *alternatives)
    for position, (row, (name, typ, mod, required)) in enumerate(zip(rows, columns), 1):
        if set(row) != {"attribute"}:
            _deny()
        a = _native_catalog_object(row["attribute"], "attribute")
        scalar = typ in (16, 20, 23, 26, 1114, 1184)
        wanted = dict(
            attrelid=relation["oid"],
            attname=name,
            atttypid=typ,
            attstattarget=-1,
            attlen=1 if typ == 16 else 8 if typ in (20, 1114, 1184) else 4 if scalar else -1,
            attnum=position if positions is None else positions[position - 1],
            attndims=0,
            attcacheoff=-1,
            atttypmod=mod,
            attbyval=scalar,
            attstorage="p" if scalar or typ == 17 else "x",
            attcompression="",
            attalign="c" if typ == 16 else "d" if typ in (20, 1114, 1184) else "i",
            attnotnull=required,
            atthasdef=False,
            atthasmissing=False,
            attidentity="",
            attgenerated="",
            attisdropped=False,
            attislocal=True,
            attinhcount=0,
            attcollation=100 if typ in (25, 1043) else 0,
            attacl=None,
            attoptions=None,
            attfdwoptions=None,
            attmissingval=None,
        )
        matching = tuple(profile for profile in accepted if a["attnotnull"] is profile[position - 1][3])
        wanted["attnotnull"] = a["attnotnull"]
        if (
            not matching
            or a != wanted
            or any(type(a[k]) is not int for k in ("attstattarget", "attlen", "attndims", "attcacheoff"))
        ):
            _deny()
        accepted = matching
        observed.append(_wire(a))
    # No orphan/default catalog entries even if atthasdef was falsified.
    if positions is not None:
        # Only required external binding attributes, not the unrelated schema.
        return tuple(observed)
    _attest_shared_zero_count(
        connection, "SELECT count(*) FROM pg_catalog.pg_attrdef WHERE adrelid=:oid", relation["oid"]
    )
    _attest_shared_zero_count(
        connection,
        "SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid=:oid AND attacl IS NOT NULL",
        relation["oid"],
    )
    return tuple(observed)


def _attest_shared_index_relation(relation, table, name, count):
    r = dict(relation)
    identity = tuple(r.pop(k) for k in ("oid", "relowner", "relnamespace"))
    if identity[1:] != (table["relowner"], table["relnamespace"]):
        _deny()
    _attest_shared_physical_types(r)
    for k in ("relfilenode", "relpages", "reltuples", "relallvisible", "relfrozenxid", "relminmxid"):
        r.pop(k)
    wanted = dict(
        relname=name,
        reltype=0,
        reloftype=0,
        relam=403,
        reltablespace=0,
        reltoastrelid=0,
        relhasindex=False,
        relisshared=False,
        relpersistence="p",
        relkind="i",
        relnatts=count,
        relchecks=0,
        relhasrules=False,
        relhastriggers=False,
        relhassubclass=False,
        relrowsecurity=False,
        relforcerowsecurity=False,
        relispopulated=True,
        relreplident="n",
        relispartition=False,
        relrewrite="0",
        relacl=None,
        reloptions=None,
        relpartbound=None,
    )
    if r != wanted:
        _deny()
    return identity


def _attest_shared_indexes(connection, relation, columns, specs):
    rows = connection.execute(text(SHARED_INDEXES_SQL), {"oid": relation["oid"]}).mappings().all()
    return _attest_index_definitions(rows, relation, columns, specs)


def _attest_index_definitions(rows, relation, columns, specs):
    if len(rows) != len(specs):
        _deny()
    ids, identities = {}, []
    for row in rows:
        if set(row) != {"index", "relation", "definition", "predicate"}:
            _deny()
        ir = _native_catalog_object(row["relation"], "relation")
        name = ir["relname"]
        if name not in specs or name in ids:
            _deny()
        if ir["oid"] in ids.values():
            _deny()
        kind, keys, predicate = specs[name]
        i = _native_catalog_object(row["index"], "index")
        types = [columns[k - 1][1] for k in keys]
        wanted = dict(
            indexrelid=ir["oid"],
            indrelid=relation["oid"],
            indnatts=len(keys),
            indnkeyatts=len(keys),
            indisunique=kind != "n",
            indnullsnotdistinct=False,
            indisprimary=kind == "p" or relation["relkind"] == "t",
            indisexclusion=False,
            indimmediate=True,
            indisvalid=True,
            indcheckxmin=False,
            indisready=True,
            indislive=True,
            indisreplident=False,
            indkey=" ".join(map(str, keys)),
            indcollation=" ".join("100" if t in (25, 1043) else "0" for t in types),
            indclass=" ".join(
                str({20: 3124, 23: 1978, 26: 1981, 25: 3126, 1043: 3126, 16: 10003, 1114: 3128, 1184: 3127}[t])
                for t in types
            ),
            indoption=" ".join("0" for _ in keys),
            indexprs=None,
        )
        # CLUSTER's chosen index is maintenance state; validity/readiness/liveness
        # and indcheckxmin remain mandatory, never excluded as maintenance.
        i.pop("indisclustered")
        tree = i.pop("indpred")
        if i != wanted or row["predicate"] != predicate or (tree is None) != (predicate is None):
            _deny()
        if tree is not None and (type(tree) is not str or not tree):
            _deny()
        definition = f"CREATE {'UNIQUE ' if kind != 'n' else ''}INDEX {name} ON " + (
            "pg_toast." if relation["relkind"] == "t" else "public."
        )
        definition += relation["relname"] + " USING btree (" + ", ".join(columns[k - 1][0] for k in keys) + ")"
        if predicate is not None:
            definition += " WHERE " + predicate
        if row["definition"] != definition:
            _deny()
        identity = _attest_shared_index_relation(ir, relation, name, len(keys))
        ids[name] = ir["oid"]
        identities.append((identity, tree))
    return ids, identities


def _attest_shared_constraints(connection, relation, columns, relations, indexes, revision_indexes):
    name = relation["relname"]
    specs = dict(SHARED_KEYS[name])
    checks = {n: (d, k) for n, d, k in SHARED_CHECKS[name]}
    specs.update({n: ("c", k, None, None) for n, (d, k) in checks.items()})
    rows = connection.execute(text(SHARED_CONSTRAINTS_SQL), {"oid": relation["oid"]}).mappings().all()
    if len(rows) != len(specs):
        _deny()
    pins = {}
    observed = set()
    identities = []
    for row in rows:
        if set(row) != {"constraint", "definition"}:
            _deny()
        c = _native_catalog_object(row["constraint"], "constraint")
        n = c["conname"]
        if n not in specs or n in observed:
            _deny()
        observed.add(n)
        pins[(name, n)] = dict(c)
        kind, keys, parent, parent_keys = specs[n]
        target = relations[parent]["oid"] if parent else 0
        backing = indexes[n] if kind in ("p", "u") else 0
        if parent:
            # The referenced PK was independently validated by this shared pass
            # or the real original revision validator on this same Connection.
            parent_name = "pk_social_ed25519_chain" if parent == CHAIN else challenges.TABLE + "_pkey"
            pk = connection.execute(
                text(
                    "SELECT oid::bigint,conindid::bigint FROM pg_catalog.pg_constraint WHERE conrelid=:oid AND conname=:name AND contype='p'"
                ),
                {"oid": target, "name": parent_name},
            ).all()
            if len(pk) != 1 or any(type(v) is not int or v <= 0 for v in pk[0]):
                _deny()
            backing = pk[0][1]
            if parent == challenges.TABLE and tuple(pk[0]) != revision_indexes[parent]:
                _deny()
            if parent == CHAIN and backing != indexes[parent_name]:
                _deny()
        deferred = kind == "t" or n == "fk_social_enrollment_receipt_challenge"
        oid = c.pop("oid")
        tree = c.pop("conbin")
        ops = [98 for _ in parent_keys] if parent else None
        wanted = dict(
            conname=n,
            connamespace=relation["relnamespace"],
            contype=kind,
            condeferrable=deferred,
            condeferred=deferred,
            convalidated=True,
            conrelid=relation["oid"],
            contypid=0,
            conindid=backing,
            conparentid=0,
            confrelid=target,
            confupdtype="a" if parent else " ",
            confdeltype="a" if parent else " ",
            confmatchtype="s" if parent else " ",
            conislocal=True,
            coninhcount=0,
            connoinherit=kind != "c",
            conkey=keys,
            confkey=parent_keys,
            conpfeqop=ops,
            conppeqop=ops,
            conffeqop=ops,
            confdelsetcols=None,
            conexclop=None,
        )
        if c != wanted or (kind == "c" and (type(tree) is not str or not tree)) or (kind != "c" and tree is not None):
            _deny()
        if kind == "c":
            definition = checks[n][0]
        elif kind == "t":
            definition = "TRIGGER DEFERRABLE INITIALLY DEFERRED"
        else:
            names = ", ".join(columns[k - 1][0] for k in keys)
            if parent:
                parent_columns = (
                    SHARED_COLUMNS[parent] if parent in SHARED_COLUMNS else (("challenge_id", 1043, 68, True),)
                )
                target_names = ", ".join(parent_columns[k - 1][0] for k in parent_keys)
                definition = f"FOREIGN KEY ({names}) REFERENCES {parent}({target_names})"
                if deferred:
                    definition += " DEFERRABLE INITIALLY DEFERRED"
            else:
                definition = ("PRIMARY KEY" if kind == "p" else "UNIQUE") + f" ({names})"
        if row["definition"] not in {definition, definition.replace("REFERENCES ", "REFERENCES public.")}:
            _deny()
        identities.append((oid, backing, target, tree))
    return identities, pins


@_sanitized
def _attest_shared_relations(connection, relations, revision_indexes):
    identities = []
    indexes = {}
    constraint_pins = {}
    for name, columns in SHARED_COLUMNS.items():
        r = relations[name]
        _attest_shared_physical_types(r)
        if r["relrewrite"] != "0":
            _deny()
        identities.append(_attest_shared_acl(connection, r))
        identities.extend(
            _attest_relation_definition(
                connection, r, column_count=len(columns), checks=len(SHARED_CHECKS[name]), has_toast=name != CHAIN
            )
        )
        _attest_shared_attributes(connection, r, columns)
        specs = {n: (kind, keys, None) for n, (kind, keys, _, _) in SHARED_KEYS[name].items() if kind in ("p", "u")}
        if name == EVENT:
            specs.update({n: ("u", keys, predicate) for n, (keys, predicate) in SHARED_PARTIAL_INDEXES.items()})
        ids, pins = _attest_shared_indexes(connection, r, columns, specs)
        indexes.update(ids)
        identities.extend(pins)
    for name, columns in SHARED_COLUMNS.items():
        pins, constraints = _attest_shared_constraints(
            connection, relations[name], columns, relations, indexes, revision_indexes
        )
        identities.extend(pins)
        constraint_pins.update(constraints)
    return identities, constraint_pins


SHARED_ACL_SQL = """
SELECT x.grantor::bigint,x.grantee::bigint,x.privilege_type,x.is_grantable,
       current_user::pg_catalog.regrole::oid::bigint
FROM pg_catalog.pg_class c CROSS JOIN LATERAL
pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) x
WHERE c.oid=:oid ORDER BY x.grantor,x.grantee,x.privilege_type
"""


def _attest_shared_acl(connection, relation, *, profiles=None):
    rows = connection.execute(text(SHARED_ACL_SQL), {"oid": relation["oid"]}).all()
    if not rows or any(len(row) != 5 for row in rows):
        _deny()
    runtime = rows[0][4]
    if type(runtime) is not int or runtime <= 0 or runtime == relation["relowner"]:
        _deny()
    actual = set()
    for grantor, grantee, privilege, grantable, observed_role in rows:
        if (
            type(grantor) is not int
            or type(grantee) is not int
            or grantor != relation["relowner"]
            or observed_role != runtime
            or type(observed_role) is not int
            or grantable is not False
            or type(privilege) is not str
        ):
            _deny()
        item = (grantee, privilege)
        if item in actual:
            _deny()
        actual.add(item)
    owner = {
        (relation["relowner"], p) for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
    }
    if profiles is None:
        runtime_privileges = ("SELECT",) if relation["relname"] == EVENT else ("SELECT", "UPDATE")
        profiles = (
            (runtime_privileges + ("INSERT",),)
            if relation["relname"] == durable.TABLE
            else (runtime_privileges, runtime_privileges + ("INSERT",))
        )
    from app.services.social_enrollment_v2_catalog_roles import peer_acl

    peer = peer_acl(
        getattr(connection, "_catalog_role_pin", None),
        relation_name=relation["relname"],
        owner=relation["relowner"],
        runtime=runtime,
    )
    accepted = tuple(owner | {(runtime, p) for p in profile} | peer for profile in profiles)
    if actual not in accepted:
        _deny()
    return tuple(sorted(actual))


@_sanitized
def _attest_original_revision_definitions(connection, relations):
    """Invoke the real original PK/FK/CHECK validator on this Connection.

    The original guarded revision reader still owns challenge authority, markers,
    privilege profiles and source guards. This read-only seam closes referenced
    index identity here too; a raw Connection supplies no issued facts.
    """
    from app.services import social_device_challenge_revision_storage as revision

    rows = revision._native_catalog_rows(connection.execute(text(revision.CATALOG_SQL)).mappings().all())
    if len(rows) != 2:
        _deny()
    by_name = {row["relation"]["relname"]: row for row in rows}
    if set(by_name) != {challenges.TABLE, revision.TABLE}:
        _deny()
    parent = by_name[challenges.TABLE]
    identities = []
    referenced = {}
    constraints = {}
    for name, columns in (
        (
            challenges.TABLE,
            (
                ("challenge_id", 1043, 68, True),
                ("context_wire", 25, -1, True),
                ("challenge_wire", 25, -1, True),
                ("routing_request_wire", 25, -1, False),
                ("state", 1043, 15, True),
            ),
        ),
        (revision.TABLE, (("challenge_id", 1043, 68, True), ("revision", 23, -1, True))),
    ):
        row = by_name[name]
        visible = relations[name]
        if any(
            row["relation"][key] != visible[key]
            for key in ("oid", "relnamespace", "relowner", "reltype", "reltoastrelid")
        ):
            _deny()
        _attest_shared_attributes(connection, visible, columns)
        identities.append(
            _attest_shared_acl(
                connection, visible, profiles=(("SELECT", "UPDATE"),) if name == challenges.TABLE else (("SELECT",),)
            )
        )
        identities.extend(
            _attest_relation_definition(
                connection,
                visible,
                column_count=len(columns),
                checks=6 if name == challenges.TABLE else 2,
                has_toast=name == challenges.TABLE,
            )
        )
        identities.extend(revision._constraints(row, parent))
        _, pins = _attest_shared_indexes(connection, visible, columns, {name + "_pkey": ("p", [1], None)})
        identities.extend(pins)
        pk = next(k["catalog"] for k in row["constraints"] if k["catalog"]["contype"] == "p")
        referenced[name] = (pk["oid"], pk["conindid"])
        constraints.update({(name, k["catalog"]["conname"]): dict(k["catalog"]) for k in row["constraints"]})
    # Original validators return dictionaries for their own private comparison.
    # Only immutable canonical catalog fingerprints leave this composed seam.
    return tuple(_wire(pin) for pin in identities), referenced, constraints


def _attest_shared_physical_types(relation):
    """Native types remain closed even for excluded physical/statistical fields."""
    from app.services.social_device_challenge_revision_storage import _native_oid

    for field in ("relfilenode", "relrewrite", "relfrozenxid", "relminmxid"):
        _native_oid(relation[field])
    for field in ("relpages", "relallvisible"):
        if type(relation[field]) is not int or not 0 <= relation[field] <= 2147483647:
            _deny()
    value = relation["reltuples"]
    if type(value) not in (int, float) or not math.isfinite(value) or not -1 <= value <= 3.4028234663852886e38:
        _deny()


def _attest_shared_zero_count(connection, sql, oid):
    value = connection.execute(text(sql), {"oid": oid}).scalar_one()
    if type(value) is not int or value != 0:
        _deny()


# Ordered native attribute profiles from pinned models; migration-only binding
# owners come from the original mobile migration. Python defaults are absent
# server defaults. No model or caller object is retained in these constants.
DEPENDENCY_COLUMNS = MappingProxyType(
    {
        "users": (
            ("id", 1043, 40, True),
            ("pubkey", 1043, 70, True),
            ("created_at", 1114, -1, True),
            ("last_login", 1114, -1, False),
            ("metadata", 114, -1, False),
            ("is_active", 16, -1, False),
        ),
        "current_entitlement_evidence": (
            ("evidence_id", 1043, 40, True),
            ("contract_version", 1043, 68, True),
            ("subject_pubkey", 1043, 68, True),
            ("identity_class", 1043, 11, True),
            ("current_full_relation_satisfied", 16, -1, True),
            ("evidence_source", 1043, 132, True),
            ("evidence_version", 1043, 68, True),
            ("source_evidence_sha256", 1043, 68, True),
            ("observed_at", 1184, -1, True),
            ("valid_until", 1184, -1, True),
            ("revoked_at", 1184, -1, False),
            ("created_at", 1184, -1, True),
        ),
        "oauth_tokens": (
            ("id", 1043, 40, True),
            ("access_token", 1043, 259, True),
            ("refresh_token", 1043, 259, False),
            ("token_type", 1043, 54, False),
            ("client_id", 1043, 259, True),
            ("user_id", 1043, 40, True),
            ("scope", 25, -1, False),
            ("created_at", 1114, -1, True),
            ("access_token_expires_at", 1114, -1, True),
            ("refresh_token_expires_at", 1114, -1, False),
            ("is_revoked", 16, -1, False),
            ("metadata", 114, -1, False),
        ),
        "sessions": (
            ("session_id", 1043, 259, True),
            ("user_id", 1043, 40, True),
            ("session_type", 1043, 54, False),
            ("created_at", 1114, -1, True),
            ("expires_at", 1114, -1, True),
            ("last_activity", 1114, -1, False),
            ("ip_address", 1043, 49, False),
            ("user_agent", 25, -1, False),
            ("metadata", 114, -1, False),
            ("is_active", 16, -1, False),
        ),
        "oauth_clients": (
            ("client_id", 1043, 259, True),
            ("client_secret", 1043, 259, True),
            ("client_name", 1043, 259, True),
            ("redirect_uris", 114, -1, True),
            ("grant_types", 114, -1, True),
            ("response_types", 114, -1, True),
            ("scope", 25, -1, False),
            ("token_endpoint_auth_method", 1043, 54, False),
            ("created_at", 1114, -1, True),
            ("metadata", 114, -1, False),
            ("is_active", 16, -1, False),
        ),
        "oauth_session_generations": (
            ("token_id", 1043, 40, True),
            ("browser_generation_id", 1043, 68, True),
            ("session_id", 1043, 259, True),
            ("user_id", 1043, 40, True),
            ("client_id", 1043, 259, True),
            ("subject", 1043, 68, True),
        ),
        "oauth_browser_generations": (
            ("generation_id", 1043, 68, True),
            ("user_id", 1043, 40, True),
            ("client_id", 1043, 259, True),
            ("subject", 1043, 68, True),
            ("proof_id", 1043, 68, True),
            ("created_at", 1114, -1, True),
            ("expires_at", 1114, -1, True),
            ("is_active", 16, -1, True),
        ),
        "social_messaging_device_bindings": (
            ("binding_id", 1043, 68, True),
            ("record_schema", 1043, 68, True),
            ("subject_pubkey", 1043, 68, True),
            ("device_id", 1043, 68, True),
            ("algorithm", 1043, 20, True),
            ("public_key", 1043, 68, True),
            ("binding_version", 20, -1, True),
            ("valid_from", 1184, -1, True),
            ("expires_at", 1184, -1, True),
            ("operation", 1043, 12, True),
            ("prior_binding_id", 1043, 68, False),
            ("request_id", 1043, 68, True),
            ("active", 16, -1, True),
            ("retired_at", 1184, -1, False),
            ("created_at", 1184, -1, True),
        ),
        "social_session_issuers": (
            ("client_id", 1043, 259, True),
            ("backend_id", 1043, 259, True),
            ("service_principal", 1043, 259, True),
            ("is_active", 16, -1, True),
        ),
        "social_messaging_mobile_operations": (
            ("operation_id", 1043, 68, True),
            ("method", 1043, 28, True),
            ("subject", 1043, 68, True),
            ("context_id", 1043, 68, True),
            ("session_commitment", 1043, 68, True),
            ("created_at", 20, -1, True),
            ("expires_at", 20, -1, True),
            ("revision", 1043, 68, False),
            ("secret_commitment", 1043, 68, False),
            ("request_id", 1043, 68, False),
            ("authorization_digest", 1043, 68, False),
            ("source", 25, -1, False),
            ("status", 1043, 28, True),
        ),
        "social_messaging_device_authorization_binding_owners": (
            ("binding_id", 1043, 68, True),
            ("request_id", 1043, 68, True),
        ),
        "social_session_v2_acceptances": (
            ("operation_id", 1043, 68, True),
            ("acceptance_id", 1043, 68, True),
            ("approval_id", 1043, 68, True),
            ("approval_wire", 25, -1, True),
            ("wire", 25, -1, True),
            ("binding_id", 1043, 68, True),
            ("accepted_at", 20, -1, True),
            ("possession_proof", 1043, 68, True),
            ("full_evidence_id", 1043, 40, True),
            ("full_evidence_version", 1043, 132, True),
            ("full_source_hash", 1043, 68, True),
            ("full_proof_id", 1043, 116, True),
            ("full_expires_at", 20, -1, True),
            ("birth_xid", 25, -1, True),
        ),
        "social_session_v2_binding_births": (
            ("binding_id", 1043, 68, True),
            ("operation_id", 1043, 68, True),
            ("birth_xid", 25, -1, True),
        ),
        "social_session_v2_invalidations": (("operation_id", 1043, 68, True),),
        "social_session_v2_issuances": (
            ("operation_id", 1043, 68, True),
            ("acceptance_id", 1043, 68, True),
            ("issuance_id", 1043, 68, True),
            ("token_id", 1043, 40, True),
            ("revision", 1043, 68, True),
            ("subject", 1043, 68, True),
            ("client_id", 1043, 259, True),
            ("backend_id", 1043, 259, True),
            ("service_principal", 1043, 259, True),
            ("issuer", 1043, 259, True),
            ("user_id", 1043, 40, True),
            ("delivery_commitment", 1043, 68, True),
            ("issued_at", 20, -1, True),
            ("expires_at", 20, -1, True),
            ("kid", 1043, 259, True),
            ("birth_xid", 25, -1, True),
        ),
        "social_session_v2_offers": (
            ("operation_id", 1043, 68, True),
            ("request_id", 1043, 68, True),
            ("authorization_digest", 1043, 68, True),
            ("wire", 25, -1, True),
            ("subject", 1043, 68, True),
            ("client_id", 1043, 259, True),
            ("backend_id", 1043, 259, True),
            ("service_principal", 1043, 259, True),
            ("issuer", 1043, 259, True),
            ("created_at", 20, -1, True),
            ("expires_at", 20, -1, True),
            ("birth_xid", 25, -1, True),
        ),
        "social_session_v2_parents": (
            ("operation_id", 1043, 68, True),
            ("token_id", 1043, 40, True),
            ("session_id", 1043, 259, True),
            ("browser_id", 1043, 68, True),
            ("user_id", 1043, 40, True),
            ("continuity", 1043, 68, True),
        ),
        "social_session_v2_token_births": (("token_id", 1043, 40, True), ("birth_xid", 25, -1, True)),
    }
)


# Closed model + lifecycle/mobile/issuer migration composition. Logical names
# and PG16 deparsing are source pins; no installed catalog supplies expectations.
AUTHORITY_CONSTRAINTS = MappingProxyType(
    {
        "users": (("users_pkey", "p", "PRIMARY KEY (id)", (1,), None, " ", " ", False, False),),
        "current_entitlement_evidence": (
            (
                "ck_current_entitlement_contract_version",
                "c",
                "CHECK (((contract_version)::text = " "'hodlxxi.current_entitlement_evidence.v1'::text))",
                (2,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_created_order",
                "c",
                "CHECK ((observed_at <= created_at))",
                (9, 12),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_evidence_id_canonical",
                "c",
                "CHECK (((evidence_id)::text ~ "
                "'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'::text))",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_evidence_id_length",
                "c",
                "CHECK ((length((evidence_id)::text) = 36))",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_hash_canonical",
                "c",
                "CHECK (((source_evidence_sha256)::text ~ '^[0-9a-f]{64}$'::text))",
                (8,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_hash_length",
                "c",
                "CHECK ((length((source_evidence_sha256)::text) = 64))",
                (8,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_identity_class",
                "c",
                "CHECK (((identity_class)::text = ANY ((ARRAY['limited'::character varying, "
                "'full'::character varying])::text[])))",
                (4,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_identity_relation",
                "c",
                "CHECK (((((identity_class)::text = 'full'::text) AND "
                "(current_full_relation_satisfied = true)) OR (((identity_class)::text = "
                "'limited'::text) AND (current_full_relation_satisfied = false))))",
                (4, 5),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_revoked_order",
                "c",
                "CHECK (((revoked_at IS NULL) OR ((revoked_at >= observed_at) AND " "(revoked_at <= created_at))))",
                (11, 9, 12),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_source_canonical",
                "c",
                "CHECK (((evidence_source)::text = btrim((evidence_source)::text)))",
                (6,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_source_length",
                "c",
                "CHECK (((length((evidence_source)::text) >= 1) AND " "(length((evidence_source)::text) <= 128)))",
                (6,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_subject_canonical",
                "c",
                "CHECK (((subject_pubkey)::text ~ '^[0-9a-f]{64}$'::text))",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_subject_length",
                "c",
                "CHECK ((length((subject_pubkey)::text) = 64))",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_validity_duration",
                "c",
                "CHECK ((valid_until <= (observed_at + '00:15:00'::interval)))",
                (10, 9),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_validity_order",
                "c",
                "CHECK ((observed_at < valid_until))",
                (9, 10),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_version_canonical",
                "c",
                "CHECK (((evidence_version)::text = btrim((evidence_version)::text)))",
                (7,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_current_entitlement_version_length",
                "c",
                "CHECK (((length((evidence_version)::text) >= 1) AND " "(length((evidence_version)::text) <= 64)))",
                (7,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            ("current_entitlement_evidence_pkey", "p", "PRIMARY KEY (evidence_id)", (1,), None, " ", " ", False, False),
        ),
        "oauth_tokens": (
            (
                "oauth_tokens_client_id_fkey",
                "f",
                "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
                (5,),
                ("oauth_clients", ("client_id",)),
                "a",
                "a",
                False,
                False,
            ),
            ("oauth_tokens_pkey", "p", "PRIMARY KEY (id)", (1,), None, " ", " ", False, False),
            (
                "oauth_tokens_user_id_fkey",
                "f",
                "FOREIGN KEY (user_id) REFERENCES users(id)",
                (6,),
                ("users", ("id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "uq_oauth_token_generation_owner",
                "u",
                "UNIQUE (id, user_id, client_id)",
                (1, 6, 5),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
        "sessions": (
            ("sessions_pkey", "p", "PRIMARY KEY (session_id)", (1,), None, " ", " ", False, False),
            (
                "sessions_user_id_fkey",
                "f",
                "FOREIGN KEY (user_id) REFERENCES users(id)",
                (2,),
                ("users", ("id",)),
                "a",
                "a",
                False,
                False,
            ),
            ("uq_session_generation_owner", "u", "UNIQUE (session_id, user_id)", (1, 2), None, " ", " ", False, False),
        ),
        "oauth_clients": (("oauth_clients_pkey", "p", "PRIMARY KEY (client_id)", (1,), None, " ", " ", False, False),),
        "oauth_session_generations": (
            (
                "fk_oauth_generation_browser_owner",
                "f",
                "FOREIGN KEY (browser_generation_id, user_id, client_id, subject) REFERENCES "
                "oauth_browser_generations(generation_id, user_id, client_id, subject)",
                (2, 4, 5, 6),
                ("oauth_browser_generations", ("generation_id", "user_id", "client_id", "subject")),
                "a",
                "a",
                False,
                False,
            ),
            (
                "fk_oauth_generation_session_owner",
                "f",
                "FOREIGN KEY (session_id, user_id) REFERENCES sessions(session_id, user_id)",
                (3, 4),
                ("sessions", ("session_id", "user_id")),
                "a",
                "a",
                False,
                False,
            ),
            (
                "fk_oauth_generation_token_owner",
                "f",
                "FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, " "user_id, client_id)",
                (1, 4, 5),
                ("oauth_tokens", ("id", "user_id", "client_id")),
                "a",
                "a",
                False,
                False,
            ),
            ("oauth_session_generations_pkey", "p", "PRIMARY KEY (token_id)", (1,), None, " ", " ", False, False),
            (
                "oauth_session_generations_session_id_key",
                "u",
                "UNIQUE (session_id)",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "oauth_session_generations_subject_check",
                "c",
                "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
                (6,),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
        "oauth_browser_generations": (
            (
                "ck_browser_generation_lifetime",
                "c",
                "CHECK ((created_at < expires_at))",
                (6, 7),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "oauth_browser_generations_client_id_fkey",
                "f",
                "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
                (3,),
                ("oauth_clients", ("client_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "oauth_browser_generations_generation_id_check",
                "c",
                "CHECK (((generation_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            ("oauth_browser_generations_pkey", "p", "PRIMARY KEY (generation_id)", (1,), None, " ", " ", False, False),
            (
                "oauth_browser_generations_proof_id_check",
                "c",
                "CHECK (((proof_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (5,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            ("oauth_browser_generations_proof_id_key", "u", "UNIQUE (proof_id)", (5,), None, " ", " ", False, False),
            (
                "oauth_browser_generations_subject_check",
                "c",
                "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
                (4,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "oauth_browser_generations_user_id_fkey",
                "f",
                "FOREIGN KEY (user_id) REFERENCES users(id)",
                (2,),
                ("users", ("id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "uq_browser_generation_owner",
                "u",
                "UNIQUE (generation_id, user_id, client_id, subject)",
                (1, 2, 3, 4),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
        "social_messaging_device_bindings": (
            (
                "ck_social_messaging_device_active_state",
                "c",
                "CHECK ((((active = true) AND ((operation)::text = ANY "
                "((ARRAY['register'::character varying, 'rotate'::character "
                "varying])::text[])) AND (retired_at IS NULL)) OR ((active = false) AND "
                "(retired_at IS NOT NULL))))",
                (13, 10, 14),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_algorithm",
                "c",
                "CHECK (((algorithm)::text = 'x25519-v1'::text))",
                (5,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_binding_id",
                "c",
                "CHECK (((binding_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_device_id",
                "c",
                "CHECK (((device_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (4,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_operation",
                "c",
                "CHECK (((operation)::text = ANY ((ARRAY['register'::character varying, "
                "'rotate'::character varying, 'revoke'::character varying])::text[])))",
                (10,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_prior",
                "c",
                "CHECK (((((operation)::text = 'register'::text) AND (prior_binding_id "
                "IS NULL) AND (binding_version = 1)) OR (((operation)::text = ANY "
                "((ARRAY['rotate'::character varying, 'revoke'::character "
                "varying])::text[])) AND (prior_binding_id IS NOT NULL) AND "
                "(binding_version >= 2))))",
                (10, 11, 7),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_public_key",
                "c",
                "CHECK (((public_key)::text ~ '^[0-9a-f]{64}$'::text))",
                (6,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_request_id",
                "c",
                "CHECK (((request_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (12,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_schema",
                "c",
                "CHECK (((record_schema)::text = " "'hodlxxi.social_messaging_device_binding_record.v1'::text))",
                (2,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_subject",
                "c",
                "CHECK (((subject_pubkey)::text ~ '^[0-9a-f]{64}$'::text))",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_validity",
                "c",
                "CHECK ((valid_from < expires_at))",
                (8, 9),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "ck_social_messaging_device_version",
                "c",
                "CHECK (((binding_version >= 1) AND (binding_version <= 1024)))",
                (7,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "fk_social_messaging_device_prior",
                "f",
                "FOREIGN KEY (prior_binding_id) REFERENCES " "social_messaging_device_bindings(binding_id)",
                (11,),
                ("social_messaging_device_bindings", ("binding_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_messaging_device_bindings_pkey",
                "p",
                "PRIMARY KEY (binding_id)",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "uq_social_messaging_device_authorization_identity",
                "u",
                "UNIQUE (binding_id, subject_pubkey, device_id, public_key, "
                "binding_version, operation, valid_from, expires_at)",
                (1, 3, 4, 6, 7, 10, 8, 9),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "uq_social_messaging_device_subject_device_version",
                "u",
                "UNIQUE (subject_pubkey, device_id, binding_version)",
                (3, 4, 7),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "uq_social_messaging_device_subject_request",
                "u",
                "UNIQUE (subject_pubkey, request_id)",
                (3, 12),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
        "social_session_issuers": (
            (
                "social_session_issuers_backend_id_check",
                "c",
                "CHECK ((length((backend_id)::text) > 0))",
                (2,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_session_issuers_client_id_backend_id_service_princip_key",
                "u",
                "UNIQUE (client_id, backend_id, service_principal)",
                (1, 2, 3),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_session_issuers_client_id_fkey",
                "f",
                "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
                (1,),
                ("oauth_clients", ("client_id",)),
                "a",
                "a",
                False,
                False,
            ),
            ("social_session_issuers_pkey", "p", "PRIMARY KEY (client_id)", (1,), None, " ", " ", False, False),
            (
                "social_session_issuers_service_principal_check",
                "c",
                "CHECK ((length((service_principal)::text) > 0))",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
        "social_messaging_mobile_operations": (
            (
                "social_messaging_mobile_opera_operation_id_request_id_autho_key",
                "u",
                "UNIQUE (operation_id, request_id, authorization_digest)",
                (1, 10, 11),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_authorization_digest_key",
                "u",
                "UNIQUE (authorization_digest)",
                (11,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_check",
                "c",
                "CHECK (((created_at < expires_at) AND (expires_at <= (created_at + " "300))))",
                (6, 7),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_check1",
                "c",
                "CHECK (((((method)::text = 'legacy_challenge_v1'::text) AND "
                "((operation_id)::text ~ "
                "'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'::text) "
                "AND (revision IS NULL) AND (secret_commitment IS NULL) AND (source "
                "IS NOT NULL) AND ((status)::text <> ALL ((ARRAY['created'::character "
                "varying, 'awaiting-approval'::character varying, "
                "'approval-claimed'::character varying])::text[]))) OR "
                "(((method)::text = 'qr_desktop_v1'::text) AND ((operation_id)::text "
                "~ '^[0-9a-f]{64}$'::text) AND ((revision)::text ~ "
                "'^[0-9a-f]{64}$'::text) AND (revision IS NOT NULL) AND "
                "((secret_commitment)::text ~ '^[0-9a-f]{64}$'::text) AND "
                "(secret_commitment IS NOT NULL) AND ((status)::text <> "
                "'reserved'::text))))",
                (2, 1, 8, 9, 12, 13),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_check2",
                "c",
                "CHECK ((((source IS NULL) AND (request_id IS NULL) AND "
                "(authorization_digest IS NULL) AND ((status)::text = ANY "
                "((ARRAY['created'::character varying, 'expired'::character varying, "
                "'cancelled'::character varying, 'abandoned'::character varying, "
                "'rejected'::character varying])::text[]))) OR ((source IS NOT NULL) "
                "AND ((octet_length(source) >= 1) AND (octet_length(source) <= "
                "16384)) AND (request_id IS NOT NULL) AND ((request_id)::text ~ "
                "'^[0-9a-f]{64}$'::text) AND (authorization_digest IS NOT NULL) AND "
                "((authorization_digest)::text ~ '^[0-9a-f]{64}$'::text) AND "
                "((status)::text <> 'created'::text))))",
                (12, 10, 11, 13),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_context_id_check",
                "c",
                "CHECK (((context_id)::text ~ '^[0-9a-f]{64}$'::text))",
                (4,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_created_at_check",
                "c",
                "CHECK ((created_at >= 0))",
                (6,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_method_check",
                "c",
                "CHECK (((method)::text = ANY "
                "((ARRAY['legacy_challenge_v1'::character varying, "
                "'qr_desktop_v1'::character varying])::text[])))",
                (2,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_pkey",
                "p",
                "PRIMARY KEY (operation_id)",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_request_id_fkey",
                "f",
                "FOREIGN KEY (request_id) REFERENCES " "social_messaging_device_authorization_requests(request_id)",
                (10,),
                ("social_messaging_device_authorization_requests", ("request_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_request_id_key",
                "u",
                "UNIQUE (request_id)",
                (10,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_session_commitment_check",
                "c",
                "CHECK (((session_commitment)::text ~ '^[0-9a-f]{64}$'::text))",
                (5,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_status_check",
                "c",
                "CHECK (((status)::text = ANY ((ARRAY['created'::character varying, "
                "'reserved'::character varying, 'awaiting-approval'::character "
                "varying, 'approval-claimed'::character varying, "
                "'accepted'::character varying, 'expired'::character varying, "
                "'cancelled'::character varying, 'abandoned'::character varying, "
                "'rejected'::character varying])::text[])))",
                (13,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_mobile_operations_subject_check",
                "c",
                "CHECK (((subject)::text ~ '^[0-9a-f]{64}$'::text))",
                (3,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "trg_social_mobile_operation_receipt",
                "t",
                "TRIGGER DEFERRABLE INITIALLY DEFERRED",
                None,
                None,
                " ",
                " ",
                True,
                True,
            ),
        ),
        "social_messaging_device_authorization_binding_owners": (
            (
                "social_messaging_device_authorization_binding_o_binding_id_fkey",
                "f",
                "FOREIGN KEY (binding_id) REFERENCES "
                "social_messaging_device_bindings(binding_id) ON "
                "DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED",
                (1,),
                ("social_messaging_device_bindings", ("binding_id",)),
                "a",
                "r",
                True,
                True,
            ),
            (
                "social_messaging_device_authorization_binding_o_request_id_fkey",
                "f",
                "FOREIGN KEY (request_id) REFERENCES "
                "social_messaging_device_authorization_requests(request_id) "
                "DEFERRABLE INITIALLY DEFERRED",
                (2,),
                ("social_messaging_device_authorization_requests", ("request_id",)),
                "a",
                "a",
                True,
                True,
            ),
            (
                "social_messaging_device_authorization_binding_ow_request_id_key",
                "u",
                "UNIQUE (request_id)",
                (2,),
                None,
                " ",
                " ",
                False,
                False,
            ),
            (
                "social_messaging_device_authorization_binding_owners_pkey",
                "p",
                "PRIMARY KEY (binding_id)",
                (1,),
                None,
                " ",
                " ",
                False,
                False,
            ),
        ),
    }
)

AUTHORITY_INDEXES = MappingProxyType(
    {
        "users": (
            ("idx_user_created", "n", (3,), None),
            ("idx_user_pubkey", "n", (2,), None),
            ("ix_users_pubkey", "u", (2,), None),
            ("users_pkey", "p", (1,), None),
        ),
        "current_entitlement_evidence": (
            ("current_entitlement_evidence_pkey", "p", (1,), None),
            ("idx_current_entitlement_revoked_at", "n", (11,), None),
            ("idx_current_entitlement_subject", "n", (3,), None),
            ("idx_current_entitlement_subject_created", "n", (3, 12), None),
            ("idx_current_entitlement_subject_observed", "n", (3, 9), None),
            ("idx_current_entitlement_valid_until", "n", (10,), None),
        ),
        "oauth_tokens": (
            ("idx_token_access", "n", (2,), None),
            ("idx_token_expires", "n", (9,), None),
            ("idx_token_refresh", "n", (3,), None),
            ("idx_token_user", "n", (6,), None),
            ("ix_oauth_tokens_access_token", "u", (2,), None),
            ("ix_oauth_tokens_refresh_token", "u", (3,), None),
            ("oauth_tokens_pkey", "p", (1,), None),
            ("uq_oauth_token_generation_owner", "u", (1, 6, 5), None),
        ),
        "sessions": (
            ("idx_session_active", "n", (10, 5), None),
            ("idx_session_expires", "n", (5,), None),
            ("idx_session_user", "n", (2,), None),
            ("sessions_pkey", "p", (1,), None),
            ("uq_session_generation_owner", "u", (1, 2), None),
        ),
        "oauth_clients": (
            ("idx_client_created", "n", (9,), None),
            ("idx_client_name", "n", (3,), None),
            ("oauth_clients_pkey", "p", (1,), None),
        ),
        "oauth_session_generations": (
            ("idx_oauth_generation_browser", "n", (2,), None),
            ("idx_oauth_generation_owner", "n", (4, 5), None),
            ("oauth_session_generations_pkey", "p", (1,), None),
            ("oauth_session_generations_session_id_key", "u", (3,), None),
        ),
        "oauth_browser_generations": (
            ("idx_browser_generation_owner", "n", (2, 3), None),
            ("oauth_browser_generations_pkey", "p", (1,), None),
            ("oauth_browser_generations_proof_id_key", "u", (5,), None),
            ("uq_browser_generation_current", "u", (2, 3), "(is_active IS TRUE)"),
            ("uq_browser_generation_owner", "u", (1, 2, 3, 4), None),
        ),
        "social_messaging_device_bindings": (
            ("idx_social_messaging_device_current_subject", "n", (3, 13, 4), None),
            ("idx_social_messaging_device_expires_at", "n", (9,), None),
            ("social_messaging_device_bindings_pkey", "p", (1,), None),
            ("uq_social_messaging_device_active_device", "u", (3, 4), "(active = true)"),
            ("uq_social_messaging_device_active_public_key", "u", (6,), "(active = true)"),
            ("uq_social_messaging_device_authorization_identity", "u", (1, 3, 4, 6, 7, 10, 8, 9), None),
            (
                "uq_social_messaging_device_historical_public_key",
                "u",
                (6,),
                "((operation)::text = ANY ((ARRAY['register'::character varying, "
                "'rotate'::character varying])::text[]))",
            ),
            ("uq_social_messaging_device_subject_device_version", "u", (3, 4, 7), None),
            ("uq_social_messaging_device_subject_request", "u", (3, 12), None),
        ),
        "social_session_issuers": (
            ("social_session_issuers_client_id_backend_id_service_princip_key", "u", (1, 2, 3), None),
            ("social_session_issuers_pkey", "p", (1,), None),
        ),
        "social_messaging_mobile_operations": (
            ("idx_social_mobile_expiry", "n", (13, 7), None),
            ("social_messaging_mobile_opera_operation_id_request_id_autho_key", "u", (1, 10, 11), None),
            ("social_messaging_mobile_operations_authorization_digest_key", "u", (11,), None),
            ("social_messaging_mobile_operations_pkey", "p", (1,), None),
            ("social_messaging_mobile_operations_request_id_key", "u", (10,), None),
        ),
        "social_messaging_device_authorization_binding_owners": (
            ("social_messaging_device_authorization_binding_ow_request_id_key", "u", (2,), None),
            ("social_messaging_device_authorization_binding_owners_pkey", "p", (1,), None),
        ),
    }
)

AUTHORITY_TRIGGERS = MappingProxyType(
    {
        "users": (
            (
                "trg_oauth_user_session_invalidation",
                "oauth_owner_session_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_oauth_user_session_invalidation BEFORE UPDATE ON public.users FOR EACH ROW "
                "EXECUTE FUNCTION oauth_owner_session_invalidation_v1()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.users FOR EACH ROW EXECUTE "
                "FUNCTION social_session_v2_invalidate()",
            ),
        ),
        "current_entitlement_evidence": (),
        "oauth_tokens": (
            (
                "trg_oauth_token_session_invalidation",
                "oauth_token_session_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_oauth_token_session_invalidation BEFORE UPDATE ON public.oauth_tokens "
                "FOR EACH ROW EXECUTE FUNCTION oauth_token_session_invalidation_v1()",
            ),
            (
                "trg_social_session_token_guard",
                "social_session_token_guard_v1",
                19,
                None,
                "CREATE TRIGGER trg_social_session_token_guard BEFORE UPDATE ON public.oauth_tokens FOR "
                "EACH ROW EXECUTE FUNCTION social_session_token_guard_v1()",
            ),
            (
                "v2_birth",
                "social_session_v2_birth",
                5,
                None,
                "CREATE TRIGGER v2_birth AFTER INSERT ON public.oauth_tokens FOR EACH ROW EXECUTE FUNCTION "
                "social_session_v2_birth()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_tokens FOR EACH ROW "
                "EXECUTE FUNCTION social_session_v2_invalidate()",
            ),
        ),
        "sessions": (
            (
                "trg_oauth_mapped_session_guard",
                "oauth_mapped_session_guard_v1",
                19,
                None,
                "CREATE TRIGGER trg_oauth_mapped_session_guard BEFORE UPDATE ON public.sessions FOR EACH ROW "
                "EXECUTE FUNCTION oauth_mapped_session_guard_v1()",
            ),
            (
                "trg_social_session_parent_invalidation",
                "social_session_parent_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_social_session_parent_invalidation BEFORE UPDATE ON public.sessions FOR "
                "EACH ROW EXECUTE FUNCTION social_session_parent_invalidation_v1()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.sessions FOR EACH ROW EXECUTE "
                "FUNCTION social_session_v2_invalidate()",
            ),
        ),
        "oauth_clients": (
            (
                "trg_oauth_client_session_invalidation",
                "oauth_owner_session_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_oauth_client_session_invalidation BEFORE UPDATE ON "
                "public.oauth_clients FOR EACH ROW EXECUTE FUNCTION oauth_owner_session_invalidation_v1()",
            ),
            (
                "trg_social_session_client_invalidation",
                "social_session_client_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_social_session_client_invalidation BEFORE UPDATE ON "
                "public.oauth_clients FOR EACH ROW EXECUTE FUNCTION "
                "social_session_client_invalidation_v1()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON public.oauth_clients FOR EACH ROW "
                "EXECUTE FUNCTION social_session_v2_invalidate()",
            ),
        ),
        "oauth_session_generations": (
            (
                "trg_oauth_generation_guard",
                "oauth_session_generation_guard_v1",
                31,
                None,
                "CREATE TRIGGER trg_oauth_generation_guard BEFORE INSERT OR DELETE OR UPDATE "
                "ON public.oauth_session_generations FOR EACH ROW EXECUTE FUNCTION "
                "oauth_session_generation_guard_v1()",
            ),
        ),
        "oauth_browser_generations": (
            (
                "trg_oauth_browser_generation_guard",
                "oauth_browser_generation_guard_v1",
                31,
                None,
                "CREATE TRIGGER trg_oauth_browser_generation_guard BEFORE INSERT OR DELETE OR "
                "UPDATE ON public.oauth_browser_generations FOR EACH ROW EXECUTE FUNCTION "
                "oauth_browser_generation_guard_v1()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
                "public.oauth_browser_generations FOR EACH ROW EXECUTE FUNCTION "
                "social_session_v2_invalidate()",
            ),
        ),
        "social_messaging_device_bindings": (
            (
                "trg_social_session_binding_invalidation",
                "social_session_binding_invalidation_v1",
                19,
                None,
                "CREATE TRIGGER trg_social_session_binding_invalidation BEFORE UPDATE "
                "ON public.social_messaging_device_bindings FOR EACH ROW EXECUTE "
                "FUNCTION social_session_binding_invalidation_v1()",
            ),
            (
                "v2_birth",
                "social_session_v2_birth",
                5,
                None,
                "CREATE TRIGGER v2_birth AFTER INSERT ON "
                "public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION "
                "social_session_v2_birth()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
                "public.social_messaging_device_bindings FOR EACH ROW EXECUTE FUNCTION "
                "social_session_v2_invalidate()",
            ),
        ),
        "social_session_issuers": (
            (
                "trg_social_session_issuer_guard",
                "social_session_issuer_guard_v1",
                31,
                None,
                "CREATE TRIGGER trg_social_session_issuer_guard BEFORE INSERT OR DELETE OR UPDATE "
                "ON public.social_session_issuers FOR EACH ROW EXECUTE FUNCTION "
                "social_session_issuer_guard_v1()",
            ),
            (
                "v2_invalidate",
                "social_session_v2_invalidate",
                27,
                None,
                "CREATE TRIGGER v2_invalidate BEFORE DELETE OR UPDATE ON "
                "public.social_session_issuers FOR EACH ROW EXECUTE FUNCTION "
                "social_session_v2_invalidate()",
            ),
        ),
        "social_messaging_mobile_operations": (
            (
                "trg_social_mobile_operation_guard",
                "guard_social_mobile_operation_v1",
                31,
                None,
                "CREATE TRIGGER trg_social_mobile_operation_guard BEFORE INSERT OR "
                "DELETE OR UPDATE ON public.social_messaging_mobile_operations FOR "
                "EACH ROW EXECUTE FUNCTION guard_social_mobile_operation_v1()",
            ),
            (
                "trg_social_mobile_operation_receipt",
                "validate_social_mobile_acceptance_v1",
                21,
                "trg_social_mobile_operation_receipt",
                "CREATE CONSTRAINT TRIGGER trg_social_mobile_operation_receipt AFTER "
                "INSERT OR UPDATE ON public.social_messaging_mobile_operations "
                "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "
                "validate_social_mobile_acceptance_v1()",
            ),
        ),
        "social_messaging_device_authorization_binding_owners": (
            (
                "trg_social_binding_owner_immutable",
                "reject_social_device_authorization_mutation_v1",
                27,
                None,
                "CREATE TRIGGER trg_social_binding_owner_immutable "
                "BEFORE DELETE OR UPDATE ON "
                "public.social_messaging_device_authorization_binding_owners "
                "FOR EACH ROW EXECUTE FUNCTION "
                "reject_social_device_authorization_mutation_v1()",
            ),
        ),
    }
)

EXTERNAL_AUTHORITY_FKS = MappingProxyType(
    {
        "oauth_codes": (
            (
                "oauth_codes_client_id_fkey",
                "f",
                "FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)",
                (2,),
                ("oauth_clients", ("client_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "oauth_codes_user_id_fkey",
                "f",
                "FOREIGN KEY (user_id) REFERENCES users(id)",
                (3,),
                ("users", ("id",)),
                "a",
                "a",
                False,
                False,
            ),
        ),
        "oauth_session_code_bindings": (
            (
                "oauth_session_code_bindings_browser_generation_id_fkey",
                "f",
                "FOREIGN KEY (browser_generation_id) REFERENCES " "oauth_browser_generations(generation_id)",
                (2,),
                ("oauth_browser_generations", ("generation_id",)),
                "a",
                "a",
                False,
                False,
            ),
        ),
        "social_messaging_device_binding_authorization_evidence": (
            (
                "fk_social_device_authorization_evidence_binding",
                "f",
                "FOREIGN KEY (binding_id, subject_pubkey, "
                "device_id, public_key, binding_version, "
                "binding_operation, binding_valid_from, "
                "binding_expires_at) REFERENCES "
                "social_messaging_device_bindings(binding_id, "
                "subject_pubkey, device_id, public_key, "
                "binding_version, operation, valid_from, "
                "expires_at) ON DELETE RESTRICT DEFERRABLE "
                "INITIALLY DEFERRED",
                (1, 7, 8, 9, 10, 11, 12, 13),
                (
                    "social_messaging_device_bindings",
                    (
                        "binding_id",
                        "subject_pubkey",
                        "device_id",
                        "public_key",
                        "binding_version",
                        "operation",
                        "valid_from",
                        "expires_at",
                    ),
                ),
                "a",
                "r",
                True,
                True,
            ),
        ),
        "social_messaging_mobile_acceptances": (
            (
                "social_messaging_mobile_accep_operation_id_request_id_auth_fkey",
                "f",
                "FOREIGN KEY (operation_id, request_id, authorization_digest) "
                "REFERENCES social_messaging_mobile_operations(operation_id, "
                "request_id, authorization_digest) ON DELETE RESTRICT DEFERRABLE "
                "INITIALLY DEFERRED",
                (1, 2, 3),
                ("social_messaging_mobile_operations", ("operation_id", "request_id", "authorization_digest")),
                "a",
                "r",
                True,
                True,
            ),
            (
                "social_messaging_mobile_acceptances_binding_id_fkey",
                "f",
                "FOREIGN KEY (binding_id) REFERENCES "
                "social_messaging_device_bindings(binding_id) ON DELETE RESTRICT",
                (4,),
                ("social_messaging_device_bindings", ("binding_id",)),
                "a",
                "r",
                False,
                False,
            ),
        ),
        "social_session_issuances": (
            (
                "social_session_issuances_binding_id_fkey",
                "f",
                "FOREIGN KEY (binding_id) REFERENCES " "social_messaging_device_bindings(binding_id)",
                (10,),
                ("social_messaging_device_bindings", ("binding_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_session_issuances_client_id_backend_id_service_prin_fkey",
                "f",
                "FOREIGN KEY (client_id, backend_id, service_principal) REFERENCES "
                "social_session_issuers(client_id, backend_id, service_principal)",
                (5, 6, 7),
                ("social_session_issuers", ("client_id", "backend_id", "service_principal")),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_session_issuances_token_id_user_id_client_id_fkey",
                "f",
                "FOREIGN KEY (token_id, user_id, client_id) REFERENCES oauth_tokens(id, " "user_id, client_id)",
                (3, 8, 5),
                ("oauth_tokens", ("id", "user_id", "client_id")),
                "a",
                "a",
                False,
                False,
            ),
        ),
        "social_session_pairing_parents": (
            (
                "social_session_pairing_parents_client_id_fkey",
                "f",
                "FOREIGN KEY (client_id) REFERENCES social_session_issuers(client_id)",
                (3,),
                ("social_session_issuers", ("client_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_session_pairing_parents_operation_id_fkey",
                "f",
                "FOREIGN KEY (operation_id) REFERENCES " "social_messaging_mobile_operations(operation_id)",
                (1,),
                ("social_messaging_mobile_operations", ("operation_id",)),
                "a",
                "a",
                False,
                False,
            ),
            (
                "social_session_pairing_parents_parent_token_id_fkey",
                "f",
                "FOREIGN KEY (parent_token_id) REFERENCES " "oauth_session_generations(token_id)",
                (2,),
                ("oauth_session_generations", ("token_id",)),
                "a",
                "a",
                False,
                False,
            ),
        ),
    }
)

EXTERNAL_BINDING_COLUMNS = MappingProxyType(
    {
        "oauth_session_code_bindings": ((2, "browser_generation_id", 1043, 68, True),),
        "social_messaging_device_binding_authorization_evidence": (
            (1, "binding_id", 1043, 68, True),
            (7, "subject_pubkey", 1043, 68, True),
            (8, "device_id", 1043, 68, True),
            (9, "public_key", 1043, 68, True),
            (10, "binding_version", 20, -1, True),
            (11, "binding_operation", 1043, 12, True),
            (12, "binding_valid_from", 1184, -1, True),
            (13, "binding_expires_at", 1184, -1, True),
        ),
        "social_session_issuances": (
            (3, "token_id", 1043, 40, True),
            (5, "client_id", 1043, 259, True),
            (6, "backend_id", 1043, 259, True),
            (7, "service_principal", 1043, 259, True),
            (8, "user_id", 1043, 40, True),
            (10, "binding_id", 1043, 68, True),
        ),
        "social_messaging_device_authorization_requests": ((1, "request_id", 1043, 68, True),),
        "social_messaging_mobile_acceptances": (
            (1, "operation_id", 1043, 68, True),
            (2, "request_id", 1043, 68, True),
            (3, "authorization_digest", 1043, 68, True),
            (4, "binding_id", 1043, 68, True),
        ),
        "social_session_pairing_parents": (
            (1, "operation_id", 1043, 68, True),
            (2, "parent_token_id", 1043, 40, True),
            (3, "client_id", 1043, 259, True),
        ),
        "oauth_codes": ((2, "client_id", 1043, 259, True), (3, "user_id", 1043, 40, True)),
    }
)

AUTHORITY_ACLS = MappingProxyType(
    {
        "users": ("SELECT", "UPDATE"),
        "current_entitlement_evidence": ("SELECT", "UPDATE"),
        "oauth_tokens": ("INSERT", "SELECT", "UPDATE"),
        "sessions": ("SELECT", "UPDATE"),
        "oauth_clients": ("SELECT", "UPDATE"),
        "oauth_session_generations": ("SELECT",),
        "oauth_browser_generations": ("SELECT", "UPDATE"),
        "social_messaging_device_bindings": ("INSERT", "SELECT", "UPDATE"),
        "social_session_issuers": ("SELECT", "UPDATE"),
        "social_messaging_mobile_operations": ("SELECT",),
        "social_messaging_device_authorization_binding_owners": ("SELECT",),
    }
)

AUTHORITY_NO_TOAST = frozenset(
    (
        "current_entitlement_evidence",
        "oauth_browser_generations",
        "social_messaging_device_bindings",
        "social_messaging_device_authorization_binding_owners",
    )
)


def _v2_definition_profiles():
    """Freeze only the seven pinned original constraint contracts, once.

    This reads Python source constants, never installed catalogs or the filesystem.
    The original attestor is still invoked by NativeV2Effects.check on its guard.
    """
    from app.services.social_session_issuance_v2_storage import CONSTRAINTS

    return MappingProxyType(
        {
            name: tuple(
                (n, kind, definition, tuple(keys), target) for n, kind, definition, keys, target in CONSTRAINTS[name]
            )
            for name in DEPENDENCY_COLUMNS
            if name.startswith("social_session_v2_")
        }
    )


V2_DEFINITION_PROFILES = _v2_definition_profiles()


def _definition_columns(name):
    if name in DEPENDENCY_COLUMNS:
        return DEPENDENCY_COLUMNS[name]
    if name == "social_messaging_device_authorization_requests":
        return (("request_id", 1043, 68, True),)
    if name in SHARED_COLUMNS:
        return SHARED_COLUMNS[name]
    if name in NATIVE_COLUMNS:
        return tuple((*column, True) for column in NATIVE_COLUMNS[name])
    if name == challenges.TABLE:
        return (
            ("challenge_id", 1043, 68, True),
            ("context_wire", 25, -1, True),
            ("challenge_wire", 25, -1, True),
            ("routing_request_wire", 25, -1, False),
            ("state", 1043, 15, True),
        )
    if name == "social_device_admission_challenge_revisions":
        return (("challenge_id", 1043, 68, True), ("revision", 23, -1, True))
    _deny()


def _attest_dependency_parent_key(connection, relations, target, target_names):
    """Validate a canonical required key; this does not attest unrelated schema.

    Parent identity originates in the separate public binding/visibility read.
    Key and index names/ordered types originate in the pinned contracts, not in
    a foreign key's claim about its parent/index OIDs.
    """
    relation = relations[target]
    columns = _definition_columns(target)
    keys = tuple(next(i for i, c in enumerate(columns, 1) if c[0] == name) for name in target_names)
    if target in AUTHORITY_CONSTRAINTS:
        specs = [
            (n, kind, k) for n, kind, _, k, *_ in AUTHORITY_CONSTRAINTS[target] if kind in ("p", "u") and k == keys
        ]
    elif target in V2_DEFINITION_PROFILES:
        specs = [
            (n, kind, k) for n, kind, _, k, _ in V2_DEFINITION_PROFILES[target] if kind in ("p", "u") and k == keys
        ]
    else:
        if keys != (1,):
            _deny()
        specs = [(target + "_pkey", "p", keys)]
    if len(specs) != 1:
        _deny()
    name, kind, keys = specs[0]
    rows = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(k) AS constraint,
        pg_catalog.pg_get_constraintdef(k.oid,false) AS definition
        FROM pg_catalog.pg_constraint k WHERE k.conrelid=:oid AND k.conname=:name"""),
            {"oid": relation["oid"], "name": name},
        )
        .mappings()
        .all()
    )
    if len(rows) != 1 or set(rows[0]) != {"constraint", "definition"}:
        _deny()
    c = _native_catalog_object(rows[0]["constraint"], "constraint")
    constraint_oid = c.pop("oid")
    index = c["conindid"]
    wanted = _definition_constraint(relation, name, kind, keys, index=index)
    if (
        c != wanted
        or rows[0]["definition"] != ("PRIMARY KEY" if kind == "p" else "UNIQUE") + " (" + ", ".join(target_names) + ")"
    ):
        _deny()
    index_rows = (
        connection.execute(
            text(SHARED_INDEXES_SQL.replace("WHERE i.indrelid=:oid", "WHERE i.indrelid=:oid AND c.relname=:name")),
            {"oid": relation["oid"], "name": name},
        )
        .mappings()
        .all()
    )
    indexes, pins = _attest_index_definitions(index_rows, relation, columns, {name: (kind, keys, None)})
    if index <= 0 or indexes[name] != index:
        _deny()
    return index, ((constraint_oid, _wire(c)), *pins)


def _definition_constraint(relation, name, kind, keys, *, index=0, parent=0, parent_keys=None, operators=None):
    return dict(
        conname=name,
        connamespace=relation["relnamespace"],
        contype=kind,
        condeferrable=kind == "t",
        condeferred=kind == "t",
        convalidated=True,
        conrelid=relation["oid"],
        contypid=0,
        conindid=index,
        conparentid=0,
        confrelid=parent,
        confupdtype="a" if kind == "f" else " ",
        confdeltype="a" if kind == "f" else " ",
        confmatchtype="s" if kind == "f" else " ",
        conislocal=True,
        coninhcount=0,
        connoinherit=kind != "c",
        conkey=list(keys) if keys is not None else None,
        confkey=list(parent_keys) if parent_keys is not None else None,
        conpfeqop=operators,
        conppeqop=operators,
        conffeqop=operators,
        confdelsetcols=None,
        conexclop=None,
        conbin=None,
    )


def _attest_dependency_definitions(connection, relations, functions):
    """Fresh supplementary source definitions on the caller's same Connection.

    Ordered model attributes and seven original companions remain independently
    checked. Eleven authority profiles close their source definitions and only
    the required external FK/key bindings, without recursive schema traversal.
    """
    identities = []
    constraint_pins = {}
    for name, columns in DEPENDENCY_COLUMNS.items():
        relation = relations[name]
        alternatives = ()
        if relation["relnatts"] != len(columns):
            _deny()
        identities.append((name, _attest_shared_attributes(connection, relation, columns, alternatives=alternatives)))
        if name not in V2_DEFINITION_PROFILES:
            continue
        profiles = V2_DEFINITION_PROFILES[name]
        expected = {n: (kind, definition, keys, target) for n, kind, definition, keys, target in profiles}
        if name == "social_session_v2_offers":
            expected["v2_complete"] = ("t", "TRIGGER DEFERRABLE INITIALLY DEFERRED", None, None)
        identities.extend(
            _attest_relation_definition(
                connection,
                relation,
                column_count=len(columns),
                checks=sum(p[1] == "c" for p in profiles),
                has_toast=name != "social_session_v2_invalidations",
            )
        )
        readonly = name in (
            "social_session_v2_invalidations",
            "social_session_v2_binding_births",
            "social_session_v2_token_births",
        )
        identities.append(
            _attest_shared_acl(connection, relation, profiles=(("SELECT",) if readonly else ("SELECT", "INSERT"),))
        )
        index_specs = {n: (kind, keys, None) for n, (kind, _, keys, _) in expected.items() if kind in ("p", "u")}
        indexes, pins = _attest_shared_indexes(connection, relation, columns, index_specs)
        identities.extend(pins)
        rows = connection.execute(text(SHARED_CONSTRAINTS_SQL), {"oid": relation["oid"]}).mappings().all()
        if len(rows) != len(expected):
            _deny()
        seen = set()
        for row in rows:
            if set(row) != {"constraint", "definition"}:
                _deny()
            c = _native_catalog_object(row["constraint"], "constraint")
            descriptor = dict(c)
            constraint_oid = c.pop("oid")
            n = c["conname"]
            if n not in expected or n in seen:
                _deny()
            seen.add(n)
            kind, definition, keys, target = expected[n]
            parent, parent_keys, operators = 0, None, None
            index = indexes[n] if kind in ("p", "u") else 0
            if target:
                parent_name, parent_names = target
                parent_columns = _definition_columns(parent_name)
                parent_keys = tuple(
                    next(i for i, col in enumerate(parent_columns, 1) if col[0] == key) for key in parent_names
                )
                operators = [{20: 410, 23: 96, 25: 98, 1043: 98}[parent_columns[k - 1][1]] for k in parent_keys]
                parent = relations[parent_name]["oid"]
                index, pins = _attest_dependency_parent_key(connection, relations, parent_name, parent_names)
                identities.extend(pins)
            tree = c.pop("conbin")
            wanted = _definition_constraint(
                relation, n, kind, keys, index=index, parent=parent, parent_keys=parent_keys, operators=operators
            )
            wanted.pop("conbin")
            definitions = {definition}
            if target:
                definitions.add(definition.replace("REFERENCES ", "REFERENCES public.", 1))
            if c != wanted or row["definition"] not in definitions or (tree is not None) != (kind == "c"):
                _deny()
            if tree is not None and (type(tree) is not str or not tree):
                _deny()
            identities.append((constraint_oid, _wire(c), tree))
            constraint_pins[(name, n)] = descriptor
        identities.extend(_attest_dependency_triggers(connection, relation, functions, constraint_pins, readonly))
    pins, constraints = _attest_authority_definitions(connection, relations, functions)
    identities.extend(pins)
    constraint_pins.update(constraints)
    return tuple(identities), constraint_pins


def _attest_dependency_triggers(connection, relation, functions, constraint_pins, readonly):
    from app.services.social_session_issuance_v2_storage import trigger_definitions

    name = relation["relname"]
    expected = {
        "v2_immutable": ("social_session_v2_immutable", 27, False),
        "v2_no_truncate": ("social_session_v2_immutable", 34, False),
    }
    if not readonly:
        expected["v2_insert"] = ("social_session_v2_guard", 7, False)
    if name == "social_session_v2_offers":
        expected["v2_complete"] = ("social_session_v2_complete", 5, True)
    rows = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(t) AS trigger,
        pg_catalog.pg_get_triggerdef(t.oid,false) AS definition
        FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname"""),
            {"oid": relation["oid"]},
        )
        .mappings()
        .all()
    )
    if len(rows) != len(expected):
        _deny()
    declarations = trigger_definitions(name)
    seen, identities = set(), []
    for row in rows:
        if set(row) != {"trigger", "definition"}:
            _deny()
        t = _native_catalog_object(row["trigger"], "trigger")
        trigger_oid = t.pop("oid")
        n = t["tgname"]
        if n not in expected or n in seen:
            _deny()
        seen.add(n)
        fn, kind, deferred = expected[n]
        constraint = constraint_pins[(name, n)]["oid"] if deferred else 0
        wanted = dict(
            tgrelid=relation["oid"],
            tgparentid=0,
            tgname=n,
            tgfoid=functions[fn],
            tgtype=kind,
            tgenabled="O",
            tgisinternal=False,
            tgconstrrelid=0,
            tgconstrindid=0,
            tgconstraint=constraint,
            tgdeferrable=deferred,
            tginitdeferred=deferred,
            tgnargs=0,
            tgattr="",
            tgargs="\\x",
            tgqual=None,
            tgoldtable=None,
            tgnewtable=None,
        )
        declaration = next(
            d
            for d in declarations
            if d.startswith("CREATE TRIGGER " + n + " ") or d.startswith("CREATE CONSTRAINT TRIGGER " + n + " ")
        )
        allowed = (declaration, declaration.replace("EXECUTE FUNCTION " + fn, "EXECUTE FUNCTION public." + fn))
        if t != wanted or row["definition"] not in allowed:
            _deny()
        identities.append((trigger_oid, _wire(t)))
    return tuple(identities)


AUTHORITY_EFFECTIVE_ACL_SQL = """
SELECT pg_catalog.has_table_privilege(current_user,:oid,'SELECT'),
 pg_catalog.has_table_privilege(current_user,:oid,'INSERT'),
 pg_catalog.has_table_privilege(current_user,:oid,'UPDATE'),
 pg_catalog.has_table_privilege(current_user,:oid,'DELETE'),
 pg_catalog.has_table_privilege(current_user,:oid,'TRUNCATE'),
 pg_catalog.has_table_privilege(current_user,:oid,'REFERENCES'),
 pg_catalog.has_table_privilege(current_user,:oid,'TRIGGER'),
 pg_catalog.has_any_column_privilege(current_user,:oid,'SELECT'),
 pg_catalog.has_any_column_privilege(current_user,:oid,'INSERT'),
 pg_catalog.has_any_column_privilege(current_user,:oid,'UPDATE'),
 pg_catalog.has_any_column_privilege(current_user,:oid,'REFERENCES')
"""


def _attest_authority_definitions(connection, relations, functions):
    """Closed model/migration definitions; external scope is only FK bindings."""
    identities, constraints = [], {}
    # Canonical visibility is established independently of any FK's claimed OID.
    names = sorted(EXTERNAL_BINDING_COLUMNS)
    rows = connection.execute(text(VISIBILITY_SQL), {"names": names}).mappings().all()
    if len(rows) != len(names):
        _deny()
    seen = set()
    public = relations["users"]["relnamespace"]
    for row in rows:
        if set(row) != {"relname", "relation", "resolves", "owns", "standalone"}:
            _deny()
        r = _native_catalog_object(row["relation"], "relation")
        name = row["relname"]
        _attest_shared_physical_types(r)
        if (
            name not in names
            or name in seen
            or r["relname"] != name
            or r["relnamespace"] != public
            or row["resolves"] is not True
            or row["owns"] is not False
            or row["standalone"] is not True
            or r["relkind"] != "r"
            or r["relpersistence"] != "p"
            or r["reltype"] == 0
            or r["relrowsecurity"]
            or r["relforcerowsecurity"]
            or r["relispartition"]
            or r["relhassubclass"]
            or r["relhasrules"]
            or r["reloftype"] != 0
            or r["relrewrite"] != "0"
            or r["relpartbound"] is not None
            or any(other["oid"] == r["oid"] or other["reltype"] == r["reltype"] for other in relations.values())
        ):
            _deny()
        seen.add(name)
        relations[name] = r
        profile = EXTERNAL_BINDING_COLUMNS[name]
        pins = _attest_shared_attributes(
            connection, r, tuple(c[1:] for c in profile), positions=tuple(c[0] for c in profile)
        )
        identities.append((name, r["oid"], r["reltype"], r["relowner"], pins))
    for name, profiles in AUTHORITY_CONSTRAINTS.items():
        r, columns = relations[name], DEPENDENCY_COLUMNS[name]
        identities.extend(
            _attest_relation_definition(
                connection,
                r,
                column_count=len(columns),
                checks=sum(p[1] == "c" for p in profiles),
                has_toast=name not in AUTHORITY_NO_TOAST,
                has_triggers=bool(AUTHORITY_TRIGGERS[name]),
            )
        )
        indexes, pins = _attest_shared_indexes(
            connection, r, columns, {n: (kind, keys, pred) for n, kind, keys, pred in AUTHORITY_INDEXES[name]}
        )
        identities.extend(pins)
        rows = connection.execute(text(SHARED_CONSTRAINTS_SQL), {"oid": r["oid"]}).mappings().all()
        pins, descriptors = _attest_source_constraints(connection, r, rows, profiles, relations, indexes)
        identities.extend(pins)
        constraints.update(descriptors)
        identities.append(_attest_shared_acl(connection, r, profiles=(AUTHORITY_ACLS[name],)))
        effective = connection.execute(text(AUTHORITY_EFFECTIVE_ACL_SQL), {"oid": r["oid"]}).one()
        order = (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "TRUNCATE",
            "REFERENCES",
            "TRIGGER",
            "SELECT",
            "INSERT",
            "UPDATE",
            "REFERENCES",
        )
        if len(effective) != len(order) or any(type(v) is not bool for v in effective):
            _deny()
        if tuple(effective) != tuple(p in AUTHORITY_ACLS[name] for p in order):
            _deny()
        identities.append(tuple(effective))
    for name, profiles in EXTERNAL_AUTHORITY_FKS.items():
        r = relations[name]
        for profile in profiles:
            rows = (
                connection.execute(
                    text(
                        SHARED_CONSTRAINTS_SQL.replace(
                            "WHERE k.conrelid=:oid", "WHERE k.conrelid=:oid AND k.conname=:name"
                        )
                    ),
                    {"oid": r["oid"], "name": profile[0]},
                )
                .mappings()
                .all()
            )
            pins, descriptors = _attest_source_constraints(connection, r, rows, (profile,), relations, {})
            identities.extend(pins)
            constraints.update(descriptors)
    for name in AUTHORITY_CONSTRAINTS:
        identities.extend(_attest_authority_triggers(connection, relations[name], functions, constraints))
    return tuple(identities), constraints


def _attest_source_constraints(connection, relation, rows, profiles, relations, indexes):
    expected = {p[0]: p for p in profiles}
    if len(rows) != len(expected):
        _deny()
    seen, identities, descriptors = set(), [], {}
    for row in rows:
        if set(row) != {"constraint", "definition"}:
            _deny()
        c = _native_catalog_object(row["constraint"], "constraint")
        descriptor = dict(c)
        oid = c.pop("oid")
        n = c["conname"]
        if n not in expected or n in seen:
            _deny()
        seen.add(n)
        _, kind, definition, keys, target, update, delete, deferrable, deferred = expected[n]
        index = indexes[n] if kind in ("p", "u") else 0
        parent, parent_keys, operators = 0, None, None
        if target:
            parent_name, parent_names = target
            parent_columns = _definition_columns(parent_name)
            parent_keys = tuple(
                next(i for i, col in enumerate(parent_columns, 1) if col[0] == key) for key in parent_names
            )
            operators = [{20: 410, 23: 96, 25: 98, 1043: 98, 1184: 1320}[parent_columns[k - 1][1]] for k in parent_keys]
            parent = relations[parent_name]["oid"]
            index, pins = _attest_dependency_parent_key(connection, relations, parent_name, parent_names)
            identities.extend(pins)
        wanted = _definition_constraint(
            relation, n, kind, keys, index=index, parent=parent, parent_keys=parent_keys, operators=operators
        )
        wanted.update(confupdtype=update, confdeltype=delete, condeferrable=deferrable, condeferred=deferred)
        tree = c.pop("conbin")
        wanted.pop("conbin")
        definitions = {definition}
        if target:
            definitions.add(definition.replace("REFERENCES ", "REFERENCES public.", 1))
        if (
            c != wanted
            or row["definition"] not in definitions
            or (tree is not None) != (kind == "c")
            or (tree is not None and (type(tree) is not str or not tree))
        ):
            _deny()
        identities.append((oid, _wire(c), tree))
        descriptors[(relation["relname"], n)] = descriptor
    return identities, descriptors


def _attest_authority_triggers(connection, relation, functions, constraints):
    expected = {p[0]: p for p in AUTHORITY_TRIGGERS[relation["relname"]]}
    rows = (
        connection.execute(
            text("""SELECT pg_catalog.to_jsonb(t) AS trigger,
      pg_catalog.pg_get_triggerdef(t.oid,false) AS definition
      FROM pg_catalog.pg_trigger t WHERE t.tgrelid=:oid AND NOT t.tgisinternal ORDER BY t.tgname"""),
            {"oid": relation["oid"]},
        )
        .mappings()
        .all()
    )
    if len(rows) != len(expected):
        _deny()
    seen, identities = set(), []
    for row in rows:
        if set(row) != {"trigger", "definition"}:
            _deny()
        t = _native_catalog_object(row["trigger"], "trigger")
        oid = t.pop("oid")
        n = t["tgname"]
        if n not in expected or n in seen:
            _deny()
        seen.add(n)
        _, fn, kind, constraint, definition = expected[n]
        deferred = constraint is not None
        wanted = dict(
            tgrelid=relation["oid"],
            tgparentid=0,
            tgname=n,
            tgfoid=functions[fn],
            tgtype=kind,
            tgenabled="O",
            tgisinternal=False,
            tgconstrrelid=0,
            tgconstrindid=0,
            tgconstraint=constraints[(relation["relname"], constraint)]["oid"] if deferred else 0,
            tgdeferrable=deferred,
            tginitdeferred=deferred,
            tgnargs=0,
            tgattr="",
            tgargs="\\x",
            tgqual=None,
            tgoldtable=None,
            tgnewtable=None,
        )
        if t != wanted or row["definition"] not in {
            definition,
            definition.replace("EXECUTE FUNCTION ", "EXECUTE FUNCTION public.", 1),
        }:
            _deny()
        identities.append((oid, _wire(t), row["definition"]))
    return identities


# PostgreSQL 16 bootstrap identities. These are system definitions, not OIDs
# allocated to this application's tables, roles, constraints or functions.
PG16_OPCLASSES = (
    (1978, "int4_ops", 1976, 23),
    (1981, "oid_ops", 1989, 26),
    (3124, "int8_ops", 1976, 20),
    (3126, "text_ops", 1994, 25),
    (3127, "timestamptz_ops", 434, 1184),
    (3128, "timestamp_ops", 434, 1114),
    (10003, "bool_ops", 424, 16),
)
# SQL-visible function names and native C symbols are separately pinned.
PG16_EQUALITY = (
    (98, 25, 531, "texteq", "text,text", "texteq"),
    (410, 20, 411, "int8eq", "bigint,bigint", "int8eq"),
    (1320, 1184, 1321, "timestamptz_eq", "timestamp with time zone,timestamp with time zone", "timestamp_eq"),
)
PG16_TYPES = (
    (16, "bool", 1, True, "c", "p", "B", 0),
    (17, "bytea", -1, False, "i", "x", "U", 0),
    (20, "int8", 8, True, "d", "p", "N", 0),
    (23, "int4", 4, True, "i", "p", "N", 0),
    (25, "text", -1, False, "i", "x", "S", 100),
    (26, "oid", 4, True, "i", "p", "N", 0),
    (114, "json", -1, False, "i", "x", "U", 0),
    (1043, "varchar", -1, False, "i", "x", "S", 100),
    (1114, "timestamp", 8, True, "d", "p", "D", 0),
    (1184, "timestamptz", 8, True, "d", "p", "D", 0),
)
PG16_TYPES_SQL = """
SELECT t.oid::bigint,t.typname,t.typlen,t.typbyval,t.typalign,t.typstorage,t.typcategory,t.typcollation::bigint,
 n.nspname,t.typtype,t.typbasetype::bigint,t.typrelid::bigint,t.typelem::bigint,
 t.oid=pg_catalog.to_regtype('pg_catalog.' || t.typname)
FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
WHERE t.oid=ANY(CAST(:oids AS oid[])) ORDER BY t.oid
"""


def _attest_pg16_system_definitions(connection):
    """Resolve canonical system types/opclasses/operators freshly on this port."""
    rows = connection.execute(text(PG16_TYPES_SQL), {"oids": [t[0] for t in PG16_TYPES]}).all()
    wanted = tuple((*t, "pg_catalog", "b", 0, 0, 0, True) for t in PG16_TYPES)
    if len(rows) != len(wanted):
        _deny()
    for row, expected in zip(rows, wanted):
        if tuple(row) != expected or any(type(v) is not type(e) for v, e in zip(row, expected)):
            _deny()
    identities = [wanted]
    for oid, name, family, typ in PG16_OPCLASSES:
        rows = (
            connection.execute(
                text("""SELECT pg_catalog.to_jsonb(o) AS opclass,n.nspname,a.amname,
          n.nspowner::bigint AS owner FROM pg_catalog.pg_opclass o
          JOIN pg_catalog.pg_namespace n ON n.oid=o.opcnamespace
          JOIN pg_catalog.pg_am a ON a.oid=o.opcmethod WHERE o.oid=:oid"""),
                {"oid": oid},
            )
            .mappings()
            .all()
        )
        if len(rows) != 1 or set(rows[0]) != {"opclass", "nspname", "amname", "owner"}:
            _deny()
        row = rows[0]
        owner = row["owner"]
        if type(owner) is not int or owner <= 0:
            _deny()
        expected = dict(
            oid=str(oid),
            opcname=name,
            opcowner=str(owner),
            opcfamily=str(family),
            opcintype=str(typ),
            opcmethod="403",
            opcdefault=True,
            opckeytype="0",
            opcnamespace="11",
        )
        if row["opclass"] != expected or row["nspname"] != "pg_catalog" or row["amname"] != "btree":
            _deny()
        if type(row["opclass"]) is not dict or row["opclass"]["opcdefault"] is not True:
            _deny()
        identities.append(_wire(expected))
    for oid, typ, negate, fn, args, implementation in PG16_EQUALITY:
        rows = (
            connection.execute(
                text("""SELECT pg_catalog.to_jsonb(o) AS operator,n.nspname,n.nspowner::bigint AS owner,
          p.prosrc,l.lanname,p.pronargs,p.prorettype::bigint,
          p.oid=pg_catalog.to_regprocedure(:function) AS canonical
          FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n ON n.oid=o.oprnamespace
          JOIN pg_catalog.pg_proc p ON p.oid=o.oprcode JOIN pg_catalog.pg_language l ON l.oid=p.prolang
          WHERE o.oid=:oid"""),
                {"oid": oid, "function": "pg_catalog." + fn + "(" + args + ")"},
            )
            .mappings()
            .all()
        )
        if len(rows) != 1 or set(rows[0]) != {
            "operator",
            "nspname",
            "owner",
            "prosrc",
            "lanname",
            "pronargs",
            "prorettype",
            "canonical",
        }:
            _deny()
        row = rows[0]
        owner = row["owner"]
        if type(owner) is not int or owner <= 0:
            _deny()
        expected = dict(
            oid=str(oid),
            oprcom=str(oid),
            oprcode=fn,
            oprjoin="eqjoinsel",
            oprkind="b",
            oprleft=str(typ),
            oprname="=",
            oprrest="eqsel",
            oprowner=str(owner),
            oprright=str(typ),
            oprnegate=str(negate),
            oprresult="16",
            oprcanhash=True,
            oprcanmerge=True,
            oprnamespace="11",
        )
        if (
            row["operator"] != expected
            or row["nspname"] != "pg_catalog"
            or row["prosrc"] != implementation
            or row["lanname"] != "internal"
            or type(row["pronargs"]) is not int
            or row["pronargs"] != 2
            or type(row["prorettype"]) is not int
            or row["prorettype"] != 16
            or row["canonical"] is not True
        ):
            _deny()
        if type(row["operator"]) is not dict or any(
            row["operator"][k] is not True for k in ("oprcanhash", "oprcanmerge")
        ):
            _deny()
        identities.append(_wire(expected))
    rows = (
        connection.execute(text("""SELECT pg_catalog.to_jsonb(c) AS collation,n.nspname,n.nspowner::bigint AS owner
      FROM pg_catalog.pg_collation c JOIN pg_catalog.pg_namespace n ON n.oid=c.collnamespace WHERE c.oid=100"""))
        .mappings()
        .all()
    )
    if len(rows) != 1 or set(rows[0]) != {"collation", "nspname", "owner"}:
        _deny()
    row = rows[0]
    if type(row["owner"]) is not int or row["owner"] <= 0:
        _deny()
    expected = dict(
        oid="100",
        collname="default",
        collctype=None,
        collowner=str(row["owner"]),
        collcollate=None,
        collversion=None,
        collencoding=-1,
        collicurules=None,
        collprovider="d",
        colliculocale=None,
        collnamespace="11",
        collisdeterministic=True,
    )
    if row["collation"] != expected or row["nspname"] != "pg_catalog":
        _deny()
    if (
        type(row["collation"]) is not dict
        or row["collation"]["collisdeterministic"] is not True
        or type(row["collation"]["collencoding"]) is not int
    ):
        _deny()
    identities.append(_wire(expected))
    return tuple(identities)
