-- Apply after Enrollment V2 challenge/association and routing registry migrations.
-- Exact consumption is durable history. This table stores no message body.
CREATE TABLE public.social_device_request_receipts_v1 (
    challenge_id VARCHAR(64) PRIMARY KEY CHECK (challenge_id ~ '^[0-9a-f]{64}$'),
    input_digest VARCHAR(128) NOT NULL,
    result_json TEXT NOT NULL CHECK (octet_length(result_json) BETWEEN 1 AND 2048),
    consumed_at BIGINT NOT NULL CHECK (consumed_at >= 0)
);
CREATE FUNCTION public.guard_social_device_request_receipt_v1()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'device request receipts are immutable'; END;
$$;
CREATE TRIGGER trg_social_request_receipt_immutable BEFORE UPDATE OR DELETE ON public.social_device_request_receipts_v1
    FOR EACH ROW EXECUTE FUNCTION public.guard_social_device_request_receipt_v1();
CREATE TRIGGER trg_social_request_receipt_no_truncate BEFORE TRUNCATE ON public.social_device_request_receipts_v1
    FOR EACH STATEMENT EXECUTE FUNCTION public.guard_social_device_request_receipt_v1();
REVOKE ALL ON public.social_device_request_receipts_v1 FROM PUBLIC;
REVOKE ALL ON FUNCTION public.guard_social_device_request_receipt_v1() FROM PUBLIC;

-- The native Enrollment V2 catalog pins the complete inbound challenge FK graph.
-- Keep that graph unchanged. This guarded reference has the same lifetime:
-- native challenge history cannot be deleted, replaced or truncated.
CREATE FUNCTION public.validate_social_device_request_receipt_v1()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE challenge RECORD; context JSONB; request JSONB; routing JSONB; result JSONB; decision RECORD;
BEGIN
    SELECT * INTO challenge FROM public.social_device_admission_challenges WHERE challenge_id=NEW.challenge_id FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'missing device request challenge'; END IF;
    context := challenge.context_wire::jsonb;
    request := (challenge.challenge_wire::jsonb->>'request')::jsonb;
    result := NEW.result_json::jsonb;
    IF challenge.state<>'issued' OR context->>'challengeKind'<>'device-request-v1'
        OR NEW.input_digest !~ '^hodlxxi-social-device-verification-input-v1-sha256:[0-9a-f]{64}$'
        OR NEW.consumed_at < (challenge.challenge_wire::jsonb->>'issuedAt')::bigint
        OR NEW.consumed_at >= (challenge.challenge_wire::jsonb->>'expiresAt')::bigint
        OR result->'allowed' IS DISTINCT FROM 'true'::jsonb
    THEN RAISE EXCEPTION 'invalid device request receipt'; END IF;
    IF request->>'operation'='ciphertext-submit' THEN
        routing := challenge.routing_request_wire::jsonb;
        SELECT * INTO decision FROM public.social_messaging_recipient_routing_decisions WHERE message_id=routing->>'messageId';
        IF NOT FOUND OR decision.viewer_subject<>context->>'subject'
            OR decision.envelope_digest<>routing->>'envelopeDigest'
            OR decision.snapshot_id<>routing->>'recipientPackageSnapshotId'
            OR result->>'recipientPackageSnapshotId'<>decision.snapshot_id
            OR result->'recipientDeviceHandles'<>routing->'recipientDeviceHandles'
            OR (result->>'senderDeviceHandle') !~ '^d_[A-Za-z0-9_-]{21}[AQgw]$'
        THEN RAISE EXCEPTION 'missing atomic message routing'; END IF;
    ELSIF request->>'operation'='recipient-self-read' THEN
        IF result->>'deviceHandle'<>request->>'recipientHandle' OR NOT EXISTS(
            SELECT 1 FROM public.social_messaging_recipient_handle_owners h
            WHERE h.device_handle=result->>'deviceHandle' AND h.recipient_subject=context->>'subject'
                AND h.device_id=context->>'deviceId' AND h.binding_id=context->>'bindingId'
                AND h.binding_version=(context->>'bindingVersion')::bigint)
        THEN RAISE EXCEPTION 'invalid exact self read'; END IF;
    ELSE RAISE EXCEPTION 'invalid message operation'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_social_request_receipt_bound BEFORE INSERT ON public.social_device_request_receipts_v1
    FOR EACH ROW EXECUTE FUNCTION public.validate_social_device_request_receipt_v1();
REVOKE ALL ON FUNCTION public.validate_social_device_request_receipt_v1() FROM PUBLIC;
