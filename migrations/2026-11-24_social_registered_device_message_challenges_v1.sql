-- A native finalizer keeps its frozen SELECT/UPDATE-only challenge-table ACL.
-- This narrow writer can create only message requests of an existing scoped
-- registered-device session. It cannot write enrollment challenges or sessions.
CREATE FUNCTION public.create_registered_device_message_challenge_v1(
    p_session text, p_credential_digest text, p_context text, p_challenge text, p_routing text
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
    original jsonb;
    ctx jsonb := p_context::jsonb;
    challenge jsonb := p_challenge::jsonb;
    actual jsonb;
BEGIN
    actual := (challenge->>'request')::jsonb;
    SELECT c.challenge_wire::jsonb INTO STRICT original
      FROM public.social_registered_device_sessions_v1 s
      JOIN public.social_registered_device_challenges_v1 c ON c.challenge_id=s.challenge_id
     WHERE s.session_id=p_session AND s.credential_digest=p_credential_digest
       AND NOT EXISTS (SELECT 1 FROM public.social_registered_device_revocations_v1 r WHERE r.session_id=s.session_id)
       AND s.issued_at <= (challenge->>'issuedAt')::bigint
       AND (challenge->>'issuedAt')::bigint < (challenge->>'expiresAt')::bigint
       AND (challenge->>'expiresAt')::bigint <= s.expires_at;
    IF (ctx->>'challengeKind'='device-request-v1'
        AND ctx->>'challengeId'=challenge->>'challengeId'
        AND challenge->>'domain'='HODLXXI_SOCIAL_MESSAGING_DEVICE_REQUEST_CHALLENGE_V1'
        AND actual->>'operation' IN ('ciphertext-submit','recipient-self-read')
        AND actual->>'sessionBinding'=ctx->>'sessionBinding'
        AND actual->>'subject'=ctx->>'subject'
        AND actual->>'deviceId'=ctx->>'deviceId'
        AND ctx->>'subject'=original->>'subject'
        AND ctx->>'deviceId'=original->>'deviceId'
        AND ctx->>'bindingId'=original->>'bindingId'
        AND ctx->>'bindingVersion'=original->>'bindingVersion'
        AND ctx->>'associationId'=original->>'associationId'
        AND ctx->>'authorityEpoch'=original->>'authorityEpoch'
        AND ctx->>'ed25519PublicKey'=original->>'ed25519PublicKey'
        AND ctx->>'audience'=original->>'audience'
    ) IS NOT TRUE THEN
        RAISE EXCEPTION 'registered device message challenge unavailable';
    END IF;
    INSERT INTO public.social_device_admission_challenges
        (challenge_id,context_wire,challenge_wire,routing_request_wire,state)
        VALUES(ctx->>'challengeId',p_context,p_challenge,p_routing,'issued');
END;
$$;
REVOKE ALL ON FUNCTION public.create_registered_device_message_challenge_v1(text,text,text,text,text) FROM PUBLIC;
