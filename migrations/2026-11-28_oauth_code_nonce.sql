-- Expand the schema before deploying the ordinary OIDC nonce read/write path.
ALTER TABLE public.oauth_codes ADD COLUMN nonce VARCHAR(256);
