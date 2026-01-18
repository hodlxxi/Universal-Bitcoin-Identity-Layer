-- 2026-01-18: billing robustness (avoid integer overflow)
-- Applied on production Postgres (hodlxxi).
--
-- 1) payments.amount_sats: int -> bigint
ALTER TABLE payments
  ALTER COLUMN amount_sats TYPE BIGINT
  USING amount_sats::bigint;

-- 2) ubid_users.sats_balance: already bigint in most setups, keep explicit
ALTER TABLE ubid_users
  ALTER COLUMN sats_balance TYPE BIGINT
  USING sats_balance::bigint;

-- 3) standardize pubkey storage width (compressed pubkey hex: 66 chars, 02/03 + 64 hex)
ALTER TABLE ubid_users
  ALTER COLUMN pubkey TYPE character varying(66);

-- NOTE:
-- You attempted to swap payments.user_pubkey FK from dev_accounts(user_pubkey) -> ubid_users(pubkey),
-- but it failed because some historical payments rows reference pubkeys not present in ubid_users.
-- Fix path later:
--   (a) backfill ubid_users from dev_accounts (or insert missing pubkeys),
--   (b) then drop/re-add the FK safely.
